use clap::{command, crate_authors, Arg, ArgAction, ArgMatches, Command};
use ip_tools::dns::DnsClient;
use ip_tools::model::{DnsRecordType, TcpObservation};
use ip_tools::report::{render_dns, render_tcp, to_json};
use ip_tools::target::Target;
use ip_tools::{get_local_ip, list_net_ifs, tcp};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Default timeout for single network operations, in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 5000;
/// Hard upper bound on concurrency to avoid resource exhaustion.
const MAX_CONCURRENCY: usize = 256;
/// Default port for `tcp` (and later TLS/HTTP) probes when none is given.
const DEFAULT_PORT: u16 = 443;

pub fn ip_tools_cli() -> ExitCode {
    let matches = parser();
    handler(&matches)
}

fn parser() -> ArgMatches {
    command!()
        .arg_required_else_help(true)
        .author(crate_authors!("\n"))
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("output in JSON format"),
        )
        .subcommand(Command::new("get").about("get the local IP address"))
        .subcommand(Command::new("list").about("list all network interfaces"))
        .subcommand(
            Command::new("dns")
                .about("resolve a hostname and inspect DNS results")
                .arg(positional_target("hostname to resolve"))
                .arg(
                    Arg::new("server")
                        .long("server")
                        .value_name("IP[:PORT]")
                        .action(ArgAction::Append)
                        .help("additional DNS server to query (repeatable); port defaults to 53"),
                )
                .arg(record_type_arg())
                .arg(timeout_arg()),
        )
        .subcommand(
            Command::new("tcp")
                .about("test TCP connectivity to a host:port across its addresses")
                .arg(positional_target("host[:port] to probe (default port 443)"))
                .arg(timeout_arg())
                .arg(concurrency_arg()),
        )
        .get_matches()
}

/// Common `--timeout` argument (milliseconds).
fn timeout_arg() -> Arg {
    Arg::new("timeout")
        .long("timeout")
        .value_name("MILLIS")
        .value_parser(clap::value_parser!(u64))
        .default_value("5000")
        .help("per-operation timeout in milliseconds")
}

/// Common `--concurrency` argument.
fn concurrency_arg() -> Arg {
    Arg::new("concurrency")
        .long("concurrency")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("32")
        .help("maximum number of parallel probes")
}

/// Select which DNS record types to query (`--ipv4` only / `--ipv6` only).
fn record_type_arg() -> Arg {
    Arg::new("ipv6")
        .long("ipv6")
        .action(ArgAction::SetTrue)
        .help("query AAAA records only (default: both A and AAAA)")
}

fn positional_target(help: &'static str) -> Arg {
    Arg::new("target").required(true).value_name("TARGET").help(help)
}

fn handler(app_m: &ArgMatches) -> ExitCode {
    match app_m.subcommand() {
        Some(("get", sub_m)) => handle_get(sub_m),
        Some(("list", sub_m)) => handle_list(sub_m),
        Some((name @ ("dns" | "tcp"), sub_m)) => run_tokio(name, sub_m),
        _ => {
            eprintln!("Error: unknown subcommand");
            ExitCode::FAILURE
        }
    }
}

/// Build a Tokio runtime and run the given async subcommand handler.
fn run_tokio(name: &str, sub_m: &ArgMatches) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match name {
        "dns" => rt.block_on(run_dns(sub_m)),
        "tcp" => rt.block_on(run_tcp(sub_m)),
        _ => unreachable!(),
    }
}

fn handle_get(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    match get_local_ip() {
        Ok(ip) => {
            if json {
                println!("{}", to_json(&IpOutput { ip }));
            } else {
                println!("{ip}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn handle_list(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    match list_net_ifs() {
        Ok(net_ifs) => {
            if json {
                let interfaces: Vec<InterfaceOutput> = net_ifs
                    .iter()
                    .map(|(name, ip)| InterfaceOutput {
                        name: name.clone(),
                        ip: *ip,
                    })
                    .collect();
                println!("{}", to_json(&interfaces));
            } else {
                for (name, ip) in &net_ifs {
                    println!("{name}: {ip}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run_dns(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let timeout = Duration::from_millis(timeout_ms);

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let custom: Vec<SocketAddr> = match parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let client = DnsClient::new(&custom, timeout, 1);
    let only_v6 = sub_m.get_flag("ipv6");

    let mut observations = Vec::new();
    let record_types = if only_v6 {
        vec![DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    };
    for rt in record_types {
        observations.extend(client.resolve(&target.host, rt).await);
    }

    if json {
        println!("{}", to_json(&observations));
    } else {
        print!("{}", render_dns(&target.host, &observations));
    }
    ExitCode::SUCCESS
}

/// Resolve a target's addresses and probe TCP connectivity to each in
/// parallel (bounded by `--concurrency`).
async fn run_tcp(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");
    let timeout = Duration::from_millis(timeout_ms);

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let addresses = match resolve_for_tcp(&target.host).await {
        Ok(addrs) => addrs,
        Err(err) => {
            eprintln!("Error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let destinations: Vec<SocketAddr> = addresses.iter().map(|ip| SocketAddr::new(*ip, target.port)).collect();

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.min(MAX_CONCURRENCY)));
    let mut tasks = tokio::task::JoinSet::new();
    for dest in destinations {
        let permit = semaphore.clone().acquire_owned().await.expect("semaphore not closed");
        tasks.spawn(async move {
            let obs = tcp::probe(dest, timeout).await;
            drop(permit);
            obs
        });
    }

    let mut results: Vec<TcpObservation> = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(obs) = res {
            results.push(obs);
        }
    }
    // Stable output ordering.
    results.sort_by_key(|o| o.destination);

    if json {
        println!("{}", to_json(&results));
    } else {
        print!("{}", render_tcp(&results));
    }
    ExitCode::SUCCESS
}

/// Resolve a hostname to its addresses (A + AAAA) for TCP probing.
///
/// If `host` is already an IP literal, it is used directly.
async fn resolve_for_tcp(host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let client = DnsClient::new(&[], Duration::from_millis(DEFAULT_TIMEOUT_MS), 1);
    let mut addrs = Vec::new();
    for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
        for obs in client.resolve(host, rt).await {
            if obs.error.is_none() {
                addrs.extend(obs.records);
            }
        }
    }
    if addrs.is_empty() {
        return Err(format!(
            "hostname {host} did not resolve to any address via the system resolver"
        ));
    }
    // De-duplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    addrs.retain(|a| seen.insert(*a));
    Ok(addrs)
}

fn parse_custom_servers(sub_m: &ArgMatches) -> Result<Vec<SocketAddr>, String> {
    let mut servers = Vec::new();
    if let Some(values) = sub_m.get_many::<String>("server") {
        for raw in values {
            let parsed = if let Ok(addr) = raw.parse::<SocketAddr>() {
                addr
            } else if let Ok(ip) = raw.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                return Err(format!("invalid DNS server {raw:?}; expected IP or IP:port"));
            };
            servers.push(parsed);
        }
    }
    Ok(servers)
}

/// Output structure for `get --json`.
#[derive(Serialize)]
struct IpOutput {
    ip: IpAddr,
}

/// Output structure for a single interface in `list --json`.
#[derive(Serialize)]
struct InterfaceOutput {
    name: String,
    ip: IpAddr,
}
