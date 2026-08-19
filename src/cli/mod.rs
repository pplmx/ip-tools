//! Command-line interface.
//!
//! This module is intentionally thin: it owns the clap argument tree, the
//! top-level dispatch, and a few shared helpers. Each subcommand's handler
//! lives in its own file under [`crate::cli`] (e.g. [`crate::cli::dns`]).

mod diagnose;
mod dns;
mod http;
mod http2;
mod http3;
mod probe;
mod route;
mod tcp;
mod tls;

use clap::{command, crate_authors, Arg, ArgAction, ArgMatches, Command};
use ip_tools::dns::DnsClient;
use ip_tools::model::DnsRecordType;
use ip_tools::report::to_json;
use ip_tools::target::Target;
use ip_tools::{get_local_ip, list_net_ifs};
use serde::Serialize;
use std::future::Future;
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

#[allow(clippy::too_many_lines)] // clap subcommand declarations
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
        .subcommand(probe_command(
            "tcp",
            "test TCP connectivity to a host:port across its addresses",
            None,
        ))
        .subcommand(probe_command(
            "tls",
            "perform TLS handshake to a host:port across its addresses",
            None,
        ))
        .subcommand(probe_command(
            "http",
            "perform an HTTPS/HTTP1.1 request to a host:port across its addresses",
            Some(method_arg()),
        ))
        .subcommand(probe_command(
            "probe",
            "repeatedly probe TCP connectivity and report latency statistics",
            Some(count_arg()),
        ))
        .subcommand(probe_command(
            "http2",
            "perform an HTTPS/HTTP2 request to a host:port across its addresses",
            Some(method_arg()),
        ))
        .subcommand(probe_command(
            "http3",
            "perform an HTTPS/HTTP3 (QUIC) request to a host:port across its addresses",
            Some(method_arg()),
        ))
        .subcommand(
            Command::new("route")
                .about("trace the network path (hops) to a host (Linux, requires root)")
                .arg(positional_target("host to trace"))
                .arg(
                    Arg::new("max-hops")
                        .long("max-hops")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8))
                        .default_value("30")
                        .help("maximum number of hops"),
                )
                .arg(
                    Arg::new("probes-per-hop")
                        .long("probes-per-hop")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8))
                        .default_value("3")
                        .help("probes per hop"),
                )
                .arg(timeout_arg()),
        )
        .subcommand(probe_command(
            "diagnose",
            "run the full probe pipeline and produce evidence-based diagnoses",
            None,
        ))
        .get_matches()
}

/// Build a per-address probe subcommand: positional target plus the shared
/// `--timeout`/`--concurrency` flags, and an optional subcommand-specific flag
/// (e.g. `--method`) inserted after the target.
fn probe_command(name: &'static str, about: &'static str, extra: Option<Arg>) -> Command {
    let mut cmd = Command::new(name)
        .about(about)
        .arg(positional_target("host[:port] to probe (default port 443)"));
    if let Some(extra) = extra {
        cmd = cmd.arg(extra);
    }
    cmd.arg(timeout_arg()).arg(concurrency_arg())
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

/// `--count` argument for repeated probing.
fn count_arg() -> Arg {
    Arg::new("count")
        .long("count")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("10")
        .help("number of repeated attempts per address")
}

/// Shared `--method` argument.
fn method_arg() -> Arg {
    Arg::new("method")
        .long("method")
        .value_name("METHOD")
        .default_value("GET")
        .help("HTTP method to use (GET or HEAD)")
}

/// Select which DNS record types to query (`--ipv6` only, else both).
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
        Some((name @ ("dns" | "tcp" | "tls" | "http" | "http2" | "http3" | "probe" | "route" | "diagnose"), sub_m)) => {
            run_tokio(name, sub_m)
        }
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
        "dns" => rt.block_on(dns::run_dns(sub_m)),
        "tcp" => rt.block_on(tcp::run_tcp(sub_m)),
        "tls" => rt.block_on(tls::run_tls(sub_m)),
        "http" => rt.block_on(http::run_http(sub_m)),
        "http2" => rt.block_on(http2::run_http2(sub_m)),
        "http3" => rt.block_on(http3::run_http3(sub_m)),
        "probe" => rt.block_on(probe::run_probe(sub_m)),
        "route" => rt.block_on(route::run_route(sub_m)),
        "diagnose" => rt.block_on(diagnose::run_diagnose(sub_m)),
        _ => unreachable!(),
    }
}

/// Shared pipeline for the per-address probe subcommands (`tcp`, `tls`,
/// `http`, `http2`, `http3`, `probe`): parse the target, resolve its
/// addresses, probe each in parallel (bounded by `--concurrency`), then emit
/// sorted human or JSON output.
///
/// `probe` is invoked once per destination with `(host, destination,
/// timeout)`; subcommand-specific state (e.g. `--method`, `--count`) is
/// captured by the caller's closure.
pub async fn run_probe_flow<O, Fut>(
    sub_m: &ArgMatches,
    render: fn(&[O]) -> String,
    sort_key: fn(&O) -> SocketAddr,
    probe: impl Fn(String, SocketAddr, Duration) -> Fut + Send + Sync + 'static,
) -> ExitCode
where
    O: Sized + serde::Serialize + Send + 'static,
    Fut: Future<Output = O> + Send + 'static,
{
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

    let destinations: Vec<SocketAddr> = addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, target.port))
        .collect();
    let host = target.host.clone();
    let mut results: Vec<O> = parallel_map(destinations, concurrency, move |dest| {
        let host = host.clone();
        probe(host, dest, timeout)
    })
    .await;
    results.sort_by_key(sort_key);

    if json {
        println!("{}", to_json(&results));
    } else {
        print!("{}", render(&results));
    }
    ExitCode::SUCCESS
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

/// Apply `f` to `items` concurrently, bounded by `concurrency` (capped at
/// [`MAX_CONCURRENCY`]).
pub async fn parallel_map<I, T, F, Fut>(items: Vec<I>, concurrency: usize, f: F) -> Vec<T>
where
    I: Send + 'static,
    T: Send + 'static,
    F: Fn(I) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.clamp(1, MAX_CONCURRENCY)));
    let f = std::sync::Arc::new(f);
    let mut tasks = tokio::task::JoinSet::new();
    for item in items {
        let permit = semaphore.clone().acquire_owned().await.expect("semaphore not closed");
        let f = std::sync::Arc::clone(&f);
        tasks.spawn(async move {
            let result = f(item).await;
            drop(permit);
            result
        });
    }
    let mut out = Vec::with_capacity(tasks.len());
    while let Some(res) = tasks.join_next().await {
        if let Ok(value) = res {
            out.push(value);
        }
    }
    out
}

/// Resolve a hostname to its addresses (A + AAAA).
///
/// If `host` is already an IP literal, it is used directly.
pub async fn resolve_for_tcp(host: &str) -> Result<Vec<IpAddr>, String> {
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

/// Parse repeatable `--server` values as DNS server socket addresses.
pub fn parse_custom_servers(sub_m: &ArgMatches) -> Result<Vec<SocketAddr>, String> {
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
