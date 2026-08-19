//! `route` subcommand handler.

use super::{resolve_for_tcp, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::report::{render_route, to_json};
use ip_tools::route as ip_route;
use ip_tools::target::Target;
use ip_tools::TracerouteConfig;
use std::process::ExitCode;
use std::time::Duration;

/// Trace the network path to a host (Linux, needs root). Runs the blocking
/// traceroute off the async runtime, then reverse-resolves router names.
pub(super) async fn run_route(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let max_hops = *sub_m.get_one::<u8>("max-hops").expect("max-hops has default");
    let probes_per_hop = *sub_m
        .get_one::<u8>("probes-per-hop")
        .expect("probes-per-hop has default");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");

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
    let Some(&dest_ip) = addresses.iter().find(|a| a.is_ipv4()) else {
        eprintln!("Error: route diagnostics need an IPv4 address for {}", target.host);
        return ExitCode::FAILURE;
    };

    let cfg = TracerouteConfig {
        max_hops: max_hops.max(1),
        timeout: Duration::from_millis(timeout_ms),
        probes_per_hop: probes_per_hop.max(1),
    };

    let hops = match tokio::task::spawn_blocking(move || ip_route::traceroute(dest_ip, &cfg)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("Error: traceroute task failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Reverse-resolve router addresses (best effort).
    let mut hops = hops;
    if let Ok(builder) = hickory_resolver::TokioResolver::builder_tokio() {
        if let Ok(resolver) = builder.build() {
            for hop in &mut hops {
                if let Some(addr) = hop.addr {
                    if let Ok(lookup) = resolver.reverse_lookup(addr).await {
                        if let Some(rec) = lookup.answers().first() {
                            if let hickory_resolver::proto::rr::RData::PTR(name) = &rec.data {
                                hop.hostname = Some(name.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    if json {
        println!("{}", to_json(&hops));
    } else {
        print!("{}", render_route(&hops));
    }
    ExitCode::SUCCESS
}
