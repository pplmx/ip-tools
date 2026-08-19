//! `http3` subcommand handler.

use super::{parallel_map, resolve_for_tcp, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::http3 as ip_http3;
use ip_tools::model::HttpObservation;
use ip_tools::report::{render_http, to_json};
use ip_tools::target::Target;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

/// Resolve a target's addresses and perform an HTTPS/HTTP3 (QUIC) request to
/// each in parallel (bounded by `--concurrency`).
pub(super) async fn run_http3(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");
    let method = sub_m.get_one::<String>("method").expect("method has default");
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
    let host = target.host.clone();
    let method = method.clone();

    let results: Vec<HttpObservation> = parallel_map(destinations, concurrency, move |dest| {
        let host = host.clone();
        let method = method.clone();
        async move { ip_http3::probe(dest, &host, &method, timeout).await }
    })
    .await;

    let mut results = results;
    results.sort_by_key(|o| o.destination);

    if json {
        println!("{}", to_json(&results));
    } else {
        print!("{}", render_http(&results));
    }
    ExitCode::SUCCESS
}
