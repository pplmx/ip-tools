//! `tcp` subcommand handler.

use super::{parallel_map, resolve_for_tcp, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::model::TcpObservation;
use ip_tools::report::{render_tcp, to_json};
use ip_tools::target::Target;
use ip_tools::tcp as ip_tcp;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

/// Resolve a target's addresses and probe TCP connectivity to each in
/// parallel (bounded by `--concurrency`).
pub(super) async fn run_tcp(sub_m: &ArgMatches) -> ExitCode {
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

    let results: Vec<TcpObservation> = parallel_map(destinations, concurrency, move |dest| async move {
        ip_tcp::probe(dest, timeout).await
    })
    .await;

    // Stable output ordering.
    let mut results = results;
    results.sort_by_key(|o| o.destination);

    if json {
        println!("{}", to_json(&results));
    } else {
        print!("{}", render_tcp(&results));
    }
    ExitCode::SUCCESS
}
