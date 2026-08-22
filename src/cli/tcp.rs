//! `tcp` subcommand handler.

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::TcpObservation;
use ip_tools::report::render_tcp;
use ip_tools::tcp as ip_tcp;
use std::process::ExitCode;

/// Resolve a target's addresses and probe TCP connectivity to each in
/// parallel (bounded by `--concurrency`).
pub(super) async fn run_tcp(sub_m: &ArgMatches) -> ExitCode {
    run_probe_flow(
        sub_m,
        render_tcp,
        |obs: &TcpObservation| obs.destination,
        |obs: &TcpObservation| !obs.success,
        None,
        |_host, dest, timeout| async move { ip_tcp::probe(dest, timeout).await },
    )
    .await
}
