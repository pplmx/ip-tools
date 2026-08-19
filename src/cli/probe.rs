//! `probe` subcommand handler (repeated TCP probing).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::ProbeResult;
use ip_tools::probe as ip_probe;
use ip_tools::report::render_probe;
use std::process::ExitCode;

/// Resolve a target's addresses and repeatedly probe TCP connectivity to each
/// (per-address, sequential attempts; addresses in parallel).
pub(super) async fn run_probe(sub_m: &ArgMatches) -> ExitCode {
    let count = *sub_m.get_one::<usize>("count").expect("count has default");
    run_probe_flow(
        sub_m,
        render_probe,
        |result: &ProbeResult| result.destination,
        move |_host, dest, timeout| async move { ip_probe::tcp_repeat(dest, count, timeout).await },
    )
    .await
}
