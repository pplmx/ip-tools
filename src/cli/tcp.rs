//! `tcp` subcommand handler.

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::TcpObservation;
use ip_tools::report::render_tcp;
use ip_tools::style::Style;
use ip_tools::tcp as ip_tcp;
use std::process::ExitCode;

/// Resolve a target's addresses and probe TCP connectivity to each in
/// parallel (bounded by `--concurrency`).
pub(super) async fn run_tcp(sub_m: &ArgMatches, style: Style) -> ExitCode {
    run_probe_flow(
        sub_m,
        style,
        render_tcp,
        |obs: &TcpObservation| obs.destination,
        |obs: &TcpObservation| !obs.success,
        Some(render_tcp_csv),
        None, /* `--expect-*` is an HTTP response-shape assertion (`tcp` has no status/body) */
        |_host, dest, timeout| async move { ip_tcp::probe(dest, timeout).await },
    )
    .await
}

/// Render a TCP fleet sweep as CSV: a header then one row per destination.
fn render_tcp_csv(per_target: &[(String, Vec<TcpObservation>)]) -> String {
    let mut out = String::from("host,destination,success,latency_ms,failure\n");
    for (host, results) in per_target {
        for o in results {
            out.push_str(&csv_field(host));
            out.push(',');
            out.push_str(&csv_field(&o.destination.to_string()));
            out.push(',');
            out.push(if o.success { '1' } else { '0' });
            out.push(',');
            out.push_str(&csv_field(&opt(o.latency_ms)));
            out.push(',');
            out.push_str(&csv_field(
                &o.failure.as_ref().map_or_else(String::new, |e| e.kind.to_string()),
            ));
            out.push('\n');
        }
    }
    out
}

fn opt(v: Option<u64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
}

/// Quote a CSV field when it contains a comma, quote, or newline (RFC 4180).
use super::csv_field;
