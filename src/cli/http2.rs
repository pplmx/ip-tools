//! `http2` subcommand handler.

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::http2 as ip_http2;
use ip_tools::model::HttpObservation;
use ip_tools::report::render_http;
use std::process::ExitCode;

/// Resolve a target's addresses and perform an HTTPS/HTTP2 request to each in
/// parallel (bounded by `--concurrency`).
pub(super) async fn run_http2(sub_m: &ArgMatches) -> ExitCode {
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    run_probe_flow(
        sub_m,
        render_http,
        |obs: &HttpObservation| obs.destination,
        move |host, dest, timeout| {
            let method = method.clone();
            async move { ip_http2::probe(dest, &host, &method, timeout).await }
        },
    )
    .await
}
