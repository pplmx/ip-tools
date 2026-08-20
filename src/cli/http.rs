//! `http` subcommand handler (HTTP/1.1).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::http as ip_http;
use ip_tools::model::HttpObservation;
use ip_tools::report::render_http;
use std::process::ExitCode;

/// Resolve a target's addresses and perform an HTTPS/HTTP1.1 request to each
/// in parallel (bounded by `--concurrency`).
pub(super) async fn run_http(sub_m: &ArgMatches) -> ExitCode {
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    let insecure = sub_m.get_flag("insecure");
    run_probe_flow(
        sub_m,
        render_http,
        |obs: &HttpObservation| obs.destination,
        |obs: &HttpObservation| obs.failure.is_some(),
        move |host, dest, timeout| {
            let method = method.clone();
            async move {
                if insecure {
                    ip_http::probe_insecure(dest, &host, &method, timeout).await
                } else {
                    ip_http::probe(dest, &host, &method, timeout).await
                }
            }
        },
    )
    .await
}
