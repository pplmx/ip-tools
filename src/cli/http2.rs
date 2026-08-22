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
    let path = sub_m.get_one::<String>("path").expect("path has default").clone();
    let insecure = sub_m.get_flag("insecure");
    let protocol = super::parse_tls_protocol(sub_m);
    let headers = match super::parse_custom_headers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let body = match super::parse_body(sub_m) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    run_probe_flow(
        sub_m,
        render_http,
        |obs: &HttpObservation| obs.destination,
        |obs: &HttpObservation| obs.failure.is_some(),
        Some(super::http::render_http_csv),
        move |host, dest, timeout| {
            let method = method.clone();
            let path = path.clone();
            let headers = headers.clone();
            let body = body.clone();
            async move {
                let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                if insecure {
                    ip_http2::probe_insecure_with_version(
                        dest,
                        &host,
                        &method,
                        &path,
                        &header_refs,
                        body.as_deref(),
                        timeout,
                        protocol,
                    )
                    .await
                } else {
                    ip_http2::probe_with_version(
                        dest,
                        &host,
                        &method,
                        &path,
                        &header_refs,
                        body.as_deref(),
                        timeout,
                        protocol,
                    )
                    .await
                }
            }
        },
    )
    .await
}
