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
        Some(render_http_csv),
        move |host, dest, timeout| {
            let method = method.clone();
            let path = path.clone();
            let headers = headers.clone();
            let body = body.clone();
            async move {
                let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                if insecure {
                    ip_http::probe_insecure_with_version(
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
                    ip_http::probe_with_version(
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

/// Render an HTTP family fleet sweep as CSV: a header then one row per
/// destination, with the response status/protocol/TTFB when present. Shared
/// by `http`, `http2` and `http3`.
pub(super) fn render_http_csv(per_target: &[(String, Vec<HttpObservation>)]) -> String {
    let mut out = String::from("host,destination,protocol,status,location,body_bytes,ttfb_ms,latency_ms,failure\n");
    for (host, results) in per_target {
        for o in results {
            out.push_str(&csv_field(host));
            out.push(',');
            out.push_str(&csv_field(&o.destination.to_string()));
            out.push(',');
            out.push_str(&csv_field(o.protocol.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(&opt(o.status.map(u64::from))));
            out.push(',');
            out.push_str(&csv_field(o.location.as_deref().unwrap_or("")));
            out.push(',');
            out.push_str(&csv_field(&opt(o.body_bytes)));
            out.push(',');
            out.push_str(&csv_field(&opt(o.ttfb_ms)));
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
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
