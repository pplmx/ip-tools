//! `probe` subcommand handler (repeated TCP/HTTP probing).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::ProbeResult;
use ip_tools::probe as ip_probe;
use ip_tools::report::render_probe;
use ip_tools::style::Style;
use std::process::ExitCode;

/// Resolve a target's addresses and repeatedly probe connectivity to each,
/// using the protocol selected by `--protocol` (TCP by default; HTTP/1.1,
/// HTTP/2, HTTP/3 via `--protocol`). Per-address attempts run sequentially;
/// addresses are probed in parallel.
#[allow(clippy::too_many_lines)] // one match arm per protocol is clearest inline
pub(super) async fn run_probe(sub_m: &ArgMatches, style: Style) -> ExitCode {
    let count = *sub_m.get_one::<usize>("count").expect("count has default");
    if count == 0 {
        // Zero attempts would render a vacuous "0 attempts, 0.0% success"
        // report as a success; a zero count is a caller mistake, so fail with
        // a clear error instead (route similarly never runs zero probes).
        eprintln!("Error: --count must be at least 1");
        return ExitCode::FAILURE;
    }
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    let path = sub_m.get_one::<String>("path").expect("path has default").clone();
    let insecure = sub_m.get_flag("insecure");
    let tls_protocol = super::parse_tls_protocol(sub_m);
    let protocol = sub_m
        .get_one::<String>("protocol")
        .expect("protocol has default")
        .clone();
    let plain = sub_m.get_flag("plain");
    if plain && protocol.as_str() != "http" {
        eprintln!("Error: --plain only applies to --protocol http (cleartext HTTP/1.1)");
        return ExitCode::FAILURE;
    }
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
        style,
        render_probe,
        |result: &ProbeResult| result.destination,
        |result: &ProbeResult| result.failures > 0,
        Some(render_probe_csv),
        move |host, dest, timeout| {
            let method = method.clone();
            let path = path.clone();
            let protocol = protocol.clone();
            let headers = headers.clone();
            let body = body.clone();
            async move {
                let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                match protocol.as_str() {
                    "tls" => {
                        ip_probe::tls_repeat_with_version(dest, &host, count, timeout, insecure, tls_protocol).await
                    }
                    "http" => {
                        if plain {
                            ip_probe::http_repeat_plain(
                                dest,
                                &host,
                                &method,
                                &path,
                                &header_refs,
                                body.as_deref(),
                                count,
                                timeout,
                            )
                            .await
                        } else {
                            ip_probe::http_repeat_with_version(
                                dest,
                                &host,
                                &method,
                                &path,
                                &header_refs,
                                body.as_deref(),
                                count,
                                timeout,
                                insecure,
                                tls_protocol,
                            )
                            .await
                        }
                    }
                    "http2" => {
                        ip_probe::http2_repeat_with_version(
                            dest,
                            &host,
                            &method,
                            &path,
                            &header_refs,
                            body.as_deref(),
                            count,
                            timeout,
                            insecure,
                            tls_protocol,
                        )
                        .await
                    }
                    "http3" => {
                        ip_probe::http3_repeat(
                            dest,
                            &host,
                            &method,
                            &path,
                            &header_refs,
                            body.as_deref(),
                            count,
                            timeout,
                            insecure,
                        )
                        .await
                    }
                    _ => ip_probe::tcp_repeat(dest, count, timeout).await,
                }
            }
        },
    )
    .await
}

/// Render every repeated-probe result as CSV: a header then one
/// `host,destination,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,jitter_ms,failures,statuses`
/// row per destination across every target. Latency statistics come from the
/// `--count` aggregation (only successful attempts).
fn render_probe_csv(per_target: &[(String, Vec<ProbeResult>)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "host,destination,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,jitter_ms,ttfb_p50_ms,ttfb_p95_ms,ttfb_max_ms,failures,statuses\n",
    );
    for (host, results) in per_target {
        for r in results {
            out.push_str(&csv_field(host));
            out.push(',');
            out.push_str(&csv_field(&r.destination.to_string()));
            out.push(',');
            out.push_str(&r.attempts.to_string());
            out.push(',');
            let _ = write!(out, "{:.4}", r.success_rate);
            out.push(',');
            out.push_str(&opt64(r.latency.p50));
            out.push(',');
            out.push_str(&opt64(r.latency.p95));
            out.push(',');
            out.push_str(&opt64(r.latency.max));
            out.push(',');
            out.push_str(&opt64(r.latency.jitter));
            out.push(',');
            // Server-response latency (HTTP repeats only): TTFB percentiles,
            // empty for the tcp/tls transport repeats.
            out.push_str(&opt64(r.ttfb.p50));
            out.push(',');
            out.push_str(&opt64(r.ttfb.p95));
            out.push(',');
            out.push_str(&opt64(r.ttfb.max));
            out.push(',');
            out.push_str(&r.failures.to_string());
            out.push(',');
            if r.status_counts.is_empty() {
                // tcp/tls transport-repeat probes carry no HTTP statuses, so
                // the statuses field is left empty (the comma already opened
                // it and the trailing newline closes it).
            } else {
                let dist: String = r
                    .status_counts
                    .iter()
                    .map(|s| format!("{}x{}", s.status, s.count))
                    .collect::<Vec<_>>()
                    .join(";");
                out.push_str(&csv_field(&dist));
            }
            out.push('\n');
        }
    }
    out
}

/// Format an optional millisecond value as an empty field or its value.
fn opt64(v: Option<u64>) -> String {
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
