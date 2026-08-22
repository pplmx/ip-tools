//! `probe` subcommand handler (repeated TCP/HTTP probing).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::ProbeResult;
use ip_tools::probe as ip_probe;
use ip_tools::report::render_probe;
use std::process::ExitCode;

/// Resolve a target's addresses and repeatedly probe connectivity to each,
/// using the protocol selected by `--protocol` (TCP by default; HTTP/1.1,
/// HTTP/2, HTTP/3 via `--protocol`). Per-address attempts run sequentially;
/// addresses are probed in parallel.
pub(super) async fn run_probe(sub_m: &ArgMatches) -> ExitCode {
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
    let protocol = sub_m
        .get_one::<String>("protocol")
        .expect("protocol has default")
        .clone();
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
        render_probe,
        |result: &ProbeResult| result.destination,
        |result: &ProbeResult| result.failures > 0,
        move |host, dest, timeout| {
            let method = method.clone();
            let path = path.clone();
            let protocol = protocol.clone();
            let headers = headers.clone();
            let body = body.clone();
            async move {
                let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
                match protocol.as_str() {
                    "tls" => ip_probe::tls_repeat(dest, &host, count, timeout, insecure).await,
                    "http" => {
                        ip_probe::http_repeat(
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
                    "http2" => {
                        ip_probe::http2_repeat(
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
