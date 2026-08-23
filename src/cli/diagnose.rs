//! `diagnose` subcommand handler.

use super::{parallel_map, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::diagnostics::{diagnose, DiagnosticInput};
use ip_tools::dns::DnsClient;
use ip_tools::http as ip_http;
use ip_tools::http2 as ip_http2;
use ip_tools::http3 as ip_http3;
use ip_tools::model::{
    Diagnosis, DiagnosticCategory, DnsObservation, DnsRecord, DnsRecordType, HttpObservation, ProbeResult,
    TcpObservation, TlsObservation,
};
use ip_tools::probe as ip_probe;
use ip_tools::report::{render_diagnoses, render_dns, render_http, render_probe, render_tcp, render_tls, to_json};
use ip_tools::target::Target;
use ip_tools::tcp as ip_tcp;
use ip_tools::tls as ip_tls;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Full diagnostic run: collect observations across layers for one or more
/// targets, then run the deterministic engine (which performs no network I/O).
///
/// `diagnose` accepts many targets — a fleet/health sweep — running the full
/// pipeline per host sequentially. Single-target JSON stays the existing
/// object; >1 target emits a JSON array; `--strict` aggregates across hosts.
#[allow(clippy::too_many_lines)] // orchestration: parse, loop hosts, render
pub(super) async fn run_diagnose(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let csv = sub_m.get_flag("csv");
    let insecure = sub_m.get_flag("insecure");
    let tls_protocol = super::parse_tls_protocol(sub_m);
    let max_body_bytes = *sub_m
        .get_one::<u64>("max-body-bytes")
        .expect("max-body-bytes has default");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");
    let timeout = Duration::from_millis(timeout_ms);

    let raw_targets: Vec<String> = sub_m
        .get_many::<String>("target")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let mut targets = Vec::with_capacity(raw_targets.len());
    for raw in &raw_targets {
        match Target::parse(raw, DEFAULT_PORT) {
            Ok(t) => targets.push(t),
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // A `--sni` override presents a chosen hostname as SNI (and HTTP `Host`)
    // while the probe pipeline still connects to each target's resolved
    // addresses — scoping the diagnosis to "how does this address behave *as*
    // that hostname". Resolution is unaffected; only the presented name
    // changes (per-host it falls back to that host's name).
    let sni = sub_m.try_get_one::<String>("sni").ok().flatten().cloned();
    // Request control for the HTTP phase, shared by every target.
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    let path = sub_m.get_one::<String>("path").expect("path has default").clone();
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
    let custom_servers = match super::parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let doh_endpoints: Vec<String> = sub_m
        .get_many::<String>("doh")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let dot_eps: Vec<String> = sub_m
        .get_many::<String>("dot")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();

    let mut reports: Vec<DiagnoseReport> = Vec::with_capacity(targets.len());
    let mut unresolved = 0usize;
    for target in targets {
        let presented = sni.clone().unwrap_or_else(|| target.host.clone());
        match diagnose_one(
            &target,
            &presented,
            &method,
            &path,
            &headers,
            body.as_deref(),
            &custom_servers,
            &doh_endpoints,
            &dot_eps,
            timeout,
            concurrency,
            insecure,
            tls_protocol,
            max_body_bytes,
        )
        .await
        {
            Some(report) => reports.push(report),
            None => unresolved += 1,
        }
    }

    // `--strict`: any non-Healthy diagnosis across any host exits non-zero.
    let anomalies = if sub_m.get_flag("strict") {
        reports
            .iter()
            .flat_map(|r| &r.diagnoses)
            .filter(|d| d.category != DiagnosticCategory::Healthy)
            .count()
    } else {
        0
    };

    if csv {
        print!("{}", render_csv(&reports));
    } else if json {
        if reports.len() == 1 {
            println!("{}", to_json(&reports[0]));
        } else {
            println!("{}", to_json(&reports));
        }
    } else {
        for report in &reports {
            print!("{}", report.render_human());
        }
    }

    if unresolved > 0 {
        eprintln!("Error: {unresolved} host(s) did not resolve to any address");
        return ExitCode::FAILURE;
    }
    if anomalies > 0 {
        eprintln!("Error: {anomalies} anomaly diagnosis(es) raised (--strict)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Run the full probe + engine pipeline for a single target and build its
/// [`DiagnoseReport`]. Returns `None` (having printed a resolution error) when
/// the hostname resolves to no address.
#[allow(clippy::too_many_arguments)] // the shared request + probe configuration
#[allow(clippy::too_many_lines)] // sequential pipeline steps are clearer inline
async fn diagnose_one(
    target: &Target,
    presented: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    custom_servers: &[SocketAddr],
    doh_endpoints: &[String],
    dot_eps: &[String],
    timeout: Duration,
    concurrency: usize,
    insecure: bool,
    tls_protocol: ip_tools::tls::TlsProtocol,
    max_body_bytes: u64,
) -> Option<DiagnoseReport> {
    // Resolve once: the DNS observations and the probed addresses come from
    // the same lookups. Custom `--server`/`--doh`/`--dot` resolvers are
    // included so the engine can see resolver disagreement. An IP-literal
    // target short-circuits resolution (used directly), which is what makes
    // `--sni` well-defined.
    let dns_client = DnsClient::new(custom_servers, timeout, 1);
    let mut dns_obs = Vec::new();
    let mut addresses: Vec<IpAddr> = Vec::new();
    let literal = target.host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        addresses.push(ip);
    } else {
        for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
            let obs = dns_client.resolve(&target.host, rt).await;
            for o in &obs {
                if o.error.is_none() {
                    addresses.extend(o.records.iter().filter_map(DnsRecord::address));
                }
            }
            dns_obs.extend(obs);
            for endpoint in doh_endpoints {
                let o = ip_tools::dns::doh_query(endpoint, &target.host, rt, timeout, insecure).await;
                if o.error.is_none() {
                    addresses.extend(o.records.iter().filter_map(DnsRecord::address));
                }
                dns_obs.push(o);
            }
            for endpoint in dot_eps {
                let o = ip_tools::dns::dot_query(endpoint, &target.host, rt, timeout, insecure).await;
                if o.error.is_none() {
                    addresses.extend(o.records.iter().filter_map(DnsRecord::address));
                }
                dns_obs.push(o);
            }
        }
        let mut seen = std::collections::HashSet::new();
        addresses.retain(|a| seen.insert(*a));
    }
    if addresses.is_empty() {
        eprintln!(
            "Error: hostname {} did not resolve to any address via the system resolver, --server, --doh, or --dot resolvers",
            target.host
        );
        return None;
    }
    let destinations: Vec<SocketAddr> = addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, target.port))
        .collect();

    let tcp_obs: Vec<TcpObservation> = parallel_map(destinations.clone(), concurrency, move |d| async move {
        ip_tcp::probe(d, timeout).await
    })
    .await;

    let sni = presented.to_string();
    let tls_obs: Vec<TlsObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let sni = sni.clone();
        let tls_protocol = tls_protocol;
        async move {
            if insecure {
                ip_tls::probe_insecure_with_version(d, &sni, timeout, tls_protocol).await
            } else {
                ip_tls::probe_with_version(d, &sni, timeout, tls_protocol).await
            }
        }
    })
    .await;

    let http_obs = collect_http_probes(
        destinations.clone(),
        presented,
        method,
        path,
        headers,
        body,
        concurrency,
        timeout,
        insecure,
        tls_protocol,
        max_body_bytes,
    )
    .await;

    let probe_obs: Vec<ProbeResult> = parallel_map(destinations.clone(), concurrency, move |d| async move {
        ip_probe::tcp_repeat(d, 3, timeout).await
    })
    .await;

    let input = DiagnosticInput {
        hostname: &target.host,
        dns: &dns_obs,
        tcp: &tcp_obs,
        tls: &tls_obs,
        http: &http_obs,
        probes: &probe_obs,
    };
    let diagnoses = diagnose(&input);

    Some(DiagnoseReport {
        target: target.host.clone(),
        diagnoses,
        dns: dns_obs,
        tcp: tcp_obs,
        tls: tls_obs,
        http: http_obs,
        probes: probe_obs,
    })
}

/// Aggregated JSON report: full raw observations (evidence) plus diagnoses.
#[derive(Serialize)]
struct DiagnoseReport {
    target: String,
    diagnoses: Vec<Diagnosis>,
    dns: Vec<DnsObservation>,
    tcp: Vec<TcpObservation>,
    tls: Vec<TlsObservation>,
    http: Vec<HttpObservation>,
    probes: Vec<ProbeResult>,
}

impl DiagnoseReport {
    /// Render the full evidence stack (DNS, TCP, TLS, HTTP/1.1+2+3, repeated
    /// probes) and the verdicts as human text, so multi-target output is the
    /// concatenation of each host's report.
    fn render_human(&self) -> String {
        let mut out = render_dns(&self.target, &self.dns);
        out.push_str(&render_tcp(&self.tcp));
        out.push_str(&render_tls(&self.tls));
        out.push_str(&render_http(&self.http));
        out.push_str(&render_probe(&self.probes));
        out.push_str(&render_diagnoses(&self.diagnoses));
        out
    }
}

/// Escape a single CSV field: quote it when it contains a comma, quote, or
/// newline, doubling embedded quotes (RFC 4180).
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Render every diagnosis across every report as CSV rows: a header line then
/// one `host,severity,category,confidence,summary` row per diagnosis. A host
/// with several verdicts (e.g. IP-literal two-family rows) yields several
/// rows, so a spreadsheet can pivot on `host`.
fn render_csv(reports: &[DiagnoseReport]) -> String {
    let mut out = String::from("host,severity,category,confidence,summary\n");
    for report in reports {
        for d in &report.diagnoses {
            out.push_str(&csv_field(&report.target));
            out.push(',');
            out.push_str(&csv_field(&format!("{:?}", d.severity)));
            out.push(',');
            out.push_str(&csv_field(&format!("{:?}", d.category)));
            out.push(',');
            out.push_str(&csv_field(&format!("{:?}", d.confidence)));
            out.push(',');
            out.push_str(&csv_field(&d.summary));
            out.push('\n');
        }
    }
    out
}

/// Probe HTTP/1.1, HTTP/2 and HTTP/3 for every address, concatenated.
// The request shape (host/method/path/headers) mirrors the underlying probes;
// the arity is a deliberate, readable signature rather than a hidden struct.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // sequential per-protocol parallel probes are clearer inline
async fn collect_http_probes(
    destinations: Vec<SocketAddr>,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    concurrency: usize,
    timeout: Duration,
    insecure: bool,
    tls_protocol: ip_tools::tls::TlsProtocol,
    max_body_bytes: u64,
) -> Vec<HttpObservation> {
    // Each `parallel_map` closure is `move` and spawns `'static` futures, so
    // every captured value (host, method, path, headers) must be an owned
    // clone per protocol that the `async move` block can take.
    let (host_1, host_2, host_3) = (host.to_string(), host.to_string(), host.to_string());
    let (method_1, method_2, method_3) = (method.to_string(), method.to_string(), method.to_string());
    let (path_1, path_2, path_3) = (path.to_string(), path.to_string(), path.to_string());
    let (headers_1, headers_2, headers_3) = (headers.to_vec(), headers.to_vec(), headers.to_vec());
    let (body_1, body_2, body_3) = (
        body.map(<[u8]>::to_vec),
        body.map(<[u8]>::to_vec),
        body.map(<[u8]>::to_vec),
    );

    let http1: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let (host, method, path, headers, body) = (
            host_1.clone(),
            method_1.clone(),
            path_1.clone(),
            headers_1.clone(),
            body_1.clone(),
        );
        async move {
            let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
            if insecure {
                ip_http::probe_insecure_with_version_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    tls_protocol,
                    max_body_bytes,
                    None,
                )
                .await
            } else {
                ip_http::probe_with_version_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    tls_protocol,
                    max_body_bytes,
                    None,
                )
                .await
            }
        }
    })
    .await;

    let http2: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let (host, method, path, headers, body) = (
            host_2.clone(),
            method_2.clone(),
            path_2.clone(),
            headers_2.clone(),
            body_2.clone(),
        );
        async move {
            let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
            if insecure {
                ip_http2::probe_insecure_with_version_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    tls_protocol,
                    max_body_bytes,
                    None,
                )
                .await
            } else {
                ip_http2::probe_with_version_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    tls_protocol,
                    max_body_bytes,
                    None,
                )
                .await
            }
        }
    })
    .await;

    let http3: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let (host, method, path, headers, body) = (
            host_3.clone(),
            method_3.clone(),
            path_3.clone(),
            headers_3.clone(),
            body_3.clone(),
        );
        async move {
            let header_refs: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
            if insecure {
                ip_http3::probe_insecure_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    max_body_bytes,
                    None,
                )
                .await
            } else {
                ip_http3::probe_output(
                    d,
                    &host,
                    &method,
                    &path,
                    &header_refs,
                    body.as_deref(),
                    timeout,
                    max_body_bytes,
                    None,
                )
                .await
            }
        }
    })
    .await;

    let mut out = http1;
    out.extend(http2);
    out.extend(http3);
    out
}
