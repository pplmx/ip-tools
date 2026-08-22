//! `diagnose` subcommand handler.

use super::{parallel_map, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::diagnostics::{diagnose, DiagnosticInput};
use ip_tools::dns::DnsClient;
use ip_tools::http as ip_http;
use ip_tools::http2 as ip_http2;
use ip_tools::http3 as ip_http3;
use ip_tools::model::{
    Diagnosis, DiagnosticCategory, DnsObservation, DnsRecordType, HttpObservation, ProbeResult, TcpObservation,
    TlsObservation,
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

/// Full diagnostic run: collect observations across layers, then run the
/// deterministic engine. The diagnostic engine performs no network I/O.
#[allow(clippy::too_many_lines)] // sequential pipeline steps are clearer inline
pub(super) async fn run_diagnose(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let insecure = sub_m.get_flag("insecure");
    let target_str = sub_m.get_one::<String>("target").expect("required target");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");
    let timeout = Duration::from_millis(timeout_ms);

    let target = match Target::parse(target_str, DEFAULT_PORT) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // A `--sni` override presents a chosen hostname as SNI (and HTTP `Host`)
    // while the probe pipeline still connects to the target's resolved
    // addresses — scoping the whole diagnosis to "how does this address
    // behave *as* that hostname" (its certificate, virtual-hosted response,
    // etc.). Resolution is unaffected; only the presented name changes.
    let presented = sub_m
        .try_get_one::<String>("sni")
        .ok()
        .flatten()
        .cloned()
        .unwrap_or_else(|| target.host.clone());
    // Request control for the HTTP phase: like `http`/`http2`/`http3`, the
    // HTTP evidence can be scoped to a specific method, path and extra
    // headers (e.g. a `/healthz` behind a WAF or an authenticated endpoint),
    // so the diagnosis covers the request the user actually cares about.
    let method = sub_m.get_one::<String>("method").expect("method has default").clone();
    let path = sub_m.get_one::<String>("path").expect("path has default").clone();
    let headers = match super::parse_custom_headers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let body: Option<Vec<u8>> = sub_m.get_one::<String>("body").map(|s| s.as_bytes().to_vec());

    // --- Measure (probe layer) ---
    // Resolve once: the DNS observations and the probed addresses come from
    // the same lookups (previously the hostname was resolved twice). Custom
    // `--server` resolvers are included so the engine can see resolver
    // disagreement, not just the system resolver's answer. An IP-literal
    // target short-circuits resolution (used directly), which is what makes
    // `--sni` on `diagnose` well-defined: the address set comes from the
    // target, the presented name comes from `--sni`.
    let custom_servers = match super::parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let dns_client = DnsClient::new(&custom_servers, timeout, 1);
    let doh_endpoints: Vec<String> = sub_m
        .get_many::<String>("doh")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let dot_eps: Vec<String> = sub_m
        .get_many::<String>("dot")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let mut dns_obs = Vec::new();
    let mut addresses: Vec<IpAddr> = Vec::new();
    // Bracket-form IPv6 literals (`[::1]`) must be recognized as literals.
    let literal = target.host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        addresses.push(ip);
    } else {
        for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
            let obs = dns_client.resolve(&target.host, rt).await;
            for o in &obs {
                if o.error.is_none() {
                    addresses.extend(o.records.iter().copied());
                }
            }
            dns_obs.extend(obs);
            // Encrypted-DNS resolvers (`--doh` / `--dot`) join the same
            // evidence and address pool: when the local path is being
            // steered, their answers feed resolver-disagreement detection
            // and are also probed.
            for endpoint in &doh_endpoints {
                let o = ip_tools::dns::doh_query(endpoint, &target.host, rt, timeout, insecure).await;
                if o.error.is_none() {
                    addresses.extend(o.records.iter().copied());
                }
                dns_obs.push(o);
            }
            for endpoint in &dot_eps {
                let o = ip_tools::dns::dot_query(endpoint, &target.host, rt, timeout, insecure).await;
                if o.error.is_none() {
                    addresses.extend(o.records.iter().copied());
                }
                dns_obs.push(o);
            }
        }
        // De-duplicate while preserving resolution order (as `resolve_for_tcp`).
        let mut seen = std::collections::HashSet::new();
        addresses.retain(|a| seen.insert(*a));
    }
    if addresses.is_empty() {
        eprintln!(
            "Error: hostname {} did not resolve to any address via the system resolver, --server, --doh, or --dot resolvers",
            target.host
        );
        return ExitCode::FAILURE;
    }
    let destinations: Vec<SocketAddr> = addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, target.port))
        .collect();

    let tcp_obs: Vec<TcpObservation> = parallel_map(destinations.clone(), concurrency, move |d| async move {
        ip_tcp::probe(d, timeout).await
    })
    .await;

    let sni = presented.clone();
    let tls_obs: Vec<TlsObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let sni = sni.clone();
        async move {
            if insecure {
                ip_tls::probe_insecure(d, &sni, timeout).await
            } else {
                ip_tls::probe(d, &sni, timeout).await
            }
        }
    })
    .await;

    let http_obs = collect_http_probes(
        destinations.clone(),
        &presented,
        &method,
        &path,
        &headers,
        body.as_deref(),
        concurrency,
        timeout,
        insecure,
    )
    .await;

    let probe_obs: Vec<ProbeResult> = parallel_map(destinations.clone(), concurrency, move |d| async move {
        ip_probe::tcp_repeat(d, 3, timeout).await
    })
    .await;

    // --- Diagnose (pure engine, no I/O) ---
    let input = DiagnosticInput {
        hostname: &target.host,
        dns: &dns_obs,
        tcp: &tcp_obs,
        tls: &tls_obs,
        http: &http_obs,
        probes: &probe_obs,
    };
    let diagnoses = diagnose(&input);

    // `--strict`: a diagnosis (other than Healthy) is an interpretation, but
    // scripting/CI often wants a non-zero exit once any anomaly was raised.
    // Computed before the JSON branch moves `diagnoses`; output is rendered
    // in full either way.
    let anomalies = if sub_m.get_flag("strict") {
        diagnoses
            .iter()
            .filter(|d| d.category != DiagnosticCategory::Healthy)
            .count()
    } else {
        0
    };

    if json {
        let report = DiagnoseReport {
            target: target.host.clone(),
            diagnoses,
            dns: dns_obs,
            tcp: tcp_obs,
            tls: tls_obs,
            http: http_obs,
            probes: probe_obs,
        };
        println!("{}", to_json(&report));
    } else {
        // Render the full evidence stack the engine reasoned over (DNS, TCP,
        // TLS, HTTP/1.1+2+3, repeated probes), not just DNS + TCP + verdicts.
        print!("{}", render_dns(&target.host, &dns_obs));
        print!("{}", render_tcp(&tcp_obs));
        print!("{}", render_tls(&tls_obs));
        print!("{}", render_http(&http_obs));
        print!("{}", render_probe(&probe_obs));
        print!("{}", render_diagnoses(&diagnoses));
    }
    if anomalies > 0 {
        eprintln!("Error: {anomalies} anomaly diagnosis(es) raised (--strict)");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
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

/// Probe HTTP/1.1, HTTP/2 and HTTP/3 for every address, concatenated.
// The request shape (host/method/path/headers) mirrors the underlying probes;
// the arity is a deliberate, readable signature rather than a hidden struct.
#[allow(clippy::too_many_arguments)]
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
                ip_http::probe_insecure(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
            } else {
                ip_http::probe(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
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
                ip_http2::probe_insecure(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
            } else {
                ip_http2::probe(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
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
                ip_http3::probe_insecure(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
            } else {
                ip_http3::probe(d, &host, &method, &path, &header_refs, body.as_deref(), timeout).await
            }
        }
    })
    .await;

    let mut out = http1;
    out.extend(http2);
    out.extend(http3);
    out
}
