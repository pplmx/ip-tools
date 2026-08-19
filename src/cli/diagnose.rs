//! `diagnose` subcommand handler.

use super::{parallel_map, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::diagnostics::{diagnose, DiagnosticInput};
use ip_tools::dns::DnsClient;
use ip_tools::http as ip_http;
use ip_tools::http2 as ip_http2;
use ip_tools::http3 as ip_http3;
use ip_tools::model::{
    Diagnosis, DnsObservation, DnsRecordType, HttpObservation, ProbeResult, TcpObservation, TlsObservation,
};
use ip_tools::probe as ip_probe;
use ip_tools::report::{render_diagnoses, render_dns, render_tcp, to_json};
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

    // --- Measure (probe layer) ---
    // Resolve once: the DNS observations and the probed addresses come from
    // the same lookups (previously the hostname was resolved twice).
    let dns_client = DnsClient::new(&[], timeout, 1);
    let mut dns_obs = Vec::new();
    let mut addresses: Vec<IpAddr> = Vec::new();
    if let Ok(ip) = target.host.parse::<IpAddr>() {
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
        }
        // De-duplicate while preserving resolution order (as `resolve_for_tcp`).
        let mut seen = std::collections::HashSet::new();
        addresses.retain(|a| seen.insert(*a));
    }
    if addresses.is_empty() {
        eprintln!(
            "Error: hostname {} did not resolve to any address via the system resolver",
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

    let sni = target.host.clone();
    let tls_obs: Vec<TlsObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let sni = sni.clone();
        async move { ip_tls::probe(d, &sni, timeout).await }
    })
    .await;

    let http_obs = collect_http_probes(destinations.clone(), &target.host, concurrency, timeout).await;

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
        print!("{}", render_dns(&target.host, &dns_obs));
        print!("{}", render_tcp(&tcp_obs));
        print!("{}", render_diagnoses(&diagnoses));
    }
    ExitCode::SUCCESS
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
async fn collect_http_probes(
    destinations: Vec<SocketAddr>,
    host: &str,
    concurrency: usize,
    timeout: Duration,
) -> Vec<HttpObservation> {
    let host_1 = host.to_string();
    let http1: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let host = host_1.clone();
        async move { ip_http::probe(d, &host, "GET", timeout).await }
    })
    .await;

    let host_2 = host.to_string();
    let http2: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let host = host_2.clone();
        async move { ip_http2::probe(d, &host, "GET", timeout).await }
    })
    .await;

    let host_3 = host.to_string();
    let http3: Vec<HttpObservation> = parallel_map(destinations.clone(), concurrency, move |d| {
        let host = host_3.clone();
        async move { ip_http3::probe(d, &host, "GET", timeout).await }
    })
    .await;

    let mut out = http1;
    out.extend(http2);
    out.extend(http3);
    out
}
