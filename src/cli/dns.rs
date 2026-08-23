//! `dns` subcommand handler.

use super::{parallel_map, parse_custom_servers, DEFAULT_PORT};
use clap::ArgMatches;
use ip_tools::dns::{aggregate_repeat, DnsClient};
use ip_tools::model::{DnsObservation, DnsRecord, DnsRecordType, DnsRepeatResult, ResolverKind};
use ip_tools::report::{render_dns, render_dns_repeat, to_json};
use ip_tools::target::Target;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Resolve one or more hostnames and report the DNS observations for each
/// record type. `dns` accepts many targets (a DNS health sweep); single-target
/// output is unchanged, `--json` with >1 target emits an array keyed by target,
/// and `--strict` aggregates failed lookups across every target.
#[allow(clippy::too_many_lines)] // orchestration: parse, loop hosts, render
pub(super) async fn run_dns(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    let csv = sub_m.get_flag("csv");
    let strict = sub_m.get_flag("strict");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
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

    let custom: Vec<SocketAddr> = match parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let only_v6 = sub_m.get_flag("ipv6");
    let insecure = sub_m.get_flag("insecure");
    let doh_endpoints: Vec<String> = sub_m
        .get_many::<String>("doh")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let dot_eps: Vec<String> = sub_m
        .get_many::<String>("dot")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let count = *sub_m.get_one::<usize>("count").expect("count has default");
    // `--concurrency` parallelizes a multi-target DNS health sweep (default 1
    // preserves the original sequential ordering/semantics).
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");

    // `--record-type` requests one specific type; else `--ipv6` restricts to
    // AAAA; else both A and AAAA (the historical default).
    let record_types = if let Some(rt) = sub_m.get_one::<String>("record-type") {
        if let Some(rt) = parse_record_type(rt) {
            vec![rt]
        } else {
            eprintln!("Error: unsupported record type {rt:?} (try A, AAAA, CNAME, MX, TXT, NS or SOA)");
            return ExitCode::FAILURE;
        }
    } else if only_v6 {
        vec![DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    };

    // Resolve every target, parallelizing across hosts when `--concurrency` > 1.
    // `parallel_map` returns results in completion order, so each item carries
    // its input index and the outputs are re-sorted back to target order to keep
    // the human/JSON/CSV rendering deterministic.
    let targets_with_index: Vec<(usize, Target)> = targets.into_iter().enumerate().collect();
    let mut indexed: Vec<(usize, TargetDns)> = parallel_map(targets_with_index, concurrency, move |(idx, target)| {
        let record_types = record_types.clone();
        let custom = custom.clone();
        let doh_endpoints = doh_endpoints.clone();
        let dot_eps = dot_eps.clone();
        async move {
            let result = dns_compute(
                &target,
                &record_types,
                &custom,
                &doh_endpoints,
                &dot_eps,
                count,
                timeout,
                insecure,
            )
            .await;
            (idx, result)
        }
    })
    .await;
    indexed.sort_by_key(|(idx, _)| *idx);
    let outputs: Vec<TargetDns> = indexed.into_iter().map(|(_, o)| o).collect();

    if csv {
        print!("{}", render_dns_csv(&outputs));
    } else if json {
        if outputs.len() == 1 {
            let o = &outputs[0];
            if o.repeat {
                println!("{}", to_json(&o.results));
            } else {
                println!("{}", to_json(&o.observations));
            }
        } else {
            let items: Vec<serde_json::Value> = outputs
                .iter()
                .map(|o| {
                    if o.repeat {
                        serde_json::json!({ "target": o.host, "results": o.results })
                    } else {
                        serde_json::json!({ "target": o.host, "observations": o.observations })
                    }
                })
                .collect();
            println!("{}", to_json(&items));
        }
    } else {
        let mut text = String::new();
        for o in &outputs {
            if o.repeat {
                text.push_str(&render_dns_repeat(&o.host, &o.results));
            } else {
                text.push_str(&render_dns(&o.host, &o.observations));
            }
        }
        print!("{text}");
    }

    // `--strict`: a failed lookup / failed repeat row is an observation, but
    // scripting/CI wants a non-zero exit when any resolver on any target
    // could not answer. Output is still rendered in full either way.
    if strict {
        let failed: usize = outputs
            .iter()
            .map(|o| {
                if o.repeat {
                    o.results.iter().filter(|r| r.failures > 0).count()
                } else {
                    o.observations.iter().filter(|obs| obs.error.is_some()).count()
                }
            })
            .sum();
        if failed > 0 {
            eprintln!("Error: {failed} DNS lookup(s) failed (--strict)");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// The per-target DNS result: whether the target used the repeat view and the
/// matching observations (`!repeat`) or aggregated results (`repeat`).
struct TargetDns {
    host: String,
    repeat: bool,
    observations: Vec<DnsObservation>,
    results: Vec<DnsRepeatResult>,
}

/// Resolve one target (system + `--server` + `--doh` + `--dot`) for each
/// record type, either as single-shot observations or (for a non-literal
/// hostname with `--count N > 1`) as the aggregated repeat view.
#[allow(clippy::too_many_arguments)] // the shared resolver/request configuration
async fn dns_compute(
    target: &Target,
    record_types: &[DnsRecordType],
    custom: &[SocketAddr],
    doh_endpoints: &[String],
    dot_eps: &[String],
    count: usize,
    timeout: Duration,
    insecure: bool,
) -> TargetDns {
    // An IP-literal target is already an address: it is reported as its own
    // record for the matching family and an empty (no-records, no-error)
    // answer for the other — like a NODATA reply, never a lookup error.
    let literal = target
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    // A DNS repeat is hostname-centric (aggregate per-resolver/per-record-type
    // latency + failure stats over `--count`), so IP-literal targets skip it.
    let repeat = literal.is_none() && count > 1;

    if let Some(literal) = literal {
        return TargetDns {
            host: target.host.clone(),
            repeat: false,
            observations: literal_observations(&target.host, literal, record_types),
            results: Vec::new(),
        };
    }

    let client = DnsClient::new(custom, timeout, 1);
    if repeat {
        let mut results = Vec::new();
        for &rt in record_types {
            results.extend(client.resolve_repeat(&target.host, rt, count).await);
            results.extend(encrypted_repeat(doh_endpoints, dot_eps, &target.host, rt, count, timeout, insecure).await);
        }
        TargetDns {
            host: target.host.clone(),
            repeat: true,
            observations: Vec::new(),
            results,
        }
    } else {
        let mut observations = Vec::new();
        for &rt in record_types {
            observations.extend(client.resolve(&target.host, rt).await);
            observations.extend(encrypted_dns(doh_endpoints, dot_eps, &target.host, rt, timeout, insecure).await);
        }
        TargetDns {
            host: target.host.clone(),
            repeat: false,
            observations,
            results: Vec::new(),
        }
    }
}

/// Query every configured encrypted-DNS endpoint (`DoH` then `DoT`) for
/// `host`/`rt`, returning one observation per endpoint.
async fn encrypted_dns(
    https_endpoints: &[String],
    tls_endpoints: &[String],
    host: &str,
    rt: DnsRecordType,
    timeout: Duration,
    insecure: bool,
) -> Vec<DnsObservation> {
    let mut out = Vec::with_capacity(https_endpoints.len() + tls_endpoints.len());
    for endpoint in https_endpoints {
        out.push(ip_tools::dns::doh_query(endpoint, host, rt, timeout, insecure).await);
    }
    for endpoint in tls_endpoints {
        out.push(ip_tools::dns::dot_query(endpoint, host, rt, timeout, insecure).await);
    }
    out
}

/// Repeatedly query each encrypted-DNS endpoint `count` times and aggregate
/// each endpoint's results into a per-(endpoint, record type) row, mirroring
/// the `dns --count` repeat view.
async fn encrypted_repeat(
    https_endpoints: &[String],
    tls_endpoints: &[String],
    host: &str,
    rt: DnsRecordType,
    count: usize,
    timeout: Duration,
    insecure: bool,
) -> Vec<DnsRepeatResult> {
    let mut out = Vec::new();
    for endpoint in https_endpoints {
        let mut bucket: Vec<DnsObservation> = Vec::with_capacity(count);
        for _ in 0..count {
            bucket.push(ip_tools::dns::doh_query(endpoint, host, rt, timeout, insecure).await);
        }
        out.push(aggregate_repeat(&bucket, rt, count));
    }
    for endpoint in tls_endpoints {
        let mut bucket: Vec<DnsObservation> = Vec::with_capacity(count);
        for _ in 0..count {
            bucket.push(ip_tools::dns::dot_query(endpoint, host, rt, timeout, insecure).await);
        }
        out.push(aggregate_repeat(&bucket, rt, count));
    }
    out
}

/// Render every DNS row across every target as CSV: a header then one
/// `host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures`
/// row per (resolver, record type). Single-shot rows are attempts=1; repeat
/// rows use the aggregated latency statistics.
fn render_dns_csv(outputs: &[TargetDns]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures\n",
    );
    for o in outputs {
        if o.repeat {
            for r in &o.results {
                out.push_str(&csv_field(&o.host));
                out.push(',');
                out.push_str(&csv_field(&resolver_label(&r.resolver)));
                out.push(',');
                out.push_str(&csv_field(&r.record_type.to_string()));
                out.push(',');
                out.push_str(&r.attempts.to_string());
                out.push(',');
                let _ = write!(out, "{:.4}", r.success_rate());
                out.push(',');
                out.push_str(&opt64(r.latency.p50));
                out.push(',');
                out.push_str(&opt64(r.latency.p95));
                out.push(',');
                out.push_str(&opt64(r.latency.max));
                out.push(',');
                out.push_str(&r.failures.to_string());
                out.push('\n');
            }
        } else {
            for obs in &o.observations {
                out.push_str(&csv_field(&o.host));
                out.push(',');
                out.push_str(&csv_field(&resolver_label(&obs.resolver)));
                out.push(',');
                out.push_str(&csv_field(&obs.record_type.to_string()));
                out.push(',');
                out.push('1');
                out.push(',');
                out.push_str(if obs.error.is_none() { "1.0000" } else { "0.0000" });
                out.push(',');
                out.push_str(&opt64(obs.latency_ms));
                out.push(',');
                out.push_str(&opt64(obs.latency_ms));
                out.push(',');
                out.push_str(&opt64(obs.latency_ms));
                out.push(',');
                out.push(if obs.error.is_some() { '1' } else { '0' });
                out.push('\n');
            }
        }
    }
    out
}

/// Format an optional millisecond value as an empty field or its value.
fn opt64(v: Option<u64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
}

/// Human label for a resolver, matching the report renderer.
fn resolver_label(r: &ResolverKind) -> String {
    match r {
        ResolverKind::System => "system".to_string(),
        ResolverKind::Custom(addr) => addr.to_string(),
        ResolverKind::Doh(endpoint) => endpoint.clone(),
        ResolverKind::Dot(endpoint) => format!("{endpoint} (DoT)"),
    }
}

/// Quote a CSV field when it contains a comma, quote, or newline (RFC 4180).
fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Observations for an IP-literal target: the literal is its own record for
/// the matching address family and an empty (no-records) observation for the
/// other family. No resolver is consulted, so the answer is deterministic and
/// never a lookup error. Reported under [`ResolverKind::System`] purely as the
/// "no resolver involved" label; the observation itself carries no ambiguity.
fn literal_observations(host: &str, literal: IpAddr, record_types: &[DnsRecordType]) -> Vec<DnsObservation> {
    record_types
        .iter()
        .map(|&rt| DnsObservation {
            hostname: host.to_string(),
            resolver: ResolverKind::System,
            record_type: rt,
            records: match (rt, literal) {
                (DnsRecordType::A, IpAddr::V4(v4)) => vec![DnsRecord::A(v4)],
                (DnsRecordType::Aaaa, IpAddr::V6(v6)) => vec![DnsRecord::Aaaa(v6)],
                _ => Vec::new(),
            },
            latency_ms: Some(0),
            error: None,
        })
        .collect()
}

/// Parse a `--record-type` argument into a [`DnsRecordType`].
fn parse_record_type(s: &str) -> Option<DnsRecordType> {
    match s.to_ascii_uppercase().as_str() {
        "A" => Some(DnsRecordType::A),
        "AAAA" => Some(DnsRecordType::Aaaa),
        "CNAME" => Some(DnsRecordType::Cname),
        "MX" => Some(DnsRecordType::Mx),
        "TXT" => Some(DnsRecordType::Txt),
        "NS" => Some(DnsRecordType::Ns),
        "SOA" => Some(DnsRecordType::Soa),
        "CAA" => Some(DnsRecordType::Caa),
        "SRV" => Some(DnsRecordType::Srv),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap an already-parsed IP literal as an address record (A/AAAA).
    fn rec_from_ip(ip: IpAddr) -> DnsRecord {
        match ip {
            IpAddr::V4(v) => DnsRecord::A(v),
            IpAddr::V6(v) => DnsRecord::Aaaa(v),
        }
    }

    #[test]
    fn literal_observations_report_the_address_for_its_records() {
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let obs = literal_observations("1.1.1.1", v4, &[DnsRecordType::A, DnsRecordType::Aaaa]);
        assert_eq!(obs.len(), 2);
        let a = obs
            .iter()
            .find(|o| o.record_type == DnsRecordType::A)
            .expect("A observation");
        assert_eq!(a.records, vec![rec_from_ip(v4)]);
        assert_eq!(a.latency_ms, Some(0));
        assert!(a.error.is_none(), "a literal is never a lookup failure");
        let aaaa = obs
            .iter()
            .find(|o| o.record_type == DnsRecordType::Aaaa)
            .expect("AAAA observation");
        assert!(aaaa.records.is_empty(), "other family is NODATA: {aaaa:?}");
        assert!(aaaa.error.is_none(), "other family is NODATA, not an error");

        // An IPv6 literal reports AAAA; its (absent) A row is empty NODATA.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let obs6 = literal_observations("[2001:db8::1]", v6, &[DnsRecordType::A, DnsRecordType::Aaaa]);
        let aaaa6 = obs6
            .iter()
            .find(|o| o.record_type == DnsRecordType::Aaaa)
            .expect("AAAA observation");
        assert_eq!(aaaa6.records, vec![rec_from_ip(v6)]);
        let a6 = obs6
            .iter()
            .find(|o| o.record_type == DnsRecordType::A)
            .expect("A observation");
        assert!(a6.records.is_empty());
        assert!(obs6.iter().all(|o| o.error.is_none()));

        // `--ipv6` (AAAA-only) still yields a per-record-type observation.
        let obs_v6_only = literal_observations("1.1.1.1", v4, &[DnsRecordType::Aaaa]);
        assert_eq!(obs_v6_only.len(), 1);
        assert!(obs_v6_only[0].records.is_empty());
    }
}
