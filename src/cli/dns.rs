//! `dns` subcommand handler.

use super::{parallel_map, parse_custom_servers};
use clap::ArgMatches;
use ip_tools::dns::{aggregate_repeat, DnsClient};
use ip_tools::model::{DnsObservation, DnsRecord, DnsRecordType, DnsRepeatResult, ResolverKind};
use ip_tools::report::{render_dns, render_dns_repeat, to_json};
use ip_tools::style::Style;
use ip_tools::target::Target;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Resolve one or more hostnames and report the DNS observations for each
/// record type. `dns` accepts many targets (a DNS health sweep); single-target
/// output is unchanged, `--json` with >1 target emits an array keyed by target,
/// and `--strict` aggregates failed lookups across every target.
#[allow(clippy::too_many_lines)] // orchestration: parse, loop hosts, render
pub(super) async fn run_dns(sub_m: &ArgMatches, style: Style) -> ExitCode {
    let json = sub_m.get_flag("json");
    let csv = sub_m.get_flag("csv");
    let strict = sub_m.get_flag("strict");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let timeout = Duration::from_millis(timeout_ms);

    if let Err(e) = super::ensure_single_output_format(sub_m) {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }

    let targets = match super::parse_targets(sub_m) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if targets.is_empty() {
        eprintln!("Error: no targets to probe (the target list is empty)");
        return ExitCode::FAILURE;
    }
    // DNS resolution queries a resolver's port (53 / 853 / the tunneled DoH
    // endpoint), not the target's own port: a `host:port` target's port is
    // never the thing queried, so silently dropping it (as resolution does)
    // would send the operator's `dns example.com:5353` to the *system*
    // resolver with no indication. Note it on stderr like the IP-literal
    // `--count` note, so a mistaken custom-port intent is surfaced instead of
    // assumed to have worked.
    for t in &targets {
        if t.port != super::DEFAULT_PORT {
            eprintln!(
                "Note: ignoring the :{} port of {} (DNS queries a resolver, not the target's port)",
                t.port, t.host
            );
        }
    }

    let custom: Vec<SocketAddr> = match parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let only_v4 = sub_m.get_flag("ipv4");
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
    super::note_concurrency_cap(sub_m);

    // `--record-type` requests one specific type; `--ipv4`/`--ipv6` restrict
    // to A-only / AAAA-only; else both A and AAAA (the historical default).
    let record_types = if let Some(rt) = sub_m.get_one::<String>("record-type") {
        if let Some(rt) = parse_record_type(rt) {
            vec![rt]
        } else {
            eprintln!("Error: unsupported record type {rt:?} (try A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV or PTR)");
            return ExitCode::FAILURE;
        }
    } else if only_v4 {
        vec![DnsRecordType::A]
    } else if only_v6 {
        vec![DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa]
    };

    // Resolve every target, parallelizing across hosts when `--concurrency` > 1.
    // `parallel_map` returns results in completion order, so each item carries
    // its input index and the outputs are re-sorted back to target order to keep
    // the human/JSON/CSV rendering deterministic. A TTY-gated per-host counter
    // keeps a large health sweep watchable on stderr (silent when piped).
    let progress = std::sync::Arc::new(super::Progress::new(targets.len(), sub_m.get_flag("no-color")));
    let progress_for_tasks = progress.clone();
    let targets_with_index: Vec<(usize, Target)> = targets.into_iter().enumerate().collect();
    let mut indexed: Vec<(usize, TargetDns)> = parallel_map(targets_with_index, concurrency, move |(idx, target)| {
        let record_types = record_types.clone();
        let custom = custom.clone();
        let doh_endpoints = doh_endpoints.clone();
        let dot_eps = dot_eps.clone();
        let progress = progress_for_tasks.clone();
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
            progress.step(&target.host);
            (idx, result)
        }
    })
    .await;
    progress.finish();
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
                text.push_str(&render_dns_repeat(&style, &o.host, &o.results));
            } else {
                text.push_str(&render_dns(&style, &o.host, &o.observations));
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
        // Reverse lookup: `--record-type PTR <ip>` builds the reverse-zone
        // name of the literal and queries PTR through the normal resolver
        // pipeline, reporting the user's literal target as the hostname so
        // the output stays stable.
        if record_types.len() == 1 && record_types[0] == DnsRecordType::Ptr {
            let query_name = reverse_zone(literal);
            let client = DnsClient::new(custom, timeout, 1);
            // `--count N` repeats the reverse lookup and aggregates
            // per-resolver latency/failure statistics exactly like any other
            // record type; the user's IP target labels the report.
            if count > 1 {
                let mut results = client.resolve_repeat(&query_name, DnsRecordType::Ptr, count).await;
                results.extend(
                    encrypted_repeat(
                        doh_endpoints,
                        dot_eps,
                        &query_name,
                        DnsRecordType::Ptr,
                        count,
                        timeout,
                        insecure,
                    )
                    .await,
                );
                return TargetDns {
                    host: target.host.clone(),
                    repeat: true,
                    observations: Vec::new(),
                    results,
                };
            }
            let mut observations = client.resolve(&query_name, DnsRecordType::Ptr).await;
            observations.extend(
                encrypted_dns(
                    doh_endpoints,
                    dot_eps,
                    &query_name,
                    DnsRecordType::Ptr,
                    timeout,
                    insecure,
                )
                .await,
            );
            for o in &mut observations {
                o.hostname.clone_from(&target.host);
            }
            return TargetDns {
                host: target.host.clone(),
                repeat: false,
                observations,
                results: Vec::new(),
            };
        }
        // A forward-record IP-literal target is reported straight from the
        // address itself — no resolver is consulted — but an operator may
        // have configured one (`--server`/`--doh`/`--dot`). Say so instead of
        // silently dropping it: the PTR branch above *does* use the resolver,
        // so the same flags do opposite things across record types and the
        // gap is easy to trip by accident.
        if !custom.is_empty() || !doh_endpoints.is_empty() || !dot_eps.is_empty() {
            eprintln!("Note: --server/--doh/--dot are ignored for an IP-literal forward lookup (the address is reported directly, nothing is resolved); use --record-type PTR <ip> to query a resolver for the reverse zone");
        }
        // An IP literal with `--count N` (N>1) is re-queried only in the
        // reverse-PTR branch above; for a forward record type `--count` has no
        // aggregation to apply (there is nothing to resolve repeatedly), so it
        // would silently degrade to a single shot. Warn instead of pretending
        // the count was honored, matching the fail-fast spirit of `--count 0`.
        if count > 1 {
            eprintln!("Note: --count {count} is ignored for an IP-literal target (no repeat aggregation applies); use --record-type PTR <ip> to repeat a reverse lookup");
        }
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
/// `host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures,ttl`
/// row per (resolver, record type). Single-shot rows are attempts=1; repeat
/// rows use the aggregated latency statistics and carry the minimum record
/// TTL observed across the successful answers (the caching-relevant bound).
/// A `records` column carries the actual resolved values (addresses, CNAME,
/// MX, TXT, ...) on single-shot rows; repeat rows leave it empty because the
/// aggregation does not retain which records each attempt answered.
fn render_dns_csv(outputs: &[TargetDns]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures,ttl,records\n",
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
                out.push(',');
                out.push_str(&r.ttl.map_or_else(String::new, |t| t.to_string()));
                out.push(','); // repeat rows aggregate; no per-answer records
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
                out.push(',');
                out.push_str(&obs.ttl.map_or_else(String::new, |t| t.to_string()));
                out.push(',');
                let records: Vec<String> = obs.records.iter().map(ToString::to_string).collect();
                out.push_str(&csv_field(&records.join(", ")));
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

/// Human label for a resolver, matching the report renderer and the `--json`
/// `resolver` field (one spelling across human/CSV/JSON; see `ResolverKind`).
fn resolver_label(r: &ResolverKind) -> String {
    r.label()
}

/// Quote a CSV field when it contains a comma, quote, or newline (RFC 4180).
use super::csv_field;

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
            ttl: None,
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
        "PTR" => Some(DnsRecordType::Ptr),
        _ => None,
    }
}

/// Build the reverse-zone name for an IP address: RFC 1035 `in-addr.arpa`
/// for IPv4 (reversed octets) and RFC 3596 `ip6.arpa` for IPv6 (reversed hex
/// nibbles), so a PTR (reverse DNS) lookup can be issued for a literal target.
pub(super) fn reverse_zone(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(32 * 2 + 9);
            for &b in v6.octets().iter().rev() {
                // Low nibble first, then high: reverse-DNS reads the nibbles
                // of the address from least-significant to most.
                for n in [b & 0x0F, b >> 4] {
                    s.push(char::from_digit(u32::from(n), 16).expect("nibble in 0..=15"));
                    s.push('.');
                }
            }
            s.push_str("ip6.arpa");
            s
        }
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

    #[test]
    fn reverse_zone_builds_ipv4_and_ipv6_arpa_names() {
        // RFC 1035: IPv4 octets reversed under `.in-addr.arpa`.
        let v4: IpAddr = "192.0.2.77".parse().unwrap();
        assert_eq!(reverse_zone(v4), "77.2.0.192.in-addr.arpa");

        // RFC 3596: IPv6 hex nibbles reversed under `.ip6.arpa` (32 nibbles).
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            reverse_zone(v6),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn parse_record_type_accepts_ptr() {
        assert_eq!(parse_record_type("PTR"), Some(DnsRecordType::Ptr));
        assert_eq!(parse_record_type("ptr"), Some(DnsRecordType::Ptr));
        assert_eq!(parse_record_type("A"), Some(DnsRecordType::A));
        assert_eq!(parse_record_type("PT"), None);
    }
}
