//! Human and JSON rendering of observations.
//!
//! Human output is tuned for terminal investigation. JSON output carries the
//! complete raw observation data (via serde `Serialize` on the model types)
//! so external systems can build their own analysis.

// String-building helpers prefer `push_str(&format!(..))` for readability; the
// `format_push_string` lint (pedantic) flags this deliberately-chosen style.
#![allow(clippy::format_push_string)]

use crate::model::{
    CertificateSummary, Diagnosis, DnsObservation, DnsRecordType, HttpObservation, ProbeResult, ResolverKind,
    TcpObservation, TlsObservation,
};
use crate::RouteHop;

/// Render DNS observations for `host` as human text.
#[must_use]
pub fn render_dns(host: &str, observations: &[DnsObservation]) -> String {
    let mut out = String::new();
    out.push_str(&format!("DNS {host}\n"));

    // Group by resolver, then list each record type's addresses.
    // Order is stable: system first, then custom resolvers.
    let mut seen_resolvers = Vec::new();
    for obs in observations {
        if !seen_resolvers.iter().any(|r| r == &obs.resolver) {
            seen_resolvers.push(obs.resolver.clone());
        }
    }
    for resolver in seen_resolvers {
        out.push_str(&format!("  {}\n", resolver_label(&resolver)));
        for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
            if let Some(obs) = observations
                .iter()
                .find(|o| o.resolver == resolver && o.record_type == rt)
            {
                out.push_str(&format!("    {:4}: ", rt_label(rt)));
                out.push_str(&render_dns_one(obs));
                out.push('\n');
            }
        }
    }
    out
}

fn render_dns_one(obs: &DnsObservation) -> String {
    match (&obs.error, obs.latency_ms) {
        (Some(err), _) => format!("{} ({})", err.kind, err.message),
        (None, Some(ms)) => {
            if obs.records.is_empty() {
                format!("no records ({ms} ms)")
            } else {
                let addrs: Vec<String> = obs.records.iter().map(ToString::to_string).collect();
                format!("{} ({} ms)", addrs.join(", "), ms)
            }
        }
        (None, None) => "no records".to_string(),
    }
}

fn resolver_label(r: &ResolverKind) -> String {
    match r {
        ResolverKind::System => "system".to_string(),
        ResolverKind::Custom(addr) => addr.to_string(),
    }
}

const fn rt_label(rt: DnsRecordType) -> &'static str {
    match rt {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
    }
}

/// Render TCP observations as human text.
#[must_use]
pub fn render_tcp(observations: &[TcpObservation]) -> String {
    let mut out = String::from("TCP connect\n");
    for obs in observations {
        let status = if obs.success {
            format!("PASS      {} ms", obs.latency_ms.unwrap_or(0))
        } else {
            let err = obs
                .failure
                .as_ref()
                .map_or_else(|| "failed".to_string(), |e| e.kind.to_string());
            format!("{err:10}")
        };
        out.push_str(&format!("  {:24} {status}\n", obs.destination));
    }
    out
}

/// Render TLS observations as human text.
#[must_use]
pub fn render_tls(observations: &[TlsObservation]) -> String {
    let mut out = String::from("TLS handshake\n");
    for obs in observations {
        out.push_str(&format!("  {}\n", obs.destination));
        if !obs.success {
            let err = obs
                .failure
                .as_ref()
                .map_or_else(|| "failed".to_string(), |e| format!("{} ({})", e.kind, e.message));
            out.push_str(&format!("    {err}\n"));
            continue;
        }
        out.push_str(&format!("    TLS: {}\n", obs.version.as_deref().unwrap_or("unknown")));
        if let Some(cipher) = &obs.cipher {
            out.push_str(&format!("    cipher: {cipher}\n"));
        }
        if let Some(alpn) = &obs.alpn {
            out.push_str(&format!("    ALPN: {alpn}\n"));
        }
        if let Some(cert) = &obs.certificate {
            out.push_str(&format!("    cert : {}\n", render_cert(cert)));
        }
        out.push_str(&format!("    latency: {} ms\n", obs.latency_ms.unwrap_or(0)));
    }
    out
}

/// Render a certificate summary compactly for the terminal.
fn render_cert(cert: &CertificateSummary) -> String {
    let valid = match (&cert.not_after_utc, &cert.not_before_utc) {
        (Some(a), Some(b)) => format!("valid {}..{}", b.trim_end_matches('Z'), a.trim_end_matches('Z')),
        _ => String::new(),
    };
    let valid = if valid.is_empty() {
        String::new()
    } else {
        format!(" ({valid})")
    };
    format!("{} issued by {}{}", cert.subject, cert.issuer, valid)
}

/// Render HTTPS/HTTP observations as human text.
#[must_use]
pub fn render_http(observations: &[HttpObservation]) -> String {
    let mut out = String::from("HTTPS\n");
    for obs in observations {
        out.push_str(&format!("  {}\n", obs.destination));
        if let Some(failure) = &obs.failure {
            out.push_str(&format!("    {} ({})\n", failure.kind, failure.message));
            continue;
        }
        out.push_str(&format!(
            "    {} {}\n",
            obs.protocol.as_deref().unwrap_or("HTTP/1.1"),
            obs.status.map_or_else(|| "no status".to_string(), |s| s.to_string())
        ));
        if let Some(location) = &obs.location {
            out.push_str(&format!("    redirect: {location}\n"));
        }
        if let Some(tls) = &obs.tls {
            if let Some(version) = &tls.version {
                out.push_str(&format!("    TLS: {version}\n"));
            }
            if let Some(alpn) = &tls.alpn {
                out.push_str(&format!("    ALPN: {alpn}\n"));
            }
        }
        if let Some(bytes) = obs.body_bytes {
            out.push_str(&format!("    body: {bytes} bytes\n"));
        }
        out.push_str(&format!("    latency: {} ms\n", obs.latency_ms.unwrap_or(0)));
    }
    out
}

/// Serialize any serde value as pretty JSON.
///
/// # Panics
///
/// Panics if serialization fails; this cannot happen for the tool's own
/// types, which are all `Serialize`.
pub fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialization to JSON cannot fail")
}

/// Render repeated probe results as human text.
#[must_use]
pub fn render_probe(results: &[ProbeResult]) -> String {
    let mut out = String::from("Repeated probes\n");
    for r in results {
        out.push_str(&format!("  {}\n", r.destination));
        out.push_str(&format!(
            "    attempts: {}\n    success:  {} ({})\n    failure:  {}\n",
            r.attempts,
            r.successes,
            format_rate(r.success_rate),
            r.failures
        ));
        let lat = &r.latency;
        if lat.count > 0 {
            out.push_str(&format!(
                "    latency:\n      min:  {} ms\n      p50:  {} ms\n      p90:  {} ms\n      p95:  {} ms\n      p99:  {} ms\n      max:  {} ms\n      jitter: {} ms\n",
                fmt(lat.min),
                fmt(lat.p50),
                fmt(lat.p90),
                fmt(lat.p95),
                fmt(lat.p99),
                fmt(lat.max),
                fmt(lat.jitter),
            ));
        }
        if !r.failure_counts.is_empty() {
            let dist: Vec<String> = r
                .failure_counts
                .iter()
                .map(|f| format!("{}: {}", f.kind, f.count))
                .collect();
            out.push_str(&format!("    failures: {}\n", dist.join(", ")));
        }
    }
    out
}

fn format_rate(rate: f64) -> String {
    format!("{:.1}%", rate * 100.0)
}

fn fmt(v: Option<u64>) -> String {
    v.map_or_else(|| "-".to_string(), |n| n.to_string())
}

/// Render traceroute hops as human text.
pub fn render_route(hops: &[RouteHop]) -> String {
    let mut out = String::from("Traceroute\n");
    for hop in hops {
        if hop.lost || hop.addr.is_none() {
            out.push_str(&format!("  {:>2}  *\n", hop.ttl));
            continue;
        }
        let addr = hop.addr.map_or_else(String::new, |a| a.to_string());
        let name = hop.hostname.as_deref().filter(|n| !n.is_empty());
        let host = match name {
            Some(n) => format!("{n} ({addr})"),
            None => addr,
        };
        let rtt = hop.rtt_ms.map_or_else(|| "-".to_string(), |ms| format!("{ms} ms"));
        out.push_str(&format!("  {:>2}  {host:40} {rtt}\n", hop.ttl));
    }
    out
}

/// Render diagnoses as human text.
#[must_use]
pub fn render_diagnoses(diagnoses: &[Diagnosis]) -> String {
    let mut out = String::from("Diagnosis\n");
    for d in diagnoses {
        let severity = format!("{:?}", d.severity).to_uppercase();
        out.push_str(&format!(
            "[{}] {:?} ({:?} confidence)\n",
            severity, d.category, d.confidence
        ));
        out.push_str(&format!("    {}\n", d.summary));
        if !d.evidence.is_empty() {
            out.push_str("    Evidence:\n");
            for e in &d.evidence {
                out.push_str(&format!("      - {}\n", e.detail));
            }
        }
        if !d.possible_causes.is_empty() {
            out.push_str("    Possible causes:\n");
            for c in &d.possible_causes {
                out.push_str(&format!("      - {c}\n"));
            }
        }
        out.push('\n');
    }
    out
}
