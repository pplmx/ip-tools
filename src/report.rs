//! Human and JSON rendering of observations.
//!
//! Human output is tuned for terminal investigation. JSON output carries the
//! complete raw observation data (via serde `Serialize` on the model types)
//! so external systems can build their own analysis.

// String-building helpers prefer `push_str(&format!(..))` for readability; the
// `format_push_string` lint (pedantic) flags this deliberately-chosen style.
#![allow(clippy::format_push_string)]

use crate::model::{
    CertificateSummary, Diagnosis, DnsObservation, DnsRecordType, DnsRepeatResult, HttpObservation, ProbeResult,
    ResolverKind, TcpObservation, TlsObservation,
};
use crate::RouteHop;

/// Whether the presented host/SNI differs from the destination's literal
/// address host — i.e. the probe connected to an address but presented a
/// different name (the `--sni` pattern), which the human report should make
/// explicit. An IP-literal presentation equal to the destination is the
/// ordinary case and is not shown.
fn presented_name_differs(presented: &str, destination: std::net::SocketAddr) -> bool {
    let trimmed = presented.trim_start_matches('[').trim_end_matches(']');
    trimmed
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip != destination.ip())
        || (trimmed.parse::<std::net::IpAddr>().is_err() && !trimmed.is_empty())
}

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
        ResolverKind::Doh(endpoint) => endpoint.clone(),
        ResolverKind::Dot(endpoint) => format!("{endpoint} (DoT)"),
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
        // Show the name actually presented as SNI when it is not the literal
        // destination address (e.g. `--sni` overrode an IP-literal target:
        // `tls 1.2.3.4 --sni example.com` still connects to 1.2.3.4 but
        // handshakes as example.com).
        if presented_name_differs(&obs.sni, obs.destination) {
            out.push_str(&format!("    SNI: {}\n", obs.sni));
        }
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

/// Render a certificate summary compactly for the terminal, annotated with
/// the remaining lifetime when it is actionable: `expired`, `expires in N
/// day(s)` within [`RENDER_CERT_EXPIRY_WINDOW_DAYS`], or nothing for a
/// comfortably-far expiry.
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
    let lifetime = cert
        .not_after_utc
        .as_deref()
        .and_then(days_until_from_rfc3339)
        .map_or_else(String::new, |days| {
            if days < 0 {
                " (expired)".to_string()
            } else if days <= RENDER_CERT_EXPIRY_WINDOW_DAYS {
                format!(" (expires in {days} day{})", if days == 1 { "" } else { "s" })
            } else {
                String::new()
            }
        });
    format!("{} issued by {}{}{}", cert.subject, cert.issuer, valid, lifetime)
}

/// Number of days before expiry the certificate report flags as expiring.
const RENDER_CERT_EXPIRY_WINDOW_DAYS: i64 = 30;

/// Days from today until the date encoded in an RFC 3339 UTC timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`); negative when that date is already past.
/// `None` when the string is not recognizably that shape.
fn days_until_from_rfc3339(rfc3339: &str) -> Option<i64> {
    let date = rfc3339.get(0..10)?;
    let (y, mo, d) = (date.get(0..4)?, date.get(5..7)?, date.get(8..10)?);
    let (year, month, day): (i64, i64, i64) = (y.parse().ok()?, mo.parse().ok()?, d.parse().ok()?);
    let now_days = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs()
            / 86_400,
    )
    .ok()?;
    Some(days_from_civil(year, month, day) - now_days)
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Hinnant's
/// algorithm, the inverse of `tls.rs format_utc`).
const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Render HTTPS/HTTP observations as human text.
#[must_use]
pub fn render_http(observations: &[HttpObservation]) -> String {
    let mut out = String::from("HTTPS\n");
    for obs in observations {
        out.push_str(&format!("  {}\n", obs.destination));
        // Show the hostname presented as SNI/Host when it is not the literal
        // destination address (see `--sni`).
        if presented_name_differs(&obs.host, obs.destination) {
            out.push_str(&format!("    host: {}\n", obs.host));
        }
        // Show the requested path when it is not the default `/` (`--path`).
        if obs.path != "/" {
            out.push_str(&format!("    path: {}\n", obs.path));
        }
        if let Some(failure) = &obs.failure {
            // Name the protocol so the HTTP/1.1, HTTP/2 and HTTP/3 rows of a
            // failing host are distinguishable (a success row already shows
            // its protocol).
            out.push_str(&format!(
                "    {} {} ({})\n",
                obs.protocol.as_deref().unwrap_or("HTTP/1.1"),
                failure.kind,
                failure.message
            ));
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
        // Show the diagnostic-relevant response headers (server identity,
        // CDN/proxy hops, caching, security markers). All headers are in the
        // JSON; this is the curated terminal view.
        for (name, value) in &obs.headers {
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "server"
                    | "via"
                    | "x-powered-by"
                    | "x-served-by"
                    | "x-cache"
                    | "x-cache-hits"
                    | "cf-ray"
                    | "cf-cache-status"
                    | "age"
                    | "cache-control"
                    | "expires"
                    | "etag"
                    | "last-modified"
                    | "content-type"
                    | "alt-svc"
                    | "set-cookie"
            ) {
                out.push_str(&format!("    {name}: {value}\n"));
            }
        }
        if let Some(bytes) = obs.body_bytes {
            out.push_str(&format!("    body: {bytes} bytes\n"));
        } else if obs.status.is_some() {
            // Headers were received but the body never completed within the
            // probe bound: the response is visibly truncated/stalled.
            out.push_str("    body: incomplete (timed out)\n");
        }
        if let Some(snippet) = &obs.body_snippet {
            out.push_str("    body content: ");
            out.push_str(snippet);
            out.push('\n');
        }
        out.push_str(&format!("    latency: {} ms\n", obs.latency_ms.unwrap_or(0)));
        if let Some(ttfb) = obs.ttfb_ms {
            out.push_str(&format!("    ttfb:    {ttfb} ms\n"));
        }
    }
    out
}

/// Render repeated DNS resolution results (`dns --count N`) as human text.
#[must_use]
pub fn render_dns_repeat(host: &str, results: &[DnsRepeatResult]) -> String {
    let mut out = String::from("Repeated DNS ");
    out.push_str(host);
    out.push('\n');
    for r in results {
        // Identify the resolver and record type on the row, like `render_dns`
        // groups by resolver then lists each record type's addresses.
        let label = match &r.resolver {
            ResolverKind::System => "system".to_string(),
            ResolverKind::Custom(addr) => addr.to_string(),
            ResolverKind::Doh(endpoint) => endpoint.clone(),
            ResolverKind::Dot(endpoint) => format!("{endpoint} (DoT)"),
        };
        out.push_str(&format!("  {label} {}\n", rt_label(r.record_type)));
        out.push_str(&format!("    attempts: {}\n", r.attempts));
        out.push_str(&format!(
            "    success:  {} ({:.1}%)\n",
            r.successes,
            r.success_rate() * 100.0
        ));
        out.push_str(&format!("    failure:  {}\n", r.failures));
        for fc in &r.failure_counts {
            out.push_str(&format!("      - {}: {}\n", fc.kind, fc.count));
        }
        if r.latency.count > 0 {
            out.push_str("    latency:\n");
            out.push_str(&format!("      min:  {} ms\n", r.latency.min.unwrap_or(0)));
            out.push_str(&format!("      p50:  {} ms\n", r.latency.p50.unwrap_or(0)));
            out.push_str(&format!("      p95:  {} ms\n", r.latency.p95.unwrap_or(0)));
            out.push_str(&format!("      p99:  {} ms\n", r.latency.p99.unwrap_or(0)));
            out.push_str(&format!("      max:  {} ms\n", r.latency.max.unwrap_or(0)));
            out.push_str(&format!("      jitter: {} ms\n", r.latency.jitter.unwrap_or(0)));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Confidence, DiagnosticCategory, Evidence, FailureCount, FailureKind, LatencyStats, ProbeError, ResolverKind,
        Severity,
    };

    fn dns_obs(
        resolver: ResolverKind,
        rt: DnsRecordType,
        addrs: &[&str],
        ms: Option<u64>,
        error: Option<&str>,
    ) -> DnsObservation {
        DnsObservation {
            hostname: "example.com".into(),
            resolver,
            record_type: rt,
            records: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            latency_ms: ms,
            error: error.map(|m| ProbeError {
                kind: FailureKind::Dns,
                message: m.into(),
            }),
        }
    }

    fn tls(cert: bool) -> TlsObservation {
        TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: cert,
            version: cert.then(|| "TLSv1.3".into()),
            cipher: cert.then(|| "TLS_AES_128_GCM_SHA256".into()),
            alpn: cert.then(|| "h2".into()),
            certificate: cert.then(|| CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=issuer".into(),
                not_before_utc: Some("2026-01-01T00:00:00Z".into()),
                not_after_utc: Some("2027-01-01T00:00:00Z".into()),
            }),
            latency_ms: cert.then_some(42),
            failure: (!cert).then(|| ProbeError {
                kind: FailureKind::TlsHandshake,
                message: "handshake failed".into(),
            }),
        }
    }

    /// Contract-style checks: every public renderer emits expected content and
    /// `to_json` yields parseable JSON. Exact column alignment is not asserted.
    #[test]
    fn render_dns_covers_success_and_failure() {
        let obs = [
            dns_obs(
                ResolverKind::System,
                DnsRecordType::A,
                &["1.1.1.1", "8.8.8.8"],
                Some(5),
                None,
            ),
            dns_obs(
                ResolverKind::Custom("9.9.9.9:53".parse().unwrap()),
                DnsRecordType::Aaaa,
                &[],
                Some(7),
                None,
            ),
            dns_obs(ResolverKind::System, DnsRecordType::Aaaa, &[], None, Some("no answer")),
        ];
        let out = render_dns("example.com", &obs);
        assert!(out.contains("DNS example.com"));
        assert!(out.contains("system"));
        assert!(out.contains("1.1.1.1"));
        assert!(out.contains("8.8.8.8"));
        assert!(out.contains("9.9.9.9:53"));
        assert!(out.contains('A'));
        assert!(out.contains("AAAA"));
        assert!(out.contains("no answer"));
    }

    #[test]
    fn render_dns_handles_empty_and_no_records() {
        // A success with no records and no latency -> "no records".
        let obs = [dns_obs(ResolverKind::System, DnsRecordType::A, &[], None, None)];
        assert!(render_dns("example.com", &obs).contains("no records"));
        assert!(render_dns("example.com", &[]).contains("DNS example.com"));
    }

    #[test]
    fn render_tcp_covers_pass_fail_and_kinds() {
        let obs = [
            TcpObservation {
                destination: "1.1.1.1:443".parse().unwrap(),
                success: true,
                latency_ms: Some(12),
                failure: None,
            },
            TcpObservation {
                destination: "2.2.2.2:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::ConnectionRefused,
                    message: "refused".into(),
                }),
            },
            TcpObservation {
                destination: "3.3.3.3:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::Timeout,
                    message: "timed out".into(),
                }),
            },
        ];
        let out = render_tcp(&obs);
        assert!(out.contains("TCP connect"));
        assert!(out.contains("PASS"));
        assert!(out.contains("12 ms"));
        assert!(out.contains("connection refused"));
        assert!(out.contains("timeout"));
        // Failure without a ProbeError object falls back to the string "failed".
        let bare = [TcpObservation {
            destination: "4.4.4.4:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: None,
        }];
        assert!(render_tcp(&bare).contains("failed"));
    }

    #[test]
    fn render_tls_covers_success_and_failure() {
        let out = render_tls(&[tls(true), tls(false)]);
        assert!(out.contains("TLS handshake"));
        assert!(out.contains("TLSv1.3"));
        assert!(out.contains("cipher: TLS_AES_128_GCM_SHA256"));
        assert!(out.contains("ALPN: h2"));
        assert!(out.contains("cert :"));
        assert!(out.contains("CN=example.com"));
        assert!(out.contains("issued by"));
        assert!(out.contains("handshake failed"));
        // Certificate without validity range degrades to no parenthetical.
        let no_validity = render_cert(&CertificateSummary {
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            not_before_utc: None,
            not_after_utc: None,
        });
        assert_eq!(no_validity, "CN=x issued by CN=y");
        // Success without latency reports 0 ms but does not panic.
        assert!(out.contains("latency: 42 ms"));
    }

    #[test]
    fn render_http_covers_success_redirect_and_failure() {
        let ok = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: Some(tls(true)),
            protocol: Some("HTTP/2".into()),
            status: Some(200),
            location: Some("https://example.com/login".into()),
            headers: Vec::new(),
            body_bytes: Some(1234),
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(30),
            failure: None,
        };
        let err = HttpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/2".into()),
            status: None,
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::Http,
                message: "request failed".into(),
            }),
        };
        let no_status = HttpObservation {
            destination: "3.3.3.3:443".parse().unwrap(),
            host: "example.com".into(),
            method: "HEAD".into(),
            path: "/".into(),
            tls: None,
            protocol: None,
            status: None,
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(1),
            failure: None,
        };
        // Headers received but no body ever completed: rendered as visibly
        // incomplete, and without an explicit protocol HTTP/1.1 is assumed.
        let truncated = HttpObservation {
            destination: "4.4.4.4:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: None,
            status: Some(301),
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: None,
        };
        let out = render_http(&[ok, err, no_status, truncated]);
        assert!(out.contains("example.com"));
        assert!(out.contains("HTTP/2"));
        assert!(out.contains("200"));
        assert!(out.contains("redirect: https://example.com/login"));
        assert!(out.contains("body: 1234 bytes"));
        assert!(out.contains("request failed"));
        // A failed observation must name its protocol so the HTTP/1.1, HTTP/2
        // and HTTP/3 rows of a failing host are distinguishable.
        assert!(out.contains("HTTP/2 http"), "failure row must name the protocol: {out}");
        assert!(out.contains("no status"));
        // Without an explicit protocol, HTTP/1.1 is assumed.
        assert!(out.contains("HTTP/1.1"));
        assert!(out.contains("301"));
        assert!(out.contains("body: incomplete"), "stalled body must be visible: {out}");
    }

    #[test]
    fn render_http_shows_body_content_snippet() {
        // A captured body snippet is rendered as a `body content:` line; the
        // explicit … marks truncation when the body continued past the cap.
        let ok = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: Some(2),
            body_snippet: Some("ok".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http(&[ok]);
        assert!(
            out.contains("body content: ok"),
            "small body snippet must be visible: {out}"
        );

        let truncated = HttpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: Some(2048),
            body_snippet: Some("xxxx…".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http(&[truncated]);
        assert!(
            out.contains("body content: xxxx…"),
            "truncated snippet with … must be visible: {out}"
        );
    }

    #[test]
    fn render_probe_covers_full_stats_and_distribution() {
        let mut stats = LatencyStats::default();
        for v in [100u64, 200, 300, 400] {
            stats.push(v);
        }
        let result = ProbeResult {
            destination: "1.1.1.1:443".parse().unwrap(),
            attempts: 6,
            successes: 4,
            failures: 2,
            success_rate: 4.0 / 6.0,
            latency: stats.summarize(),
            failure_counts: vec![FailureCount {
                kind: FailureKind::Timeout,
                count: 2,
            }],
        };
        let no_latency = ProbeResult {
            destination: "2.2.2.2:443".parse().unwrap(),
            attempts: 2,
            successes: 0,
            failures: 2,
            success_rate: 0.0,
            latency: LatencyStats::default().summarize(),
            failure_counts: vec![],
        };
        let out = render_probe(&[result, no_latency]);
        assert!(out.contains("Repeated probes"));
        assert!(out.contains("attempts: 6"));
        assert!(out.contains("66.7%"));
        assert!(out.contains("p50:"));
        assert!(out.contains("p99:"));
        assert!(out.contains("jitter:"));
        assert!(out.contains("timeout: 2"));
        // No samples -> latency block omitted; no failures -> defaults.
        assert!(out.contains("0.0%"));
    }

    #[test]
    fn render_dns_repeat_covers_success_latency_and_failures() {
        let mut stats = LatencyStats::default();
        for v in [10u64, 20, 30] {
            stats.push(v);
        }
        let ok = DnsRepeatResult {
            resolver: ResolverKind::Custom("9.9.9.9:53".parse().unwrap()),
            record_type: DnsRecordType::A,
            attempts: 4,
            successes: 3,
            failures: 1,
            latency: stats.summarize(),
            failure_counts: vec![FailureCount {
                kind: FailureKind::Dns,
                count: 1,
            }],
        };
        let out = render_dns_repeat("host.example", &[ok]);
        assert!(out.contains("Repeated DNS host.example"));
        assert!(out.contains("9.9.9.9:53 A"));
        assert!(out.contains("attempts: 4"));
        assert!(out.contains("success:  3 (75.0%)"));
        assert!(out.contains("failure:  1"));
        assert!(out.contains("dns: 1"));
        assert!(out.contains("p50:"));
        assert!(out.contains("jitter:"));
    }

    #[test]
    fn render_route_covers_hops_lost_and_empty() {
        let hops = [
            RouteHop {
                ttl: 1,
                addr: Some("192.0.2.1".parse().unwrap()),
                hostname: Some("r1.example.com".into()),
                rtt_ms: Some(3),
                lost: false,
            },
            RouteHop {
                ttl: 2,
                addr: Some("192.0.2.2".parse().unwrap()),
                hostname: None,
                rtt_ms: None,
                lost: true,
            },
            RouteHop {
                ttl: 3,
                addr: None,
                hostname: None,
                rtt_ms: None,
                lost: true,
            },
            RouteHop {
                ttl: 4,
                addr: Some("192.0.2.4".parse().unwrap()),
                hostname: None,
                rtt_ms: None,
                lost: false,
            },
        ];
        let out = render_route(&hops);
        assert!(out.contains("Traceroute"));
        assert!(out.contains("r1.example.com (192.0.2.1)"));
        assert!(out.contains("3 ms"));
        // Lost hop prints `*`; a reachable hop with no RTT prints `-`.
        assert!(out.contains('*'));
        assert!(out.contains("192.0.2.4"));
    }

    #[test]
    fn render_diagnoses_covers_healthy_and_anomalous() {
        let healthy = Diagnosis {
            severity: Severity::Info,
            category: DiagnosticCategory::Healthy,
            confidence: Confidence::High,
            summary: "everything fine".into(),
            evidence: vec![Evidence {
                detail: "dns ok".into(),
            }],
            possible_causes: vec![],
        };
        let anomaly = Diagnosis {
            severity: Severity::High,
            category: DiagnosticCategory::TotalConnectivityLoss,
            confidence: Confidence::Medium,
            summary: "no tcp".into(),
            evidence: vec![Evidence {
                detail: "0/3 reachable".into(),
            }],
            possible_causes: vec!["server down".into(), "firewall".into()],
        };
        let out = render_diagnoses(&[healthy, anomaly]);
        assert!(out.contains("Diagnosis"));
        assert!(out.contains("[INFO] Healthy (High confidence)"));
        assert!(out.contains("[HIGH] TotalConnectivityLoss (Medium confidence)"));
        assert!(out.contains("Evidence:"));
        assert!(out.contains("Possible causes:"));
        assert!(out.contains("firewall"));
    }

    #[test]
    fn to_json_emits_valid_serializable_json() {
        #[derive(serde::Serialize)]
        struct Probe {
            dest: String,
            ok: bool,
        }
        let json = to_json(&Probe {
            dest: "1.1.1.1:443".into(),
            ok: true,
        });
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["dest"], "1.1.1.1:443");
        assert_eq!(parsed["ok"], true);
        // An empty collection still serializes as `[]` (not null or absent).
        let empty: Vec<u64> = Vec::new();
        assert_eq!(to_json(&empty), "[]");
    }

    #[test]
    fn days_from_civil_inverts_known_dates() {
        // 1970-01-01 is epoch day 0.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        // 2000-01-01 is 10957 days after the epoch (canonical Hinnant value);
        // the next day is 10958.
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(days_from_civil(2000, 1, 2), 10_958);
        // Later dates are larger day counts.
        assert!(days_from_civil(2026, 7, 29) > days_from_civil(2026, 7, 1));
    }

    #[test]
    fn days_until_measures_expiry_relative_to_today() {
        // The epoch reference date is far in the past.
        assert!(days_until_from_rfc3339("1970-01-01T00:00:00Z").is_some_and(|d| d < -1000));

        // A timestamp built from `today + 5` must read as exactly 5 days out —
        // the same `days_from_civil` the production code uses makes the
        // round-trip exact with no time-of-day skew.
        let now_days = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("epoch")
                .as_secs()
                / 86_400,
        )
        .expect("days fit i64");
        let (y, m, d) = civil_from_days(now_days + 5);
        let rfc = format!("{y:04}-{m:02}-{d:02}T00:00:00Z");
        assert_eq!(days_until_from_rfc3339(&rfc), Some(5), "5 days out: {rfc}");

        // Malformed input is rejected, not partially parsed.
        assert_eq!(days_until_from_rfc3339("garbage"), None);
        assert_eq!(days_until_from_rfc3339("not-a-date"), None);
    }

    #[test]
    fn render_cert_annotates_expiry_lifetime() {
        let cert = |days: i64| CertificateSummary {
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            not_before_utc: Some("2026-01-01T00:00:00Z".into()),
            not_after_utc: Some(days_out_rfc3339(days)),
        };
        // Far future: no lifetime annotation.
        let far = render_cert(&cert(400));
        assert!(!far.contains("expires in"), "far expiry has no annotation: {far}");
        assert!(!far.contains("expired"), "far expiry has no annotation: {far}");
        // Near expiry: annotated.
        let near = render_cert(&cert(5));
        assert!(near.contains("expires in 5 days"), "near expiry annotated: {near}");
        // Already expired: annotated.
        let past = render_cert(&cert(-3));
        assert!(past.contains("expired"), "expired annotated: {past}");
    }

    /// RFC 3339 UTC string for the civil date `now + offset` days from today,
    /// used to build deterministic expiry timestamps in tests.
    fn days_out_rfc3339(offset: i64) -> String {
        let now_days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs()
            / 86_400;
        let (y, m, d) = civil_from_days(i64::try_from(now_days).expect("days fit i64") + offset);
        format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
    }

    /// Civil (y, m, d) for a day count since the epoch (Hinnant's algorithm,
    /// the inverse of the production `days_from_civil`).
    fn civil_from_days(days: i64) -> (i64, u32, u32) {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (
            if m <= 2 { y + 1 } else { y },
            u32::try_from(m).expect("month"),
            u32::try_from(d).expect("day"),
        )
    }
}
