//! Human and JSON rendering of observations.
//!
//! Human output is tuned for terminal investigation. Every human renderer
//! takes a [`Style`], whose `auto()` form colors status/severity verdicts
//! only for a TTY (with `--no-color`/`NO_COLOR` escapes); with a plain style
//! the output is byte-identical to the historical monochrome text, so piping,
//! golden tests and CSV/JSON formats are never disturbed. JSON output carries
//! the complete raw observation data (via serde `Serialize` on the model
//! types) so external systems can build their own analysis.

// String-building helpers prefer `push_str(&format!(..))` for readability; the
// `format_push_string` lint (pedantic) flags this deliberately-chosen style.
#![allow(clippy::format_push_string)]

use crate::model::{
    CertificateSummary, Diagnosis, DiagnosticCategory, DnsObservation, DnsRecordType, DnsRepeatResult, FailureKind,
    HttpObservation, ProbeResult, ResolverKind, Severity, TcpObservation, TlsObservation,
};
use crate::style::Style;
use crate::{RouteHop, RouteRepeat};

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
pub fn render_dns(style: &Style, host: &str, observations: &[DnsObservation]) -> String {
    let mut out = String::new();
    out.push_str(&format!("DNS {host}\n"));

    // Group by resolver, then list each record type's observations. Order is
    // stable: system first, then custom resolvers. Every observation is
    // rendered — not just the first per (resolver, record type) — so a
    // resolver that legitimately produced more than one (e.g. `diagnose
    // --reverse` resolves every address and adds a PTR row labelled with the
    // address) keeps all of them in the human report, matching CSV/JSON which
    // iterate the full set (the dedicated `dns` command yields exactly one
    // observation per key, so its output is unchanged).
    let mut seen_resolvers = Vec::new();
    for obs in observations {
        if !seen_resolvers.iter().any(|r| r == &obs.resolver) {
            seen_resolvers.push(obs.resolver.clone());
        }
    }
    for resolver in seen_resolvers {
        out.push_str(&format!("  {}\n", resolver_label(&resolver)));
        for rt in ALL_DNS_RECORD_TYPES {
            let matched: Vec<&DnsObservation> = observations
                .iter()
                .filter(|o| o.resolver == resolver && o.record_type == rt)
                .collect();
            if matched.is_empty() {
                continue;
            }
            for obs in matched {
                // A row whose observation's `hostname` (e.g. one address of a
                // multi-address `--reverse` sweep) differs from the section's
                // target is labelled, so which address's answer it is stays
                // visible instead of collapsing into ambiguity.
                let label = if obs.hostname != host && !obs.hostname.is_empty() {
                    format!("{} :: ", obs.hostname)
                } else {
                    String::new()
                };
                out.push_str(&format!("    {:4}: {label}", rt_label(rt)));
                out.push_str(&render_dns_one(*style, obs));
                out.push('\n');
            }
        }
    }
    out
}

fn render_dns_one(style: Style, obs: &DnsObservation) -> String {
    match (&obs.error, obs.latency_ms) {
        // A failed lookup is the row that matters in a terminal scan: red. The
        // `Dns` kind would just reprint the resolver context the row already
        // sits under (the message itself says what happened, e.g. 'does not
        // exist (NXDOMAIN)'); other kinds (timeout, resets) carry information
        // and stay.
        (Some(err), _) => {
            let detail = if matches!(err.kind, FailureKind::Dns) {
                err.message.clone()
            } else {
                format!("{} ({})", err.kind, err.message)
            };
            style.fail(detail)
        }
        (None, Some(ms)) => {
            if obs.records.is_empty() {
                format!("no records ({ms} ms)")
            } else {
                let addrs: Vec<String> = obs.records.iter().map(ToString::to_string).collect();
                let ttl = obs.ttl.map_or_else(String::new, |t| format!(", ttl {t}s"));
                format!("{}{} ({} ms)", addrs.join(", "), ttl, ms)
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
        DnsRecordType::Cname => "CNAME",
        DnsRecordType::Mx => "MX",
        DnsRecordType::Txt => "TXT",
        DnsRecordType::Ns => "NS",
        DnsRecordType::Soa => "SOA",
        DnsRecordType::Caa => "CAA",
        DnsRecordType::Srv => "SRV",
        DnsRecordType::Ptr => "PTR",
    }
}

/// Canonical order in which DNS record types are rendered.
const ALL_DNS_RECORD_TYPES: [DnsRecordType; 10] = [
    DnsRecordType::A,
    DnsRecordType::Aaaa,
    DnsRecordType::Cname,
    DnsRecordType::Mx,
    DnsRecordType::Txt,
    DnsRecordType::Ns,
    DnsRecordType::Soa,
    DnsRecordType::Caa,
    DnsRecordType::Srv,
    DnsRecordType::Ptr,
];

/// Render TCP observations as human text.
#[must_use]
pub fn render_tcp(style: &Style, observations: &[TcpObservation]) -> String {
    let mut out = String::from("TCP connect\n");
    // Share a column width across all rows so a long destination (a long
    // hostname, or an IPv6 literal) doesn't leave the status column ragged
    // where shorter rows keep the historical 24-wide column.
    let dest_w = observations
        .iter()
        .map(|o| o.destination.to_string().len())
        .max()
        .unwrap_or(24)
        .max(24);
    for obs in observations {
        // The padded status token is painted as a whole so the fixed 10-wide
        // column survives coloring; a plain style is byte-identical.
        let status = if obs.success {
            style.pass(format!("PASS      {}", ms_or_dash(obs.latency_ms)))
        } else {
            let err = obs
                .failure
                .as_ref()
                .map_or_else(|| "failed".to_string(), |e| e.kind.to_string());
            style.fail(format!("{err:10}"))
        };
        out.push_str(&format!("  {:<dest_w$} {status}\n", obs.destination));
    }
    out
}

/// Render an optional millisecond latency for the human report: `N ms` when
/// measured, or a bare `-` when unmeasured. A `None` latency is present only
/// by model construction (probe paths always record `Some`), but rendering it
/// as a literal `0 ms` would fabricate a measured value; `-` is the honest
/// placeholder.
fn ms_or_dash(ms: Option<u64>) -> String {
    ms.map_or_else(|| "-".to_string(), |n| format!("{n} ms"))
}

/// Render TLS observations as human text.
#[must_use]
pub fn render_tls(style: &Style, observations: &[TlsObservation]) -> String {
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
            out.push_str(&format!("    {}\n", style.fail(err)));
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
            out.push_str(&format!("    cert : {}\n", render_cert(*style, cert)));
            let covers = if cert_covers_hostname(&obs.sni, &cert.sans) {
                style.pass("yes")
            } else {
                style.fail("no")
            };
            out.push_str(&format!("    covers {}: {covers}\n", obs.sni));
        }
        out.push_str(&format!("    latency: {}\n", ms_or_dash(obs.latency_ms)));
    }
    out
}

/// Whether any subject alternative name covers the presented hostname/`SNI`.
///
/// Uses `RFC 6125`-style matching: an `IP`-literal `SNI` must match an
/// `IPAddress` SAN exactly, and a DNS `SNI` matches a `DNSName` SAN
/// case-insensitively, where a leading `*.` wildcard matches only a single
/// left-most label.
#[must_use]
pub fn cert_covers_hostname(sni: &str, sans: &[String]) -> bool {
    // An IPv6-literal SNI keeps its brackets (`Target::parse("[2001:db8::1]", _)`
    // stores the host as `[2001:db8::1]`), which fails to parse as an address.
    // Strip them so the presented name matches the bare IP SAN — the human
    // report's `presented_name_differs` already trims for its sideline.
    let sni = sni.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
        return sans.iter().any(|san| san.parse::<std::net::IpAddr>().ok() == Some(ip));
    }
    let sni_lower = sni.to_ascii_lowercase();
    sans.iter().any(|san| {
        let san_lower = san.to_ascii_lowercase();
        // A `*.` SAN covers exactly one left-most label below the suffix.
        san_lower.strip_prefix("*.").map_or_else(
            || san_lower == sni_lower,
            |wildcard| sni_lower.split_once('.').is_some_and(|(_, rest)| rest == wildcard),
        )
    })
}

/// Render a certificate summary compactly for the terminal, annotated with
/// the remaining lifetime when it is actionable: `expired`, `expires today`
/// for a certificate running out today, or `expires in N day(s)` within
/// [`RENDER_CERT_EXPIRY_WINDOW_DAYS`], or nothing for a comfortably-far
/// expiry. The actionable lifetime annotation is painted — red when expired,
/// yellow when expiring — so a terminal scan finds it.
fn render_cert(style: Style, cert: &CertificateSummary) -> String {
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
        .map_or_else(String::new, move |days| {
            if days < 0 {
                style.fail(" (expired)")
            } else if days == 0 {
                style.warn(" (expires today)")
            } else if days <= RENDER_CERT_EXPIRY_WINDOW_DAYS {
                style.warn(format!(" (expires in {days} day{})", if days == 1 { "" } else { "s" }))
            } else {
                String::new()
            }
        });
    let sans = if cert.sans.is_empty() {
        String::new()
    } else {
        format!("; sans: {}", cert.sans.join(", "))
    };
    format!(
        "{} issued by {}{}{}{}",
        cert.subject, cert.issuer, valid, lifetime, sans
    )
}

/// Number of days before expiry the certificate report flags as expiring.
/// Shared with the diagnostic engine so a `diagnose` health sweep raises the
/// same expiry window the human TLS report annotates.
pub(crate) const RENDER_CERT_EXPIRY_WINDOW_DAYS: i64 = 30;

/// Days from today until the date encoded in an RFC 3339 UTC timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`); negative when that date is already past.
/// `None` when the string is not recognizably that shape.
pub(crate) fn days_until_from_rfc3339(rfc3339: &str) -> Option<i64> {
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

/// Build an RFC 3339 UTC date string `N` days from today (negative = past),
/// shared by the TLS report tests and the diagnostic engine tests.
#[cfg(test)]
pub(crate) fn rfc3339_days_from_now(days: i64) -> String {
    let now_days = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_secs()
            / 86_400,
    )
    .expect("days fit i64");
    let (y, m, d) = civil_from_days(now_days + days);
    format!("{y:04}-{m:02}-{d:02}T00:00:00Z")
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Hinnant's
/// algorithm, the inverse of `tls.rs format_utc`).
pub(crate) const fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Render an HTTP status code, colored by class: 2xx green, 3xx yellow,
/// 4xx/5xx red, everything else plain (`0`/unknown stays plain).
#[must_use]
fn render_status(style: Style, status: u16) -> String {
    let text = status.to_string();
    match status {
        200..=299 => style.pass(text),
        300..=399 => style.warn(text),
        400..=599 => style.fail(text),
        _ => text,
    }
}

/// Term-print-safe rendering of a server-controlled body snippet for the
/// human report. C0 control characters — above all the ANSI ESC (`\x1b`) that
/// a hostile body could otherwise use to spoof the tool's own styled verdicts,
/// plus newlines that would split the `body content:` row — are emitted as
/// visible escapes, so the report's rows and the terminal stay intact. JSON
/// escapes by its serializer and CSV by its field quoting; this is the
/// human-only guard.
fn sanitize_snippet(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\x1b' => out.push_str("\\x1b"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", u32::from(c)));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Render HTTPS observations as human text.
///
/// HTTP/2 and HTTP/3 always run over TLS, and the HTTP/1.1 command defaults to
/// a TLS run, so the block is headed `HTTPS` — including a run whose handshake
/// *failed*, which the observations cannot signal on their own (`tls` is only
/// set on success). Cleartext runs (`http --plain`, `diagnose --plain`) use
/// [`render_http_plain`] instead.
#[must_use]
pub fn render_http(style: &Style, observations: &[HttpObservation]) -> String {
    render_http_impl(*style, false, observations)
}

/// Render a cleartext (`http --plain` / `diagnose --plain`) run's observations
/// as human text, headed `HTTP`.
///
/// There is no TLS layer at all, so the honest label is the plain protocol
/// name (see [`render_http`] for the TLS side).
#[must_use]
pub fn render_http_plain(style: &Style, observations: &[HttpObservation]) -> String {
    render_http_impl(*style, true, observations)
}

/// Shared body for the HTTPS/HTTP human renderers; `plain` selects the header
/// label only — the rows are identical.
fn render_http_impl(style: Style, plain: bool, observations: &[HttpObservation]) -> String {
    let mut out = String::from(if plain { "HTTP\n" } else { "HTTPS\n" });
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
                "    {}\n",
                style.fail(format!(
                    "{} {} ({})",
                    obs.protocol.as_deref().unwrap_or("HTTP/1.1"),
                    failure.kind,
                    failure.message
                ))
            ));
            continue;
        }
        out.push_str(&format!(
            "    {} {}\n",
            obs.protocol.as_deref().unwrap_or("HTTP/1.1"),
            obs.status
                .map_or_else(|| "no status".to_string(), |s| render_status(style, s))
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
            // Parity with the `tls` command: surface the serving certificate
            // and the SAN-coverage verdict for the presented SNI. This is
            // what makes a wrong-host/wildcard mismatch visible in an HTTPS
            // inspection — especially under `--insecure`, where chain
            // validation is skipped and coverage is the only mismatch signal.
            if let Some(cert) = &tls.certificate {
                out.push_str(&format!("    cert : {}\n", render_cert(style, cert)));
                let covers = if cert_covers_hostname(&tls.sni, &cert.sans) {
                    style.pass("yes")
                } else {
                    style.fail("no")
                };
                out.push_str(&format!("    covers {}: {covers}\n", tls.sni));
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
            // A body that hit the `max-body-bytes` cap is not the response's
            // true size — a download endpoint that sent more than the cap
            // would otherwise be reported as ending exactly at the cap count,
            // which reads as its real length. Mark it explicitly.
            if obs.body_capped {
                out.push_str(&format!("    {}: {bytes} bytes\n", style.warn("body (capped)")));
            } else {
                out.push_str(&format!("    body: {bytes} bytes\n"));
            }
        } else if obs.status.is_some() {
            // Headers were received but the body never completed within the
            // probe bound: the response is visibly truncated/stalled.
            out.push_str(&format!("    {}\n", style.warn("body: incomplete (timed out)")));
        }
        if let Some(snippet) = &obs.body_snippet {
            out.push_str("    body content: ");
            out.push_str(&sanitize_snippet(snippet));
            out.push('\n');
        }
        out.push_str(&format!("    latency: {}\n", ms_or_dash(obs.latency_ms)));
        if let Some(ttfb) = obs.ttfb_ms {
            out.push_str(&format!("    ttfb:    {ttfb} ms\n"));
        }
    }
    out
}

/// Render repeated DNS resolution results (`dns --count N`) as human text.
#[must_use]
pub fn render_dns_repeat(style: &Style, host: &str, results: &[DnsRepeatResult]) -> String {
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
        out.push_str(&format!(
            "    failure:  {}\n",
            if r.failures > 0 {
                style.fail(r.failures.to_string())
            } else {
                r.failures.to_string()
            }
        ));
        for fc in &r.failure_counts {
            out.push_str(&format!(
                "      - {}\n",
                style.fail(format!("{}: {}", fc.kind, fc.count))
            ));
        }
        if let Some(ttl) = r.ttl {
            out.push_str(&format!("    ttl: {ttl} s\n"));
        }
        if r.latency.count > 0 {
            out.push_str("    latency:\n");
            out.push_str(&format!("      min:  {}\n", ms_or_dash(r.latency.min)));
            out.push_str(&format!("      p50:  {}\n", ms_or_dash(r.latency.p50)));
            out.push_str(&format!("      p95:  {}\n", ms_or_dash(r.latency.p95)));
            out.push_str(&format!("      p99:  {}\n", ms_or_dash(r.latency.p99)));
            out.push_str(&format!("      max:  {}\n", ms_or_dash(r.latency.max)));
            out.push_str(&format!("      jitter: {}\n", ms_or_dash(r.latency.jitter)));
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
pub fn render_probe(style: &Style, results: &[ProbeResult]) -> String {
    let mut out = String::from("Repeated probes\n");
    for r in results {
        out.push_str(&format!("  {}\n", r.destination));
        out.push_str(&format!(
            "    attempts: {}\n    success:  {} ({})\n    failure:  {}\n",
            r.attempts,
            r.successes,
            format_rate(r.success_rate),
            if r.failures > 0 {
                style.fail(r.failures.to_string())
            } else {
                r.failures.to_string()
            }
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
        // Server-response latency (HTTP repeats only): the time from sending
        // the request to receiving the response headers, aggregated separately
        // from total latency so a slow-to-respond backend is distinguishable
        // from a slow body transfer.
        let ttfb = &r.ttfb;
        if ttfb.count > 0 {
            out.push_str(&format!(
                "    ttfb:\n      min:  {} ms\n      p50:  {} ms\n      p95:  {} ms\n      max:  {} ms\n",
                fmt(ttfb.min),
                fmt(ttfb.p50),
                fmt(ttfb.p95),
                fmt(ttfb.max),
            ));
        }
        if !r.failure_counts.is_empty() {
            let dist: Vec<String> = r
                .failure_counts
                .iter()
                .map(|f| style.fail(format!("{}: {}", f.kind, f.count)))
                .collect();
            out.push_str(&format!("    failures: {}\n", dist.join(", ")));
        }
        if !r.status_counts.is_empty() {
            // Each observed status is colored by its class like `render_http`
            // (2xx green, 3xx yellow, 4xx/5xx red); the whole `200x5` token is
            // painted so the count shares the status's color.
            let dist: Vec<String> = r
                .status_counts
                .iter()
                .map(|s| {
                    let token = format!("{}x{}", s.status, s.count);
                    match s.status {
                        200..=299 => (*style).pass(token),
                        300..=399 => (*style).warn(token),
                        400..=599 => (*style).fail(token),
                        _ => token,
                    }
                })
                .collect();
            out.push_str(&format!("    status:   {}\n", dist.join(", ")));
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
#[must_use]
pub fn render_route(style: &Style, hops: &[RouteHop]) -> String {
    let mut out = String::from("Traceroute\n");
    // Column width shared across rows: the historical 40-wide host column
    // stays so short rows are byte-identical, but a longer hostname / IPv6
    // literal widens the column so the rtt column never lands ragged.
    let host_w = hops
        .iter()
        .map(|h| {
            if h.lost || h.addr.is_none() {
                0
            } else {
                route_host_cell(h).len()
            }
        })
        .max()
        .unwrap_or(0)
        .max(40);
    for hop in hops {
        if hop.lost || hop.addr.is_none() {
            out.push_str(&format!("  {:>2}  {}\n", hop.ttl, style.fail("*")));
            continue;
        }
        let host = route_host_cell(hop);
        let rtt = hop.rtt_ms.map_or_else(|| "-".to_string(), |ms| format!("{ms} ms"));
        out.push_str(&format!("  {:>2}  {host:<host_w$} {rtt}\n", hop.ttl));
    }
    out
}

/// The host cell shown for an answered traceroute hop: `name (addr)` when a
/// hostname is known, the bare address otherwise.
fn route_host_cell(hop: &RouteHop) -> String {
    let addr = hop.addr.map_or_else(String::new, |a| a.to_string());
    let hostname = hop.hostname.as_deref().filter(|n| !n.is_empty());
    match hostname {
        Some(n) => format!("{n} ({addr})"),
        None => addr,
    }
}

/// The host cell shown for an answered repeated-traceroute hop (may list
/// several distinct addresses across runs).
fn route_repeat_host_cell(hop: &crate::RouteHopStats) -> String {
    let addrs = hop.addrs.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    let hostname = hop.hostname.as_deref().filter(|n| !n.is_empty());
    match hostname {
        Some(n) => format!("{n} ({addrs})"),
        None => addrs,
    }
}

/// Render a repeated-traceroute aggregation as human text.
///
/// Each hop shows how many runs it answered in, a min/p50/max latency bound,
/// and a `path changed` marker when its router changed between runs.
#[must_use]
pub fn render_route_repeat(style: &Style, repeat: &RouteRepeat) -> String {
    let mut out = format!("Traceroute ({} runs)\n", repeat.runs);
    // Shared host column width like `render_route`: 40 when all hosts fit,
    // widened to the longest host so the answered/lost columns stay aligned.
    let host_w = repeat
        .hops
        .iter()
        .filter(|h| h.answered > 0)
        .map(|h| route_repeat_host_cell(h).len())
        .max()
        .unwrap_or(0)
        .max(40);
    for hop in &repeat.hops {
        if hop.answered == 0 {
            out.push_str(&format!(
                "  {:>2}  {}  {}/{}\n",
                hop.ttl,
                style.fail("*"),
                0,
                style.fail(format!("{} (lost)", repeat.runs))
            ));
            continue;
        }
        let host = route_repeat_host_cell(hop);
        let mut line = format!(
            "  {:>2}  {host:<host_w$} {}/{} answered",
            hop.ttl, hop.answered, repeat.runs
        );
        let mut tail: Vec<String> = Vec::new();
        if let Some(ms) = hop.rtt.min {
            tail.push(format!("min {ms} ms"));
        }
        if let Some(ms) = hop.rtt.p50 {
            tail.push(format!("p50 {ms} ms"));
        }
        if let Some(ms) = hop.rtt.max {
            tail.push(format!("max {ms} ms"));
        }
        if hop.path_changed {
            tail.push(style.warn("path changed"));
        }
        if !tail.is_empty() {
            line.push_str("  ");
            line.push_str(&tail.join("  "));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Render the severity badge colored by how bad the diagnosis is: `HIGH` red,
/// `MEDIUM` yellow, `INFO` cyan; `LOW` stays plain.
#[must_use]
fn render_severity_badge(style: Style, severity: Severity) -> String {
    let text = format!("{severity:?}").to_uppercase();
    match severity {
        Severity::High => style.fail(text),
        Severity::Medium => style.warn(text),
        Severity::Info => style.info(text),
        Severity::Low => text,
    }
}

/// Render diagnoses as human text.
#[must_use]
pub fn render_diagnoses(style: &Style, diagnoses: &[Diagnosis]) -> String {
    let mut out = String::from("Diagnosis\n");
    for d in diagnoses {
        out.push_str(&format!(
            "[{}] {:?} ({:?} confidence)\n",
            render_severity_badge(*style, d.severity),
            d.category,
            d.confidence
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
    // A final verdict line answers a fleet scan's one question — "did anything
    // turn up?" — without reading every row. Rendered only when a non-Healthy
    // diagnosis exists, so a healthy run stays byte-identical. Colored red
    // when any High-severity anomaly is present, yellow otherwise.
    let anomaly_count = diagnoses
        .iter()
        .filter(|d| d.category != DiagnosticCategory::Healthy)
        .count();
    if anomaly_count > 0 {
        let mut parts: Vec<String> = Vec::new();
        for severity in [Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
            let count = diagnoses
                .iter()
                .filter(|d| d.category != DiagnosticCategory::Healthy && d.severity == severity)
                .count();
            if count > 0 {
                parts.push(format!("{severity:?}: {count}").to_uppercase());
            }
        }
        let token = format!("Anomalies: {anomaly_count} ({})", parts.join(", "));
        let line = if diagnoses.iter().any(|d| d.severity == Severity::High) {
            style.fail(token)
        } else {
            style.warn(token)
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Confidence, DiagnosticCategory, DnsRecord, DnsRecordType, Evidence, FailureCount, FailureKind, LatencyStats,
        ProbeError, ResolverKind, Severity,
    };
    use crate::style::Style;

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
            ttl: Some(60),
            records: addrs
                .iter()
                .map(|a| match a.parse::<std::net::IpAddr>().unwrap() {
                    std::net::IpAddr::V4(v) => DnsRecord::A(v),
                    std::net::IpAddr::V6(v) => DnsRecord::Aaaa(v),
                })
                .collect(),
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
                sans: vec!["example.com".into(), "www.example.com".into()],
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
        let out = render_dns(&Style::plain(), "example.com", &obs);
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
        assert!(render_dns(&Style::plain(), "example.com", &obs).contains("no records"));
        assert!(render_dns(&Style::plain(), "example.com", &[]).contains("DNS example.com"));
    }

    #[test]
    fn render_dns_keeps_every_observation_not_just_the_first_per_resolver() {
        // `diagnose --reverse` on a multi-address host adds one System PTR
        // observation per resolved address; the human report must keep all of
        // them (each labelled with the address it answers) instead of
        // rendering only the first, matching JSON/CSV which iterate the full
        // set. The dedicated `dns` command yields one observation per
        // (resolver, record type), so its output is unchanged by this.
        let ptr = |addr: &str, target: &str| DnsObservation {
            hostname: addr.to_string(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::Ptr,
            records: vec![DnsRecord::Ptr(target.to_string())],
            ttl: Some(60),
            latency_ms: Some(2),
            error: None,
        };
        let obs = [ptr("192.0.2.1", "one.example"), ptr("192.0.2.2", "two.example")];
        let out = render_dns(&Style::plain(), "example.com", &obs);
        assert!(
            out.contains("192.0.2.1 :: one.example"),
            "the first reverse row must carry its address label: {out}"
        );
        assert!(
            out.contains("192.0.2.2 :: two.example"),
            "the second reverse row must not be dropped: {out}"
        );
    }

    #[test]
    fn render_dns_shows_non_address_record_types() {
        let mx = DnsObservation {
            hostname: "example.com".into(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::Mx,
            ttl: Some(60),
            records: vec![DnsRecord::Mx {
                preference: 10,
                exchange: "mail.example.com".into(),
            }],
            latency_ms: Some(4),
            error: None,
        };
        let txt = DnsObservation {
            hostname: "example.com".into(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::Txt,
            ttl: Some(60),
            records: vec![DnsRecord::Txt("v=spf1 include:spf.example ~all".into())],
            latency_ms: Some(4),
            error: None,
        };
        let out = render_dns(&Style::plain(), "example.com", &[mx, txt]);
        assert!(out.contains("MX"), "MX row missing: {out}");
        assert!(out.contains("10 mail.example.com"), "MX record missing: {out}");
        assert!(out.contains("TXT"), "TXT row missing: {out}");
        assert!(
            out.contains("\"v=spf1 include:spf.example ~all\""),
            "TXT record missing: {out}"
        );
    }

    #[test]
    fn render_dns_shows_caa_and_srv() {
        let caa = DnsObservation {
            hostname: "example.com".into(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::Caa,
            ttl: Some(60),
            records: vec![DnsRecord::Caa {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into(),
            }],
            latency_ms: Some(4),
            error: None,
        };
        let srv = DnsObservation {
            hostname: "_sip._tcp.example.com".into(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::Srv,
            ttl: Some(60),
            records: vec![DnsRecord::Srv {
                priority: 1,
                weight: 2,
                port: 5060,
                target: "sip.example.com".into(),
            }],
            latency_ms: Some(4),
            error: None,
        };
        let out = render_dns(&Style::plain(), "example.com", &[caa, srv]);
        assert!(out.contains("CAA"), "CAA row missing: {out}");
        assert!(out.contains("0 issue letsencrypt.org"), "CAA record missing: {out}");
        assert!(out.contains("SRV"), "SRV row missing: {out}");
        assert!(out.contains("1 2 5060 sip.example.com"), "SRV record missing: {out}");
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
        let out = render_tcp(&Style::plain(), &obs);
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
        assert!(render_tcp(&Style::plain(), &bare).contains("failed"));
    }

    #[test]
    fn render_tls_covers_success_and_failure() {
        let out = render_tls(&Style::plain(), &[tls(true), tls(false)]);
        assert!(out.contains("TLS handshake"));
        assert!(out.contains("TLSv1.3"));
        assert!(out.contains("cipher: TLS_AES_128_GCM_SHA256"));
        assert!(out.contains("ALPN: h2"));
        assert!(out.contains("cert :"));
        assert!(out.contains("CN=example.com"));
        assert!(out.contains("issued by"));
        assert!(out.contains("handshake failed"));
        // Certificate without validity range degrades to no parenthetical.
        let no_validity = render_cert(
            Style::plain(),
            &CertificateSummary {
                subject: "CN=x".into(),
                issuer: "CN=y".into(),
                not_before_utc: None,
                not_after_utc: None,
                sans: Vec::new(),
            },
        );
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
            body_capped: false,
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
            body_capped: false,
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
            body_capped: false,
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
            body_capped: false,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: None,
        };
        let out = render_http(&Style::plain(), &[ok, err, no_status, truncated]);
        assert!(out.contains("example.com"));
        assert!(out.contains("HTTP/2"));
        assert!(out.contains("200"));
        assert!(out.contains("redirect: https://example.com/login"));
        assert!(out.contains("body: 1234 bytes"));
        // The HTTPS report must now surface the serving certificate and the
        // SAN-coverage verdict (parity with the `tls` command), not just the
        // negotiated TLS version/ALPN.
        assert!(
            out.contains("cert : CN=example.com"),
            "http report must show the cert: {out}"
        );
        assert!(
            out.contains("covers example.com: yes"),
            "http report must show a covers verdict: {out}"
        );
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
    fn render_http_labels_a_cleartext_block_http() {
        // `http --plain` / `diagnose --plain` carry no TLS observation:
        // heading the block `HTTPS` would present a plaintext endpoint as
        // encrypted, against the `HTTP/1.1` rows underneath.
        let plain = HttpObservation {
            destination: "192.0.2.1:80".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: Some(2),
            body_capped: false,
            body_snippet: Some("ok".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http_plain(&Style::plain(), std::slice::from_ref(&plain));
        assert!(
            out.starts_with("HTTP\n"),
            "a cleartext block must be labelled HTTP, not HTTPS: {out}"
        );
        // Any TLS observation flips the block back to HTTPS.
        let with_tls = HttpObservation {
            tls: Some(crate::model::TlsObservation {
                destination: "192.0.2.1:443".parse().unwrap(),
                sni: "example.com".into(),
                success: true,
                version: Some("TLSv1.3".into()),
                cipher: Some("AES_256_GCM".into()),
                alpn: Some("h2".into()),
                certificate: None,
                latency_ms: Some(5),
                failure: None,
            }),
            ..plain
        };
        assert!(
            render_http(&Style::plain(), std::slice::from_ref(&with_tls)).starts_with("HTTPS\n"),
            "a TLS block keeps the HTTPS label"
        );
        // A TLS run whose handshake *failed* must stay `HTTPS` too: the
        // observation cannot signal the intended protocol on its own (`tls` is
        // only recorded on success), and mislabelling it `HTTP` would present
        // a failed-encryption endpoint as a plaintext one.
        let failed_tls = HttpObservation {
            tls: None,
            failure: Some(crate::model::ProbeError {
                kind: crate::model::FailureKind::TlsHandshake,
                message: "tls handshake eof".into(),
            }),
            ..with_tls
        };
        assert!(
            render_http(&Style::plain(), std::slice::from_ref(&failed_tls)).starts_with("HTTPS\n"),
            "a TLS run with a failed handshake must keep the HTTPS label"
        );
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
            body_capped: false,
            body_snippet: Some("ok".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http(&Style::plain(), &[ok]);
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
            body_capped: false,
            body_snippet: Some("xxxx…".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http(&Style::plain(), &[truncated]);
        assert!(
            out.contains("body content: xxxx…"),
            "truncated snippet with … must be visible: {out}"
        );
    }

    #[test]
    fn render_http_marks_a_capped_body_as_not_the_true_size() {
        // The same byte count is read differently depending on why the read
        // stopped: a body that hit the `max-body-bytes` cap is *not* known to
        // be that size (the response may continue past it), so it must be
        // marked capped instead of reading as `body: N bytes` — which a user
        // would take to be the true response length.
        let capped = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: Some(1024 * 1024),
            body_capped: true,
            body_snippet: Some("0000…".into()),
            ttfb_ms: None,
            latency_ms: Some(10),
            failure: None,
        };
        let out = render_http(&Style::plain(), std::slice::from_ref(&capped));
        assert!(
            out.contains("body (capped): 1048576 bytes"),
            "capped body must be marked, not presented as the true size: {out}"
        );
        assert!(
            !out.contains("\n    body: 1048576 bytes"),
            "a capped body must not read as `body: N bytes`: {out}"
        );
        // The same byte count with body_capped unset is the genuine size.
        let mut complete = capped;
        complete.body_capped = false;
        let out = render_http(&Style::plain(), &[complete]);
        assert!(
            out.contains("\n    body: 1048576 bytes"),
            "an uncapped body at the same count stays the true size: {out}"
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
            ttfb: LatencyStats::default().summarize(),
            failure_counts: vec![FailureCount {
                kind: FailureKind::Timeout,
                count: 2,
            }],
            status_counts: Vec::new(),
        };
        let no_latency = ProbeResult {
            destination: "2.2.2.2:443".parse().unwrap(),
            attempts: 2,
            successes: 0,
            failures: 2,
            success_rate: 0.0,
            latency: LatencyStats::default().summarize(),
            ttfb: LatencyStats::default().summarize(),
            failure_counts: vec![],
            status_counts: Vec::new(),
        };
        let out = render_probe(&Style::plain(), &[result, no_latency]);
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
            success_rate: 3.0 / 4.0,
            latency: stats.summarize(),
            failure_counts: vec![FailureCount {
                kind: FailureKind::Dns,
                count: 1,
            }],
            ttl: Some(300),
        };
        let out = render_dns_repeat(&Style::plain(), "host.example", &[ok]);
        assert!(out.contains("Repeated DNS host.example"));
        assert!(out.contains("9.9.9.9:53 A"));
        assert!(out.contains("attempts: 4"));
        assert!(out.contains("success:  3 (75.0%)"));
        assert!(out.contains("failure:  1"));
        assert!(out.contains("dns: 1"));
        assert!(out.contains("ttl: 300 s"));
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
        let out = render_route(&Style::plain(), &hops);
        assert!(out.contains("Traceroute"));
        assert!(out.contains("r1.example.com (192.0.2.1)"));
        assert!(out.contains("3 ms"));
        // Lost hop prints `*`; a reachable hop with no RTT prints `-`.
        assert!(out.contains('*'));
        assert!(out.contains("192.0.2.4"));
    }

    #[test]
    fn render_route_repeat_covers_answered_rate_and_path_change() {
        let mut stable = LatencyStats::default();
        stable.push(2);
        stable.push(4);
        let mut changed = LatencyStats::default();
        changed.push(9);
        let repeat = RouteRepeat {
            runs: 2,
            hops: vec![
                crate::RouteHopStats {
                    ttl: 1,
                    answered: 2,
                    addrs: vec!["192.0.2.1".parse().unwrap()],
                    hostname: Some("r1.example.com".into()),
                    rtt: stable.summarize(),
                    path_changed: false,
                },
                crate::RouteHopStats {
                    ttl: 2,
                    answered: 2,
                    addrs: vec!["192.0.2.2".parse().unwrap(), "192.0.2.9".parse().unwrap()],
                    hostname: None,
                    rtt: changed.summarize(),
                    path_changed: true,
                },
                crate::RouteHopStats {
                    ttl: 3,
                    answered: 0,
                    addrs: Vec::new(),
                    hostname: None,
                    rtt: LatencyStats::default().summarize(),
                    path_changed: false,
                },
            ],
        };
        let out = render_route_repeat(&Style::plain(), &repeat);
        assert!(out.contains("Traceroute (2 runs)"), "header missing: {out}");
        assert!(out.contains("r1.example.com (192.0.2.1)"), "host label missing: {out}");
        assert!(out.contains("2/2 answered"), "answered rate missing: {out}");
        assert!(out.contains("min 2 ms"), "min latency missing: {out}");
        assert!(out.contains("max 4 ms"), "max latency missing: {out}");
        assert!(out.contains("path changed"), "divergent hop must be flagged: {out}");
        assert!(out.contains("0/2 (lost)"), "fully-lost hop must render as lost: {out}");
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
        // A healthy-only run stays unchanged: no trailer.
        assert!(
            !render_diagnoses(&Style::plain(), std::slice::from_ref(&healthy)).contains("Anomalies:"),
            "healthy run must have no trailer"
        );
        let out = render_diagnoses(&Style::plain(), &[healthy, anomaly]);
        assert!(out.contains("Diagnosis"));
        assert!(out.contains("[INFO] Healthy (High confidence)"));
        assert!(out.contains("[HIGH] TotalConnectivityLoss (Medium confidence)"));
        assert!(out.contains("Evidence:"));
        assert!(out.contains("Possible causes:"));
        assert!(out.contains("firewall"));
        // A final verdict trailer is appended only when an anomaly exists, and
        // names the High-severity count.
        assert!(out.contains("Anomalies: 1 (HIGH: 1)"), "verdict trailer missing: {out}");
    }

    #[test]
    fn diagnoses_verdict_trailer_aggregates_severities_and_colors_high_red() {
        let mk = |severity, category| Diagnosis {
            severity,
            category,
            confidence: Confidence::Low,
            summary: "s".into(),
            evidence: Vec::new(),
            possible_causes: Vec::new(),
        };
        let mixed = [
            mk(Severity::High, DiagnosticCategory::TotalConnectivityLoss),
            mk(Severity::Medium, DiagnosticCategory::Certificate),
            mk(Severity::Info, DiagnosticCategory::Healthy),
        ];
        let plain = render_diagnoses(&Style::plain(), &mixed);
        assert!(
            plain.contains("Anomalies: 2 (HIGH: 1, MEDIUM: 1)"),
            "severity aggregation missing: {plain}"
        );
        // High severity present -> the whole trailer line is red.
        let colored = render_diagnoses(&Style::colored_for_tests(), &mixed);
        assert!(
            colored.contains("\x1b[31mAnomalies: 2 (HIGH: 1, MEDIUM: 1)\x1b[0m"),
            "trailer must be red when any High anomaly is present: {colored:?}"
        );
        // Medium-only -> yellow; an all-INFO/Low anomaly list stays plain.
        let med = [mk(Severity::Medium, DiagnosticCategory::Certificate)];
        let colored_med = render_diagnoses(&Style::colored_for_tests(), &med);
        assert!(
            colored_med.contains("\x1b[33mAnomalies: 1 (MEDIUM: 1)\x1b[0m"),
            "trailer must be yellow without High: {colored_med:?}"
        );
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
            sans: Vec::new(),
        };
        // Far future: no lifetime annotation.
        let far = render_cert(Style::plain(), &cert(400));
        assert!(!far.contains("expires in"), "far expiry has no annotation: {far}");
        assert!(!far.contains("expired"), "far expiry has no annotation: {far}");
        // Near expiry: annotated.
        let near = render_cert(Style::plain(), &cert(5));
        assert!(near.contains("expires in 5 days"), "near expiry annotated: {near}");
        // Expiring today: the clearer terminal phrasing, not "0 days".
        let today = render_cert(Style::plain(), &cert(0));
        assert!(today.contains("expires today"), "today expiry phrased clearly: {today}");
        // Already expired: annotated.
        let past = render_cert(Style::plain(), &cert(-3));
        assert!(past.contains("expired"), "expired annotated: {past}");
    }

    #[test]
    fn render_cert_shows_subject_alternative_names() {
        let with_sans = CertificateSummary {
            subject: "CN=example.com".into(),
            issuer: "CN=CA".into(),
            not_before_utc: None,
            not_after_utc: None,
            sans: vec!["example.com".into(), "127.0.0.1".into()],
        };
        let out = render_cert(Style::plain(), &with_sans);
        assert!(
            out.contains("; sans: example.com, 127.0.0.1"),
            "SANs should be rendered: {out}"
        );

        // No SANs -> no annotation (keeps old output shape).
        let none = CertificateSummary {
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            not_before_utc: None,
            not_after_utc: None,
            sans: Vec::new(),
        };
        assert_eq!(render_cert(Style::plain(), &none), "CN=x issued by CN=y");
    }

    #[test]
    fn cert_covers_hostname_matches_rfc6125_semantics() {
        let sans = |s: &[&str]| s.iter().map(ToString::to_string).collect::<Vec<_>>();
        // Exact DNS match.
        assert!(cert_covers_hostname(
            "example.com",
            &sans(&["example.com", "www.example.com"])
        ));
        // Case-insensitive.
        assert!(cert_covers_hostname("EXAMPLE.COM", &sans(&["example.com"])));
        // Wildcard covers a single left-most label.
        assert!(cert_covers_hostname("api.example.com", &sans(&["*.example.com"])));
        // Wildcard does not cover multiple labels, nor the bare apex.
        assert!(!cert_covers_hostname("a.b.example.com", &sans(&["*.example.com"])));
        assert!(!cert_covers_hostname("example.com", &sans(&["*.example.com"])));
        // IP-literal SNI matches an IP SAN exactly.
        assert!(cert_covers_hostname("127.0.0.1", &sans(&["127.0.0.1"])));
        assert!(!cert_covers_hostname("192.0.2.1", &sans(&["127.0.0.1"])));
        // No match.
        assert!(!cert_covers_hostname("other.example", &sans(&["example.com"])));
    }

    #[test]
    fn cert_covers_hostname_matches_bracketed_ipv6_literal_sni() {
        // `Target::parse("[2001:db8::1]", _)` keeps the brackets on the host,
        // which flows through to the SNI. The IP-literal branch parses the SNI
        // as an address; brackets made that parse fail and dropped the match
        // to a bare IP SAN (`covers ...: no` on a cert that does cover the
        // address) — in the human TLS/HTTP reports, both CSVs, and the
        // diagnose certificate-coverage rule.
        let sans = |s: &[&str]| s.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(cert_covers_hostname("[2001:db8::1]", &sans(&["2001:db8::1"])));
        assert!(!cert_covers_hostname("[2001:db8::1]", &sans(&["2001:db8::2"])));
        // Bracketed IPv4 (an unusual but accepted input form) matches too.
        assert!(cert_covers_hostname("[127.0.0.1]", &sans(&["127.0.0.1"])));
        assert!(cert_covers_hostname("2001:db8::1", &sans(&["2001:db8::1"])));
    }

    #[test]
    fn render_tls_reports_cert_hostname_coverage_verdict() {
        let covered = TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_128_GCM_SHA256".into()),
            alpn: None,
            certificate: Some(CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=CA".into(),
                not_before_utc: None,
                not_after_utc: None,
                sans: vec!["example.com".into(), "127.0.0.1".into()],
            }),
            latency_ms: Some(7),
            failure: None,
        };
        assert!(render_tls(&Style::plain(), std::slice::from_ref(&covered)).contains("covers example.com: yes"));

        let mut mismatch = covered;
        mismatch.sni = "attacker.example".into();
        assert!(render_tls(&Style::plain(), std::slice::from_ref(&mismatch)).contains("covers attacker.example: no"));
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

    /// A colored [`Style`] for tests (bypasses the TTY/env gate).
    fn colored() -> Style {
        Style::colored_for_tests()
    }

    #[test]
    fn colored_renderers_inject_ansi_for_verdicts_and_status_classes() {
        let colored = colored();
        let plain = Style::plain();

        // TCP: PASS green, refused/timeout red; plain stays byte-identical.
        let tcp = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(12),
            failure: None,
        }];
        let out = render_tcp(&colored, &tcp);
        assert!(out.contains("\x1b[32mPASS"), "PASS should be green: {out:?}");
        // The plain style is byte-identical to the historical text: no escape
        // codes anywhere, and the PASS line keeps its exact historical shape.
        let plain_out = render_tcp(&plain, &tcp);
        assert!(
            !plain_out.contains('\u{1b}'),
            "plain must have no escapes: {plain_out:?}"
        );
        assert!(plain_out.contains("PASS      12 ms"), "PASS line shape: {plain_out:?}");
        let fails = [TcpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::ConnectionRefused,
                message: "refused".into(),
            }),
        }];
        assert!(render_tcp(&colored, &fails).contains("\x1b[31m"));

        // HTTP: 2xx green, 3xx yellow, 5xx red.
        assert_eq!(render_status(colored, 200), "\x1b[32m200\x1b[0m");
        assert_eq!(render_status(colored, 302), "\x1b[33m302\x1b[0m");
        assert_eq!(render_status(colored, 503), "\x1b[31m503\x1b[0m");
        assert_eq!(render_status(plain, 200), "200");

        // Diagnosis badges: HIGH red, MEDIUM yellow, INFO cyan, LOW plain.
        assert_eq!(render_severity_badge(colored, Severity::High), "\x1b[31mHIGH\x1b[0m");
        assert_eq!(
            render_severity_badge(colored, Severity::Medium),
            "\x1b[33mMEDIUM\x1b[0m"
        );
        assert_eq!(render_severity_badge(colored, Severity::Info), "\x1b[36mINFO\x1b[0m");
        assert_eq!(render_severity_badge(colored, Severity::Low), "LOW");
    }

    #[test]
    fn unmeasured_latency_renders_dash_not_fabricated_zero() {
        // A success row whose latency is absent (possible only by model
        // construction — probe paths always record `Some`) must not present a
        // fabricated "0 ms" as a measured value; `-` is the honest placeholder.
        let tcp = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: None,
            failure: None,
        }];
        let out = render_tcp(&Style::plain(), &tcp);
        assert!(out.contains("PASS      -"), "unmeasured PASS shows '-' not 0 ms: {out}");
        assert!(!out.contains("0 ms"), "no fabricated 0 ms: {out}");

        let tls = TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: None,
            alpn: None,
            certificate: None,
            latency_ms: None,
            failure: None,
        };
        let tlso = render_tls(&Style::plain(), &[tls]);
        assert!(tlso.contains("latency: -"), "TLS latency is '-' not 0 ms: {tlso}");

        let http = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_capped: false,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: None,
        };
        let hout = render_http(&Style::plain(), &[http]);
        assert!(hout.contains("latency: -"), "HTTP latency is '-' not 0 ms: {hout}");
    }

    #[test]
    fn long_host_widens_column_so_status_aligns() {
        // A destination longer than the historical fixed 24-wide column must
        // not shove its status token past where the shorter rows put theirs:
        // the column widens to the longest destination, keeping the rows
        // aligned. Short-only output stays byte-identical.
        let short = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(5),
            failure: None,
        }];
        let short_out = render_tcp(&Style::plain(), &short);
        assert!(
            short_out.contains("PASS      5 ms"),
            "short stays 24-wide: {short_out:?}"
        );

        let long = [
            TcpObservation {
                destination: "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443".parse().unwrap(),
                success: true,
                latency_ms: Some(5),
                failure: None,
            },
            TcpObservation {
                destination: "[2001:db8::1]:443".parse().unwrap(),
                success: true,
                latency_ms: Some(6),
                failure: None,
            },
        ];
        let long_out = render_tcp(&Style::plain(), &long);
        // Both rows must place the PASS status token at the same column: the
        // widest destination (the long hostname) sets the shared width.
        let col = |line: &str| line.find("PASS").expect("row has PASS");
        let mut lines = long_out.lines().filter(|l| l.contains("PASS"));
        let first = lines.next().expect("first PASS row");
        let second = lines.next().expect("second PASS row");
        assert_eq!(
            col(first),
            col(second),
            "PASS column must align under a long host:\n{long_out}"
        );
        // And the historical 24-wide shape is preserved when all hosts fit.
        assert_ne!(short_out, long_out);
    }

    #[test]
    fn colored_render_equals_plain_after_stripping_escape_bytes() {
        // The column-alignment hazard that ANSI would otherwise introduce: if
        // any renderer padded a *colored* token (so the escape bytes counted
        // toward the width), the columns under a colored style would drift
        // from the plain style. Every padded token is painted whole, so
        // removing SGR escape sequences reproduces the plain text exactly.
        let colored = colored();
        let plain = Style::plain();

        let tcp = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(12),
            failure: None,
        }];
        let colored_tcp = render_tcp(&colored, &tcp);
        let plain_tcp = render_tcp(&plain, &tcp);
        assert_eq!(
            strip_sgr(&colored_tcp),
            plain_tcp,
            "TCP columns stable: {colored_tcp:?}"
        );

        // Capture the failure row too (its `{err:10}` pad must be painted whole).
        let tcp_fail = [TcpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::ConnectionRefused,
                message: "refused".into(),
            }),
        }];
        let colored_fail = render_tcp(&colored, &tcp_fail);
        let plain_fail = render_tcp(&plain, &tcp_fail);
        assert_eq!(
            strip_sgr(&colored_fail),
            plain_fail,
            "fail pad stable: {colored_fail:?}"
        );

        // HTTP status class colors live at the end of an unpadded row, so they
        // cannot shift a column either.
        let http = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/2".into()),
            status: Some(503),
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_capped: false,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(9),
            failure: None,
        };
        // Render the same observation with both styles; `from_ref` avoids a
        // clone of the whole observation for the (immutable) colored pass.
        let colored_http = render_http(&colored, std::slice::from_ref(&http));
        let plain_http = render_http(&plain, &[http]);
        assert_eq!(
            strip_sgr(&colored_http),
            plain_http,
            "HTTP columns stable: {colored_http:?}"
        );
    }

    /// Remove ANSI SGR escape sequences (`ESC[...m`) from a string, so a
    /// colored render can be compared with the same render under a plain style
    /// to prove escape bytes never shift column alignment.
    fn strip_sgr(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' && chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                for inner in chars.by_ref() {
                    if ('@'..='~').contains(&inner) {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn colored_marks_route_losses_expiry_and_cert_coverage() {
        let colored = colored();

        // A lost route hop's `*` is red.
        let hops = [RouteHop {
            ttl: 2,
            addr: None,
            hostname: None,
            rtt_ms: None,
            lost: true,
        }];
        assert!(render_route(&colored, &hops).contains("\x1b[31m*\x1b[0m"));

        // Repeat aggregation: `(lost)` red, `path changed` yellow.
        let repeat = RouteRepeat {
            runs: 2,
            hops: vec![
                crate::RouteHopStats {
                    ttl: 1,
                    answered: 0,
                    addrs: Vec::new(),
                    hostname: None,
                    rtt: LatencyStats::default().summarize(),
                    path_changed: false,
                },
                crate::RouteHopStats {
                    ttl: 2,
                    answered: 2,
                    addrs: vec!["192.0.2.2".parse().unwrap()],
                    hostname: None,
                    rtt: LatencyStats::default().summarize(),
                    path_changed: true,
                },
            ],
        };
        let out = render_route_repeat(&colored, &repeat);
        assert!(out.contains("\x1b[31m*\x1b[0m"), "lost-hop star red: {out:?}");
        assert!(out.contains("\x1b[31m2 (lost)\x1b[0m"), "lost marker red: {out:?}");
        assert!(
            out.contains("\x1b[33mpath changed\x1b[0m"),
            "path change yellow: {out:?}"
        );

        // Certificate lifetime: expired red, expiring yellow.
        let expired = CertificateSummary {
            subject: "CN=x".into(),
            issuer: "CN=y".into(),
            not_before_utc: None,
            not_after_utc: Some(days_out_rfc3339(-3)),
            sans: Vec::new(),
        };
        assert!(render_cert(colored, &expired).contains("\x1b[31m (expired)\x1b[0m"));
        let near = CertificateSummary {
            not_after_utc: Some(days_out_rfc3339(5)),
            ..expired
        };
        assert!(render_cert(colored, &near).contains("\x1b[33m (expires in 5 days)\x1b[0m"));

        // `covers <host>: no` is red in TLS and HTTPS reports.
        let tls_no = TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "attacker.example".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("x".into()),
            alpn: None,
            certificate: Some(CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=y".into(),
                not_before_utc: None,
                not_after_utc: None,
                sans: vec!["example.com".into()],
            }),
            latency_ms: Some(1),
            failure: None,
        };
        assert!(render_tls(&colored, std::slice::from_ref(&tls_no)).contains("\x1b[31mno\x1b[0m"));
        assert!(
            render_tls(&colored, std::slice::from_ref(&tls_no)).contains("covers attacker.example: \x1b[31mno\x1b[0m")
        );
    }

    #[test]
    fn sanitize_snippet_neutralizes_terminal_control_characters() {
        // ANSI escape (would spoof the tool's own verdict color), newlines
        // (would split the body-content row), and other C0 controls must all
        // render as visible escapes; ordinary text passes through unchanged.
        assert_eq!(sanitize_snippet("ok"), "ok");
        assert_eq!(sanitize_snippet("\x1b[31mFAIL\x1b[0m"), "\\x1b[31mFAIL\\x1b[0m");
        assert_eq!(sanitize_snippet("line1\nline2"), "line1\\nline2");
        assert_eq!(sanitize_snippet("a\tb"), "a\\tb");
        assert_eq!(sanitize_snippet("nul\x00byte"), "nul\\x00byte");
    }
}
