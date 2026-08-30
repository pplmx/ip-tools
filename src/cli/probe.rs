//! `probe` subcommand handler (repeated TCP/HTTP probing).

use super::run_probe_flow;
use clap::ArgMatches;
use ip_tools::model::ProbeResult;
use ip_tools::probe as ip_probe;
use ip_tools::report::render_probe;
use ip_tools::style::Style;
use std::process::ExitCode;

/// The user-asserted reliability expectations of a repeated probe
/// (`--expect-status` / `--expect-rate`), evaluated per resolved address
/// against the aggregate [`ProbeResult`]. This is the stability-dimension
/// counterpart of the single-shot [`super::Expectation`] (DEC-074): a single
/// response can only assert its own shape, while a repeat probe exists to
/// answer "did the endpoint *reliably* answer the way I asserted over time".
#[derive(Clone, Debug, Default)]
struct ProbeExpectation {
    /// Every observed HTTP status in the status distribution must match this
    /// spec (`200` exact or `2xx` class); only HTTP-family protocols carry a
    /// distribution.
    status: Option<super::StatusSpec>,
    /// The aggregate `success_rate` must be at least this threshold (0..=1).
    rate: Option<f64>,
}

impl ProbeExpectation {
    /// The reason this per-address aggregate violates the asserted
    /// expectations, or `None` when it satisfies them all.
    ///
    /// `--expect-status` asserts the accepted status *set*: every status that
    /// appeared across the `--count` attempts must match (a mixed distribution
    /// like `200x57 / 503x3` reveals status flapping a single response cannot).
    /// A repeat whose attempts produced no HTTP response at all (empty
    /// distribution) carries no response to assert on, so it can never satisfy
    /// the assertion — that is itself the violation, mirroring the single-shot
    /// `Expectation`.
    ///
    /// `--expect-rate` asserts the aggregate `success_rate`. The two compose:
    /// `--expect-status` catches the wrong status, `--expect-rate` catches
    /// transport flakiness/timeouts (which produce no response at all).
    fn violation(&self, r: &ProbeResult) -> Option<String> {
        let mut reasons = Vec::new();
        if let Some(spec) = &self.status {
            if r.status_counts.is_empty() {
                // The report just showed `attempts: N / success: 0`, so say
                // plainly that the attempts ran but none produced a response
                // (an HTTP response always carries a status, so an empty
                // distribution means every attempt failed at the transport).
                reasons.push("no response to assert on (every attempt failed)".to_string());
            } else {
                let outside: Vec<String> = r
                    .status_counts
                    .iter()
                    .filter(|sc| !spec.matches(sc.status))
                    .map(|sc| format!("{}x{}", sc.status, sc.count))
                    .collect();
                if !outside.is_empty() {
                    reasons.push(format!(
                        "statuses {{{}}} outside expected {}",
                        outside.join(", "),
                        spec.describes()
                    ));
                }
            }
        }
        if let Some(min) = self.rate {
            if r.success_rate < min {
                reasons.push(format!(
                    "success rate {:.1}% (expected ≥ {:.1}%)",
                    r.success_rate * 100.0,
                    min * 100.0
                ));
            }
        }
        if reasons.is_empty() {
            None
        } else {
            Some(format!("{}: {}", r.destination, reasons.join(", ")))
        }
    }
}

/// Parse a `--expect-rate` threshold: a success-rate fraction in `(0, 1]`
/// (`0.97`, `.97`, `1`) or a percent (`97%`, `100%`). A zero threshold is a
/// caller mistake — it would make every run pass vacuously — and is rejected
/// along with malformed text, so a typo fails at the CLI instead of silently
/// gating nothing.
fn parse_expect_rate(spec: &str) -> Result<f64, String> {
    let s = spec.trim();
    let rate = if let Some(pct) = s.strip_suffix('%') {
        let pct: f64 = pct.trim().parse().map_err(|_| {
            format!("invalid --expect-rate '{spec}': expected a fraction like 0.97 or a percent like 97%")
        })?;
        if !pct.is_finite() || pct <= 0.0 || pct > 100.0 {
            return Err(format!("invalid --expect-rate '{spec}': a percent must be in (0, 100]"));
        }
        pct / 100.0
    } else {
        let v: f64 = s.parse().map_err(|_| {
            format!("invalid --expect-rate '{spec}': expected a fraction like 0.97 or a percent like 97%")
        })?;
        if !v.is_finite() || v <= 0.0 || v > 1.0 {
            return Err(format!(
                "invalid --expect-rate '{spec}': a fraction must be in (0, 1], e.g. 0.97 for 97%"
            ));
        }
        v
    };
    Ok(rate)
}

/// Parse `probe`'s `--expect-status` / `--expect-rate` args. `--expect-status`
/// asserts an observed HTTP status distribution, so it only applies to the
/// HTTP-family protocols (a tcp/tls repeat has no status to assert on and is a
/// call-time error, not a silent no-op); `--expect-rate` applies to every
/// protocol. Returns `Ok(None)` when neither flag is present.
fn parse_probe_expectation(sub_m: &ArgMatches, protocol: &str) -> Result<Option<ProbeExpectation>, String> {
    let status = match sub_m.try_get_one::<String>("expect-status").ok().flatten() {
        Some(spec) => {
            if !matches!(protocol, "http" | "http2" | "http3") {
                return Err("--expect-status only applies to --protocol http|http2|http3 (a tcp/tls repeat has no HTTP status to assert on)".into());
            }
            Some(super::parse_status_spec(spec)?)
        }
        None => None,
    };
    let rate = match sub_m.try_get_one::<String>("expect-rate").ok().flatten() {
        Some(spec) => Some(parse_expect_rate(spec)?),
        None => None,
    };
    if status.is_none() && rate.is_none() {
        Ok(None)
    } else {
        Ok(Some(ProbeExpectation { status, rate }))
    }
}

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
    // HTTP-request flags are silently ignored by the tcp/tls protocol arms
    // (their probes take no request at all): an operator passing `--path /x`
    // with `--protocol tls` would believe the path was used. Reject the
    // mismatch up front, the same fail-fast `--plain` and `--expect-status`
    // already apply.
    let is_http = matches!(protocol.as_str(), "http" | "http2" | "http3");
    if !is_http {
        // An option's clap *default* (e.g. `--method`'s `GET`, `--path`'s `/`,
        // `--tls-version`'s `auto`) is present in the matches and must not
        // count as "passed": the guard must fire only when the operator
        // actually typed the flag, so it checks `value_source`. The previous
        // value-comparison against the defaults let explicitly-passed but
        // default-shaped values (`--method GET`, `--path /`, `--tls-version
        // auto` on a tcp/tls repeat) slip through silently.
        let explicitly_given =
            |name: &str| matches!(sub_m.value_source(name), Some(clap::parser::ValueSource::CommandLine));
        if explicitly_given("method")
            || explicitly_given("path")
            || explicitly_given("header")
            || explicitly_given("body")
        {
            eprintln!("Error: --method/--path/--header/--body only apply to --protocol http|http2|http3 (the {protocol} repeat sends no HTTP request)");
            return ExitCode::FAILURE;
        }
        if protocol.as_str() == "tcp" && explicitly_given("tls-version") {
            eprintln!("Error: --tls-version only applies to --protocol tls|http|http2|http3 (a tcp repeat has no TLS handshake)");
            return ExitCode::FAILURE;
        }
    }
    // QUIC is always TLS 1.3 (rustls on quinn offers 1.3 only), so a
    // `--tls-version 1.2` request on the http3 repeat is meaningless and would
    // otherwise run silently as 1.3 — reject it up front, matching the
    // standalone `http3` subcommand which does not even define the flag.
    if protocol.as_str() == "http3"
        && matches!(
            sub_m.value_source("tls-version"),
            Some(clap::parser::ValueSource::CommandLine)
        )
    {
        eprintln!("Error: --tls-version does not apply to --protocol http3 (QUIC is always TLS 1.3)");
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
    // `--expect-status`/`--expect-rate`: the repeat probe's assertion gate
    // (DEC-075), the stability-dimension counterpart of the single-shot
    // `--expect-*` (DEC-074). Each per-address aggregate must satisfy the
    // asserted status distribution and success-rate threshold; violations are
    // verdicts on the run, gated independently of `--strict`.
    let expectations = match parse_probe_expectation(sub_m, &protocol) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let expect_check =
        expectations.map(|e| -> super::ExpectCheck<ProbeResult> { Box::new(move |r: &ProbeResult| e.violation(r)) });
    run_probe_flow(
        sub_m,
        style,
        render_probe,
        |result: &ProbeResult| result.destination,
        |result: &ProbeResult| result.failures > 0,
        Some(render_probe_csv),
        expect_check,
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
/// `host,destination,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,jitter_ms,ttfb_p50_ms,ttfb_p95_ms,ttfb_max_ms,failures,statuses`
/// row per destination across every target. Latency statistics come from the
/// `--count` aggregation (only successful attempts); the `ttfb_*` columns
/// carry the server-response latency on HTTP repeats (empty for `tcp`/`tls`).
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
use super::csv_field;

#[cfg(test)]
mod tests {
    use super::{parse_expect_rate, ProbeExpectation};
    use ip_tools::model::probe::StatusCount;
    use ip_tools::model::{LatencyStats, ProbeResult};
    use std::net::SocketAddr;

    fn addr() -> SocketAddr {
        "192.0.2.1:443".parse().expect("fixed test addr")
    }

    /// Build an aggregate with the given success rate and status distribution
    /// (sufficient for the assertion checks, which only read `success_rate`
    /// and `status_counts`).
    fn result(rate: f64, statuses: &[(u16, usize)]) -> ProbeResult {
        ProbeResult {
            destination: addr(),
            attempts: statuses.iter().map(|(_, c)| c).sum(),
            successes: 0,
            failures: 0,
            success_rate: rate,
            latency: LatencyStats::default().summarize(),
            ttfb: LatencyStats::default().summarize(),
            failure_counts: Vec::new(),
            status_counts: statuses
                .iter()
                .map(|(s, c)| StatusCount { status: *s, count: *c })
                .collect(),
        }
    }

    #[test]
    fn expect_rate_parses_fractions_and_percents() {
        // Fractions (`0.97`, `.97`, `1`) and percents (`97%`, `100%`) are all
        // caller-friendly spellings of a 0..=1 success-rate threshold.
        let near = |a: f64, b: f64| (a - b).abs() < f64::EPSILON;
        assert!(near(parse_expect_rate("0.97").expect("fraction"), 0.97));
        assert!(near(parse_expect_rate(".97").expect("leading-dot fraction"), 0.97));
        assert!(near(parse_expect_rate("1").expect("whole fraction"), 1.0));
        assert!(near(parse_expect_rate("97%").expect("percent"), 0.97));
        assert!(near(parse_expect_rate("100%").expect("full percent"), 1.0));
        assert!(near(parse_expect_rate(" 0.5 ").expect("trimmed"), 0.5));
    }

    #[test]
    fn expect_rate_rejects_vacuous_and_malformed_specs() {
        // A zero threshold would make every run pass vacuously, a low percent
        // is a lie about intent, and malformed strings are caller mistakes —
        // all must fail fast with a clear parse error.
        for bad in ["0", "0.0", "0%", "2", "1.5", "150%", "abc", "", "%", "-0.5"] {
            assert!(
                parse_expect_rate(bad).is_err(),
                "--expect-rate {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn probe_expectation_status_accepts_a_clean_distribution() {
        let e = ProbeExpectation {
            status: Some(super::super::StatusSpec::Class(2)),
            rate: None,
        };
        assert_eq!(
            e.violation(&result(1.0, &[(200, 60)])),
            None,
            "all-200 distribution satisfies 2xx"
        );
        assert_eq!(
            e.violation(&result(1.0, &[(200, 59), (204, 1)])),
            None,
            "204 satisfies 2xx alongside 200"
        );
    }

    #[test]
    fn probe_expectation_status_rejects_mixed_and_empty_distributions() {
        let e = ProbeExpectation {
            status: Some(super::super::StatusSpec::Class(2)),
            rate: None,
        };
        let v = e.violation(&result(1.0, &[(200, 57), (503, 3)]));
        assert!(
            v.as_deref().is_some_and(|m| m.contains("503x3") && m.contains("2xx")),
            "a 503 in the distribution must violate a 2xx assertion: {v:?}"
        );
        // No attempt produced a response: there is no response to assert on,
        // so the status assertion is violated even though no status was seen.
        let v = e.violation(&result(0.0, &[]));
        assert!(
            v.as_deref().is_some_and(|m| m.contains("no response to assert on")),
            "an address with zero completed responses must violate: {v:?}"
        );
    }

    #[test]
    fn probe_expectation_rate_gates_the_aggregate() {
        let e = ProbeExpectation {
            status: None,
            rate: Some(0.97),
        };
        assert_eq!(e.violation(&result(1.0, &[])), None, "100% meets a 97% bar");
        assert_eq!(e.violation(&result(0.97, &[])), None, "exactly at the bar passes");
        let v = e.violation(&result(0.9, &[]));
        assert!(
            v.as_deref().is_some_and(|m| m.contains("90.0%") && m.contains("97.0%")),
            "a 90% rate must violate a 97% bar: {v:?}"
        );
    }

    #[test]
    fn probe_expectation_status_and_rate_compose() {
        // Both assertions gate together: either failure is a violation.
        let e = ProbeExpectation {
            status: Some(super::super::StatusSpec::Class(2)),
            rate: Some(1.0),
        };
        assert_eq!(e.violation(&result(1.0, &[(200, 5)])), None, "clean health");
        let v = e.violation(&result(0.8, &[(200, 4), (503, 1)]));
        assert!(
            v.as_deref()
                .is_some_and(|m| m.contains("503x1") && m.contains("success rate 80.0%")),
            "a 503 and a low rate must both be reported: {v:?}"
        );
    }
}
