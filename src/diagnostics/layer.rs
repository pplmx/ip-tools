//! Protocol-layer diagnostic rules: TLS, HTTP, QUIC and intermittent probes.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, Evidence, FailureKind, ProbeResult, Severity};

/// TLS handshake failures on addresses where TCP connected.
pub(super) fn tls_layer_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    // Where TCP connected but TLS failed on the same address.
    let mut failing: Vec<String> = Vec::new();
    for t in input.tls.iter().filter(|o| !o.success) {
        let tcp_ok = input.tcp.iter().any(|o| o.destination == t.destination && o.success);
        if tcp_ok {
            failing.push(t.destination.to_string());
        }
    }
    if !failing.is_empty() {
        out.push(Diagnosis {
            severity: Severity::Medium,
            category: DiagnosticCategory::Tls,
            confidence: Confidence::Medium,
            summary: format!("TLS handshake fails where TCP connects ({})", failing.join(", ")),
            evidence: vec![Evidence {
                detail: "TCP established, TLS handshake did not".into(),
            }],
            possible_causes: vec![
                "server TLS configuration / disabled TLS".into(),
                "certificate validation failure".into(),
                "SNI/ALPN mismatch".into(),
                "middlebox interfering with TLS".into(),
            ],
        });
    }
}

/// HTTP-layer errors (non-2xx status or an HTTP-protocol-layer failure).
pub(super) fn http_layer_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let mut failing: Vec<String> = Vec::new();
    for h in input.http {
        // Where TCP could not connect at all, the HTTP observation merely
        // inherits the TCP failure (no request was attempted): that is a
        // reachability issue reported at the TCP layer, not an HTTP-layer
        // error. Only count it here when TCP actually connected.
        let inherited_tcp =
            h.failure.is_some() && input.tcp.iter().any(|t| t.destination == h.destination && !t.success);
        // Failures owned by another layer's rule must not be re-reported
        // here: a QUIC transport failure is the `quic_rules` verdict and a
        // TLS handshake / certificate failure is `tls_layer_rules`' — the
        // same cause must not be double-counted as an HTTP-layer error. This
        // reaches beyond the failure *kind*: an HTTP/3 probe runs over QUIC,
        // so a wall-clock QUIC handshake timeout surfaces as `Timeout` (not
        // `Quic`) yet is still the QUIC path failing — only a genuine
        // HTTP/3-protocol error (`Http`/`Protocol`; or a non-2xx status
        // below) is an HTTP-layer error for the h3 row. HTTP/1.1+/2-over-TLS
        // keep the kind-based exclusion (a request timeout there is the
        // server not answering HTTP, which belongs here).
        let own_failure = h.failure.as_ref().is_some_and(|e| {
            if h.protocol.as_deref() == Some("HTTP/3") {
                matches!(e.kind, FailureKind::Http | FailureKind::Protocol)
            } else {
                !matches!(
                    e.kind,
                    FailureKind::Quic | FailureKind::TlsHandshake | FailureKind::Certificate
                )
            }
        });
        let layer_failed = (own_failure && !inherited_tcp) || h.status.is_some_and(|s| s >= 400);
        if layer_failed {
            failing.push(format!(
                "{} -> {}",
                h.destination,
                h.status.map_or_else(|| "error".into(), |s| s.to_string())
            ));
        }
    }
    if !failing.is_empty() {
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::Http,
            confidence: Confidence::Low,
            summary: format!("HTTP-layer errors returned by {}", input.hostname),
            evidence: vec![Evidence {
                detail: failing.join("; "),
            }],
            possible_causes: vec![
                "application error / server-side issue".into(),
                "redirect loop or auth required".into(),
                "HTTP (not TLS) protocol problem".into(),
            ],
        });
    }
}

/// HTTP responses whose headers arrived but whose body never completed.
///
/// With the probes' body-completion semantics, `status` present + no
/// `body_bytes` means the response head was received and then the body read
/// stalled until the probe bound: a truncated/streaming response, not a
/// clean exchange.
pub(super) fn truncated_body_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let truncated: Vec<String> = input
        .http
        .iter()
        .filter(|h| h.failure.is_none() && h.status.is_some() && h.body_bytes.is_none())
        .map(|h| h.destination.to_string())
        .collect();
    if !truncated.is_empty() {
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::Http,
            confidence: Confidence::Low,
            summary: format!("HTTP response body did not complete for {}", input.hostname),
            evidence: vec![Evidence {
                detail: format!("headers received, body stalled ({})", truncated.join(", ")),
            }],
            possible_causes: vec![
                "response truncated by a proxy / load balancer".into(),
                "server keep-alive without content-length or chunked coding".into(),
                "connection reset or packet loss mid-transfer".into(),
                "streaming endpoint that never finishes".into(),
            ],
        });
    }
}

/// QUIC/HTTP3 failing while the TCP path succeeds.
pub(super) fn quic_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let tcp_http_ok = input
        .http
        .iter()
        .any(|h| h.failure.is_none() && h.status.is_some_and(|s| s < 400));
    let quic_http = input.http.iter().filter(|h| h.protocol.as_deref() == Some("HTTP/3"));
    let quic_ok = quic_http.clone().any(|h| h.failure.is_none());
    let has_quic = quic_http.clone().count() > 0;
    if has_quic && tcp_http_ok && !quic_ok {
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::Quic,
            confidence: Confidence::Medium,
            summary: format!("QUIC/HTTP3 fails while TCP+HTTPS succeeds for {}", input.hostname),
            evidence: vec![Evidence {
                detail: "TCP path OK; UDP/QUIC path failed".into(),
            }],
            possible_causes: vec![
                "QUIC disabled / not offered by server".into(),
                "UDP blocked or rate-limited on a path".into(),
                "middlebox/NAT interfering with QUIC".into(),
                "server prefers TCP".into(),
            ],
        });
    }
}

/// Intermittent connectivity from repeated-probe results.
pub(super) fn intermittent_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    for p in input.probes {
        if p.attempts > 1 && p.failures > 0 && p.successes > 0 {
            let rate = p.success_rate * 100.0;
            out.push(Diagnosis {
                severity: Severity::Medium,
                category: DiagnosticCategory::Intermittent,
                confidence: Confidence::High,
                summary: format!("Intermittent connectivity to {} ({:.1}% success)", p.destination, rate),
                evidence: vec![
                    Evidence {
                        detail: format!("{}/{} success", p.successes, p.attempts),
                    },
                    Evidence {
                        detail: failure_summary_opt(p),
                    },
                ],
                possible_causes: vec![
                    "packet loss / unstable path".into(),
                    "congested transit".into(),
                    "flapping routing".into(),
                    "intermittent filtering".into(),
                ],
            });
        }
    }
}

/// Automated certificate-lifetime diagnosis: a serving certificate that is
/// already expired, or expires within the same 30-day window the human TLS
/// report annotates, should surface from `diagnose` so an automated /
/// scripted health sweep can catch it — not just appear in the rendered cert
/// row. Uses the shared day-diff helper from the report layer so the engine
/// and the report agree on "expired" vs "expires in N day(s)".
pub(super) fn certificate_lifetime_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    for t in input.tls {
        let Some(cert) = t.certificate.as_ref() else { continue };
        // A certificate whose `notBefore` is in the future is NOT YET valid:
        // real clients (and any chain-validation path) will refuse it even
        // though an `--insecure` handshake completes, so this must not be
        // reported as Healthy. The cause is inherently ambiguous — server
        // misissuance vs. clock skew on either side — hence Medium confidence.
        // Integer-day granularity means only strictly-future dates are flagged
        // (a same-day notBefore avoids short-period clock jitter).
        if let Some(not_before) = cert.not_before_utc.as_deref() {
            if let Some(days) = crate::report::days_until_from_rfc3339(not_before) {
                if days > 0 {
                    out.push(Diagnosis {
                        severity: Severity::Medium,
                        category: DiagnosticCategory::Certificate,
                        confidence: Confidence::Medium,
                        summary: format!(
                            "Certificate for {} is not yet valid (starts in {days} day(s), subject {})",
                            t.sni, cert.subject
                        ),
                        evidence: vec![Evidence {
                            detail: format!("peer certificate notBefore is in the future: {not_before}"),
                        }],
                        possible_causes: vec![
                            "certificate issued with a future notBefore (misissuance)".into(),
                            "server or client clock skew".into(),
                            "certificate deployed before its validity window began".into(),
                        ],
                    });
                }
            }
        }
        let Some(not_after) = cert.not_after_utc.as_deref() else {
            continue;
        };
        let Some(days) = crate::report::days_until_from_rfc3339(not_after) else {
            continue;
        };
        if days < 0 {
            out.push(Diagnosis {
                severity: Severity::Medium,
                category: DiagnosticCategory::Certificate,
                confidence: Confidence::High,
                summary: format!(
                    "Certificate for {} expired {} day(s) ago (subject {})",
                    t.sni, -days, cert.subject
                ),
                evidence: vec![Evidence {
                    detail: format!("peer certificate notAfter is in the past: {not_after}"),
                }],
                possible_causes: vec![
                    "certificate not renewed before its notAfter".into(),
                    "operator is serving a stale/revoked deployment".into(),
                ],
            });
        } else if days <= crate::report::RENDER_CERT_EXPIRY_WINDOW_DAYS {
            out.push(Diagnosis {
                severity: Severity::Low,
                category: DiagnosticCategory::Certificate,
                confidence: Confidence::Medium,
                summary: format!(
                    "Certificate for {} expires in {days} day(s) (subject {})",
                    t.sni, cert.subject
                ),
                evidence: vec![Evidence {
                    detail: format!("peer certificate notAfter is in {days} day(s): {not_after}"),
                }],
                possible_causes: vec!["certificate approaching its renewal date".into()],
            });
        }
    }
}

/// Automated certificate hostname-coverage diagnosis: a serving certificate
/// whose SANs do not cover the SNI the client presented (a wrong-host cert, or
/// a wildcard/exact mismatch) is a real misconfiguration — especially under
/// `--insecure`, where chain validation is skipped and the mismatch would
/// otherwise be silent. Reuses the report's matcher so `diagnose` and the
/// human `covers <sni>: yes/no` row always agree.
pub(super) fn certificate_coverage_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    for t in input.tls {
        let Some(cert) = t.certificate.as_ref() else { continue };
        // A certificate with no SAN data cannot be matched; treat as not
        // covered (it would not validate for the host anyway).
        if cert.sans.is_empty() {
            out.push(Diagnosis {
                severity: Severity::Medium,
                category: DiagnosticCategory::Certificate,
                confidence: Confidence::Medium,
                summary: format!(
                    "Certificate for {} has no Subject Alternative Names (subject {})",
                    t.sni, cert.subject
                ),
                evidence: vec![Evidence {
                    detail: "the served certificate lists no SANs to match the presented hostname".into(),
                }],
                possible_causes: vec![
                    "mis-issued certificate without SANs (needs SANs for modern validation)".into(),
                    "server is presenting the wrong leaf certificate".into(),
                ],
            });
            continue;
        }
        if !crate::report::cert_covers_hostname(&t.sni, &cert.sans) {
            out.push(Diagnosis {
                severity: Severity::Medium,
                category: DiagnosticCategory::Certificate,
                confidence: Confidence::Medium,
                summary: format!(
                    "Certificate for {} does not cover the presented hostname (subject {})",
                    t.sni, cert.subject
                ),
                evidence: vec![Evidence {
                    detail: format!("SANs {} do not match presented SNI {}", cert.sans.join(", "), t.sni),
                }],
                possible_causes: vec![
                    "wrong-host or shared-host certificate presented".into(),
                    "wildcard/exact SAN mismatch for the requested hostname".into(),
                    "connection is to an IP that the certificate does not cover".into(),
                ],
            });
        }
    }
}

/// Automated redirect observation into a diagnosis: a 3xx response with a
/// `Location` on a reachable host is a very common real-world signal — a
/// captive portal, a login/auth wall, a moved domain, or middleware rewriting
/// — that `diagnose` currently ignores. This surfaces it (Low) without ever
/// following the redirect (see DEC-003: a redirect is an observation, not
/// followed).
pub(super) fn redirect_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let redirects: Vec<String> = input
        .http
        .iter()
        .filter(|h| h.failure.is_none())
        .filter_map(|h| {
            let status = h.status?;
            if (300..400).contains(&status) {
                let target = h.location.as_deref().unwrap_or("(no Location header)");
                Some(format!("{} -> {status} {target}", h.destination))
            } else {
                None
            }
        })
        .collect();
    if !redirects.is_empty() {
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::Http,
            confidence: Confidence::Low,
            summary: format!("HTTP {} which redirected", input.hostname),
            evidence: vec![Evidence {
                detail: format!("redirect observed ({})", redirects.join("; ")),
            }],
            possible_causes: vec![
                "captive portal / login wall intercepting the request".into(),
                "site or resource permanently moved".into(),
                "authentication or session redirect".into(),
                "CDN / middleware rewriting the URL".into(),
            ],
        });
    }
}

/// Summarize the classified failure counts of a probe result.
fn failure_summary_opt(p: &ProbeResult) -> String {
    if p.failure_counts.is_empty() {
        "no classified failures".to_string()
    } else {
        p.failure_counts
            .iter()
            .map(|f| format!("{}: {}", f.kind, f.count))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FailureCount, FailureKind, HttpObservation, LatencyStats, ProbeError, TcpObservation, TlsObservation,
    };

    fn http(dest: &str, protocol: &str, status: Option<u16>, failure: Option<&str>) -> HttpObservation {
        HttpObservation {
            destination: dest.parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some(protocol.into()),
            status,
            location: None,
            headers: Vec::new(),
            body_bytes: Some(status.map_or(0, |_| 100)),
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: status.map(|_| 20),
            failure: failure.map(|m| ProbeError {
                kind: FailureKind::Http,
                message: m.into(),
            }),
        }
    }

    fn probes(failures: usize, attempts: usize) -> ProbeResult {
        let mut stats = LatencyStats::default();
        for _ in 0..(attempts - failures) {
            stats.push(10);
        }
        ProbeResult {
            destination: "1.1.1.1:443".parse().unwrap(),
            attempts,
            successes: attempts - failures,
            failures,
            success_rate: (attempts - failures) as f64 / attempts as f64,
            latency: stats.summarize(),
            failure_counts: if failures > 0 {
                vec![FailureCount {
                    kind: FailureKind::Timeout,
                    count: failures,
                }]
            } else {
                Vec::new()
            },
        }
    }

    fn input<'a>(
        tls: &'a [TlsObservation],
        http: &'a [HttpObservation],
        probes: &'a [ProbeResult],
    ) -> DiagnosticInput<'a> {
        DiagnosticInput {
            hostname: "example.com",
            dns: &[],
            tcp: &[],
            tls,
            http,
            probes,
        }
    }

    #[test]
    fn quic_fires_when_http3_fails_but_tcp_http_ok() {
        let obs = [
            http("1.1.1.1:443", "HTTP/1.1", Some(200), None),
            http("1.1.1.1:443", "HTTP/3", None, Some("quic handshake failed")),
        ];
        let mut out = Vec::new();
        quic_rules(&input(&[], &obs, &[]), &mut out);
        let q = out.iter().find(|d| d.category == DiagnosticCategory::Quic);
        assert!(q.is_some(), "QUIC diagnosis should fire: {out:?}");
        assert_eq!(q.unwrap().confidence, Confidence::Medium);
    }

    #[test]
    fn quic_does_not_fire_when_no_http3_or_http_fails() {
        let only_h3_fail = [http("1.1.1.1:443", "HTTP/3", None, Some("fail"))];
        let mut out = Vec::new();
        // Without a healthy TCP/HTTP path, quic_rules stays silent.
        quic_rules(&input(&[], &only_h3_fail, &[]), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn http_layer_fires_on_server_error_status() {
        let obs = [http("1.1.1.1:443", "HTTP/1.1", Some(500), None)];
        let mut out = Vec::new();
        http_layer_rules(&input(&[], &obs, &[]), &mut out);
        assert!(out.iter().any(|d| d.category == DiagnosticCategory::Http));
    }

    #[test]
    fn http_layer_fires_on_transport_failure() {
        let obs = [http("2.2.2.2:443", "HTTP/1.1", None, Some("request failed"))];
        let mut out = Vec::new();
        http_layer_rules(&input(&[], &obs, &[]), &mut out);
        assert!(out.iter().any(|d| d.category == DiagnosticCategory::Http));
    }

    #[test]
    fn http_layer_ignores_failures_owned_by_other_layers() {
        // A QUIC transport failure, a wall-clock QUIC handshake timeout, and
        // a TLS handshake/certificate failure each belong to their own layer
        // rule; on a TCP-connected address they must not be re-raised as an
        // HTTP-layer error too. (The HTTP/3 *timeout* matters: a silent-UDP
        // or stalled QUIC peer surfaces as `Timeout`, not `Quic`, and must
        // not be double-counted as an HTTP-layer error.)
        let with_kind = |kind| HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/3".into()),
            status: None,
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind,
                message: "another layer's failure".into(),
            }),
        };
        let tcp_ok = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(5),
            failure: None,
        }];
        for kind in [
            FailureKind::Quic,
            FailureKind::TlsHandshake,
            FailureKind::Certificate,
            FailureKind::Timeout,
        ] {
            let mut out = Vec::new();
            http_layer_rules(
                &DiagnosticInput {
                    hostname: "example.com",
                    dns: &[],
                    tcp: &tcp_ok,
                    tls: &[],
                    http: &[with_kind(kind)],
                    probes: &[],
                },
                &mut out,
            );
            assert!(out.is_empty(), "{kind:?} must not be re-raised as an HTTP-layer error");
        }

        // A genuine HTTP-protocol-layer failure still raises it.
        let mut out = Vec::new();
        http_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_ok,
                tls: &[],
                http: &[with_kind(FailureKind::Http)],
                probes: &[],
            },
            &mut out,
        );
        assert!(out.iter().any(|d| d.category == DiagnosticCategory::Http));
    }

    #[test]
    fn redirect_fires_on_3xx_with_location() {
        let obs = [HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(302),
            location: Some("https://example.com/login".into()),
            headers: Vec::new(),
            body_bytes: Some(0),
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(20),
            failure: None,
        }];
        let mut out = Vec::new();
        redirect_rules(&input(&[], &obs, &[]), &mut out);
        let r = out.iter().find(|d| d.summary.contains("redirected"));
        assert!(r.is_some(), "redirect diagnosis should fire: {out:?}");
        assert_eq!(r.unwrap().severity, Severity::Low);
        assert!(
            out.iter().any(|d| d
                .evidence
                .iter()
                .any(|e| e.detail.contains("https://example.com/login"))),
            "redirect evidence should name the Location target: {out:?}"
        );
    }

    #[test]
    fn redirect_silent_on_2xx_and_on_failure() {
        // A successful 2xx carries no redirect signal.
        let ok = [http("1.1.1.1:443", "HTTP/1.1", Some(200), None)];
        let mut out = Vec::new();
        redirect_rules(&input(&[], &ok, &[]), &mut out);
        assert!(out.is_empty(), "2xx must not raise a redirect diagnosis: {out:?}");

        // A failed probe is owned by the HTTP-layer error rule, not a redirect
        // claim (the redirect rule only looks at completed observations).
        let failed = [http("1.1.1.1:443", "HTTP/1.1", None, Some("request failed"))];
        let mut out = Vec::new();
        redirect_rules(&input(&[], &failed, &[]), &mut out);
        assert!(
            out.is_empty(),
            "failed probe must not raise a redirect diagnosis: {out:?}"
        );
    }

    #[test]
    fn http_layer_counts_request_timeouts_for_tls_but_not_quic() {
        // The layer boundary is per-transport: an HTTP/1.1+2 row whose request
        // timed out after TLS is the server not answering HTTP (a genuine
        // HTTP-layer signal, e.g. a port that accepts TLS but never serves
        // HTTP) — it fires. An HTTP/3 row whose *QUIC handshake* timed out is
        // the QUIC path (quic_rules' verdict) and must not fire (cc58b2d).
        let tcp_ok = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(5),
            failure: None,
        }];
        let obs = |protocol: &str| HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some(protocol.into()),
            status: None,
            location: None,
            headers: Vec::new(),
            body_bytes: None,
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::Timeout,
                message: "request timed out".into(),
            }),
        };
        for protocol in ["HTTP/1.1", "HTTP/2"] {
            let mut out = Vec::new();
            http_layer_rules(
                &DiagnosticInput {
                    hostname: "example.com",
                    dns: &[],
                    tcp: &tcp_ok,
                    tls: &[],
                    http: &[obs(protocol)],
                    probes: &[],
                },
                &mut out,
            );
            assert!(
                out.iter().any(|d| d.category == DiagnosticCategory::Http),
                "{protocol} request timeout must count as an HTTP-layer error"
            );
        }
        let mut out = Vec::new();
        http_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_ok,
                tls: &[],
                http: &[obs("HTTP/3")],
                probes: &[],
            },
            &mut out,
        );
        assert!(
            !out.iter().any(|d| d.category == DiagnosticCategory::Http),
            "an HTTP/3 timeout is the QUIC path, not an HTTP-layer error: {out:?}"
        );
    }

    #[test]
    fn http_layer_ignores_failure_inherited_from_tcp() {
        // Where TCP could not connect at all, the HTTP observation merely
        // inherits that failure (no request was attempted): it is a
        // reachability issue reported at the TCP layer, not an HTTP-layer
        // error, and must not raise an HTTP diagnosis.
        let obs = [http("2.2.2.2:443", "HTTP/1.1", None, Some("connect failed"))];
        let tcp_fail = [TcpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::Timeout,
                message: "timeout".into(),
            }),
        }];
        let mut out = Vec::new();
        http_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_fail,
                tls: &[],
                http: &obs,
                probes: &[],
            },
            &mut out,
        );
        assert!(out.is_empty(), "inherited TCP failure must not raise HTTP diagnosis");

        // Where TCP actually connected, the same transport failure IS an
        // HTTP-layer signal.
        let tcp_ok = [TcpObservation {
            destination: "2.2.2.2:443".parse().unwrap(),
            success: true,
            latency_ms: Some(5),
            failure: None,
        }];
        let mut out = Vec::new();
        http_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_ok,
                tls: &[],
                http: &obs,
                probes: &[],
            },
            &mut out,
        );
        assert!(out.iter().any(|d| d.category == DiagnosticCategory::Http));
    }

    #[test]
    fn http_layer_ignores_success() {
        let obs = [http("1.1.1.1:443", "HTTP/2", Some(204), None)];
        let mut out = Vec::new();
        http_layer_rules(&input(&[], &obs, &[]), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_body_rule_fires_when_headers_arrive_but_body_stalls() {
        let truncated = HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: None, // headers received, body never completed
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(30),
            failure: None,
        };
        let mut out = Vec::new();
        truncated_body_rules(&input(&[], &[truncated], &[]), &mut out);
        let d = out.iter().find(|d| d.category == DiagnosticCategory::Http);
        assert!(d.is_some(), "truncated body must be diagnosed: {out:?}");
        assert!(out[0].evidence[0].detail.contains("stalled"));

        // A completed body (or a failure) must not trigger the rule.
        let completed = http("1.1.1.1:443", "HTTP/1.1", Some(200), None);
        let mut out = Vec::new();
        truncated_body_rules(&input(&[], &[completed], &[]), &mut out);
        assert!(out.is_empty(), "completed body must not be truncated: {out:?}");
    }

    #[test]
    fn tls_layer_requires_tcp_connected_on_same_address() {
        let fail = TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: false,
            version: None,
            cipher: None,
            alpn: None,
            certificate: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::TlsHandshake,
                message: "failed".into(),
            }),
        };
        let tcp_ok = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: true,
            latency_ms: Some(5),
            failure: None,
        }];
        let mut out = Vec::new();
        tls_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_ok,
                tls: std::slice::from_ref(&fail),
                http: &[],
                probes: &[],
            },
            &mut out,
        );
        assert!(out.iter().any(|d| d.category == DiagnosticCategory::Tls));

        // Where TCP also failed on that address, no TLS diagnosis is made.
        let tcp_fail = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::Timeout,
                message: "timeout".into(),
            }),
        }];
        let mut out = Vec::new();
        tls_layer_rules(
            &DiagnosticInput {
                hostname: "example.com",
                dns: &[],
                tcp: &tcp_fail,
                tls: &[fail],
                http: &[],
                probes: &[],
            },
            &mut out,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn intermittent_requires_multiple_attempts_with_both_outcomes() {
        let all_fail = [probes(3, 3)];
        let mut out = Vec::new();
        intermittent_rules(&input(&[], &[], &all_fail), &mut out);
        assert!(out.is_empty(), "all-failure with no successes is not intermittent");

        let mixed = [probes(1, 4)];
        let mut out = Vec::new();
        intermittent_rules(&input(&[], &[], &mixed), &mut out);
        let d = out.iter().find(|d| d.category == DiagnosticCategory::Intermittent);
        assert!(d.is_some(), "mixed failure must be intermittent");
        assert_eq!(d.unwrap().confidence, Confidence::High);
        // The failure distribution is reported in the evidence.
        assert_eq!(d.unwrap().evidence.len(), 2);
    }

    fn tls_with_cert(not_after: &str) -> TlsObservation {
        TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("AES_256_GCM".into()),
            alpn: Some("h2".into()),
            certificate: Some(crate::model::CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=CA".into(),
                not_before_utc: None,
                not_after_utc: Some(not_after.into()),
                sans: Vec::new(),
            }),
            latency_ms: Some(7),
            failure: None,
        }
    }

    #[test]
    fn certificate_lifetime_raises_expired_and_expiring() {
        // An expired cert is a High-confidence Medium diagnosis.
        let expired = [tls_with_cert(&crate::report::rfc3339_days_from_now(-5))];
        let mut out = Vec::new();
        certificate_lifetime_rules(&input(&expired, &[], &[]), &mut out);
        let d = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::Certificate)
            .expect("expired verdict");
        assert_eq!(d.severity, Severity::Medium);
        assert_eq!(d.confidence, Confidence::High);
        assert!(d.summary.contains("expired"), "summary names expiry: {}", d.summary);

        // A cert expiring within the 30-day window is a Low diagnosis.
        let near = [tls_with_cert(&crate::report::rfc3339_days_from_now(5))];
        let mut out = Vec::new();
        certificate_lifetime_rules(&input(&near, &[], &[]), &mut out);
        let d = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::Certificate)
            .expect("near verdict");
        assert_eq!(d.severity, Severity::Low);
        assert!(d.summary.contains("expires in"), "summary names expiry: {}", d.summary);

        // A comfortably-far cert does not raise a verdict.
        let far = [tls_with_cert(&crate::report::rfc3339_days_from_now(400))];
        let mut out = Vec::new();
        certificate_lifetime_rules(&input(&far, &[], &[]), &mut out);
        assert!(out.is_empty(), "far expiry must not raise a verdict: {out:?}");
    }

    #[test]
    fn certificate_lifetime_raises_not_yet_valid() {
        // A cert whose `notBefore` is in the future is not yet valid: even
        // though an --insecure handshake completes, real clients/validation
        // would refuse it, so diagnose must not report Healthy. The verdict
        // is a Medium Certificate diagnosis naming how far off validity is.
        let tls_with_bounds = |not_before: &str, not_after: &str| TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("AES_256_GCM".into()),
            alpn: Some("h2".into()),
            certificate: Some(crate::model::CertificateSummary {
                subject: "CN=example.com".into(),
                issuer: "CN=CA".into(),
                not_before_utc: Some(not_before.into()),
                not_after_utc: Some(not_after.into()),
                sans: Vec::new(),
            }),
            latency_ms: Some(7),
            failure: None,
        };

        // notBefore in the future -> Medium not-yet-valid verdict.
        let not_yet = [tls_with_bounds(
            &crate::report::rfc3339_days_from_now(10),
            &crate::report::rfc3339_days_from_now(400),
        )];
        let mut out = Vec::new();
        certificate_lifetime_rules(&input(&not_yet, &[], &[]), &mut out);
        let d = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::Certificate)
            .expect("not-yet-valid verdict");
        assert_eq!(d.severity, Severity::Medium);
        assert_eq!(d.confidence, Confidence::Medium);
        assert!(
            d.summary.contains("not yet valid"),
            "summary names the not-yet-valid state: {}",
            d.summary
        );

        // A cert already past its notBefore must not raise the verdict.
        let started = [tls_with_bounds(
            &crate::report::rfc3339_days_from_now(-100),
            &crate::report::rfc3339_days_from_now(400),
        )];
        let mut out = Vec::new();
        certificate_lifetime_rules(&input(&started, &[], &[]), &mut out);
        assert!(
            !out.iter().any(|d| d.summary.contains("not yet valid")),
            "past notBefore must not raise not-yet-valid: {out:?}"
        );
    }

    #[test]
    fn certificate_coverage_raises_wrong_host_wildcard_and_ip_mismatch() {
        // A cert whose SANs do not cover the presented SNI must raise a
        // Certificate diagnosis (the coverage check is separate from expiry,
        // which the lifetime rule owns).
        let cert_with_sans = |sans: Vec<String>| TlsObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            sni: "example.com".into(),
            success: true,
            version: Some("TLSv1.3".into()),
            cipher: Some("AES_256_GCM".into()),
            alpn: Some("h2".into()),
            certificate: Some(crate::model::CertificateSummary {
                subject: "CN=other.invalid".into(),
                issuer: "CN=CA".into(),
                not_before_utc: None,
                not_after_utc: Some(crate::report::rfc3339_days_from_now(400)),
                sans,
            }),
            latency_ms: Some(7),
            failure: None,
        };

        // Exact hostname mismatch -> raises.
        let mut out = Vec::new();
        certificate_coverage_rules(
            &input(&[cert_with_sans(vec!["other.invalid".into()])], &[], &[]),
            &mut out,
        );
        let d = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::Certificate)
            .expect("wrong-host verdict");
        assert_eq!(d.severity, Severity::Medium);
        assert!(d.summary.contains("does not cover"), "summary: {}", d.summary);

        // Wildcard for the wrong apex -> raises.
        let mut out = Vec::new();
        certificate_coverage_rules(
            &input(&[cert_with_sans(vec!["*.other.invalid".into()])], &[], &[]),
            &mut out,
        );
        assert!(
            out.iter().any(|d| d.category == DiagnosticCategory::Certificate),
            "wrong-apex wildcard mismatch must raise: {out:?}"
        );

        // A cert that DOES cover the hostname must not raise.
        let mut out = Vec::new();
        certificate_coverage_rules(
            &input(
                &[cert_with_sans(vec!["example.com".into(), "*.example.com".into()])],
                &[],
                &[],
            ),
            &mut out,
        );
        assert!(
            out.iter().all(|d| d.category != DiagnosticCategory::Certificate),
            "covering cert must not raise: {out:?}"
        );

        // Empty SANs (no data to match) -> raises.
        let mut out = Vec::new();
        certificate_coverage_rules(&input(&[cert_with_sans(Vec::new())], &[], &[]), &mut out);
        assert!(
            out.iter().any(|d| d.category == DiagnosticCategory::Certificate),
            "cert with no SANs must be flagged: {out:?}"
        );
    }
}
