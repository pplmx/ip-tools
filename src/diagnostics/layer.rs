//! Protocol-layer diagnostic rules: TLS, HTTP, QUIC and intermittent probes.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, Evidence, ProbeResult, Severity};

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

/// HTTP-layer errors (non-2xx status or transport failure).
pub(super) fn http_layer_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let mut failing: Vec<String> = Vec::new();
    for h in input.http {
        let layer_failed = h.failure.is_some() || h.status.is_some_and(|s| s >= 400);
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
            tls: None,
            protocol: Some(protocol.into()),
            status,
            location: None,
            body_bytes: Some(status.map_or(0, |_| 100)),
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
    fn http_layer_ignores_success() {
        let obs = [http("1.1.1.1:443", "HTTP/2", Some(204), None)];
        let mut out = Vec::new();
        http_layer_rules(&input(&[], &obs, &[]), &mut out);
        assert!(out.is_empty());
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
}
