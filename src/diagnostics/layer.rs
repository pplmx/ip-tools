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
