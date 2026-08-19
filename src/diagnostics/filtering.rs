//! Conservative network-filtering analysis.
//!
//! Only fires when several independent signals agree, and never with high
//! confidence.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, Evidence, FailureKind, Severity};

/// Evaluate independent filtering signals; raise a low/medium confidence
/// diagnosis when several align.
pub(super) fn filtering_rules(input: &DiagnosticInput, dns_disagreement: bool, out: &mut Vec<Diagnosis>) {
    let mut signals = 0;
    let mut evidence = Vec::new();

    if dns_disagreement {
        signals += 1;
        evidence.push(Evidence {
            detail: "resolvers returned different address sets".into(),
        });
    }
    let has_address_specific = input.tcp.iter().any(|o| o.failure.is_some()) && input.tcp.iter().any(|o| o.success);
    if has_address_specific {
        signals += 1;
        evidence.push(Evidence {
            detail: "address-specific reachability (some IPs fail, others pass)".into(),
        });
    }
    let has_reset = input.tcp.iter().any(|o| {
        o.failure
            .as_ref()
            .is_some_and(|e| e.kind == FailureKind::ConnectionReset)
    });
    if has_reset {
        signals += 1;
        evidence.push(Evidence {
            detail: "TCP resets observed".into(),
        });
    }
    let has_tls_fail = input.tls.iter().any(|o| !o.success);
    if has_tls_fail {
        signals += 1;
        evidence.push(Evidence {
            detail: "TLS handshake failures observed".into(),
        });
    }
    let has_quic_only = input
        .http
        .iter()
        .any(|h| h.protocol.as_deref() == Some("HTTP/3") && h.failure.is_some())
        && input
            .http
            .iter()
            .any(|h| h.protocol.as_deref() != Some("HTTP/3") && h.failure.is_none());
    if has_quic_only {
        signals += 1;
        evidence.push(Evidence {
            detail: "protocol-selective failure (QUIC only)".into(),
        });
    }
    let has_repeat_fail = input.probes.iter().any(|p| p.failures > 0);
    if has_repeat_fail {
        signals += 1;
        evidence.push(Evidence {
            detail: "failures reproducible across repeated attempts".into(),
        });
    }

    if signals >= 2 {
        let confidence = if signals >= 4 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::PossibleNetworkFiltering,
            confidence,
            summary: format!(
                "Multiple independent signals are consistent with possible network filtering towards {}",
                input.hostname
            ),
            evidence,
            possible_causes: vec![
                "destination/cdn failure".into(),
                "routing asymmetry".into(),
                "packet loss / congestion".into(),
                "local or ISP firewall / proxy".into(),
                "IPv6 misconfiguration".into(),
                "TLS/HTTP protocol incompatibility".into(),
                "network filtering or censorship (not proven)".into(),
            ],
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        FailureKind, HttpObservation, LatencyStats, ProbeError, ProbeResult, TcpObservation, TlsObservation,
    };

    fn tcp(dest: &str, ok: bool, kind: FailureKind) -> TcpObservation {
        TcpObservation {
            destination: dest.parse().unwrap(),
            success: ok,
            latency_ms: ok.then_some(5),
            failure: (!ok).then(|| ProbeError {
                kind,
                message: format!("{kind}"),
            }),
        }
    }

    fn tls_fail(dest: &str) -> TlsObservation {
        TlsObservation {
            destination: dest.parse().unwrap(),
            sni: "example.com".into(),
            success: false,
            version: None,
            cipher: None,
            alpn: None,
            certificate: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::TlsHandshake,
                message: "hs".into(),
            }),
        }
    }

    fn http(dest: &str, protocol: &str, failed: bool) -> HttpObservation {
        HttpObservation {
            destination: dest.parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            tls: None,
            protocol: Some(protocol.into()),
            status: failed.then_some(0).or(Some(200)),
            location: None,
            body_bytes: None,
            latency_ms: Some(1),
            failure: failed.then(|| ProbeError {
                kind: FailureKind::Quic,
                message: "quic fail".into(),
            }),
        }
    }

    fn probe(failures: usize) -> ProbeResult {
        ProbeResult {
            destination: "1.1.1.1:443".parse().unwrap(),
            attempts: 3,
            successes: 3 - failures,
            failures,
            success_rate: (3 - failures) as f64 / 3.0,
            latency: LatencyStats::default().summarize(),
            failure_counts: vec![crate::model::FailureCount {
                kind: FailureKind::Timeout,
                count: failures,
            }],
        }
    }

    fn input<'a>(
        tcp: &'a [TcpObservation],
        tls: &'a [TlsObservation],
        http: &'a [HttpObservation],
        probes: &'a [ProbeResult],
    ) -> DiagnosticInput<'a> {
        DiagnosticInput {
            hostname: "example.com",
            dns: &[],
            tcp,
            tls,
            http,
            probes,
        }
    }

    fn filtering<'a>(
        dns_disagreement: bool,
        tcp: &'a [TcpObservation],
        tls: &'a [TlsObservation],
        http: &'a [HttpObservation],
        probes: &'a [ProbeResult],
    ) -> Vec<Confidence> {
        let mut out = Vec::new();
        filtering_rules(&input(tcp, tls, http, probes), dns_disagreement, &mut out);
        out.into_iter()
            .map(|d| {
                assert_eq!(d.category, DiagnosticCategory::PossibleNetworkFiltering);
                d.confidence
            })
            .collect()
    }

    #[test]
    fn single_signal_does_not_fire() {
        // One reset alone must not raise a filtering conclusion.
        let tcp = [tcp("1.1.1.1:443", false, FailureKind::ConnectionReset)];
        assert!(filtering(false, &tcp, &[], &[], &[]).is_empty());
    }

    #[test]
    fn arguably_two_signals_yield_low_confidence() {
        // address-specific reachability (one ok, one failed) plus a reset.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("2.2.2.2:443", false, FailureKind::ConnectionReset),
        ];
        let lows = filtering(false, &tcp, &[], &[], &[]);
        assert_eq!(lows.len(), 1);
        assert_eq!(lows[0], Confidence::Low);
    }

    #[test]
    fn four_signals_raise_medium_confidence() {
        // disagreement + address-specific + reset + tls-fail = 4 signals.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("2.2.2.2:443", false, FailureKind::ConnectionReset),
        ];
        let tls = [tls_fail("2.2.2.2:443")];
        let meds = filtering(true, &tcp, &tls, &[], &[]);
        assert_eq!(meds.len(), 1);
        assert_eq!(meds[0], Confidence::Medium);
    }

    #[test]
    fn quic_only_failure_counts_as_a_signal() {
        // QUIC fails while the TCP-path HTTP succeeds → one signal. Combined
        // with a reset (TCP) that is exactly two signals → Low confidence.
        let tcp = [tcp("1.1.1.1:443", false, FailureKind::ConnectionReset)];
        let http = [
            http("1.1.1.1:443", "HTTP/1.1", false),
            http("1.1.1.1:443", "HTTP/3", true),
        ];
        let lows = filtering(false, &tcp, &[], &http, &[]);
        assert_eq!(lows.len(), 1);
        assert_eq!(lows[0], Confidence::Low);
    }

    #[test]
    fn repeat_failures_count_as_a_signal() {
        let probes = [probe(1)];
        let lows = filtering(false, &[], &[], &[], &probes);
        // Sequential repeated failures on their own is only one signal.
        let count = lows.len();
        assert_eq!(count, 0);
        // With an address-specific TCP split it crosses the two-signal bar.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("2.2.2.2:443", false, FailureKind::Timeout),
        ];
        let lows = filtering(false, &tcp, &[], &[], &probes);
        assert_eq!(lows.len(), 1);
        assert_eq!(lows[0], Confidence::Low);
    }
}
