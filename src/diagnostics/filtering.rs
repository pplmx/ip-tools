//! Conservative network-filtering analysis.
//!
//! Only fires when several independent signals agree, and never with high
//! confidence.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, Evidence, FailureKind, Severity, TcpObservation};

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
    // "Address-specific" means some addresses genuinely fail *on the path*
    // while others pass. A failure classified unreachable (ENETUNREACH /
    // EHOSTUNREACH) is reported by the local stack when no route exists to
    // the destination (e.g. a family with no global route): no packet ever
    // leaves the host, so it is a local routing condition, not evidence of
    // destination-specific filtering, and must not count as a signal.
    let path_failure = |o: &TcpObservation| {
        o.failure
            .as_ref()
            .is_some_and(|e| !matches!(e.kind, FailureKind::NetworkUnreachable | FailureKind::HostUnreachable))
    };
    let has_address_specific = input.tcp.iter().any(path_failure) && input.tcp.iter().any(|o| o.success);
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
    // A TLS failure only counts when TCP actually connected on that address:
    // where TCP could not connect at all, the TLS observation merely inherits
    // the TCP failure (no handshake was attempted), so it is not an
    // independent signal. This mirrors `tls_layer_rules`.
    let has_tls_fail = input
        .tls
        .iter()
        .any(|o| !o.success && input.tcp.iter().any(|t| t.destination == o.destination && t.success));
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
    // Genuine *intermittency*: both successes and failures on the same
    // address. Where every attempt of a repeated probe fails on an address
    // that TCP could never reach, the result is not an independent signal —
    // it is the same reachability cause already covered above.
    let has_repeat_fail = input.probes.iter().any(|p| p.successes > 0 && p.failures > 0);
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
            path: "/".into(),
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
        // The TLS failure must sit on an address where TCP connected (3.3.3.3)
        // to be an independent TLS-layer signal.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("2.2.2.2:443", false, FailureKind::ConnectionReset),
            tcp("3.3.3.3:443", true, FailureKind::Timeout),
        ];
        let tls = [tls_fail("3.3.3.3:443")];
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
    fn tls_failure_inherited_from_tcp_failure_is_not_a_signal() {
        // A healthy dual-stack host whose IPv6 is locally unreachable: TCP
        // fails with NetworkUnreachable on the IPv6 address, and the TLS
        // observation merely inherits that TCP failure (no handshake was
        // attempted). That TLS "failure" must not be counted as an
        // independent filtering signal.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("[2001:db8::1]:443", false, FailureKind::NetworkUnreachable),
        ];
        // address-specific is real, but the inherited TLS failure must not
        // add a second signal.
        let tls = [TlsObservation {
            destination: "[2001:db8::1]:443".parse().unwrap(),
            sni: "example.com".into(),
            success: false,
            version: None,
            cipher: None,
            alpn: None,
            certificate: None,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::NetworkUnreachable,
                message: "network unreachable".into(),
            }),
        }];
        let lows = filtering(false, &tcp, &tls, &[], &[]);
        // Address-specific alone is only one signal, below the two-signal bar:
        // filtering must not fire.
        assert_eq!(lows.len(), 0, "inherited TLS failure must not add a signal");
    }

    #[test]
    fn all_failing_repeats_on_an_unreachable_address_are_not_a_signal() {
        // Repeat probes that fail because the address itself is unreachable
        // (IPv6 locally down) are the same cause as the TCP failure, not an
        // independent signal. Only genuine intermittency (mixed successes and
        // failures) counts.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("[2001:db8::1]:443", false, FailureKind::NetworkUnreachable),
        ];
        let probes = [ProbeResult {
            destination: "[2001:db8::1]:443".parse().unwrap(),
            attempts: 3,
            successes: 0,
            failures: 3,
            success_rate: 0.0,
            latency: LatencyStats::default().summarize(),
            failure_counts: vec![crate::model::FailureCount {
                kind: FailureKind::NetworkUnreachable,
                count: 3,
            }],
        }];
        let lows = filtering(false, &tcp, &[], &[], &probes);
        // address-specific (1) + repeats-all-fail (not counted) = one signal:
        // below the bar, so filtering must not fire.
        assert_eq!(lows.len(), 0, "unreachable repeats must not add a signal");
    }

    #[test]
    fn local_unreachability_is_not_an_address_specific_path_signal() {
        // Every failing address fails with a LOCAL no-route error (IPv6 with
        // no global route): the local stack reports ENETUNREACH/EHOSTUNREACH
        // before any packet is sent, so this is a routing condition, not
        // evidence of destination-specific filtering. It must not count as
        // the "address-specific reachability" signal; combined with genuine
        // repeated intermittency on the reachable family (both signals old
        // code would have seen) it stays below the two-signal bar.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("[2001:db8::1]:443", false, FailureKind::NetworkUnreachable),
            tcp("[2001:db8::2]:443", false, FailureKind::HostUnreachable),
        ];
        let probes = [probe(1)]; // genuine intermittency: 2/3 success
        let lows = filtering(false, &tcp, &[], &[], &probes);
        assert_eq!(
            lows.len(),
            0,
            "local unreachability must not be read as a destination-filtering signal"
        );
    }

    #[test]
    fn unreachable_plus_reset_still_fires_on_the_real_signals() {
        // When a genuine reset signal exists alongside an unreachable
        // address, filtering still fires (Low): the reset is a real
        // independent signal, and address-specific here is driven by the
        // reachable-vs-unreachable split across genuinely probed paths.
        let tcp = [
            tcp("1.1.1.1:443", true, FailureKind::Timeout),
            tcp("2.2.2.2:443", false, FailureKind::ConnectionReset),
            tcp("[2001:db8::1]:443", false, FailureKind::NetworkUnreachable),
        ];
        let lows = filtering(false, &tcp, &[], &[], &[]);
        // reset + address-specific (IPv4 ok vs IPv4 reset) = 2 signals.
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
