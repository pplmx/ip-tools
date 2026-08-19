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
