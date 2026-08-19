//! TCP connectivity diagnostic rules: total loss, partial reachability, and
//! address-family asymmetries.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, Evidence, FailureKind, Severity, TcpObservation};

/// Total or partial TCP connectivity loss.
pub(super) fn connectivity_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    if input.tcp.is_empty() {
        return;
    }
    let ok: Vec<&TcpObservation> = input.tcp.iter().filter(|o| o.success).collect();
    let bad: Vec<&TcpObservation> = input.tcp.iter().filter(|o| !o.success).collect();

    if ok.is_empty() && !bad.is_empty() {
        // All addresses fail.
        let kinds = failure_summary(&bad);
        out.push(Diagnosis {
            severity: Severity::High,
            category: DiagnosticCategory::TotalConnectivityLoss,
            confidence: Confidence::High,
            summary: format!("No address of {} accepts TCP connections", input.hostname),
            evidence: vec![
                Evidence {
                    detail: format!("{} addresses probed, {} failed", bad.len(), bad.len()),
                },
                Evidence { detail: kinds },
            ],
            possible_causes: vec![
                "destination server down".into(),
                "firewall / ACL blocking".into(),
                "wrong port".into(),
                "routing failure".into(),
                "local egress restriction".into(),
            ],
        });
        return;
    }

    if !ok.is_empty() && !bad.is_empty() {
        // Partial reachability.
        let failing: Vec<String> = bad.iter().map(|o| o.destination.to_string()).collect();
        let passing: Vec<String> = ok.iter().map(|o| o.destination.to_string()).collect();
        // A single failing address on an otherwise reachable host might just
        // be one bad node, so withhold High confidence until several
        // destinations fail. (`bad` is already the failing subset.)
        let confidence = if bad.len() > 1 {
            Confidence::High
        } else {
            Confidence::Medium
        };
        out.push(Diagnosis {
            severity: Severity::Medium,
            category: DiagnosticCategory::PartialConnectivity,
            confidence,
            summary: format!("Only some addresses of {} are reachable", input.hostname),
            evidence: vec![
                Evidence {
                    detail: format!("reachable: {}", passing.join(", ")),
                },
                Evidence {
                    detail: format!("unreachable: {}", failing.join(", ")),
                },
            ],
            possible_causes: vec![
                "CDN / load balancer node failure".into(),
                "destination-specific filtering".into(),
                "routing asymmetry between addresses".into(),
                "packet loss on a subset of paths".into(),
            ],
        });
    }
}

/// IPv4 vs IPv6 asymmetry.
pub(super) fn family_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    if input.tcp.is_empty() {
        return;
    }
    let family_result = |ipv4: bool| -> Option<bool> {
        let group: Vec<&TcpObservation> = input.tcp.iter().filter(|o| o.destination.is_ipv4() == ipv4).collect();
        if group.is_empty() {
            return None;
        }
        Some(group.iter().all(|o| o.success))
    };
    let v4 = family_result(true);
    let v6 = family_result(false);
    if let (Some(v4_ok), Some(v6_ok)) = (v4, v6) {
        if v4_ok != v6_ok {
            let failing = if v4_ok { "IPv6" } else { "IPv4" };
            out.push(Diagnosis {
                severity: Severity::Low,
                category: DiagnosticCategory::AddressFamily,
                confidence: Confidence::Medium,
                summary: format!("{failing} connectivity fails while the other family works"),
                evidence: vec![
                    Evidence {
                        detail: if v4_ok {
                            "IPv4: reachable".into()
                        } else {
                            "IPv4: unreachable".into()
                        },
                    },
                    Evidence {
                        detail: if v6_ok {
                            "IPv6: reachable".into()
                        } else {
                            "IPv6: unreachable".into()
                        },
                    },
                ],
                possible_causes: vec![
                    "broken or missing IPv6".into(),
                    "destination has no working IPv6".into(),
                    "firewall / ISP IPv6 filtering".into(),
                    "routing problem for one family".into(),
                ],
            });
        }
    }
}

/// Summarize the distinct failure kinds across the given observations.
fn failure_summary(bad: &[&TcpObservation]) -> String {
    let mut counts: Vec<(FailureKind, usize)> = Vec::new();
    for obs in bad {
        if let Some(f) = &obs.failure {
            if let Some(entry) = counts.iter_mut().find(|(k, _)| k == &f.kind) {
                entry.1 += 1;
            } else {
                counts.push((f.kind, 1));
            }
        }
    }
    counts
        .iter()
        .map(|(k, n)| format!("{k}: {n}"))
        .collect::<Vec<_>>()
        .join(", ")
}
