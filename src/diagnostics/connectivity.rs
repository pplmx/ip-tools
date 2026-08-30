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
        // All addresses fail. A failure the host's own stack reports as
        // `network unreachable` / `host unreachable` (ENETUNREACH /
        // EHOSTUNREACH) is emitted *before any packet is sent* for an
        // address, e.g. an address family with no global route. When every
        // failing address is such a verdict, no probe ever reached the path:
        // there is no evidence that the destination is down, and a HIGH
        // "no address accepts TCP" verdict (plus its `--strict` failure)
        // would blame the destination for the host's own missing route. The
        // address-family rule reports that local condition instead; the
        // per-address failures stay visible in the evidence stack.
        if all_local_unreachability(&bad) {
            return;
        }
        let kinds = failure_summary(&bad);
        // A single observation cannot claim High — the model docs forbid High
        // from a single observation type, and the partial branch already
        // withholds it below two failing addresses. Several addresses failing
        // identically is High; a lone target down is Medium.
        let confidence = if bad.len() > 1 {
            Confidence::High
        } else {
            Confidence::Medium
        };
        out.push(Diagnosis {
            severity: Severity::High,
            category: DiagnosticCategory::TotalConnectivityLoss,
            confidence,
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
        // (Same local-unreachability consideration as the total-loss branch:
        // if every failing address failed with the host's own no-route
        // verdict, there is no path evidence of a partially reachable
        // destination — the address-family rule reports the local condition.)
        if all_local_unreachability(&bad) {
            return;
        }
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

/// IPv4 vs IPv6 asymmetry, plus the single-family local-unreachability note.
#[allow(clippy::too_many_lines)] // two verdict blocks mirrored in one rule
pub(super) fn family_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    if input.tcp.is_empty() {
        return;
    }
    // A family counts as reachable when ANY address of it answered: a mixed
    // IPv4 set (one address up, one down) is partial connectivity between
    // addresses — which `connectivity_rules` reports with the failing
    // addresses' names — not "IPv4 fails". The family verdict must mean the
    // whole family produced no success at all.
    let family_result = |ipv4: bool| -> Option<bool> {
        let group: Vec<&TcpObservation> = input.tcp.iter().filter(|o| o.destination.is_ipv4() == ipv4).collect();
        if group.is_empty() {
            return None;
        }
        Some(group.iter().any(|o| o.success))
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
    // A single-family probe (e.g. `--ipv6` scoping, or a name that only has
    // AAAA records) has no cross-family asymmetry to compare. When its lone
    // family is entirely locally unreachable (`network unreachable` / `host
    // unreachable` — the host reports no route before any packet is sent),
    // `connectivity_rules` deliberately stays quiet (that is the exclusion the
    // two-family case relies on here), so without this branch the engine would
    // fall through to a false Healthy. Name the local condition instead.
    let single = match (v4, v6) {
        (Some(ok), None) => Some((true, ok)),
        (None, Some(ok)) => Some((false, ok)),
        _ => None,
    };
    if let Some((ipv4, ok)) = single {
        if !ok {
            let bad: Vec<&TcpObservation> = input
                .tcp
                .iter()
                .filter(|o| o.destination.is_ipv4() == ipv4 && !o.success)
                .collect();
            if all_local_unreachability(&bad) {
                let fam = if ipv4 { "IPv4" } else { "IPv6" };
                out.push(Diagnosis {
                    severity: Severity::Low,
                    category: DiagnosticCategory::AddressFamily,
                    confidence: Confidence::Medium,
                    summary: format!(
                        "{fam} connectivity is locally unreachable (no route) for {}",
                        input.hostname
                    ),
                    evidence: vec![Evidence {
                        detail: format!("{fam}: every address locally unreachable (network/host unreachable)"),
                    }],
                    possible_causes: vec![
                        format!("no {fam} route / global address on the probing host"),
                        format!("{fam} disabled on the destination or its network"),
                        format!("firewall or policy blocking {fam} traffic locally"),
                    ],
                });
            }
        }
    }
}

/// Whether every failing observation failed with the host's own
/// no-route verdict (`network unreachable` / `host unreachable`,
/// ENETUNREACH / EHOSTUNREACH) — a local routing condition reported by the
/// stack before any packet is sent, not evidence about the destination. Both
/// the total-loss and the partial-reachability branches stay quiet then, and
/// the address-family rule reports the local condition instead.
fn all_local_unreachability(bad: &[&TcpObservation]) -> bool {
    bad.iter().all(|o| {
        o.failure
            .as_ref()
            .is_some_and(|f| matches!(f.kind, FailureKind::NetworkUnreachable | FailureKind::HostUnreachable))
    })
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
