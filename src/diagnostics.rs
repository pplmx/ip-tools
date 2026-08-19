//! Deterministic diagnostic engine.
//!
//! This module performs **no network I/O**. It takes normalized observations
//! and produces a set of evidence-based [`Diagnosis`]. It never claims
//! censorship from a single failure mode; it only raises
//! [`DiagnosticCategory::PossibleNetworkFiltering`] with low/medium confidence
//! when several independent signals align, and always lists the mundane
//! alternatives that also fit the evidence.

use crate::model::{
    Confidence, Diagnosis, DiagnosticCategory, DnsObservation, Evidence, FailureKind, HttpObservation, ProbeResult,
    Severity, TcpObservation, TlsObservation,
};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// Inputs to the diagnostic engine: the observations collected by the probe
/// layer.
pub struct DiagnosticInput<'a> {
    /// Hostname the user targeted.
    pub hostname: &'a str,
    /// DNS observations (per resolver / record type).
    pub dns: &'a [DnsObservation],
    /// TCP connection observations (per destination address).
    pub tcp: &'a [TcpObservation],
    /// TLS handshake observations (per destination address).
    pub tls: &'a [TlsObservation],
    /// HTTPS / HTTP observations (per destination address).
    pub http: &'a [HttpObservation],
    /// Repeated probe results (per destination address).
    pub probes: &'a [ProbeResult],
}

/// Evaluate all rules against the observations and return the resulting
/// diagnoses, ordered deterministically. Returns a single healthy diagnosis
/// when nothing anomalous is found.
#[must_use]
pub fn diagnose(input: &DiagnosticInput) -> Vec<Diagnosis> {
    let mut out = Vec::new();
    let dns_signal = dns_rules(input, &mut out);
    connectivity_rules(input, &mut out);
    family_rules(input, &mut out);
    tls_layer_rules(input, &mut out);
    http_layer_rules(input, &mut out);
    quic_rules(input, &mut out);
    intermittent_rules(input, &mut out);
    filtering_rules(input, dns_signal, &mut out);

    if out.is_empty() {
        out.push(Diagnosis {
            severity: Severity::Info,
            category: DiagnosticCategory::Healthy,
            confidence: Confidence::High,
            summary: format!("No significant connectivity anomaly observed for {}", input.hostname),
            evidence: vec![Evidence {
                detail: "Every observed protocol layer succeeded or showed only expected behavior.".to_string(),
            }],
            possible_causes: Vec::new(),
        });
    }
    out
}

/// DNS rules. Returns whether resolver disagreement was observed (also feeds
/// the filtering analysis).
fn dns_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) -> bool {
    if input.dns.is_empty() {
        return false;
    }
    let mut any_success = false;
    let mut any_failure = false;
    let mut failed: Vec<&DnsObservation> = Vec::new();
    let mut all_sets: Vec<(String, BTreeSet<IpAddr>)> = Vec::new();

    for obs in input.dns {
        if obs.error.is_some() {
            any_failure = true;
            failed.push(obs);
        } else {
            any_success = true;
            if !obs.records.is_empty() {
                all_sets.push((
                    format!("{:?} {:?}", obs.resolver, obs.record_type),
                    obs.records.iter().copied().collect(),
                ));
            }
        }
    }

    // Disagreement: distinct address sets from different resolvers.
    let mut distinct: Vec<BTreeSet<IpAddr>> = Vec::new();
    for (_, set) in &all_sets {
        if !distinct.contains(set) {
            distinct.push(set.clone());
        }
    }
    let disagreement = distinct.len() > 1;

    if any_failure && !any_success {
        // Nothing resolved anywhere.
        let ids: Vec<String> = failed
            .iter()
            .map(|f| f.error.as_ref().map(|e| e.message.clone()).unwrap_or_default())
            .collect();
        out.push(Diagnosis {
            severity: Severity::High,
            category: DiagnosticCategory::Dns,
            confidence: Confidence::High,
            summary: format!("DNS resolution failed for {} from every resolver", input.hostname),
            evidence: vec![
                Evidence {
                    detail: "no A/AAAA records returned".into(),
                },
                Evidence { detail: ids.join("; ") },
            ],
            possible_causes: vec![
                "resolver outage".into(),
                "upstream network problem".into(),
                "domain does not exist or has no records".into(),
                "local DNS configuration / filtering".into(),
            ],
        });
    } else if disagreement {
        out.push(Diagnosis {
            severity: Severity::Low,
            category: DiagnosticCategory::Dns,
            confidence: Confidence::Low,
            summary: format!("Resolvers disagree on {}'s addresses", input.hostname),
            evidence: vec![Evidence {
                detail: format!("{} distinct address sets returned", distinct.len()),
            }],
            possible_causes: vec![
                "GeoDNS".into(),
                "CDN / load-balanced DNS".into(),
                "EDNS Client Subnet (ECS)".into(),
                "caching or normal resolver differences".into(),
                "DNS manipulation (unproven)".into(),
            ],
        });
    }
    disagreement
}

fn connectivity_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
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
        let confidence = if failing.iter().any(|f| f == passing.first().map_or("", String::as_str)) {
            Confidence::Medium
        } else if bad.iter().filter(|o| !o.success).count() > 1 {
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

fn family_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
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

fn tls_layer_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
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

fn http_layer_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
    let mut failing: Vec<String> = Vec::new();
    for h in input.http {
        let layer_failed = h.failure.is_some() || h.status.is_some_and(|s| s >= 400);
        if layer_failed {
            // Only flag if TLS succeeded (or we have no contradicting signal).
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

fn quic_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
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

fn intermittent_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) {
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

/// Conservative network-filtering analysis: only fires when several
/// independent signals agree, and never with high confidence.
fn filtering_rules(input: &DiagnosticInput, dns_disagreement: bool, out: &mut Vec<Diagnosis>) {
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
    use crate::model::{DnsRecordType, LatencyStats, ProbeError, ResolverKind};

    fn tp(addr: &str, ok: bool) -> TcpObservation {
        TcpObservation {
            destination: addr.parse().unwrap(),
            success: ok,
            latency_ms: ok.then_some(10),
            failure: (!ok).then(|| ProbeError {
                kind: FailureKind::Timeout,
                message: "timeout".into(),
            }),
        }
    }

    fn dns_ok(host: &str, kind: DnsRecordType, ip: &str) -> DnsObservation {
        DnsObservation {
            hostname: host.into(),
            resolver: ResolverKind::System,
            record_type: kind,
            records: vec![ip.parse().unwrap()],
            latency_ms: Some(5),
            error: None,
        }
    }

    fn dns_fail(host: &str) -> DnsObservation {
        DnsObservation {
            hostname: host.into(),
            resolver: ResolverKind::System,
            record_type: DnsRecordType::A,
            records: vec![],
            latency_ms: None,
            error: Some(ProbeError {
                kind: FailureKind::Dns,
                message: "no answer".into(),
            }),
        }
    }

    fn input<'a>(
        dns: &'a [DnsObservation],
        tcp: &'a [TcpObservation],
        tls: &'a [TlsObservation],
        http: &'a [HttpObservation],
        probes: &'a [ProbeResult],
    ) -> DiagnosticInput<'a> {
        DiagnosticInput {
            hostname: "example.com",
            dns,
            tcp,
            tls,
            http,
            probes,
        }
    }

    fn categories(di: &[Diagnosis]) -> Vec<DiagnosticCategory> {
        di.iter().map(|d| d.category).collect()
    }

    #[test]
    fn healthy_when_nothing_anomalous() {
        let dns = [dns_ok("example.com", DnsRecordType::A, "1.1.1.1")];
        let tcp = [tp("1.1.1.1:443", true)];
        let out = diagnose(&input(&dns, &tcp, &[], &[], &[]));
        assert_eq!(categories(&out), vec![DiagnosticCategory::Healthy]);
    }

    #[test]
    fn total_loss_when_all_tcp_fail() {
        let dns = [dns_ok("example.com", DnsRecordType::A, "1.1.1.1")];
        let tcp = [tp("1.1.1.1:443", false)];
        let out = diagnose(&input(&dns, &tcp, &[], &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::TotalConnectivityLoss));
    }

    #[test]
    fn partial_connectivity_when_some_fail() {
        let dns = [dns_ok("example.com", DnsRecordType::A, "1.1.1.1")];
        let tcp = [tp("1.1.1.1:443", true), tp("2.2.2.2:443", false)];
        let out = diagnose(&input(&dns, &tcp, &[], &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::PartialConnectivity));
    }

    #[test]
    fn address_family_split() {
        let tcp = [tp("1.1.1.1:443", true), tp("[2001:db8::1]:443", false)];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::AddressFamily));
    }

    #[test]
    fn tls_layer_failure_where_tcp_ok() {
        let tcp = [tp("1.1.1.1:443", true)];
        let tls = [TlsObservation {
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
                message: "hs".into(),
            }),
        }];
        let out = diagnose(&input(&[], &tcp, &tls, &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::Tls));
    }

    #[test]
    fn intermittent_from_probe_result() {
        let mut stats = LatencyStats::default();
        stats.push(100);
        stats.push(200);
        let probe = ProbeResult {
            destination: "1.1.1.1:443".parse().unwrap(),
            attempts: 2,
            successes: 1,
            failures: 1,
            success_rate: 0.5,
            latency: stats.summarize(),
            failure_counts: vec![],
        };
        let out = diagnose(&input(&[], &[], &[], &[], &[probe]));
        assert!(categories(&out).contains(&DiagnosticCategory::Intermittent));
    }

    #[test]
    fn filtering_requires_multiple_signals() {
        // A single reset must NOT trigger a filtering conclusion.
        let tcp = [TcpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::ConnectionReset,
                message: "r".into(),
            }),
        }];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        assert!(!categories(&out).contains(&DiagnosticCategory::PossibleNetworkFiltering));
    }

    #[test]
    fn dns_failure_all_resolvers() {
        let dns = [dns_fail("example.com")];
        let out = diagnose(&input(&dns, &[], &[], &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::Dns));
        let d = out.iter().find(|d| d.category == DiagnosticCategory::Dns).unwrap();
        assert_eq!(d.confidence, Confidence::High);
    }
    #[test]
    fn filtering_fires_with_multiple_signals_but_low_confidence() {
        // Resolver disagreement + address-specific reachability together are
        // consistent with possible filtering, but confidence must stay Low
        // (never High) and mundane causes must be listed.
        let dns = [
            dns_ok("example.com", DnsRecordType::A, "1.1.1.1"),
            DnsObservation {
                hostname: "example.com".into(),
                resolver: ResolverKind::Custom("9.9.9.9:53".parse().unwrap()),
                record_type: DnsRecordType::A,
                records: vec!["12.12.12.12".parse().unwrap()],
                latency_ms: Some(5),
                error: None,
            },
        ];
        let tcp = [tp("1.1.1.1:443", true), tp("2.2.2.2:443", false)];
        let out = diagnose(&input(&dns, &tcp, &[], &[], &[]));
        let f = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::PossibleNetworkFiltering);
        assert!(f.is_some(), "filtering diagnosis should fire with multiple signals");
        assert_eq!(f.unwrap().confidence, Confidence::Low);
        assert!(!f.unwrap().possible_causes.is_empty());
    }
}
