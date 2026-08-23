//! Deterministic diagnostic engine.
//!
//! This module performs **no network I/O**. It takes normalized observations
//! and produces a set of evidence-based [`Diagnosis`]. It never claims
//! censorship from a single failure mode; it only raises
//! [`DiagnosticCategory::PossibleNetworkFiltering`] with low/medium confidence
//! when several independent signals align, and always lists the mundane
//! alternatives that also fit the evidence.
//!
//! The rule families live in submodules: `dns` (resolution), `connectivity`
//! (TCP reachability), `layer` (TLS/HTTP/QUIC/intermittent) and `filtering`
//! (conservative multi-signal analysis).

mod connectivity;
mod dns;
mod filtering;
mod layer;

use crate::model::{
    Confidence, Diagnosis, DiagnosticCategory, DnsObservation, Evidence, HttpObservation, ProbeResult, Severity,
    TcpObservation, TlsObservation,
};

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
    let dns_signal = dns::dns_rules(input, &mut out);
    connectivity::connectivity_rules(input, &mut out);
    connectivity::family_rules(input, &mut out);
    layer::tls_layer_rules(input, &mut out);
    layer::certificate_lifetime_rules(input, &mut out);
    layer::certificate_coverage_rules(input, &mut out);
    layer::http_layer_rules(input, &mut out);
    layer::redirect_rules(input, &mut out);
    layer::http_consistency_rules(input, &mut out);
    layer::truncated_body_rules(input, &mut out);
    layer::quic_rules(input, &mut out);
    layer::intermittent_rules(input, &mut out);
    filtering::filtering_rules(input, dns_signal, &mut out);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsRecord, DnsRecordType, FailureCount, FailureKind, LatencyStats, ProbeError, ResolverKind};

    /// Wrap an IP string as an address record (A/AAAA).
    fn addr_rec(ip: &str) -> DnsRecord {
        match ip.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(v) => DnsRecord::A(v),
            std::net::IpAddr::V6(v) => DnsRecord::Aaaa(v),
        }
    }

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
            records: vec![addr_rec(ip)],
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
    fn address_family_fires_in_both_orientations() {
        // The reverse asymmetry (IPv4 fails while IPv6 works — an IPv6-only
        // host) must be diagnosed with the *failing* family named in the
        // evidence, not just the IPv6-fails/IPv4-works direction.
        let tcp = [
            TcpObservation {
                destination: "192.0.2.1:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::Timeout,
                    message: "timeout".into(),
                }),
            },
            tp("[2001:db8::1]:443", true),
        ];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        let af = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::AddressFamily)
            .expect("address-family diagnosis");
        let evidence: String = af
            .evidence
            .iter()
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            evidence.contains("IPv4: unreachable"),
            "failing family must be named: {evidence:?}"
        );
        assert!(evidence.contains("IPv6: reachable"));
        assert_eq!(af.severity, Severity::Low);
    }

    #[test]
    fn ipv4_locally_unreachable_reports_family_asymmetry_only() {
        // Reverse of `partial_connectivity_not_raised_*`: an IPv6-only host
        // whose IPv4 fails with NetworkUnreachable (a local no-route verdict,
        // not path evidence) must NOT be read as destination partial
        // connectivity; the address-family rule names the asymmetry instead.
        let tcp = [
            TcpObservation {
                destination: "192.0.2.1:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::NetworkUnreachable,
                    message: "network unreachable".into(),
                }),
            },
            tp("[2001:db8::1]:443", true),
        ];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        assert!(
            !categories(&out).contains(&DiagnosticCategory::PartialConnectivity),
            "locally-unroutable IPv4 must not be partial connectivity: {out:?}"
        );
        assert!(categories(&out).contains(&DiagnosticCategory::AddressFamily));
    }

    #[test]
    fn partial_connectivity_not_raised_when_all_failures_are_local_unreachability() {
        // A healthy dual-stack host whose IPv6 has no route (this machine's
        // exact condition): the IPv6 TCP observations fail with
        // NetworkUnreachable, which the host's own stack reports before any
        // packet is sent — a local routing verdict, not evidence about the
        // destination. The reachability rule must not read it as "only some
        // destination addresses work" (its causes are CDN node failure /
        // destination filtering / routing asymmetry): the address-family rule
        // already reports the local cause. See `ipv6_locally_unreachable_does_*`.
        let tcp = [
            tp("1.1.1.1:443", true),
            TcpObservation {
                destination: "[2001:db8::1]:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::NetworkUnreachable,
                    message: "network unreachable".into(),
                }),
            },
            TcpObservation {
                destination: "[2001:db8::2]:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::NetworkUnreachable,
                    message: "network unreachable".into(),
                }),
            },
        ];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        assert!(
            !categories(&out).contains(&DiagnosticCategory::PartialConnectivity),
            "locally-unroutable family must not be read as destination partial connectivity: {out:?}"
        );
        // The correct, honest diagnosis for the failed family is still raised.
        assert!(categories(&out).contains(&DiagnosticCategory::AddressFamily));
    }

    #[test]
    fn partial_connectivity_fires_when_any_failure_is_path_evidence() {
        // As soon as one failing address shows a genuine path failure (a
        // timeout — a packet was sent and no answer came back), partial
        // connectivity is real and must still fire even if other failures on
        // the same destination are locally unreachable.
        let tcp = [
            tp("1.1.1.1:443", true),
            TcpObservation {
                destination: "[2001:db8::1]:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::NetworkUnreachable,
                    message: "network unreachable".into(),
                }),
            },
            TcpObservation {
                destination: "[2001:db8::2]:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::Timeout,
                    message: "timed out".into(),
                }),
            },
        ];
        let out = diagnose(&input(&[], &tcp, &[], &[], &[]));
        assert!(categories(&out).contains(&DiagnosticCategory::PartialConnectivity));
        // With more than one failing address the reachability rule still
        // claims High confidence — the local-unreachability addresses are also
        // genuinely unreachable, and at least one path failure is real.
        let p = out
            .iter()
            .find(|d| d.category == DiagnosticCategory::PartialConnectivity)
            .unwrap();
        assert_eq!(p.confidence, Confidence::High);
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
    fn http3_quic_path_failure_is_not_an_http_layer_error() {
        // An HTTP/3 probe whose QUIC handshake times out (e.g. a silent UDP
        // peer) is the QUIC path failing — `quic_rules`' verdict — not an
        // HTTP-layer error. It must not be double-counted as an Http
        // diagnosis while the healthy TCP+HTTPS path succeeds.
        let dns = [dns_ok("example.com", DnsRecordType::A, "1.1.1.1")];
        let tcp = [tp("1.1.1.1:443", true)];
        let http = [
            HttpObservation {
                destination: "1.1.1.1:443".parse().unwrap(),
                host: "example.com".into(),
                method: "GET".into(),
                path: "/".into(),
                tls: None,
                protocol: Some("HTTP/1.1".into()),
                status: Some(200),
                location: None,
                headers: Vec::new(),
                body_bytes: Some(100),
                body_snippet: None,
                ttfb_ms: None,
                latency_ms: Some(30),
                failure: None,
            },
            HttpObservation {
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
                    kind: FailureKind::Timeout,
                    message: "quic handshake to 1.1.1.1:443 timed out".into(),
                }),
            },
        ];
        let out = diagnose(&input(&dns, &tcp, &[], &http, &[]));
        assert!(
            !categories(&out).contains(&DiagnosticCategory::Http),
            "an h3 QUIC timeout must not be an HTTP-layer error: {out:?}"
        );
        assert!(
            categories(&out).contains(&DiagnosticCategory::Quic),
            "the QUIC path failure is quic_rules' verdict: {out:?}"
        );
    }

    #[test]
    fn truncated_http_body_is_diagnosed() {
        let dns = [dns_ok("example.com", DnsRecordType::A, "1.1.1.1")];
        let tcp = [tp("1.1.1.1:443", true)];
        let http = [HttpObservation {
            destination: "1.1.1.1:443".parse().unwrap(),
            host: "example.com".into(),
            method: "GET".into(),
            path: "/".into(),
            tls: None,
            protocol: Some("HTTP/1.1".into()),
            status: Some(200),
            location: None,
            headers: Vec::new(),
            body_bytes: None, // headers received, body stalled
            body_snippet: None,
            ttfb_ms: None,
            latency_ms: Some(30),
            failure: None,
        }];
        let out = diagnose(&input(&dns, &tcp, &[], &http, &[]));
        let truncated = out.iter().find(|d| d.category == DiagnosticCategory::Http);
        assert!(
            truncated.is_some_and(|d| d.severity == Severity::Low),
            "truncated body must be a Low diagnosis: {out:?}"
        );
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
    fn single_resolver_a_and_aaaa_do_not_count_as_disagreement() {
        // A single resolver returning both A and AAAA is answering normally,
        // not disagreeing with itself. Before this was fixed, the IPv4 set and
        // the IPv6 set were compared as separate "resolvers", flagging every
        // dual-stack hostname as disagreement and feeding a false filtering
        // signal.
        let dns = [
            dns_ok("example.com", DnsRecordType::A, "1.1.1.1"),
            dns_ok("example.com", DnsRecordType::Aaaa, "2001:db8::1"),
        ];
        let out = diagnose(&input(&dns, &[], &[], &[], &[]));
        assert!(
            !categories(&out).contains(&DiagnosticCategory::Dns),
            "A+AAAA from one resolver must not be a disagreement: {out:?}"
        );
    }

    #[test]
    fn ipv6_locally_unreachable_does_not_raise_filtering() {
        // A healthy dual-stack host whose IPv6 has no route (this machine's
        // exact condition): all IPv4 layers pass, IPv6 fails with
        // NetworkUnreachable at TCP/TLS/repeat. The single mundane cause must
        // not be read as "multiple independent filtering signals".
        let dns = [
            dns_ok("example.com", DnsRecordType::A, "1.1.1.1"),
            dns_ok("example.com", DnsRecordType::Aaaa, "2001:db8::1"),
        ];
        let tcp = [
            tp("1.1.1.1:443", true),
            TcpObservation {
                destination: "[2001:db8::1]:443".parse().unwrap(),
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind: FailureKind::NetworkUnreachable,
                    message: "network unreachable".into(),
                }),
            },
        ];
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
        let stats = LatencyStats::default();
        let probes = [ProbeResult {
            destination: "[2001:db8::1]:443".parse().unwrap(),
            attempts: 3,
            successes: 0,
            failures: 3,
            success_rate: 0.0,
            latency: stats.summarize(),
            failure_counts: vec![FailureCount {
                kind: FailureKind::NetworkUnreachable,
                count: 3,
            }],
        }];
        let out = diagnose(&input(&dns, &tcp, &tls, &[], &probes));
        assert!(
            !categories(&out).contains(&DiagnosticCategory::PossibleNetworkFiltering),
            "local IPv6 unreachability must not be read as filtering: {out:?}"
        );
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
                records: vec![addr_rec("12.12.12.12")],
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
