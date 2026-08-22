//! DNS-resolution diagnostic rules.

use super::DiagnosticInput;
use crate::model::{Confidence, Diagnosis, DiagnosticCategory, DnsObservation, DnsRecord, Evidence, Severity};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// DNS rules. Returns whether resolver disagreement was observed (also feeds
/// the filtering analysis).
pub(super) fn dns_rules(input: &DiagnosticInput, out: &mut Vec<Diagnosis>) -> bool {
    if input.dns.is_empty() {
        return false;
    }
    let mut any_success = false;
    let mut any_failure = false;
    let mut failed: Vec<&DnsObservation> = Vec::new();
    // Per *resolver* combined address sets (A + AAAA together). Disagreement
    // is meaningful only across different resolvers: a single resolver that
    // returns both an A and an AAAA set is answering normally, not disagreeing
    // with itself — comparing those as separate sets would flag every
    // dual-stack hostname as "resolvers disagree".
    let mut per_resolver: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();

    for obs in input.dns {
        if obs.error.is_some() {
            any_failure = true;
            failed.push(obs);
        } else {
            any_success = true;
            if !obs.records.is_empty() {
                per_resolver
                    .entry(format!("{:?}", obs.resolver))
                    .or_default()
                    .extend(obs.records.iter().filter_map(DnsRecord::address));
            }
        }
    }

    // Disagreement: distinct combined address sets across different resolvers.
    let mut distinct: Vec<BTreeSet<IpAddr>> = Vec::new();
    for set in per_resolver.values() {
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
