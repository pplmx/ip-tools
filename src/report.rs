//! Human and JSON rendering of observations.
//!
//! Human output is tuned for terminal investigation. JSON output carries the
//! complete raw observation data (via serde `Serialize` on the model types)
//! so external systems can build their own analysis.

use crate::model::{DnsObservation, DnsRecordType, ResolverKind, TcpObservation};

/// Render DNS observations for `host` as human text.
pub fn render_dns(host: &str, observations: &[DnsObservation]) -> String {
    let mut out = String::new();
    out.push_str(&format!("DNS {host}\n"));

    // Group by resolver, then list each record type's addresses.
    // Order is stable: system first, then custom resolvers.
    let mut seen_resolvers = Vec::new();
    for obs in observations {
        if !seen_resolvers.iter().any(|r| r == &obs.resolver) {
            seen_resolvers.push(obs.resolver.clone());
        }
    }
    for resolver in seen_resolvers {
        out.push_str(&format!("  {}\n", resolver_label(&resolver)));
        for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
            if let Some(obs) = observations
                .iter()
                .find(|o| o.resolver == resolver && o.record_type == rt)
            {
                out.push_str(&format!("    {:4}: ", rt_label(rt)));
                out.push_str(&render_dns_one(obs));
                out.push('\n');
            }
        }
    }
    out
}

fn render_dns_one(obs: &DnsObservation) -> String {
    match (&obs.error, obs.latency_ms) {
        (Some(err), _) => format!("{} ({})", err.kind, err.message),
        (None, Some(ms)) => {
            if obs.records.is_empty() {
                format!("no records ({} ms)", ms)
            } else {
                let addrs: Vec<String> = obs.records.iter().map(ToString::to_string).collect();
                format!("{} ({} ms)", addrs.join(", "), ms)
            }
        }
        (None, None) => "no records".to_string(),
    }
}

fn resolver_label(r: &ResolverKind) -> String {
    match r {
        ResolverKind::System => "system".to_string(),
        ResolverKind::Custom(addr) => addr.to_string(),
    }
}

fn rt_label(rt: DnsRecordType) -> &'static str {
    match rt {
        DnsRecordType::A => "A",
        DnsRecordType::Aaaa => "AAAA",
    }
}

/// Render TCP observations as human text.
pub fn render_tcp(observations: &[TcpObservation]) -> String {
    let mut out = String::from("TCP connect\n");
    for obs in observations {
        let status = if obs.success {
            format!("PASS      {} ms", obs.latency_ms.unwrap_or(0))
        } else {
            let err = obs
                .failure
                .as_ref()
                .map(|e| e.kind.to_string())
                .unwrap_or_else(|| "failed".to_string());
            format!("{err:10}")
        };
        out.push_str(&format!("  {:24} {status}\n", obs.destination));
    }
    out
}

/// Serialize any serde value as pretty JSON.
pub fn to_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).expect("serialization to JSON cannot fail")
}
