//! DNS observation types.

use std::net::{IpAddr, SocketAddr};

use super::latency::LatencySummary;
use super::probe::FailureCount;

/// Which resolver produced a DNS observation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum ResolverKind {
    /// The operating system's configured resolver.
    System,
    /// An explicitly configured DNS server.
    Custom(SocketAddr),
    /// A DNS-over-HTTPS (RFC 8484) endpoint, e.g. `https://1.1.1.1/dns-query`.
    Doh(String),
}

/// A DNS record type/query family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        })
    }
}

/// A single DNS query result for one record type via one resolver.
///
/// `latency_ms` and `error` are exclusive: a successful query has a latency
/// and an empty `error`; a failed query has an error and no latency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DnsObservation {
    /// Hostname that was queried.
    pub hostname: String,
    /// Resolver that answered (or failed).
    pub resolver: ResolverKind,
    /// Record type queried.
    pub record_type: DnsRecordType,
    /// Addresses returned (empty on failure).
    pub records: Vec<IpAddr>,
    /// Query latency in milliseconds, when the query succeeded.
    pub latency_ms: Option<u64>,
    /// Failure detail, when the query failed.
    pub error: Option<super::ProbeError>,
}

/// Aggregated result of repeatedly resolving one hostname (`dns --count N`).
///
/// Mirrors [`crate::model::ProbeResult`] but is keyed by resolver + record
/// type rather than a socket address, since DNS resolution is hostname-centric.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsRepeatResult {
    /// Resolver that answered (or failed).
    pub resolver: ResolverKind,
    /// Record type queried.
    pub record_type: DnsRecordType,
    /// Total query attempts.
    pub attempts: usize,
    /// Queries that answered.
    pub successes: usize,
    /// Queries that failed.
    pub failures: usize,
    /// Latency statistics over the successful queries.
    pub latency: LatencySummary,
    /// Failure distribution (count per failure kind).
    pub failure_counts: Vec<FailureCount>,
}

impl DnsRepeatResult {
    /// Success rate in `0.0..=1.0`.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f64 / self.attempts as f64
        }
    }
}
