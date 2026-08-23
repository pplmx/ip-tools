//! DNS observation types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
    /// A DNS-over-TLS (RFC 7858) endpoint, e.g. `1.1.1.1` (port 853).
    Dot(String),
}

/// A DNS record type/query family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Canonical name (alias) record.
    Cname,
    /// Mail exchange record.
    Mx,
    /// Text record (SPF, DKIM, etc.).
    Txt,
    /// Authoritative name-server record.
    Ns,
    /// Start-of-authority record.
    Soa,
    /// Certification Authority Authorization record.
    Caa,
    /// Service (SRV) record.
    Srv,
    /// Reverse-lookup (PTR) pointer record.
    Ptr,
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Caa => "CAA",
            Self::Srv => "SRV",
            Self::Ptr => "PTR",
        })
    }
}

/// A typed DNS record value returned for a queried record type.
///
/// Serializes to its human-readable form (e.g. `1.1.1.1`, `10 mail.example`)
/// so JSON output stays a plain array of strings; the variant keeps the
/// structured data (e.g. an MX preference) available to callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    /// IPv4 address (A).
    A(Ipv4Addr),
    /// IPv6 address (AAAA).
    Aaaa(Ipv6Addr),
    /// Canonical-name target (CNAME).
    Cname(String),
    /// Mail exchange: priority plus the exchange hostname (MX).
    Mx { preference: u16, exchange: String },
    /// Text blob (TXT); a single TXT record's character-strings are joined.
    Txt(String),
    /// Authoritative name server (NS).
    Ns(String),
    /// Start-of-authority fields, space-joined (SOA).
    Soa(String),
    /// Certification Authority Authorization: flags, tag and value (CAA).
    Caa { flags: u8, tag: String, value: String },
    /// Service endpoint: priority, weight, port and target hostname (SRV).
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Reverse-lookup pointer (PTR): the hostname mapped to the queried
    /// address (used for reverse DNS).
    Ptr(String),
}

impl DnsRecord {
    /// The resolved address for A/AAAA records.
    #[must_use]
    pub const fn address(&self) -> Option<IpAddr> {
        match self {
            Self::A(ip) => Some(IpAddr::V4(*ip)),
            Self::Aaaa(ip) => Some(IpAddr::V6(*ip)),
            _ => None,
        }
    }
}

impl std::fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::Aaaa(ip) => write!(f, "{ip}"),
            Self::Cname(name) | Self::Ns(name) | Self::Ptr(name) => write!(f, "{name}"),
            Self::Mx { preference, exchange } => write!(f, "{preference} {exchange}"),
            Self::Txt(text) => write!(f, "{text:?}"),
            Self::Soa(s) => write!(f, "{s}"),
            Self::Caa { flags, tag, value } => write!(f, "{flags} {tag} {value}"),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {target}"),
        }
    }
}

impl serde::Serialize for DnsRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
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
    /// Records returned (empty on failure).
    pub records: Vec<DnsRecord>,
    /// Time-to-live in seconds of the first answering record, when the query
    /// succeeded (`None` on failure or a literal short-circuit).
    pub ttl: Option<u32>,
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
