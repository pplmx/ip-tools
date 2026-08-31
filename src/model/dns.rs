//! DNS observation types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::latency::LatencySummary;
use super::probe::FailureCount;

/// Which resolver produced a DNS observation.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl ResolverKind {
    /// The single human/`--json`/CSV spelling for a resolver: `system`, a
    /// socket address, a `DoH` endpoint, or a `host (DoT)` label — the same
    /// string the JSON serializer and the human/CSV renderers use, so a
    /// consumer joining JSON to either never sees a third spelling. Mirrors
    /// `LatencyStats`'s accessor style on the public model.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::System => "system".to_string(),
            Self::Custom(addr) => addr.to_string(),
            Self::Doh(endpoint) => endpoint.clone(),
            Self::Dot(endpoint) => format!("{endpoint} (DoT)"),
        }
    }
}

// Serialize as that stable label string, not the derived externally-tagged
// shape (`"System"` unit on one row but `{"Custom": "…"}` object on the next
// within the same document — a JSON type swap that breaks any single filter).
impl serde::Serialize for ResolverKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.label())
    }
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

/// Present a name-bearing record value for terminal/CSV safety: printable
/// bytes (including non-ASCII UTF-8 labels) verbatim, every control byte as
/// hickory's `\NNN` octal escape (0x1b ESC → `\033`, LF → `\012`). The wire
/// decoders (`dns::read_name`/`read_txt`) pass raw bytes through
/// `from_utf8_lossy`, so a hostile DNS answer can place a live ANSI ESC, CR or
/// LF into a CNAME/NS/PTR/SOA label — rendered raw in the human report a
/// terminal would reinterpret, or un-quoted into a CSV cell a spreadsheet
/// would split. Escaping once on the shared `Display` funnel both resolution
/// paths use keeps the invariant both now honor: no resolution path emits a
/// raw control byte — hickory additionally backslash-escapes a few
/// hostname-unsafe *printable* bytes (`[` → `\[`) and appends the root dot,
/// but that cosmetic difference is independent of the safety property here.
fn esc_present(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_control() {
            let _ = write!(out, "\\{:03o}", ch as u32);
        } else {
            out.push(ch);
        }
    }
    out
}

impl std::fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(ip) => write!(f, "{ip}"),
            Self::Aaaa(ip) => write!(f, "{ip}"),
            Self::Cname(name) | Self::Ns(name) | Self::Ptr(name) => write!(f, "{}", esc_present(name)),
            Self::Mx { preference, exchange } => write!(f, "{preference} {}", esc_present(exchange)),
            Self::Txt(text) => write!(f, "{text:?}"),
            Self::Soa(s) => write!(f, "{}", esc_present(s)),
            Self::Caa { flags, tag, value } => write!(f, "{flags} {tag} {}", esc_present(value)),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{priority} {weight} {port} {}", esc_present(target)),
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
    /// Success rate in `0.0..=1.0`, serialized like [`crate::model::ProbeResult`]'s
    /// own `success_rate` so `dns --count --json` and `probe --json` expose the
    /// same aggregate schema.
    pub success_rate: f64,
    /// Latency statistics over the successful queries.
    pub latency: LatencySummary,
    /// Failure distribution (count per failure kind).
    pub failure_counts: Vec<FailureCount>,
    /// Minimum record time-to-live (seconds) observed across the successful
    /// answers — the caching-relevant bound (a record with a shorter TTL
    /// expires sooner). `None` when no attempt returned a TTL.
    pub ttl: Option<u32>,
}

impl DnsRepeatResult {
    /// Success rate in `0.0..=1.0` (the serialized [`Self::success_rate`]
    /// field; kept as an accessor for callers that predate the field).
    #[must_use]
    pub const fn success_rate(&self) -> f64 {
        self.success_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_label_is_the_single_spelling_across_variants() {
        assert_eq!(ResolverKind::System.label(), "system");
        assert_eq!(
            ResolverKind::Custom("127.0.0.1:5399".parse().unwrap()).label(),
            "127.0.0.1:5399"
        );
        assert_eq!(
            ResolverKind::Doh("https://1.1.1.1/dns-query".to_string()).label(),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(ResolverKind::Dot("1.1.1.1".to_string()).label(), "1.1.1.1 (DoT)");
    }

    #[test]
    fn resolver_json_is_a_stable_string_not_a_type_swapping_tagged_object() {
        // The derived externally-tagged shape mixed `"System"` (unit → string)
        // with `{"Custom": "…"}` (newtype → object) in ONE document, so no
        // single `.[] | .resolver` filter survived both. Every variant must
        // serialize to the same plain-string label the human/CSV renderers use.
        assert_eq!(serde_json::to_string(&ResolverKind::System).unwrap(), "\"system\"");
        assert_eq!(
            serde_json::to_string(&ResolverKind::Custom("127.0.0.1:5399".parse().unwrap())).unwrap(),
            "\"127.0.0.1:5399\""
        );
        assert_eq!(
            serde_json::to_string(&ResolverKind::Doh("https://1.1.1.1/dns-query".to_string())).unwrap(),
            "\"https://1.1.1.1/dns-query\""
        );
        assert_eq!(
            serde_json::to_string(&ResolverKind::Dot("1.1.1.1".to_string())).unwrap(),
            "\"1.1.1.1 (DoT)\""
        );
    }

    #[test]
    fn dns_record_display_escapes_control_bytes_like_hickory() {
        // A hostile DNS answer can carry a control byte (ANSI ESC) in a
        // CNAME/NS/PTR label — the wire decoders pass the raw byte through —
        // and the human report / CSV render via `Display`. Control bytes must
        // render as hickory's octal `\NNN` spelling (ESC 0x1b → `\033`),
        // never as a live terminal sequence, while printable ASCII survives.
        let evil = DnsRecord::Cname("\u{1b}[31mEVIL.example".to_string());
        assert_eq!(evil.to_string(), "\\033[31mEVIL.example");
        // Printable (incl. non-ASCII IDN labels) must stay verbatim.
        let idn = DnsRecord::Ns("例子.测试".to_string());
        assert_eq!(idn.to_string(), "例子.测试");
        // Newline and carriage return are also escaped (CSV-cell safety).
        assert_eq!(DnsRecord::Ptr("a\r\nb".to_string()).to_string(), "a\\015\\012b");
        // TXT already Debug-escapes; ensure it stays that way.
        assert_eq!(DnsRecord::Txt("x\u{1b}y".to_string()).to_string(), "\"x\\u{1b}y\"");
        // JSON serializes through Display (collect_str) → the CSV/human-safe
        // spelling, no raw control byte in the document.
        let json = serde_json::to_string(&DnsRecord::Cname("\u{1b}red".to_string())).unwrap();
        assert!(!json.contains('\u{1b}'), "JSON must not carry a raw 0x1b: {json}");
    }
}
