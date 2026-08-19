//! Core typed data model for network observations and diagnoses.
//!
//! This module is intentionally free of any networking code. It is the
//! normalized vocabulary used between the measurement layer and the
//! (pure) diagnostic engine so that observations can be produced,
//! serialized and diagnosed independently of how they were measured.

pub mod diagnosis;
pub mod dns;
pub mod http;
pub mod latency;
pub mod probe;
pub mod tcp;
pub mod tls;

pub use diagnosis::{Confidence, Diagnosis, DiagnosticCategory, Evidence, Severity};
pub use dns::{DnsObservation, DnsRecordType, ResolverKind};
pub use http::HttpObservation;
pub use latency::{LatencyStats, LatencySummary};
pub use probe::{FailureCount, ProbeResult};
pub use tcp::TcpObservation;
pub use tls::{CertificateSummary, TlsObservation};

/// A classified low-level failure with a human-readable context message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProbeError {
    /// The classified failure mode.
    pub kind: FailureKind,
    /// Human-readable context, e.g. `connection refused by 1.2.3.4:443`.
    pub message: String,
}

/// Classification of a network failure into a distinct, observable mode.
///
/// The variants are kept deliberately distinct because `timeout != reset !=
/// refused`: each implies a different failure mechanism and must never be
/// silently collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Operation did not complete within its configured deadline.
    Timeout,
    /// Destination actively refused the connection (RST from listener).
    ConnectionRefused,
    /// Connection was reset out-of-band during the operation (RST).
    ConnectionReset,
    /// Network reported the destination network as unreachable.
    NetworkUnreachable,
    /// Network reported the destination host as unreachable.
    HostUnreachable,
    /// DNS resolution failed.
    Dns,
    /// TLS handshake failed / was aborted.
    TlsHandshake,
    /// TLS certificate validation failed.
    Certificate,
    /// A protocol-level violation.
    Protocol,
    /// An HTTP-level error.
    Http,
    /// A failure that does not fit a more specific category.
    Other,
    /// The failure could not be characterised.
    Unknown,
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use FailureKind::*;
        let s = match self {
            Timeout => "timeout",
            ConnectionRefused => "connection refused",
            ConnectionReset => "connection reset",
            NetworkUnreachable => "network unreachable",
            HostUnreachable => "host unreachable",
            Dns => "dns",
            TlsHandshake => "tls handshake",
            Certificate => "certificate",
            Protocol => "protocol",
            Http => "http",
            Other => "other",
            Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Version of the IP protocol an endpoint uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}
