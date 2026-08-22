//! TLS observation types.

use std::net::SocketAddr;

/// Summary of the peer-end entity certificate presented during the handshake.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CertificateSummary {
    /// Raw subject (DN).
    pub subject: String,
    /// Raw issuer (DN).
    pub issuer: String,
    /// `notBefore` as an RFC 3339 UTC timestamp, when available.
    pub not_before_utc: Option<String>,
    /// `notAfter` as an RFC 3339 UTC timestamp, when available.
    pub not_after_utc: Option<String>,
    /// Subject Alternative Names (hostnames / IPs / emails / URIs) that the
    /// certificate is valid for, in certificate order.
    pub sans: Vec<String>,
}

/// A single TLS handshake to one destination socket address.
///
/// `sni` records which server name was presented, independently of the
/// address connected to (the brief requires explicit SNI control even when
/// connecting to a specific IP). `version`/`cipher`/`alpn`/`certificate` are
/// only populated on success.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TlsObservation {
    /// Destination socket address probed.
    pub destination: SocketAddr,
    /// Server Name Indication presented in the `ClientHello`.
    pub sni: String,
    /// Whether the TLS handshake completed.
    pub success: bool,
    /// Negotiated TLS version, e.g. `TLSv1.3`.
    pub version: Option<String>,
    /// Negotiated cipher suite.
    pub cipher: Option<String>,
    /// Negotiated ALPN protocol (e.g. `h2`, `http/1.1`).
    pub alpn: Option<String>,
    /// Peer certificate summary.
    pub certificate: Option<CertificateSummary>,
    /// Handshake latency in milliseconds on success.
    pub latency_ms: Option<u64>,
    /// Classified failure mode and context, when not successful.
    pub failure: Option<super::ProbeError>,
}
