//! ip-tools — a network observability and diagnostics toolkit.
//!
//! The project measures *what actually happens* when a destination is reached
//! at each protocol layer (DNS, TCP, TLS, HTTP, …), records strongly typed
//! observations, and then — separately — interprets them. Measurement and
//! diagnosis are kept apart: the diagnostic engine is deterministic and does
//! no network I/O.
//!
//! The toolkit does **not** claim that a network failure is censorship merely
//! because a connection fails. It reports evidence and confidence, and always
//! lists alternative explanations that remain consistent with the evidence.
//!
//! # Modules
//!
//! * [`model`] — the typed observation and diagnosis vocabulary.
//! * [`dns`] — DNS resolution probes.
//! * [`tcp`] — TCP connect probes with failure-mode classification.
//! * [`tls`] — TLS handshake probes (SNI, ALPN, certificate).
//! * [`http`] — HTTPS / HTTP1.1 request probes.
//! * [`probe`] — repeated probing and latency statistics.
//! * [`target`] — target (host/port) parsing.
//! * [`report`] — human and JSON rendering.
//! * [`error`] — context-preserving error types.
//!
//! # Local IP helpers
//!
//! The historical local-IP surface is preserved: [`get_local_ip`] and
//! [`list_net_ifs`] with [`IpToolsError`].

pub mod dns;
pub mod error;
pub mod http;
pub mod http2;
pub mod model;
pub mod probe;
pub mod report;
pub mod target;
pub mod tcp;
pub mod tls;

pub use model::{
    CertificateSummary, Confidence, Diagnosis, DiagnosticCategory, DnsObservation, DnsRecordType, Evidence,
    FailureKind, HttpObservation, IpVersion, LatencyStats, ProbeError, ProbeResult, ResolverKind, Severity,
    TcpObservation, TlsObservation,
};

// ---------------------------------------------------------------------------
// Local IP convenience helpers (legacy surface)
// ---------------------------------------------------------------------------

use local_ip_address::{list_afinet_netifas, local_ip};
use std::net::IpAddr;

/// Error type for the legacy local-IP helpers.
#[derive(Debug, thiserror::Error)]
pub enum IpToolsError {
    /// Failed to determine the local IP address.
    #[error("failed to get local IP address: {0}")]
    LocalIp(#[from] local_ip_address::Error),
    /// Failed to list network interfaces.
    #[error("failed to list network interfaces: {0}")]
    ListInterfaces(#[source] local_ip_address::Error),
}

/// Retrieves the local IP address.
///
/// # Errors
///
/// Returns [`Err`] containing an [`IpToolsError`] if the local IP cannot be
/// determined, e.g. when no network interface is configured.
pub fn get_local_ip() -> Result<IpAddr, IpToolsError> {
    Ok(local_ip()?)
}

/// Lists all network interfaces and their IP addresses.
///
/// # Errors
///
/// Returns [`Err`] containing an [`IpToolsError`] if the interface list
/// cannot be retrieved.
pub fn list_net_ifs() -> Result<Vec<(String, IpAddr)>, IpToolsError> {
    list_afinet_netifas().map_err(IpToolsError::ListInterfaces)
}
