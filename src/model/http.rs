//! HTTP observation types.

use std::net::SocketAddr;

use super::ProbeError;
use crate::model::TlsObservation;

/// A single HTTPS/HTTP request to one destination socket address.
///
/// `tls` carries the underlying TLS handshake details (when the handshake
/// succeeded) so a single HTTP probe also reveals the negotiated TLS version,
/// cipher, ALPN and certificate. `protocol` identifies the wire protocol
/// actually used (e.g. `HTTP/1.1`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HttpObservation {
    /// Destination socket address probed.
    pub destination: SocketAddr,
    /// Host used for SNI and the `Host` header.
    pub host: String,
    /// HTTP method used (e.g. `GET`, `HEAD`).
    pub method: String,
    /// Underlying TLS handshake when it succeeded.
    pub tls: Option<TlsObservation>,
    /// Wire protocol, e.g. `HTTP/1.1`.
    pub protocol: Option<String>,
    /// HTTP response status code.
    pub status: Option<u16>,
    /// `Location` header (redirect target), when present.
    pub location: Option<String>,
    /// Response body bytes read (capped).
    pub body_bytes: Option<u64>,
    /// Overall latency (TLS + HTTP) in milliseconds on success.
    pub latency_ms: Option<u64>,
    /// Classified failure mode and context, when not successful.
    pub failure: Option<ProbeError>,
}
