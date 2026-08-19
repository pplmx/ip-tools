//! Shared helpers for the HTTP-family probes (HTTP/1.1, HTTP/2, HTTP/3).

use crate::model::{FailureKind, ProbeError, TlsObservation};
use crate::tls;
use std::net::SocketAddr;

/// Reconstruct a [`TlsObservation`] from an established connection helper so
/// the bearer HTTP observation carries TLS details.
pub fn build_tls_observation(conn: &tls::TlsConnection, destination: SocketAddr, host: &str) -> TlsObservation {
    TlsObservation {
        destination,
        sni: host.to_string(),
        success: true,
        version: conn.version.clone(),
        cipher: conn.cipher.clone(),
        alpn: conn.alpn.clone(),
        certificate: conn.certificate.clone(),
        latency_ms: Some(conn.latency_ms),
        failure: None,
    }
}

/// Build a probe error describing a failed HTTP-layer step.
pub fn http_error(step: &str, e: &hyper::Error) -> ProbeError {
    ProbeError {
        kind: FailureKind::Http,
        message: format!("{step} failed: {e}"),
    }
}
