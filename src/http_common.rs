//! Shared helpers for the HTTP-family probes (HTTP/1.1, HTTP/2, HTTP/3).

use crate::model::{FailureKind, ProbeError, TlsObservation};
use crate::tls;
use std::net::SocketAddr;

/// Cap on the response body read from the server, to bound resource use.
pub const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Cap on the number of response headers recorded per observation, so a
/// hostile or chatty server cannot balloon the probe's memory.
pub const MAX_RESPONSE_HEADERS: usize = 24;

/// Collect the response headers into a bounded (name, value) list for the
/// observation. Only lossy-convertible values are kept (raw bytes that are
/// not valid UTF-8 are skipped); order is preserved, and the `Location`
/// header is recorded separately by the probes rather than here.
pub fn collect_response_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .take(MAX_RESPONSE_HEADERS)
        .filter_map(|(name, value)| {
            let name = name.as_str();
            let value = value.to_str().ok()?;
            if name.eq_ignore_ascii_case("location") {
                return None;
            }
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

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
pub fn http_error(step: &str, e: impl std::fmt::Display) -> ProbeError {
    ProbeError {
        kind: FailureKind::Http,
        message: format!("{step} failed: {e}"),
    }
}
