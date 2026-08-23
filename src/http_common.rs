//! Shared helpers for the HTTP-family probes (HTTP/1.1, HTTP/2, HTTP/3).

use crate::model::{FailureKind, ProbeError, TlsObservation};
use crate::tls;
use std::net::SocketAddr;

/// Cap on the response body read from the server, to bound resource use.
pub const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Cap on the response-body text snippet kept in each observation, so a
/// hostile or binary body cannot balloon the probe's memory or dump unbounded
/// content into a report.
pub const BODY_SNIPPET_BYTES: usize = 1024;

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

/// Append up to [`BODY_SNIPPET_BYTES`] of `data` to the running snippet,
/// stopping once the cap is reached.
pub fn push_body_snippet(snippet: &mut Vec<u8>, data: &[u8]) {
    if snippet.len() >= BODY_SNIPPET_BYTES {
        return;
    }
    let take = (BODY_SNIPPET_BYTES - snippet.len()).min(data.len());
    snippet.extend_from_slice(&data[..take]);
}

/// Build the lossy-UTF8 text snippet from the captured bytes. Returns `None`
/// when nothing was captured; appends `…` when the body had more content than
/// the snippet cap (`truncated`).
#[must_use]
pub fn body_snippet_string(snippet: &[u8], truncated: bool) -> Option<String> {
    if snippet.is_empty() {
        return None;
    }
    let mut text = String::from_utf8_lossy(snippet).into_owned();
    if truncated {
        text.push('…');
    }
    Some(text)
}

/// Write the accumulated bounded response body to `path` (best effort). Only
/// the bytes read up to [`MAX_BODY_BYTES`] are retained, so a hostile or
/// multi-megabyte body is capped just like the in-memory body handling. The
/// write happens only after the probe body loop finishes, so a write error
/// doesn't corrupt an otherwise-complete observation.
pub fn write_body_to_file(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, body)
}
