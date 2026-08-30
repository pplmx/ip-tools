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
        // Filter BEFORE taking the cap: `.take(24)` on the raw iterator would
        // run ahead of the filter, so headers skipped for non-UTF-8 or the
        // separately-recorded `Location` would silently consume slots and a
        // chatty first-24 response could register far fewer than the recorded
        // cap while valid later headers were discarded.
        .filter_map(|(name, value)| {
            let name = name.as_str();
            let value = value.to_str().ok()?;
            if name.eq_ignore_ascii_case("location") {
                return None;
            }
            Some((name.to_owned(), value.to_owned()))
        })
        .take(MAX_RESPONSE_HEADERS)
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

/// The wire-presented host: a bracketed IPv6-literal target keeps its
/// brackets on the `host` string (`Target::parse("[::1]", _)` → `"[::1]"`),
/// but the wire forms must not carry them — the `Host` header / `:authority`
/// value is unbracketed (RFC 7230 §5.4 / RFC 9113 §8.3.1), and a TLS/QUIC
/// server name cannot include them at all (quinn's `ServerName::try_from`
/// rejects `"[::1]"`). Idempotent.
#[must_use]
pub fn wire_host(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// The URI-authority form of a wire host: an IPv6 literal must be bracketed
/// (`https://[::1]/` is a valid authority; `https://::1/` is not, RFC 3986
/// §3.2.2), while hostnames and IPv4 pass through unaltered.
#[must_use]
pub fn uri_authority(host: &str) -> std::borrow::Cow<'_, str> {
    let bare = wire_host(host);
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => std::borrow::Cow::Owned(format!("[{bare}]")),
        _ => std::borrow::Cow::Borrowed(bare),
    }
}

/// Scheme default ports: the port omitted from a wire authority is 443 for
/// HTTPS and 80 for HTTP (RFC 7230 §5.4).
pub const HTTPS_DEFAULT_PORT: u16 = 443;
pub const HTTP_DEFAULT_PORT: u16 = 80;

/// The wire `Host` header / `:authority` value for a target probed at `port`:
/// the port is appended when it is not the scheme default (`example.com` at
/// 8080 → `example.com:8080`; at 443 → `example.com`), because an origin
/// server doing host-based virtual hosting keys on host **and** port — sending
/// the bare host for a non-default port routes a request to the wrong vhost
/// or returns 404/421 (RFC 7230 §5.4 / RFC 9113 §8.3.1 / RFC 9114 §4.3.1).
/// `tls` selects the scheme (443 vs 80). Brackets are stripped from an IPv6
/// literal, matching [`wire_host`]; `port == 0` (unset) is never named.
#[must_use]
pub fn wire_authority(host: &str, port: u16, tls: bool) -> String {
    let bare = wire_host(host);
    let default = if tls { HTTPS_DEFAULT_PORT } else { HTTP_DEFAULT_PORT };
    if port != 0 && port != default {
        format!("{bare}:{port}")
    } else {
        bare.to_string()
    }
}

/// The URI-authority form of a wire host at a destination port, for
/// `https://host[:port]/path`: the IPv6 literal is re-bracketed (RFC 3986
/// §3.2.2) and the port is appended when it is not the HTTPS default 443 —
/// so the `:authority` pseudo-header on the h2/h3 wire names the exact port
/// the probe connects to (RFC 9113 §8.3.1 / RFC 9114 §4.3.1).
#[must_use]
pub fn uri_authority_at(host: &str, port: u16) -> std::borrow::Cow<'_, str> {
    let mut base = uri_authority(host).into_owned();
    if port != 0 && port != HTTPS_DEFAULT_PORT {
        base.push(':');
        base.push_str(&port.to_string());
    }
    std::borrow::Cow::Owned(base)
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

/// Accumulate one response-body chunk into the observation, honoring the
/// `--max-body-bytes` read cap as a **strict** bound: the chunk is truncated
/// to the remaining budget before the snippet (and the retained `--output-body`
/// copy, when requested) is extended, so the retained bytes — and therefore
/// the reported `body_bytes` — can never exceed the cap even by a partial
/// frame, and a 0-byte cap reads nothing at all. Returns `true` once the cap
/// is reached so the caller can stop reading further frames.
pub fn push_bounded_body(
    snippet: &mut Vec<u8>,
    full_body: Option<&mut Vec<u8>>,
    bytes_read: &mut u64,
    max_body_bytes: u64,
    data: &[u8],
) -> bool {
    let remaining = max_body_bytes.saturating_sub(*bytes_read);
    let take = (data.len() as u64).min(remaining) as usize;
    let bounded = &data[..take];
    push_body_snippet(snippet, bounded);
    *bytes_read += take as u64;
    if let Some(full_body) = full_body {
        full_body.extend_from_slice(bounded);
    }
    *bytes_read >= max_body_bytes
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

#[cfg(test)]
mod tests {
    use super::{
        collect_response_headers, push_bounded_body, uri_authority, uri_authority_at, wire_authority, wire_host,
    };

    #[test]
    fn wire_host_strips_brackets_only() {
        // A bracketed IPv6-literal target keeps its brackets on the host
        // string; the wire Host/SNI must not carry them.
        assert_eq!(wire_host("[::1]"), "::1");
        assert_eq!(wire_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(wire_host("::1"), "::1");
        assert_eq!(wire_host("vhost.example"), "vhost.example");
        assert_eq!(wire_host("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn uri_authority_rebrackets_a_bare_ipv6_literal() {
        // `https://[::1]/` is the only valid URI authority for an IPv6
        // literal (RFC 3986 §3.2.2); a bare `::1` override is re-bracketed.
        assert_eq!(uri_authority("[::1]"), "[::1]");
        assert_eq!(uri_authority("::1"), "[::1]");
        assert_eq!(uri_authority("vhost.example"), "vhost.example");
        assert_eq!(uri_authority("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn wire_authority_appends_only_a_non_default_port() {
        // The scheme default (443 for TLS / 80 for plain) is omitted; any
        // other port is named so vhost-by-host:port routing still works.
        assert_eq!(wire_authority("example.com", 443, true), "example.com");
        assert_eq!(wire_authority("example.com", 80, false), "example.com");
        assert_eq!(wire_authority("example.com", 8080, true), "example.com:8080");
        assert_eq!(wire_authority("example.com", 8080, false), "example.com:8080");
        // A port that is default for one scheme is non-default for the other:
        // plain HTTP on 443 (or HTTPS on 80) must still be named.
        assert_eq!(wire_authority("example.com", 443, false), "example.com:443");
        assert_eq!(wire_authority("example.com", 80, true), "example.com:80");
        // IPv4 and IPv6 literals (brackets stripped) behave the same.
        assert_eq!(wire_authority("1.2.3.4", 443, true), "1.2.3.4");
        assert_eq!(wire_authority("1.2.3.4", 8443, true), "1.2.3.4:8443");
        assert_eq!(wire_authority("[2001:db8::1]", 8443, true), "2001:db8::1:8443");
        assert_eq!(wire_authority("[::1]", 443, true), "::1");
        // An unset port (0) is treated as "not named".
        assert_eq!(wire_authority("example.com", 0, true), "example.com");
    }

    #[test]
    fn uri_authority_at_appends_only_a_non_443_port() {
        // The h2/h3 `:authority` must name the exact port the probe connects
        // to, unless it is the https default 443.
        assert_eq!(uri_authority_at("example.com", 443), "example.com");
        assert_eq!(uri_authority_at("example.com", 8080), "example.com:8080");
        assert_eq!(uri_authority_at("::1", 443), "[::1]");
        assert_eq!(uri_authority_at("::1", 8443), "[::1]:8443");
        assert_eq!(uri_authority_at("[::1]", 8443), "[::1]:8443");
        assert_eq!(uri_authority_at("1.2.3.4", 8443), "1.2.3.4:8443");
    }

    #[test]
    fn cap_truncates_a_oversized_chunk_to_the_remaining_budget() {
        let mut snippet = Vec::new();
        let mut read = 0u64;
        let capped = push_bounded_body(&mut snippet, None, &mut read, 5, b"abcdefghij");
        assert_eq!(read, 5, "only the cap budget is consumed");
        assert_eq!(snippet, b"abcde");
        assert!(capped, "reaching the cap must flag the end");
    }

    #[test]
    fn zero_cap_reads_nothing_but_is_immediately_capped() {
        let mut snippet = Vec::new();
        let mut read = 0u64;
        let capped = push_bounded_body(&mut snippet, None, &mut read, 0, b"hello");
        assert_eq!(read, 0);
        assert!(snippet.is_empty());
        assert!(capped);
    }

    #[test]
    fn accumulation_stops_exactly_at_the_cap_across_chunks() {
        let mut snippet = Vec::new();
        let mut read = 0u64;
        assert!(!push_bounded_body(&mut snippet, None, &mut read, 10, b"abcdef"));
        assert!(
            push_bounded_body(&mut snippet, None, &mut read, 10, b"ghij"),
            "the chunk crossing the cap flags the end"
        );
        assert_eq!(read, 10);
        assert_eq!(snippet, b"abcdefghij");

        // A further chunk (would only appear if the caller ignored the flag)
        // retains nothing.
        assert!(push_bounded_body(&mut snippet, None, &mut read, 10, b"xxxx"));
        assert_eq!(read, 10);
        assert_eq!(snippet, b"abcdefghij");
    }

    #[test]
    fn header_cap_is_applied_after_filtering() {
        // The cap bounds *recorded* headers, not iterated ones: headers skipped
        // for non-UTF-8 or the separately-recorded `Location` must not consume
        // slots, and valid later headers must still be recorded. A map with
        // `Location` interspersed early exercises exactly that.
        let mut map = hyper::HeaderMap::new();
        // 24 distinct valid headers plus 3 Locations mixed in ahead of them
        // would, under an iterate-then-take(24) scheme, drop the later valid
        // ones. Insert Location at the start and keep the valid set distinct.
        map.insert("location", hyper::header::HeaderValue::from_static("/moved"));
        for i in 0..24 {
            let name =
                hyper::header::HeaderName::from_bytes(format!("x-hdr-{i}").as_bytes()).expect("valid header name");
            map.append(name, hyper::header::HeaderValue::from_static("v"));
        }
        let collected = collect_response_headers(&map);
        assert_eq!(collected.len(), 24, "all 24 valid headers survive the filter-first cap");
        assert!(
            collected.iter().all(|(n, _)| !n.eq_ignore_ascii_case("location")),
            "Location must be excluded before the cap: {collected:?}"
        );
        assert_eq!(collected[0].0, "x-hdr-0", "iteration order preserved: {collected:?}");
    }

    #[test]
    fn retained_output_body_obeys_the_same_cap() {
        let mut full = Vec::new();
        let mut snippet = Vec::new();
        let mut read = 0u64;
        push_bounded_body(&mut snippet, Some(&mut full), &mut read, 4, b"abcdefgh");
        assert_eq!(full, b"abcd", "the --output-body copy must not exceed the cap");
        assert_eq!(read, 4);
    }
}
