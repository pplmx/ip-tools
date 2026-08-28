//! HTTP/2 probing.
//!
//! A separate transport probe over the same target: TCP + TLS with ALPN `h2`,
//! then a single HTTP/2 request via the `h2` crate. Keeping this separate from
//! the HTTP/1.1 probe makes `HTTP/1.1 PASS / HTTP/2 FAIL` (and the reverse) a
//! first-class, observable distinction.

use crate::http_common::{
    body_snippet_string, build_tls_observation, collect_response_headers, http_error, push_bounded_body,
    BODY_SNIPPET_BYTES, MAX_BODY_BYTES,
};
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Perform a single HTTPS/HTTP/2 request to `destination` (connecting to its
/// IP) presenting `host` as SNI, bounded by `timeout`.
///
/// `path` is the request target (e.g. `/`, `/healthz`). Extra `headers`
/// (each `name`, `value`) are sent verbatim on the request.
pub async fn probe(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Roots(&crate::tls::roots()),
        crate::tls::TlsProtocol::Auto,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe`] offering only the given TLS protocol version.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/protocol
pub async fn probe_with_version(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    protocol: crate::tls::TlsProtocol,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Roots(&crate::tls::roots()),
        protocol,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe`] trusting an explicit root store, for verifying TLS fixtures.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/roots
pub async fn probe_with_roots(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Roots(roots),
        crate::tls::TlsProtocol::Auto,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe`] without certificate validation (the `--insecure` CLI flag).
pub async fn probe_insecure(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Insecure,
        crate::tls::TlsProtocol::Auto,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe_with_version`] with a configurable body-read cap and optional
/// `--output-body` capture.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/protocol/max/output
pub async fn probe_with_version_output(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    protocol: crate::tls::TlsProtocol,
    max_body_bytes: u64,
    output: Option<&std::path::Path>,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Roots(&crate::tls::roots()),
        protocol,
        max_body_bytes,
        output,
    )
    .await
}

/// [`probe_insecure`] offering only the given TLS protocol version.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/protocol
pub async fn probe_insecure_with_version(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    protocol: crate::tls::TlsProtocol,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Insecure,
        protocol,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe_insecure_with_version`] with a configurable body-read cap and
/// optional `--output-body` capture.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/protocol/max/output
pub async fn probe_insecure_with_version_output(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    protocol: crate::tls::TlsProtocol,
    max_body_bytes: u64,
    output: Option<&std::path::Path>,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        crate::tls::TlsMode::Insecure,
        protocol,
        max_body_bytes,
        output,
    )
    .await
}

/// Shared probe body for the given trust mode.
#[allow(clippy::too_many_arguments)]
async fn probe_impl(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    mode: crate::tls::TlsMode<'_>,
    protocol: crate::tls::TlsProtocol,
    max_body_bytes: u64,
    body_output: Option<&std::path::Path>,
) -> HttpObservation {
    let start = Instant::now();
    // Name the protocol up front so a *failed* observation keeps its identity
    // (an h2 failure would otherwise look like a bare base and the HTTP/2 row
    // of a failing host would be mislabeled).
    let base = HttpObservation {
        protocol: Some("HTTP/2".to_string()),
        ..HttpObservation::base(destination, host, method, path)
    };

    let conn = match crate::tls::connect_to(destination, host, crate::tls::ALPN_H2, timeout, mode, protocol).await {
        Ok(c) => c,
        Err(failure) => return base.with_failure(failure),
    };
    let tls_obs = build_tls_observation(&conn, destination, host);

    let (mut send_request, connection) = match tokio::time::timeout(timeout, h2::client::handshake(conn.stream)).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return base.with_failure(http_error("HTTP/2 handshake", &e)),
        Err(_) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("http/2 handshake to {destination} timed out after {timeout:?}"),
            });
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // Build the request; h2 needs an authority, so construct the URI from a
    // full URL (hyper fills the :authority pseudo-header). An explicit `host`
    // header overrides that authority (routing a shared-IP vhost) and is not
    // re-emitted as a second `host` header alongside :authority.
    let custom_host = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| *v);
    let effective_host = custom_host.unwrap_or(host);
    // The URI authority drives hyper's `:authority`. A bracketed IPv6-literal
    // host stays bracketed (`https://[::1]/` is a valid authority); a bare
    // IPv6 override (e.g. a user `host` header written without brackets) is
    // re-bracketed so the URI stays valid (RFC 3986 §3.2.2).
    let uri = format!("https://{}{path}", crate::http_common::uri_authority(effective_host));
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*");
    for (name, value) in headers {
        if custom_host.is_none() || !name.eq_ignore_ascii_case("host") {
            builder = builder.header(*name, *value);
        }
    }
    // A request body is announced with an explicit content-length.
    let builder = match body {
        Some(bytes) => builder.header("content-length", bytes.len().to_string()),
        None => builder,
    };
    let request = match builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Protocol,
                message: format!("could not build http/2 request: {e}"),
            });
        }
    };

    // send_request() returns (ResponseFuture, SendStream) synchronously; the
    // ResponseFuture then resolves to the response. With a body we keep the
    // stream open (end_of_stream=false), push the bytes via SendStream, then
    // finish with trailers (END_STREAM). Without a body we end immediately.
    let ttfb_start = Instant::now();
    let (response_future, mut send_stream) = match send_request.send_request(request, body.is_none()) {
        Ok(pair) => pair,
        Err(e) => return base.with_failure(http_error("http/2 request", &e)),
    };
    if let Some(bytes) = body {
        if let Err(e) = send_stream.send_data(bytes::Bytes::copy_from_slice(bytes), false) {
            return base.with_failure(http_error("http/2 body send", &e));
        }
        if let Err(e) = send_stream.send_trailers(hyper::HeaderMap::new()) {
            return base.with_failure(http_error("http/2 body finish", &e));
        }
    }
    let response = match tokio::time::timeout(timeout, response_future).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return base.with_failure(http_error("http/2 response", &e)),
        Err(_) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("http/2 request to {destination} timed out after {timeout:?}"),
            });
        }
    };
    let ttfb_ms = Some(ttfb_start.elapsed().as_millis() as u64);

    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let headers = collect_response_headers(response.headers());

    // Drain the response body (bounded). `ended` distinguishes a body that
    // completed (end-of-stream reached, or the cap) from one that stalled:
    // a read that times out mid-body must leave the response visibly
    // incomplete (`None`) rather than appearing as a full reply. A transport
    // error mid-body is a failed observation, already returned above.
    let mut body = response.into_body();
    let mut bytes_read: u64 = 0;
    let mut ended = false;
    let mut snippet: Vec<u8> = Vec::with_capacity(BODY_SNIPPET_BYTES);
    let mut full_body: Vec<u8> = Vec::new();
    // Whole-body-deadline: a slow-dripping body cannot stall past --timeout.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, body.data()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(e))) => return base.with_failure(http_error("http/2 body", &e)),
            Ok(None) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
        };
        let capped = push_bounded_body(
            &mut snippet,
            body_output.is_some().then_some(&mut full_body),
            &mut bytes_read,
            max_body_bytes,
            &chunk[..],
        );
        // The whole chunk was read off the wire (whatever was retained), so
        // release its full flow-control window.
        let _ = body.flow_control().release_capacity(chunk.len());
        if capped {
            ended = true;
            break;
        }
    }

    let body_snippet = body_snippet_string(&snippet, (bytes_read as usize) > snippet.len());
    if let Some(path) = body_output {
        if let Err(e) = crate::http_common::write_body_to_file(path, &full_body) {
            eprintln!("Warning: could not write response body to {}: {e}", path.display());
        }
    }
    HttpObservation {
        tls: Some(tls_obs),
        status: Some(status),
        protocol: Some("HTTP/2".to_string()),
        location,
        headers,
        body_bytes: ended.then_some(bytes_read),
        body_snippet,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ttfb_ms,
        ..base
    }
}
