//! HTTP/2 probing.
//!
//! A separate transport probe over the same target: TCP + TLS with ALPN `h2`,
//! then a single HTTP/2 request via the `h2` crate. Keeping this separate from
//! the HTTP/1.1 probe makes `HTTP/1.1 PASS / HTTP/2 FAIL` (and the reverse) a
//! first-class, observable distinction.

use crate::http_common::{build_tls_observation, http_error, MAX_BODY_BYTES};
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Perform a single HTTPS/HTTP/2 request to `destination` (connecting to its
/// IP) presenting `host` as SNI, bounded by `timeout`.
pub async fn probe(destination: SocketAddr, host: &str, method: &str, timeout: Duration) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        timeout,
        crate::tls::TlsMode::Roots(&crate::tls::roots()),
    )
    .await
}

/// [`probe`] trusting an explicit root store, for verifying TLS fixtures.
pub async fn probe_with_roots(
    destination: SocketAddr,
    host: &str,
    method: &str,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> HttpObservation {
    probe_impl(destination, host, method, timeout, crate::tls::TlsMode::Roots(roots)).await
}

/// [`probe`] without certificate validation (the `--insecure` CLI flag).
pub async fn probe_insecure(destination: SocketAddr, host: &str, method: &str, timeout: Duration) -> HttpObservation {
    probe_impl(destination, host, method, timeout, crate::tls::TlsMode::Insecure).await
}

/// Shared probe body for the given trust mode.
async fn probe_impl(
    destination: SocketAddr,
    host: &str,
    method: &str,
    timeout: Duration,
    mode: crate::tls::TlsMode<'_>,
) -> HttpObservation {
    let start = Instant::now();
    // Name the protocol up front so a *failed* observation keeps its identity
    // (an h2 failure would otherwise look like a bare base and the HTTP/2 row
    // of a failing host would be mislabeled).
    let base = HttpObservation {
        protocol: Some("HTTP/2".to_string()),
        ..HttpObservation::base(destination, host, method)
    };

    let conn = match crate::tls::connect_to(destination, host, crate::tls::ALPN_H2, timeout, mode).await {
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
    // full URL (hyper fills the :authority pseudo-header).
    let uri = format!("https://{host}/");
    let request = match hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*")
        .body(())
    {
        Ok(r) => r,
        Err(e) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Protocol,
                message: format!("could not build http/2 request: {e}"),
            });
        }
    };

    // send_request() returns (ResponseFuture, SendStream) synchronously; the
    // ResponseFuture then resolves to the response.
    // Body-less request: mark end-of-stream so the server responds (an open
    // stream would make it wait for request data).
    let (response_future, _send_stream) = match send_request.send_request(request, true) {
        Ok(pair) => pair,
        Err(e) => return base.with_failure(http_error("http/2 request", &e)),
    };
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

    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Drain the response body (bounded). `ended` distinguishes a body that
    // completed (end-of-stream reached, or the cap) from one that stalled:
    // a read that times out mid-body must leave the response visibly
    // incomplete (`None`) rather than appearing as a full reply. A transport
    // error mid-body is a failed observation, already returned above.
    let mut body = response.into_body();
    let mut bytes_read: u64 = 0;
    let mut ended = false;
    loop {
        let chunk = match tokio::time::timeout(timeout, body.data()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(e))) => return base.with_failure(http_error("http/2 body", &e)),
            Ok(None) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
        };
        bytes_read = bytes_read.saturating_add(chunk.len() as u64);
        let _ = body.flow_control().release_capacity(chunk.len());
        if bytes_read >= MAX_BODY_BYTES {
            ended = true;
            break;
        }
    }

    HttpObservation {
        tls: Some(tls_obs),
        status: Some(status),
        protocol: Some("HTTP/2".to_string()),
        location,
        body_bytes: ended.then_some(bytes_read),
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ..base
    }
}
