//! HTTP/2 probing.
//!
//! A separate transport probe over the same target: TCP + TLS with ALPN `h2`,
//! then a single HTTP/2 request via the `h2` crate. Keeping this separate from
//! the HTTP/1.1 probe makes `HTTP/1.1 PASS / HTTP/2 FAIL` (and the reverse) a
//! first-class, observable distinction.

use crate::http::build_tls_observation;
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError};
use crate::tls;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Cap on the response body read, to bound resource use.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Perform a single HTTPS/HTTP/2 request to `destination` (connecting to its
/// IP) presenting `host` as SNI, bounded by `timeout`.
pub async fn probe(destination: SocketAddr, host: &str, method: &str, timeout: Duration) -> HttpObservation {
    let start = Instant::now();
    let base = HttpObservation {
        destination,
        host: host.to_string(),
        method: method.to_string(),
        tls: None,
        protocol: None,
        status: None,
        location: None,
        body_bytes: None,
        latency_ms: None,
        failure: None,
    };

    let conn = match tls::connect(destination, host, tls::ALPN_H2, timeout).await {
        Ok(c) => c,
        Err(failure) => return base.with_failure(failure),
    };
    let tls_obs = build_tls_observation(&conn, destination, host);

    let (mut send_request, connection) = match tokio::time::timeout(timeout, h2::client::handshake(conn.stream)).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return base.with_failure(h2_error("HTTP/2 handshake", &e)),
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
        Err(e) => return base.with_failure(h2_error("http/2 request", &e)),
    };
    let response = match tokio::time::timeout(timeout, response_future).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return base.with_failure(h2_error("http/2 response", &e)),
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

    // Drain the response body (bounded).
    let mut body = response.into_body();
    let mut bytes_read: u64 = 0;
    loop {
        let chunk = match tokio::time::timeout(timeout, body.data()).await {
            Ok(Some(Ok(chunk))) => chunk,
            Ok(Some(Err(e))) => return base.with_failure(h2_error("http/2 body", &e)),
            Ok(None) | Err(_) => break,
        };
        bytes_read = bytes_read.saturating_add(chunk.len() as u64);
        let _ = body.flow_control().release_capacity(chunk.len());
        if bytes_read >= MAX_BODY_BYTES {
            break;
        }
    }

    HttpObservation {
        tls: Some(tls_obs),
        status: Some(status),
        protocol: Some("HTTP/2".to_string()),
        location,
        body_bytes: Some(bytes_read),
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ..base
    }
}

fn h2_error(step: &str, e: &h2::Error) -> ProbeError {
    ProbeError {
        kind: FailureKind::Http,
        message: format!("{step} failed: {e}"),
    }
}
