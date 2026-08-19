//! HTTPS / HTTP/1.1 probing.
//!
//! Each probe connects TCP + TLS (with SNI = the target host) to one specific
//! destination socket address, then issues a single HTTP request over the
//! connection. Redirection is *not* followed by default: a redirect is
//! recorded, not chased, so the raw server behaviour is visible.

use crate::http_common::{build_tls_observation, http_error};
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Cap on the response body read from the server, to bound resource use.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Perform a single HTTPS/HTTP/1.1 request to `destination` (connecting to
/// its IP) presenting `host` as SNI and `Host` header, bounded by `timeout`.
///
/// `method` is `GET`, `HEAD`, etc. Failures are captured in the observation.
pub async fn probe(destination: SocketAddr, host: &str, method: &str, timeout: Duration) -> HttpObservation {
    probe_with_roots(destination, host, method, timeout, &crate::tls::roots()).await
}

/// [`probe`] trusting an explicit root store, for verifying TLS fixtures.
pub async fn probe_with_roots(
    destination: SocketAddr,
    host: &str,
    method: &str,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> HttpObservation {
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

    // 1. TLS handshake (HTTP/1.1 ALPN).
    let tls_obs;
    let conn = match crate::tls::connect_with_roots(destination, host, crate::tls::ALPN_HTTP1, timeout, roots).await {
        Ok(c) => {
            tls_obs = build_tls_observation(&c, destination, host);
            c
        }
        Err(failure) => return base.with_failure(failure),
    };

    // 2. Drive the hyper HTTP/1.1 connection.
    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(conn.stream));
    let (mut sender, connection) = match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return base.with_failure(http_error("HTTP/1.1 handshake", &e)),
        Err(_) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("http/1.1 handshake to {destination} timed out after {timeout:?}"),
            });
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    // 3. Build and send the request.
    let request = match hyper::Request::builder()
        .method(method)
        .uri("/")
        .header("host", host)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*")
        .body(Empty::<hyper::body::Bytes>::new())
    {
        Ok(r) => r,
        Err(e) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Protocol,
                message: format!("could not build http request: {e}"),
            });
        }
    };

    let response = match tokio::time::timeout(timeout, sender.send_request(request)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return base.with_failure(http_error("http request", &e)),
        Err(_) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("http request to {destination} timed out after {timeout:?}"),
            });
        }
    };

    // 4. Read a bounded amount of the response body.
    let status = response.status().as_u16();
    let protocol = Some(format!("{:?}", response.version()));
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = response.into_body();
    let limited = Limited::new(body, MAX_BODY_BYTES as usize);
    let body_bytes = match tokio::time::timeout(timeout, limited.collect()).await {
        Ok(Ok(collected)) => Some(collected.to_bytes().len() as u64),
        Ok(Err(_e)) => Some(MAX_BODY_BYTES), // truncated at the cap
        Err(_) => None,
    };

    HttpObservation {
        tls: Some(tls_obs),
        status: Some(status),
        protocol,
        location,
        body_bytes,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ..base
    }
}

impl HttpObservation {
    pub(crate) fn with_failure(mut self, failure: ProbeError) -> Self {
        self.failure = Some(failure);
        self
    }
}
