//! HTTPS / HTTP/1.1 probing.
//!
//! Each probe connects TCP + TLS (with SNI = the target host) to one specific
//! destination socket address, then issues a single HTTP request over the
//! connection. Redirection is *not* followed by default: a redirect is
//! recorded, not chased, so the raw server behaviour is visible.

use crate::http_common::{build_tls_observation, http_error, MAX_BODY_BYTES};
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Perform a single HTTPS/HTTP/1.1 request to `destination` (connecting to
/// its IP) presenting `host` as SNI and `Host` header, bounded by `timeout`.
///
/// `method` is `GET`, `HEAD`, etc. `path` is the request target (e.g. `/`,
/// `/healthz`). Failures are captured in the observation.
pub async fn probe(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    timeout: Duration,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
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
    path: &str,
    timeout: Duration,
    roots: &rustls::RootCertStore,
) -> HttpObservation {
    probe_impl(
        destination,
        host,
        method,
        path,
        timeout,
        crate::tls::TlsMode::Roots(roots),
    )
    .await
}

/// [`probe`] without certificate validation (the `--insecure` CLI flag).
pub async fn probe_insecure(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    timeout: Duration,
) -> HttpObservation {
    probe_impl(destination, host, method, path, timeout, crate::tls::TlsMode::Insecure).await
}

/// Shared probe body for the given trust mode.
async fn probe_impl(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    timeout: Duration,
    mode: crate::tls::TlsMode<'_>,
) -> HttpObservation {
    let start = Instant::now();
    // Name the protocol up front so a *failed* observation keeps its identity
    // (HTTP/2 and HTTP/3 failures would otherwise be indistinguishable from a
    // bare base and the QUIC diagnostics could never see a failed h3 probe).
    let base = HttpObservation {
        protocol: Some("HTTP/1.1".to_string()),
        ..HttpObservation::base(destination, host, method, path)
    };

    // 1. TLS handshake (HTTP/1.1 ALPN).
    let tls_obs;
    let conn = match crate::tls::connect_to(destination, host, crate::tls::ALPN_HTTP1, timeout, mode).await {
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
        .uri(path)
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

    // 4. Read a bounded amount of the response body. `ended` distinguishes a
    // body that completed (end-of-stream reached, or the cap) from one that
    // stalled: a read that times out mid-body must leave the response visibly
    // incomplete (`None`) rather than appearing as a full reply, and a
    // transport error mid-body is a failed observation, not a capped success.
    let status = response.status().as_u16();
    let protocol = Some(format!("{:?}", response.version()));
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut body = response.into_body();
    let mut bytes_read: u64 = 0;
    let mut ended = false;
    loop {
        let frame = match tokio::time::timeout(timeout, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => return base.with_failure(http_error("HTTP/1.1 body", &e)),
            Ok(None) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
        };
        if let Ok(data) = frame.into_data() {
            bytes_read = bytes_read.saturating_add(data.len() as u64);
        }
        if bytes_read >= MAX_BODY_BYTES {
            ended = true;
            break;
        }
    }
    let body_bytes = ended.then_some(bytes_read);

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
