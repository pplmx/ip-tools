//! HTTP/3 / QUIC probing over the UDP path.
//!
//! A completely separate transport path: UDP + QUIC (TLS 1.3 inside) +
//! HTTP/3, via `quinn` and `h3`. Keeping this distinct from the TCP path makes
//! `TCP/HTTPS PASS / QUIC/HTTP3 FAIL` (and the reverse) observable.

use crate::http_common::{
    body_snippet_string, collect_response_headers, push_body_snippet, BODY_SNIPPET_BYTES, MAX_BODY_BYTES,
};
use crate::model::http::HttpObservation;
use crate::model::tls::TlsObservation;
use crate::model::{FailureKind, ProbeError};
use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Build a QUIC client configuration for the given trust mode (insecure skips
/// certificate validation, per the `--insecure` CLI flag).
fn quic_client_config_from(mode: crate::tls::TlsMode<'_>) -> Result<QuinnClientConfig, String> {
    let rustls_cfg = match mode {
        crate::tls::TlsMode::Roots(roots) => {
            let mut cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots.clone())
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"h3".to_vec()];
            cfg
        }
        crate::tls::TlsMode::Insecure => {
            let cfg = crate::tls::insecure_client_config(&[b"h3"], crate::tls::TlsProtocol::Auto);
            (*cfg).clone()
        }
    };
    let quic_cfg = QuicClientConfig::try_from(rustls_cfg).map_err(|e| format!("invalid QUIC config: {e}"))?;
    Ok(QuinnClientConfig::new(Arc::new(quic_cfg)))
}

/// Bind a client QUIC endpoint on an ephemeral port suitable for `destination`.
fn client_endpoint(destination: SocketAddr) -> Result<Endpoint, String> {
    let bind_addr: SocketAddr = match destination.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().expect("static ipv4 bind"),
        IpAddr::V6(_) => "[::]:0".parse().expect("static ipv6 bind"),
    };
    Endpoint::client(bind_addr).map_err(|e| format!("could not bind QUIC endpoint {bind_addr}: {e}"))
}

/// Perform a single HTTP/3 request over QUIC to `destination` (its IP)
/// presenting `host` as the server name, bounded by `timeout`.
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
    )
    .await
}

/// [`probe`] trusting an explicit root store, for verifying QUIC fixtures.
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
) -> HttpObservation {
    let start = Instant::now();
    // Name the protocol up front so a *failed* observation keeps its identity:
    // the QUIC diagnostics and the QUIC-only filtering signal match on
    // `protocol == "HTTP/3"`, so a failed h3 probe that lost its protocol
    // would be invisible to them.
    let base = HttpObservation {
        protocol: Some("HTTP/3".to_string()),
        ..HttpObservation::base(destination, host, method, path)
    };

    let mut endpoint = match client_endpoint(destination) {
        Ok(e) => e,
        Err(msg) => return base.with_failure(failure(FailureKind::Other, msg)),
    };
    let config = match quic_client_config_from(mode) {
        Ok(c) => c,
        Err(msg) => return base.with_failure(failure(FailureKind::Other, msg)),
    };
    endpoint.set_default_client_config(config);

    // QUIC handshake (UDP), bounded.
    let connecting = match endpoint.connect(destination, host) {
        Ok(c) => c,
        Err(e) => return base.with_failure(failure(FailureKind::Quic, format!("quic connect failed: {e}"))),
    };
    let quic_conn = match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return base.with_failure(failure(FailureKind::Quic, format!("quic handshake failed: {e}"))),
        Err(_) => {
            return base.with_failure(failure(
                FailureKind::Timeout,
                format!("quic handshake to {destination} timed out after {timeout:?}"),
            ));
        }
    };

    // HTTP/3 connection over the QUIC connection.
    let h3_quinn = h3_quinn::Connection::new(quic_conn.clone());
    let (driver, mut send_request) = match tokio::time::timeout(timeout, h3::client::new(h3_quinn)).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 setup failed: {e}"))),
        Err(_) => {
            return base.with_failure(failure(
                FailureKind::Timeout,
                format!("http/3 setup to {destination} timed out after {timeout:?}"),
            ));
        }
    };
    tokio::spawn(async move {
        let mut driver = driver;
        let _ = driver.wait_idle().await;
    });

    let uri = format!("https://{host}{path}");
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    // A request body is announced with an explicit content-length.
    let builder = match body {
        Some(bytes) => builder.header("content-length", bytes.len().to_string()),
        None => builder,
    };
    let request = match builder.body(()) {
        Ok(r) => r,
        Err(e) => return base.with_failure(failure(FailureKind::Protocol, format!("could not build request: {e}"))),
    };

    // TTFB: time from sending the request to receiving the response headers.
    let ttfb_start = Instant::now();
    let mut req_stream = match tokio::time::timeout(timeout, send_request.send_request(request)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 request failed: {e}"))),
        Err(_) => {
            return base.with_failure(failure(
                FailureKind::Timeout,
                format!("http/3 request to {destination} timed out after {timeout:?}"),
            ));
        }
    };
    let ttfb_ms = Some(ttfb_start.elapsed().as_millis() as u64);
    // A request body is pushed on the request stream as a DATA frame before
    // the stream is finished.
    if let Some(bytes) = body {
        match tokio::time::timeout(timeout, req_stream.send_data(bytes::Bytes::copy_from_slice(bytes))).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return base.with_failure(failure(FailureKind::Http, format!("http/3 body send failed: {e}")))
            }
            Err(_) => {
                return base.with_failure(failure(
                    FailureKind::Timeout,
                    format!("http/3 body send to {destination} timed out after {timeout:?}"),
                ))
            }
        }
    }
    let _ = tokio::time::timeout(timeout, req_stream.finish()).await;

    let response = match tokio::time::timeout(timeout, req_stream.recv_response()).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 response failed: {e}"))),
        Err(_) => {
            return base.with_failure(failure(
                FailureKind::Timeout,
                format!("http/3 response from {destination} timed out after {timeout:?}"),
            ));
        }
    };

    let status = response.status().as_u16();
    let location = response
        .headers()
        .get(hyper::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let headers = collect_response_headers(response.headers());

    // Read the (bounded) response body. `ended` distinguishes a body that
    // completed (end-of-stream reached, or the cap) from one that stalled:
    // a read that times out mid-body must leave the response visibly
    // incomplete (`None`) rather than appearing as a full reply. A transport
    // error mid-body is a failed observation, already returned above.
    let mut bytes_read: u64 = 0;
    let mut ended = false;
    let mut snippet: Vec<u8> = Vec::with_capacity(BODY_SNIPPET_BYTES);
    loop {
        let chunk = match tokio::time::timeout(timeout, req_stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
            Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 body failed: {e}"))),
        };
        push_body_snippet(&mut snippet, chunk.chunk());
        bytes_read = bytes_read.saturating_add(chunk.remaining() as u64);
        if bytes_read >= MAX_BODY_BYTES {
            ended = true;
            break;
        }
    }

    let body_snippet = body_snippet_string(&snippet, (bytes_read as usize) > snippet.len());
    HttpObservation {
        tls: Some(quic_tls_summary(&quic_conn, destination, host)),
        status: Some(status),
        protocol: Some("HTTP/3".to_string()),
        location,
        headers,
        body_bytes: ended.then_some(bytes_read),
        body_snippet,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ttfb_ms,
        ..base
    }
}

/// Capture the (minimal) TLS/QUIC negotiated parameters for the observation.
fn quic_tls_summary(conn: &quinn::Connection, destination: SocketAddr, host: &str) -> TlsObservation {
    let alpn = conn
        .handshake_data()
        .and_then(|hd| hd.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hd| hd.protocol.clone())
        .map(|p| String::from_utf8_lossy(&p).into_owned());
    TlsObservation {
        destination,
        sni: host.to_string(),
        success: true,
        version: Some("TLSv1.3".to_string()),
        cipher: None,
        alpn,
        certificate: None,
        latency_ms: None,
        failure: None,
    }
}

const fn failure(kind: FailureKind, message: String) -> ProbeError {
    ProbeError { kind, message }
}
