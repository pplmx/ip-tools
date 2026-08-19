//! HTTP/3 / QUIC probing over the UDP path.
//!
//! A completely separate transport path: UDP + QUIC (TLS 1.3 inside) +
//! HTTP/3, via `quinn` and `h3`. Keeping this distinct from the TCP path makes
//! `TCP/HTTPS PASS / QUIC/HTTP3 FAIL` (and the reverse) observable.

use crate::model::http::HttpObservation;
use crate::model::tls::TlsObservation;
use crate::model::{FailureKind, ProbeError};
use bytes::Buf;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Endpoint};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Cap on the response body read, to bound resource use.
const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// Build a QUIC client configuration verifying against `roots` and
/// advertising ALPN `h3`.
fn quic_client_config(roots: &rustls::RootCertStore) -> Result<QuinnClientConfig, String> {
    let mut rustls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    rustls_cfg.alpn_protocols = vec![b"h3".to_vec()];
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
pub async fn probe(destination: SocketAddr, host: &str, method: &str, timeout: Duration) -> HttpObservation {
    probe_with_roots(destination, host, method, timeout, &crate::tls::roots()).await
}

/// [`probe`] trusting an explicit root store, for verifying QUIC fixtures.
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

    let mut endpoint = match client_endpoint(destination) {
        Ok(e) => e,
        Err(msg) => return base.with_failure(failure(FailureKind::Other, msg)),
    };
    let config = match quic_client_config(roots) {
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

    let uri = format!("https://{host}/");
    let request = match hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*")
        .body(())
    {
        Ok(r) => r,
        Err(e) => return base.with_failure(failure(FailureKind::Protocol, format!("could not build request: {e}"))),
    };

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

    // Read the (bounded) response body.
    let mut bytes_read: u64 = 0;
    loop {
        let chunk = match tokio::time::timeout(timeout, req_stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) | Err(_) => break,
            Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 body failed: {e}"))),
        };
        bytes_read = bytes_read.saturating_add(chunk.remaining() as u64);
        if bytes_read >= MAX_BODY_BYTES {
            break;
        }
    }

    HttpObservation {
        tls: Some(quic_tls_summary(&quic_conn, destination, host)),
        status: Some(status),
        protocol: Some("HTTP/3".to_string()),
        location,
        body_bytes: Some(bytes_read),
        latency_ms: Some(start.elapsed().as_millis() as u64),
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
