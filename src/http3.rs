//! HTTP/3 / QUIC probing over the UDP path.
//!
//! A completely separate transport path: UDP + QUIC (TLS 1.3 inside) +
//! HTTP/3, via `quinn` and `h3`. Keeping this distinct from the TCP path makes
//! `TCP/HTTPS PASS / QUIC/HTTP3 FAIL` (and the reverse) observable.

use crate::http_common::{
    body_snippet_string, collect_response_headers, push_bounded_body, BODY_SNIPPET_BYTES, MAX_BODY_BYTES,
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
        MAX_BODY_BYTES,
        None,
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
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe`] with a configurable body-read cap and optional `--output-body`
/// capture.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/max/output
pub async fn probe_output(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
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
        max_body_bytes,
        output,
    )
    .await
}

/// [`probe_insecure`] with a configurable body-read cap and optional
/// `--output-body` capture.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/max/output
pub async fn probe_insecure_output(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
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
    max_body_bytes: u64,
    body_output: Option<&std::path::Path>,
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

    // QUIC handshake (UDP), bounded. The server name is bracket-stripped: a
    // bracketed IPv6-literal target (`Target::parse("[::1]", _)`) would
    // otherwise reach quinn's crypto layer as `ServerName::try_from("[::1]")`
    // → `InvalidServerName`, breaking HTTP/3 before any packet is sent.
    let connecting = match endpoint.connect(destination, crate::http_common::wire_host(host)) {
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

    // An explicit `host` header replaces the default in both the URI authority
    // (which drives h3's :authority) and the `host` header, instead of stacking
    // a second malformed Host on top of the default (RFC 7230 §5.4).
    let custom_host = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
        .map(|(_, v)| *v);
    let effective_host = custom_host.unwrap_or(host);
    // The URI authority is bracketed for an IPv6 literal (`https://[::1]/`),
    // while the `host` header value is bracket-stripped — so `:authority`
    // (driven by the URI) and `host` agree on the unbracketed form, matching
    // the h2 handling (RFC 9114 §4.3.1 requires them to match). Both name the
    // destination port when it is not 443, so host+port vhosting routes.
    let uri = format!(
        "https://{}{path}",
        crate::http_common::uri_authority_at(effective_host, destination.port())
    );
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "host",
            crate::http_common::wire_authority(effective_host, destination.port(), true),
        )
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
    // Finalize the request stream (FIN). A failure or a stall here means the
    // request side never completed — blame the request, not a later response
    // timeout (which would otherwise mislabel an un-flushable upload).
    match tokio::time::timeout(timeout, req_stream.finish()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            return base.with_failure(failure(FailureKind::Http, format!("http/3 request finish failed: {e}")))
        }
        Err(_) => {
            return base.with_failure(failure(
                FailureKind::Timeout,
                format!("http/3 request finish to {destination} timed out after {timeout:?}"),
            ))
        }
    }

    // TTFB: time from the request being sent to receiving the response
    // headers. The request stream resolves as soon as it is accepted — the
    // response head arrives separately via `recv_response` — so the clock must
    // start here, not around `send_request` (which would only measure request
    // enqueue and always report ~0).
    let ttfb_start = Instant::now();
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
    let ttfb_ms = Some(ttfb_start.elapsed().as_millis() as u64);

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
    let mut body_capped = false;
    let mut snippet: Vec<u8> = Vec::with_capacity(BODY_SNIPPET_BYTES);
    let mut full_body: Vec<u8> = Vec::new();
    // Whole-body-deadline: a slow-dripping body cannot stall past --timeout.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let chunk = match tokio::time::timeout_at(deadline, req_stream.recv_data()).await {
            Ok(Ok(Some(chunk))) => chunk,
            Ok(Ok(None)) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
            Ok(Err(e)) => return base.with_failure(failure(FailureKind::Http, format!("http/3 body failed: {e}"))),
        };
        let capped = push_bounded_body(
            &mut snippet,
            body_output.is_some().then_some(&mut full_body),
            &mut bytes_read,
            max_body_bytes,
            chunk.chunk(),
        );
        if capped {
            ended = true;
            body_capped = true;
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
        tls: Some(quic_tls_summary(&quic_conn, destination, host)),
        status: Some(status),
        protocol: Some("HTTP/3".to_string()),
        location,
        headers,
        body_bytes: ended.then_some(bytes_read),
        body_capped,
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
