//! HTTPS / HTTP/1.1 probing.
//!
//! Each probe connects TCP + TLS (with SNI = the target host) to one specific
//! destination socket address, then issues a single HTTP request over the
//! connection, unless `--plain` selects cleartext HTTP/1.1 (no TLS) for
//! internal / captive-portal / health-check endpoints. Redirection is *not*
//! followed by default: a redirect is recorded, not chased, so the raw server
//! behaviour is visible.

use crate::http_common::{
    body_snippet_string, build_tls_observation, collect_response_headers, http_error, push_bounded_body,
    BODY_SNIPPET_BYTES, MAX_BODY_BYTES,
};
use crate::model::http::HttpObservation;
use crate::model::{FailureKind, ProbeError, TlsObservation};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Perform a single HTTPS/HTTP/1.1 request to `destination` (connecting to
/// its IP) presenting `host` as SNI and `Host` header, bounded by `timeout`.
///
/// `method` is `GET`, `HEAD`, etc. `path` is the request target (e.g. `/`,
/// `/healthz`). Extra `headers` (each `name`, `value`) are sent verbatim;
/// the `user-agent` and `accept` defaults are always added. Failures are
/// captured in the observation.
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

/// Perform a single **cleartext** HTTP/1.1 request (no TLS handshake) to
/// `destination`, presenting `host` as the `Host` header.
///
/// For services that speak plain HTTP — internal endpoints, captive portals,
/// HTTP-only health checks, plaintext proxies — where a TLS probe would fail
/// with a handshake error instead of observing the real HTTP behaviour.
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout
pub async fn probe_plain(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> HttpObservation {
    plain_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        MAX_BODY_BYTES,
        None,
    )
    .await
}

/// [`probe_plain`] with a configurable body-read cap and optional
/// `--output-body` capture (mirrors [`probe_with_version_output`]).
#[allow(clippy::too_many_arguments)] // destination/host/method/path/headers/body/timeout/max/output
pub async fn probe_plain_output(
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
    plain_impl(
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        max_body_bytes,
        output,
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
///
/// `max_body_bytes` bounds the response-body read (and thus the `--output-body`
/// write); pass the crate constant `MAX_BODY_BYTES` (1 MiB) for the default.
/// `output` is `Some(path)` to persist the bounded body verbatim (so a WAF
/// block page, JS challenge, captive-portal prompt or API error is inspectable
/// without re-running in curl). The observation (status/snippet/size/latency)
/// is unchanged; only the body read cap and any body write differ.
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

/// Shared HTTPS probe body for the given trust mode.
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
    let base = HttpObservation {
        protocol: Some("HTTP/1.1".to_string()),
        ..HttpObservation::base(destination, host, method, path)
    };

    // 1. TLS handshake (HTTP/1.1 ALPN).
    let tls_obs;
    let conn = match crate::tls::connect_to(destination, host, crate::tls::ALPN_HTTP1, timeout, mode, protocol).await {
        Ok(c) => {
            tls_obs = build_tls_observation(&c, destination, host);
            c
        }
        Err(failure) => return base.with_failure(failure),
    };
    drive_http1(
        TokioIo::new(conn.stream),
        base,
        Some(tls_obs),
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        max_body_bytes,
        body_output,
        start,
    )
    .await
}

/// Shared cleartext HTTP/1.1 probe body: raw TCP, no TLS handshake.
#[allow(clippy::too_many_arguments)]
async fn plain_impl(
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    max_body_bytes: u64,
    body_output: Option<&std::path::Path>,
) -> HttpObservation {
    let start = Instant::now();
    let base = HttpObservation {
        protocol: Some("HTTP/1.1".to_string()),
        ..HttpObservation::base(destination, host, method, path)
    };

    // 1. Raw TCP connect (no TLS).
    let stream = match tokio::time::timeout(timeout, TcpStream::connect(destination)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return base.with_failure(ProbeError {
                kind: crate::tcp::classify_io_error(&e),
                message: format!("tcp connect to {destination} failed: {e}"),
            });
        }
        Err(_elapsed) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("tcp connect to {destination} timed out after {timeout:?}"),
            });
        }
    };

    drive_http1(
        TokioIo::new(stream),
        base,
        None,
        destination,
        host,
        method,
        path,
        headers,
        body,
        timeout,
        max_body_bytes,
        body_output,
        start,
    )
    .await
}

/// Drive one HTTP/1.1 request + bounded body read over an already-connected
/// stream (TLS-wrapped for HTTPS, a bare TCP stream for `--plain`). Handles
/// the hyper handshake, the request send, the response read and the bounded
/// body capture; `tls` is embedded into the observation for HTTPS and left
/// `None` for cleartext.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // hand-written sequential HTTP steps are clearest inline
async fn drive_http1<S>(
    io: TokioIo<S>,
    base: HttpObservation,
    tls: Option<TlsObservation>,
    destination: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
    max_body_bytes: u64,
    body_output: Option<&std::path::Path>,
    start: Instant,
) -> HttpObservation
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 2. Drive the hyper HTTP/1.1 connection.
    let handshake = hyper::client::conn::http1::handshake(io);
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

    // 3. Build and send the request. An explicit `host` header (e.g.
    // `--header 'host: vhost.example'` against a shared-IP virtual host)
    // replaces the default Host instead of stacking a second, RFC 7230 §5.4-
    // malformed Host on top of it. Both the override and the default are
    // bracket-stripped: a bracketed IPv6-literal target (`tls [::1]`) must
    // put the unbracketed `::1` on the wire (RFC 7230 §5.4 requires the host
    // without brackets).
    let mut custom_host: Option<&str> = None;
    let default_host = match headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("host")) {
        Some((_, v)) => {
            let v = crate::http_common::wire_host(v);
            custom_host = Some(v);
            v
        }
        None => crate::http_common::wire_host(host),
    };
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", default_host)
        .header("user-agent", "ip-tools")
        .header("accept", "*/*");
    for (name, value) in headers {
        if custom_host.is_none() || !name.eq_ignore_ascii_case("host") {
            builder = builder.header(*name, *value);
        }
    }
    // A request body is sent with an explicit content-length. When there is
    // no body (the default GET), keep the body-less `Empty` so nothing extra
    // (a `content-length: 0` / chunked terminator) is emitted on the wire.
    // Both are boxed to a shared `BoxBody` so the request type is uniform.
    if let Some(bytes) = body {
        builder = builder.header("content-length", bytes.len().to_string());
    }
    let request_body = body.map_or_else(
        || http_body_util::Empty::<bytes::Bytes>::new().boxed(),
        |bytes| http_body_util::Full::new(bytes::Bytes::copy_from_slice(bytes)).boxed(),
    );
    let request = match builder.body(request_body) {
        Ok(r) => r,
        Err(e) => {
            return base.with_failure(ProbeError {
                kind: FailureKind::Protocol,
                message: format!("could not build http request: {e}"),
            });
        }
    };

    // TTFB: time from sending the request to receiving the response headers.
    let ttfb_start = Instant::now();
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
    let ttfb_ms = Some(ttfb_start.elapsed().as_millis() as u64);

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
    let headers = collect_response_headers(response.headers());
    let mut body = response.into_body();
    let mut bytes_read: u64 = 0;
    let mut ended = false;
    let mut body_capped = false;
    let mut snippet: Vec<u8> = Vec::with_capacity(BODY_SNIPPET_BYTES);
    // When `--output-body` is requested, also retain the bounded full body so
    // it can be written verbatim to the file after the probe completes (the
    // snippet alone would force a re-run in curl to inspect a WAF page, a JS
    // challenge, a captive-portal prompt or an API error).
    let mut full_body: Vec<u8> = Vec::new();
    // The whole body read is one operation: deadline from the first byte so a
    // slow-dripping body (a fresh chunk every <timeout period) cannot stall the
    // probe past `--timeout` indefinitely — each read bounded by the same wall
    // clock, not a separately-reset per-frame timer.
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => return base.with_failure(http_error("HTTP/1.1 body", &e)),
            Ok(None) => {
                ended = true;
                break;
            }
            Err(_) => break, // body read timed out before completion
        };
        if let Ok(data) = frame.into_data() {
            let capped = push_bounded_body(
                &mut snippet,
                body_output.is_some().then_some(&mut full_body),
                &mut bytes_read,
                max_body_bytes,
                &data[..],
            );
            if capped {
                ended = true;
                body_capped = true;
                break;
            }
        }
    }
    let body_bytes = ended.then_some(bytes_read);
    let body_snippet = body_snippet_string(&snippet, (bytes_read as usize) > snippet.len());
    if let Some(path) = body_output {
        // Best effort: a write failure is reported on stderr but does not
        // turn a completed probe into a failure — the observation is valid.
        if let Err(e) = crate::http_common::write_body_to_file(path, &full_body) {
            eprintln!("Warning: could not write response body to {}: {e}", path.display());
        }
    }

    HttpObservation {
        tls,
        status: Some(status),
        protocol,
        location,
        headers,
        body_bytes,
        body_capped,
        body_snippet,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ttfb_ms,
        ..base
    }
}
