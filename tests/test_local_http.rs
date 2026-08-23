//! Integration tests for the probe pipeline against a fully local TLS/HTTP
//! fixture (self-signed cert + HTTP/1.1, HTTP/2 and HTTP/3 servers).
//!
//! Deterministic: no external network. Enabled by
//! `cargo test --features test-server`.
#![cfg(feature = "test-server")]

use assert_cmd::Command;
use ip_tools::http;
use ip_tools::http2;
use ip_tools::http3;
use ip_tools::probe;
use ip_tools::tcp;
use ip_tools::test_support::FixtureServer;
use ip_tools::tls;
use std::net::SocketAddr;
use std::time::Duration;

const fn timeout() -> Duration {
    Duration::from_secs(5)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_probe_reaches_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = tcp::probe(fixture.tcp_addr(), timeout()).await;
    assert!(obs.success, "tcp probe to local fixture should succeed: {obs:?}");
    assert!(obs.latency_ms.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_probe_handshakes_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = tls::probe_with_roots(fixture.tcp_addr(), "localhost", timeout(), &fixture.roots).await;
    assert!(obs.success, "tls probe to local fixture should succeed: {obs:?}");
    assert_eq!(obs.version.as_deref(), Some("TLSv1.3"));
    // The self-signed fixture cert is generated with known SANs; the summary
    // must surface them so operators can see what the cert actually covers.
    let cert = obs.certificate.as_ref().expect("fixture presents a certificate");
    assert!(
        cert.sans.iter().any(|s| s == "localhost"),
        "expected localhost SAN on fixture cert: {cert:?}"
    );
    assert!(
        cert.sans.iter().any(|s| s == "127.0.0.1"),
        "expected 127.0.0.1 SAN on fixture cert: {cert:?}"
    );
    // A probe presented as `localhost` gets an end-to-end coverage verdict.
    assert!(
        ip_tools::report::render_tls(std::slice::from_ref(&obs)).contains("covers localhost: yes"),
        "fixture cert should be reported as covering the presented SNI"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_probe_forces_the_requested_protocol_version() {
    // The rustls fixture supports both TLS 1.2 and 1.3, so forcing each must
    // handshake and report the forced version — proving --tls-version actually
    // restricts the offered protocol set.
    let fixture = FixtureServer::start().await;

    let v13 =
        tls::probe_insecure_with_version(fixture.tcp_addr(), "localhost", timeout(), tls::TlsProtocol::Tls13).await;
    assert!(v13.success, "forced TLS 1.3 handshake should succeed: {v13:?}");
    assert_eq!(v13.version.as_deref(), Some("TLSv1.3"));

    let v12 =
        tls::probe_insecure_with_version(fixture.tcp_addr(), "localhost", timeout(), tls::TlsProtocol::Tls12).await;
    assert!(v12.success, "forced TLS 1.2 handshake should succeed: {v12:?}");
    assert_eq!(v12.version.as_deref(), Some("TLSv1.2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn http_and_http2_probes_force_tls_version() {
    let fixture = FixtureServer::start().await;
    // Forced TLS 1.3 against the fixture succeeds for both HTTP/1.1 and HTTP/2
    // (the rustls fixture supports 1.3) — proving --tls-version on these
    // commands actually restricts the offered protocol set.
    let h1 = http::probe_insecure_with_version(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        tls::TlsProtocol::Tls13,
    )
    .await;
    assert!(h1.failure.is_none(), "forced TLS 1.3 http1 probe failed: {h1:?}");
    assert_eq!(h1.status, Some(200));

    let h2 = http2::probe_insecure_with_version(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        tls::TlsProtocol::Tls13,
    )
    .await;
    assert!(h2.failure.is_none(), "forced TLS 1.3 http2 probe failed: {h2:?}");
    assert_eq!(h2.status, Some(200));
}

#[tokio::test(flavor = "multi_thread")]
async fn repeat_probes_force_tls_version() {
    // The `probe` (repeat) command's TLS-over-TCP protocols must honor
    // `--tls-version`: forcing TLS 1.3 against the fixture (which supports
    // 1.2 and 1.3) handshakes and succeeds over repeated tls/http/http2.
    let fixture = FixtureServer::start().await;
    let addr = fixture.tcp_addr();

    let tls_r = probe::tls_repeat_with_version(addr, "localhost", 3, timeout(), true, tls::TlsProtocol::Tls13).await;
    assert_eq!(tls_r.failures, 0, "forced TLS 1.3 repeated tls failed: {tls_r:?}");
    assert!(tls_r.success_rate > 0.0);

    let h1 = probe::http_repeat_with_version(
        addr,
        "localhost",
        "GET",
        "/",
        &[],
        None,
        3,
        timeout(),
        true,
        tls::TlsProtocol::Tls13,
    )
    .await;
    assert_eq!(h1.failures, 0, "forced TLS 1.3 repeated http failed: {h1:?}");

    let h2 = probe::http2_repeat_with_version(
        addr,
        "localhost",
        "GET",
        "/",
        &[],
        None,
        3,
        timeout(),
        true,
        tls::TlsProtocol::Tls13,
    )
    .await;
    assert_eq!(h2.failures, 0, "forced TLS 1.3 repeated http2 failed: {h2:?}");
}

#[test]
fn probe_cli_tls_version_forces_protocol() {
    // `probe --tls-version 1.3` over tls/http/http2 must succeed against the
    // local fixture — proving the flag threads through the repeat-probe CLI.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    for protocol in ["tls", "http", "http2"] {
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([
                "probe",
                &addr,
                "--protocol",
                protocol,
                "--count",
                "2",
                "--insecure",
                "--tls-version",
                "1.3",
                "--timeout",
                "2000",
            ])
            .output()
            .unwrap_or_else(|e| panic!("run probe --protocol {protocol} --tls-version 1.3: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "probe --protocol {protocol} --tls-version 1.3 should succeed: {stdout}
{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("success:  2"),
            "expected a 2/2 success row for {protocol}: {stdout}"
        );
    }
}

#[test]
fn http_cli_tls_version_forces_protocol() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    for cmd in ["http", "http2"] {
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([cmd, &addr, "--insecure", "--tls-version", "1.3", "--timeout", "2000"])
            .output()
            .unwrap_or_else(|e| panic!("run {cmd} --tls-version 1.3: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{cmd} --tls-version 1.3 should succeed: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("200"), "{cmd} forced TLS 1.3: {stdout}");
    }
}

#[test]
fn tls_cli_tls_version_forces_protocol() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["tls", &addr, "--insecure", "--tls-version", "1.3", "--timeout", "2000"])
        .output()
        .expect("run tls --tls-version 1.3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "tls --tls-version 1.3 should succeed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("TLSv1.3"), "expected TLSv1.3: {stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn http1_probe_gets_200_from_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = http::probe_with_roots(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(obs.failure.is_none(), "http1 probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/1.1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_probe_gets_200_from_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = http2::probe_with_roots(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(obs.failure.is_none(), "http2 probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/2"), "expected HTTP/2: {obs:?}");
    if let Some(tls) = &obs.tls {
        assert_eq!(tls.alpn.as_deref(), Some("h2"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_gets_200_from_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = http3::probe_with_roots(
        fixture.udp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(obs.failure.is_none(), "http3 probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200 over QUIC: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/3"), "expected HTTP/3: {obs:?}");
}

// --- TTFB (time-to-first-byte) ---------------------------------------------

/// Every HTTP-family probe must capture TTFB (request-send to response
/// headers): on success `ttfb_ms` is present and <= the total latency.
#[tokio::test(flavor = "multi_thread")]
async fn http_probes_capture_ttfb() {
    let fixture = FixtureServer::start().await;

    let h1 = http::probe_with_roots(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(h1.ttfb_ms.is_some(), "http1 must capture ttfb: {h1:?}");
    assert!(
        h1.ttfb_ms <= h1.latency_ms,
        "ttfb must not exceed total latency: {h1:?}"
    );

    let h2 = http2::probe_with_roots(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(h2.ttfb_ms.is_some(), "http2 must capture ttfb: {h2:?}");
    assert!(
        h2.ttfb_ms <= h2.latency_ms,
        "ttfb must not exceed total latency: {h2:?}"
    );

    let h3 = http3::probe_with_roots(
        fixture.udp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        &fixture.roots,
    )
    .await;
    assert!(h3.ttfb_ms.is_some(), "http3 must capture ttfb: {h3:?}");
    assert!(
        h3.ttfb_ms <= h3.latency_ms,
        "ttfb must not exceed total latency: {h3:?}"
    );
}

// --- request body sending (`--body`) ---------------------------------------

/// The `echo.invalid` route echoes the request body back. Probing it with a
/// body and asserting the echoed bytes appear in the response proves a request
/// body was sent on the wire on each protocol (h1/h2/h3).
#[tokio::test(flavor = "multi_thread")]
async fn http_probes_send_request_body_through_echo() {
    let fixture = FixtureServer::start().await;
    let marker = b"body-marker-7f3a";

    let h1 = http::probe_insecure(
        fixture.tcp_addr(),
        "echo.invalid",
        "POST",
        "/",
        &[],
        Some(marker),
        timeout(),
    )
    .await;
    assert!(h1.failure.is_none(), "h1 body probe: {h1:?}");
    assert!(
        h1.body_snippet.as_deref().unwrap_or("").contains("body-marker-7f3a"),
        "h1 must echo the request body: {h1:?}"
    );

    let h2 = http2::probe_insecure(
        fixture.tcp_addr(),
        "echo.invalid",
        "POST",
        "/",
        &[],
        Some(marker),
        timeout(),
    )
    .await;
    assert!(h2.failure.is_none(), "h2 body probe: {h2:?}");
    assert!(
        h2.body_snippet.as_deref().unwrap_or("").contains("body-marker-7f3a"),
        "h2 must echo the request body: {h2:?}"
    );

    let h3 = http3::probe_insecure(
        fixture.udp_addr(),
        "echo.invalid",
        "POST",
        "/",
        &[],
        Some(marker),
        timeout(),
    )
    .await;
    assert!(h3.failure.is_none(), "h3 body probe: {h3:?}");
    assert!(
        h3.body_snippet.as_deref().unwrap_or("").contains("body-marker-7f3a"),
        "h3 must echo the request body: {h3:?}"
    );
}

// --- --insecure (no certificate validation) ---------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn default_verification_rejects_self_signed_but_insecure_accepts() {
    let fixture = FixtureServer::start().await;

    // Against the self-signed fixture, system-roots verification must fail
    // with a certificate error...
    let rejected = tls::probe(fixture.tcp_addr(), "localhost", timeout()).await;
    assert!(
        !rejected.success,
        "system roots must reject the self-signed fixture: {rejected:?}"
    );
    assert!(
        rejected
            .failure
            .as_ref()
            .is_some_and(|e| matches!(e.kind, ip_tools::FailureKind::Certificate)),
        "expected a certificate failure: {rejected:?}"
    );

    // ...while the `--insecure` path skips validation and completes.
    let accepted = tls::probe_insecure(fixture.tcp_addr(), "localhost", timeout()).await;
    assert!(accepted.success, "insecure tls probe should succeed: {accepted:?}");
    assert_eq!(accepted.version.as_deref(), Some("TLSv1.3"));
}

#[tokio::test(flavor = "multi_thread")]
async fn http_probes_work_insecure_against_self_signed_fixture() {
    let fixture = FixtureServer::start().await;
    let h1 = http::probe_insecure(fixture.tcp_addr(), "localhost", "GET", "/", &[], None, timeout()).await;
    assert_eq!(h1.status, Some(200), "http1 insecure: {h1:?}");
    let h2 = http2::probe_insecure(fixture.tcp_addr(), "localhost", "GET", "/", &[], None, timeout()).await;
    assert_eq!(h2.status, Some(200), "http2 insecure: {h2:?}");
    assert_eq!(h2.protocol.as_deref(), Some("HTTP/2"));
    let h3 = http3::probe_insecure(fixture.udp_addr(), "localhost", "GET", "/", &[], None, timeout()).await;
    assert_eq!(h3.status, Some(200), "http3 insecure: {h3:?}");
    assert_eq!(h3.protocol.as_deref(), Some("HTTP/3"));
}

// --- redirect recording and the response-body cap -----------------------------
//
// The fixture routes by request host: `redirect.invalid` answers 302 with a
// `Location`, `big.invalid` streams `2 * 1 MiB` in 64 KiB chunks. The probes
// must *record* the redirect (never chase it) and *cap* the body at 1 MiB.
// `host` changes every round because the self-signed fixture certificate only
// covers `localhost`, so these paths exercise the `--insecure` variant.

const MAX_BODY_BYTES: u64 = 1024 * 1024;

#[tokio::test(flavor = "multi_thread")]
async fn http_probes_record_302_location_instead_of_following() {
    let fixture = FixtureServer::start().await;

    let h1 = http::probe_insecure(fixture.tcp_addr(), "redirect.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h1.failure.is_none(), "http1 redirect probe: {h1:?}");
    assert_eq!(h1.status, Some(302), "http1 must record the 302: {h1:?}");
    assert_eq!(
        h1.location.as_deref(),
        Some("https://redirect.invalid/landed"),
        "http1 must record the Location, not chase it: {h1:?}"
    );

    let h2 = http2::probe_insecure(fixture.tcp_addr(), "redirect.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h2.failure.is_none(), "http2 redirect probe: {h2:?}");
    assert_eq!(h2.status, Some(302), "http2 must record the 302: {h2:?}");
    assert_eq!(
        h2.location.as_deref(),
        Some("https://redirect.invalid/landed"),
        "http2 must record the Location, not chase it: {h2:?}"
    );

    let h3 = http3::probe_insecure(fixture.udp_addr(), "redirect.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h3.failure.is_none(), "http3 redirect probe: {h3:?}");
    assert_eq!(h3.status, Some(302), "http3 must record the 302: {h3:?}");
    assert_eq!(
        h3.location.as_deref(),
        Some("https://redirect.invalid/landed"),
        "http3 must record the Location, not chase it: {h3:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_probes_cap_oversized_response_bodies() {
    let fixture = FixtureServer::start().await;

    // Each probe must stop at the 1 MiB cap instead of buffering the whole
    // 2 MiB body.
    let h1 = http::probe_insecure(fixture.tcp_addr(), "big.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h1.failure.is_none(), "http1 big-body probe: {h1:?}");
    assert_eq!(h1.status, Some(200), "http1 big-body probe: {h1:?}");
    assert!(
        h1.body_bytes.is_some_and(|b| b < 2 * MAX_BODY_BYTES),
        "http1 must cap the body at {MAX_BODY_BYTES} bytes, got {h1:?}"
    );

    let h2 = http2::probe_insecure(fixture.tcp_addr(), "big.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h2.failure.is_none(), "http2 big-body probe: {h2:?}");
    assert_eq!(h2.status, Some(200), "http2 big-body probe: {h2:?}");
    assert!(
        h2.body_bytes.is_some_and(|b| b < 2 * MAX_BODY_BYTES),
        "http2 must cap the body at {MAX_BODY_BYTES} bytes, got {h2:?}"
    );

    let h3 = http3::probe_insecure(fixture.udp_addr(), "big.invalid", "GET", "/", &[], None, timeout()).await;
    assert!(h3.failure.is_none(), "http3 big-body probe: {h3:?}");
    assert_eq!(h3.status, Some(200), "http3 big-body probe: {h3:?}");
    assert!(
        h3.body_bytes.is_some_and(|b| b < 2 * MAX_BODY_BYTES),
        "http3 must cap the body at {MAX_BODY_BYTES} bytes, got {h3:?}"
    );
}

/// The body must still be observable (non-zero) when a real body is served —
/// guards against the cap truncating everything or the fixture being bypassed.
#[tokio::test(flavor = "multi_thread")]
async fn http3_capped_body_is_still_sized() {
    let fixture = FixtureServer::start().await;
    let h3 = http3::probe_insecure(fixture.udp_addr(), "big.invalid", "GET", "/", &[], None, timeout()).await;
    let bytes = h3.body_bytes.expect("http3 body bytes present");
    assert!(
        bytes > MAX_BODY_BYTES - 128 * 1024,
        "http3 should read at least ~1 MiB before stopping, got {bytes}"
    );
}

/// A server that sends headers + a partial body and then stalls must surface
/// as an *incomplete* response (`body_bytes: None`, but headers received) on
/// every protocol — not as a clean partial-body success. All three readers
/// agree on the body-completion semantics.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_body_reports_incomplete_for_all_protocols() {
    let fixture = FixtureServer::start().await;
    let stall = Duration::from_secs(2);

    let h1 = http::probe_insecure(fixture.tcp_addr(), "stall.invalid", "GET", "/", &[], None, stall).await;
    assert_eq!(h1.status, Some(200), "http1 headers received: {h1:?}");
    assert!(
        h1.failure.is_none(),
        "headers received is not a transport failure: {h1:?}"
    );
    assert_eq!(
        h1.body_bytes, None,
        "http1 must report a stalled body as incomplete: {h1:?}"
    );

    let h2 = http2::probe_insecure(fixture.tcp_addr(), "stall.invalid", "GET", "/", &[], None, stall).await;
    assert_eq!(h2.status, Some(200), "http2 headers received: {h2:?}");
    assert!(
        h2.failure.is_none(),
        "headers received is not a transport failure: {h2:?}"
    );
    assert_eq!(
        h2.body_bytes, None,
        "http2 must report a stalled body as incomplete: {h2:?}"
    );

    let h3 = http3::probe_insecure(fixture.udp_addr(), "stall.invalid", "GET", "/", &[], None, stall).await;
    assert_eq!(h3.status, Some(200), "http3 headers received: {h3:?}");
    assert!(
        h3.failure.is_none(),
        "headers received is not a transport failure: {h3:?}"
    );
    assert_eq!(
        h3.body_bytes, None,
        "http3 must report a stalled body as incomplete: {h3:?}"
    );
}

/// A server that accepts the HTTP/3 request (QUIC + h3 control path works)
/// but never sends a response — a hung server. The probe's response wait must
/// hit its wall-clock bound and fail cleanly, never hang or report success.
#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_times_out_when_server_never_responds() {
    let fixture = FixtureServer::start().await;
    let obs = http3::probe_insecure(
        fixture.udp_addr(),
        "quiesce.invalid",
        "GET",
        "/",
        &[],
        None,
        Duration::from_millis(600),
    )
    .await;
    assert!(
        obs.failure.is_some() && obs.status.is_none(),
        "a hung h3 server must not report success: {obs:?}"
    );
    assert_eq!(
        obs.failure.as_ref().expect("failure").kind,
        ip_tools::FailureKind::Timeout,
        "expected a clean Timeout, got {obs:?}"
    );
}

/// A QUIC endpoint that completes the handshake but never establishes the h3
/// layer: the probe's h3 setup must time out cleanly (never hang, never
/// report success).
#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_times_out_when_quic_handshake_never_reaches_h3() {
    let fixture = FixtureServer::start().await;
    let obs = http3::probe_with_roots(
        fixture.stalled_quic_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        Duration::from_millis(600),
        &fixture.roots,
    )
    .await;
    assert!(
        obs.failure.is_some() && obs.status.is_none(),
        "an h3-less QUIC server must not report success: {obs:?}"
    );
    assert_eq!(
        obs.failure.as_ref().expect("failure").kind,
        ip_tools::FailureKind::Timeout,
        "expected a clean Timeout, got {obs:?}"
    );
    // A failed h3 probe must keep its protocol identity so the QUIC
    // diagnostics and the report can see it as HTTP/3.
    assert_eq!(
        obs.protocol.as_deref(),
        Some("HTTP/3"),
        "failed h3 probe must retain its protocol: {obs:?}"
    );
}

// --- repeated HTTP probing (probe --protocol) ---------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn http_repeat_against_fixture_aggregates_all_protocols() {
    let fixture = FixtureServer::start().await;
    let c = 3usize;
    let h1 = probe::http_repeat(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        c,
        timeout(),
        true,
    )
    .await;
    assert_eq!(h1.successes, c, "http1 repeat should be all-success: {h1:?}");
    let h2 = probe::http2_repeat(
        fixture.tcp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        c,
        timeout(),
        true,
    )
    .await;
    assert_eq!(h2.successes, c, "http2 repeat should be all-success: {h2:?}");
    let h3 = probe::http3_repeat(
        fixture.udp_addr(),
        "localhost",
        "GET",
        "/",
        &[],
        None,
        c,
        timeout(),
        true,
    )
    .await;
    assert_eq!(h3.successes, c, "http3 repeat should be all-success: {h3:?}");
    assert_eq!(h3.latency.count, c, "http3 repeat should yield latency samples");
    assert!(h3.failure_counts.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_repeat_against_fixture_aggregates_handshake_latency() {
    let fixture = FixtureServer::start().await;
    let c = 3usize;
    let t = probe::tls_repeat(fixture.tcp_addr(), "localhost", c, timeout(), true).await;
    assert_eq!(t.successes, c, "tls repeat should be all-success: {t:?}");
    assert_eq!(t.latency.count, c, "tls repeat should yield latency samples");
    assert!(t.failure_counts.is_empty(), "no failures expected: {t:?}");
    // Without --insecure, the self-signed fixture must fail every handshake
    // and count as failures (a classified handshake/certificate failure),
    // never a silent success.
    let strict = probe::tls_repeat(fixture.tcp_addr(), "localhost", c, timeout(), false).await;
    assert_eq!(
        strict.successes, 0,
        "self-signed fixture must fail hardened: {strict:?}"
    );
    assert_eq!(strict.failures, c, "every handshake should be a failure: {strict:?}");
}

// --- HTTP/3 error paths (QUIC handshake/black-hole UDP) ---------------------

#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_times_out_against_silent_udp_socket() {
    // A bound-but-silent UDP socket accepts the QUIC client's packets and
    // never answers: the handshake must time out (our wall-clock bound), not
    // hang forever or report success.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent udp");
    let addr = sock.local_addr().expect("silent udp addr");

    let obs = http3::probe(addr, "localhost", "GET", "/", &[], None, Duration::from_millis(600)).await;
    assert!(obs.failure.is_some(), "silent UDP must not report success: {obs:?}");
    let failure = obs.failure.as_ref().expect("expected a timeout failure");
    assert_eq!(
        failure.kind,
        ip_tools::FailureKind::Timeout,
        "unexpected kind: {failure:?}"
    );
    assert_eq!(
        obs.protocol.as_deref(),
        Some("HTTP/3"),
        "failed h3 probe must retain its protocol: {obs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_fails_against_closed_udp_port() {
    // Nothing bound on the port (bound then dropped): the OS may surface an
    // ICMP port-unreachable immediately, or the probe times out. Either way it
    // must be a failure, never a success.
    let port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe port");
        s.local_addr().expect("probe port addr").port()
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let obs = http3::probe(addr, "localhost", "GET", "/", &[], None, Duration::from_millis(800)).await;
    assert_eq!(
        obs.protocol.as_deref(),
        Some("HTTP/3"),
        "failed h3 probe must retain its protocol: {obs:?}"
    );
    assert!(
        obs.failure.is_some(),
        "closed UDP port must not report success: {obs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_and_http_probe_time_out_when_server_never_responds() {
    // A TCP listener that accepts connections but never sends TLS bytes: the
    // handshake must hit our wall-clock bound (Timeout), not hang or succeed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let held = tokio::spawn(async move {
        // Hold every accepted stream open (a dropped stream would send EOF/RST
        // and the client would fail fast with a handshake error, not timeout).
        // `forget` leaks the fd purposely: it stays open, unread, for the rest
        // of the test process.
        while let Ok((stream, _peer)) = listener.accept().await {
            std::mem::forget(stream);
        }
    });

    let obs = tls::probe(addr, "localhost", Duration::from_millis(500)).await;
    assert!(!obs.success, "black-holed TLS must not succeed: {obs:?}");
    assert_eq!(
        obs.failure.as_ref().map(|f| f.kind),
        Some(ip_tools::FailureKind::Timeout),
        "expected a TLS handshake timeout: {obs:?}"
    );

    let obs = http::probe(addr, "localhost", "GET", "/", &[], None, Duration::from_millis(500)).await;
    assert_eq!(
        obs.failure.as_ref().map(|f| f.kind),
        Some(ip_tools::FailureKind::Timeout),
        "expected an HTTP handshake timeout: {obs:?}"
    );

    held.abort();
}

#[test]
fn dns_cli_queries_doh_fixture_endpoint() {
    // End-to-end DNS-over-HTTPS: `dns --doh <fixture>/dns-query --insecure`
    // must GET the endpoint (which the fixture serves with a canned RFC 8484
    // response) and surface the A and AAAA records it answered, labeled by
    // the endpoint URL.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "host.example",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --doh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --doh should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("192.0.2.77"), "DoH A record missing: {stdout}");
    assert!(stdout.contains("2001:db8::77"), "DoH AAAA record missing: {stdout}");
    assert!(
        stdout.contains(&endpoint),
        "DoH endpoint should be labeled in output: {stdout}"
    );
}

#[test]
fn output_body_respects_raised_max_body_bytes() {
    // With the default 1 MiB cap, --output-body writes only ~1 MiB of the
    // fixture's 2 MiB big.invalid body; raising --max-body-bytes captures the
    // full 2 MiB. This proves the cap is configurable and the write honors it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let dir = std::env::temp_dir();
    let p_default = dir.join(format!("ip-tools-max-default-{}.bin", std::process::id()));
    let p_raised = dir.join(format!("ip-tools-max-raised-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&p_default);
    let _ = std::fs::remove_file(&p_raised);

    // Default cap: the written body is ~1 MiB (truncated).
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--insecure",
            "--sni",
            "big.invalid",
            "--output-body",
            p_default.to_str().unwrap(),
            "--timeout",
            "3000",
        ])
        .output()
        .expect("run http big.invalid default cap");
    assert!(
        out.status.success(),
        "http big.invalid default cap should exit 0: {}
{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let def_len = std::fs::metadata(&p_default)
        .map(|m| m.len())
        .expect("default body file");
    assert!(
        ((1024 * 1024)..2 * 1024 * 1024).contains(&def_len),
        "default cap should write ~1 MiB (truncated), got {def_len}"
    );

    // Raised cap: full 2 MiB is written.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--insecure",
            "--sni",
            "big.invalid",
            "--output-body",
            p_raised.to_str().unwrap(),
            "--max-body-bytes",
            "3000000",
            "--timeout",
            "4000",
        ])
        .output()
        .expect("run http big.invalid raised cap");
    assert!(
        out.status.success(),
        "http big.invalid raised cap should exit 0: {}
{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let raised_len = std::fs::metadata(&p_raised).map(|m| m.len()).expect("raised body file");
    assert_eq!(
        raised_len,
        2 * 1024 * 1024,
        "raised cap should write the full 2 MiB body"
    );

    let _ = std::fs::remove_file(&p_default);
    let _ = std::fs::remove_file(&p_raised);
}

#[test]
fn diagnose_max_body_bytes_bounds_http_phase() {
    // diagnose's HTTP phase runs the same http/http2/http3 probes as the
    // single-shot commands, so --max-body-bytes must bound the response-body
    // read there too: against the fixture's 2 MiB big.invalid route, the
    // default 1 MiB cap yields a truncated ~1 MiB body_bytes, while a raised
    // cap captures the full 2 MiB. Parse the HTTP evidence from the JSON.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let run = |max: Option<&str>| {
        let mut args = vec![
            "diagnose".to_string(),
            addr.clone(),
            "--insecure".to_string(),
            "--sni".to_string(),
            "big.invalid".to_string(),
            "--timeout".to_string(),
            "4000".to_string(),
            "--json".to_string(),
        ];
        if let Some(m) = max {
            args.push("--max-body-bytes".to_string());
            args.push(m.to_string());
        }
        Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("run diagnose big.invalid: {e}"))
    };

    let out = run(None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose big.invalid default cap should exit 0: {stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("body_bytes"),
        "default diagnose JSON must carry http body_bytes: {stdout}"
    );
    // Default 1 MiB cap: the served 2 MiB body is truncated to under 2 MiB
    // (chunked reads stop once past the cap, so not exactly 1 MiB).
    let default_bytes: Option<u64> = parse_body_bytes(&stdout);
    let default_bytes = default_bytes.expect("default body_bytes present");
    assert!(
        ((1024 * 1024)..2 * 1024 * 1024).contains(&default_bytes),
        "default cap should bound the body under 2 MiB, got {default_bytes}"
    );

    let out = run(Some("3000000"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose big.invalid raised cap should exit 0: {stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let raised_bytes = parse_body_bytes(&stdout).expect("raised body_bytes present");
    assert_eq!(
        raised_bytes,
        2 * 1024 * 1024,
        "raised cap should yield the full 2 MiB body_bytes: {stdout}"
    );
}

/// Extract the first top-level http `body_bytes` value from a diagnose JSON
/// string (the diagnose report is an object with an `http` array of
/// observations).
fn parse_body_bytes(json: &str) -> Option<u64> {
    // Find the first occurrence of "body_bytes" and read its numeric value.
    let needle = r#""body_bytes":"#;
    let idx = json.find(needle)?;
    let rest = &json[idx + needle.len()..];
    let trimmed = rest.trim_start();
    let num: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
    num.parse().ok()
}

#[test]
fn probe_command_resolves_through_doh_fixture_endpoint() {
    // The per-address probe commands must resolve the target through the
    // encrypted `--doh`/`--dot` resolvers (parity with `dns`/`diagnose`). The
    // fixture's canned DoH answer resolves `host.example` to the TEST-NET
    // 192.0.2.77 (A) / 2001:db8::77 (AAAA) — unroutable, so the probe cannot
    // connect, but the run must probe that DoH-resolved address rather than
    // report "did not resolve". The fixture cert is self-signed, so `probe`
    // (which has `--insecure`) skips cert validation of the DoH endpoint.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let doh = format!("https://{}/dns-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            "host.example",
            "--doh",
            &doh,
            "--insecure",
            "--count",
            "1",
            "--timeout",
            "800",
        ])
        .output()
        .expect("run probe --doh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("did not resolve") && !stderr.contains("did not resolve"),
        "probe --doh must resolve via DoH, not fail to resolve: {stdout}
{stderr}"
    );
    assert!(
        stdout.contains("192.0.2.77") || stderr.contains("192.0.2.77"),
        "probe --doh must probe the DoH-resolved A record: {stdout}
{stderr}"
    );
}

#[test]
fn probe_command_resolves_through_dot_fixture_endpoint() {
    // DNS-over-TLS resolution on a probe command: the fixture's raw DoT
    // listener answers `host.example` with the same canned A record, which
    // must become the probed destination (not an unresolved error).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let dot = fixture.dot_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            "host.example",
            "--dot",
            &dot,
            "--insecure",
            "--count",
            "1",
            "--timeout",
            "800",
        ])
        .output()
        .expect("run probe --dot");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("did not resolve") && !stderr.contains("did not resolve"),
        "probe --dot must resolve via DoT, not fail: {stdout}
{stderr}"
    );
    assert!(
        stdout.contains("192.0.2.77") || stderr.contains("192.0.2.77"),
        "probe --dot must probe the DoT-resolved A record: {stdout}
{stderr}"
    );
}

#[test]
fn dns_cli_doh_reports_error_from_a_non_dns_endpoint() {
    // A 200 response that is not a DNS message (the fixture's plain route)
    // must surface as a DoH error observation, not an empty success.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "host.example",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --doh against a non-DNS endpoint");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --doh should still exit 0 (an error is an observation): {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("invalid response"),
        "expected a DoH parse-error observation: {stdout}"
    );
}

#[test]
fn dns_cli_queries_dot_fixture_endpoint() {
    // End-to-end DNS-over-TLS (RFC 7858): `dns --dot <addr> --insecure` must
    // open a TLS connection to the fixture's raw DoT listener, send the
    // 2-byte-length-prefixed query, read the canned response, and surface the
    // A and AAAA records labeled with the DoT endpoint.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = fixture.dot_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "host.example",
            "--dot",
            &endpoint,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --dot");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --dot should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("192.0.2.77"), "DoT A record missing: {stdout}");
    assert!(stdout.contains("2001:db8::77"), "DoT AAAA record missing: {stdout}");
    assert!(
        stdout.contains(&format!("{endpoint} (DoT)")),
        "DoT endpoint should be labeled in output: {stdout}"
    );
}

#[test]
fn dns_cli_dot_repeat_aggregates() {
    // `dns --dot <addr> --count N` must loop the DoT query N times and render
    // the aggregated view (latency + success) rather than a single row.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = fixture.dot_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "host.example",
            "--dot",
            &endpoint,
            "--insecure",
            "--count",
            "3",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --dot --count");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --dot --count should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("{endpoint} (DoT)")) && stdout.contains("100.0%"),
        "expected a DoT repeat row with 100.0% success: {stdout}"
    );
}

#[test]
fn dns_cli_multiple_targets_render_each_and_emit_json_array() {
    // `dns` accepts multiple targets (a DNS health sweep). IP literals
    // short-circuit resolution deterministically (no network): each renders
    // its own report, and `--json` with >1 target emits a per-target array.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "1.1.1.1", "8.8.8.8"])
        .output()
        .expect("run dns with two targets");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target dns should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("DNS 1.1.1.1") && stdout.contains("DNS 8.8.8.8"),
        "each target's report must render: {stdout}"
    );

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "1.1.1.1", "8.8.8.8", "--json"])
        .output()
        .expect("run multi-target dns --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target dns --json should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("dns --json must parse");
    let reports = parsed.as_array().expect(">1 target must yield a JSON array");
    assert_eq!(reports.len(), 2, "expected 2 reports: {stdout}");
    let targets: Vec<&str> = reports
        .iter()
        .filter_map(|r| r.get("target").and_then(serde_json::Value::as_str))
        .collect();
    assert!(targets.contains(&"1.1.1.1"), "report for 1.1.1.1 missing: {targets:?}");
    assert!(targets.contains(&"8.8.8.8"), "report for 8.8.8.8 missing: {targets:?}");
}

#[test]
fn dns_cli_concurrency_parallelizes_and_preserves_target_order() {
    // `dns --concurrency N` parallelizes a multi-target DNS health sweep, but
    // must still render targets in input order (deterministic human/JSON/CSV).
    // IP literals short-circuit resolution, so they complete fast and any
    // reordering bug would show in the JSON array.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "1.1.1.1", "8.8.8.8", "--concurrency", "2", "--json"])
        .output()
        .expect("run dns --concurrency 2 --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --concurrency should exit 0: {stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("dns --json must parse");
    let reports = parsed.as_array().expect(">1 target must yield a JSON array");
    assert_eq!(reports.len(), 2, "expected 2 reports: {stdout}");
    let targets: Vec<&str> = reports
        .iter()
        .filter_map(|r| r.get("target").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(
        targets,
        vec!["1.1.1.1", "8.8.8.8"],
        "concurrent dns must preserve input target order: {targets:?}"
    );

    // `--concurrency 0` must clamp to a safe minimum (not deadlock/divide), the
    // same way the probe commands bound concurrency.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "1.1.1.1", "8.8.8.8", "--concurrency", "0", "--json"])
        .output()
        .expect("run dns --concurrency 0");
    assert!(
        out.status.success(),
        "dns --concurrency 0 should clamp and succeed: {}
{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn dns_cli_csv_export_renders_rows() {
    // `dns --csv` emits a header + one row per (host,resolver,record_type)
    // across every target, so a DNS health sweep loads into a spreadsheet.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "1.1.1.1", "8.8.8.8", "--csv"])
        .output()
        .expect("run multi-target dns --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target dns --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures"),
        "CSV header: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("1.1.1.1,system,A,1,1.0000")),
        "expected an A row for 1.1.1.1: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("8.8.8.8,")),
        "expected rows for 8.8.8.8: {stdout}"
    );
}

#[test]
fn tcp_cli_multiple_targets_produce_per_target_array() {
    // The per-address probe commands (`tcp`, etc.) accept multiple targets
    // too: each is resolved and probed, human output labels each host block,
    // and `--json` emits a per-target array.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr1 = fixture.tcp_addr().to_string();
    let addr2 = "127.0.0.2:443".to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["tcp", &addr1, &addr2, "--timeout", "1000"])
        .output()
        .expect("run tcp with two targets");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target tcp should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("127.0.0.1:") && stdout.contains("127.0.0.2:"),
        "each target block must be labeled: {stdout}"
    );

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["tcp", &addr1, &addr2, "--json", "--timeout", "1000"])
        .output()
        .expect("run multi-target tcp --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target tcp --json should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("tcp --json must parse");
    let reports = parsed.as_array().expect(">1 target must yield a JSON array");
    assert_eq!(reports.len(), 2, "expected 2 reports: {stdout}");
    let targets: Vec<&str> = reports
        .iter()
        .filter_map(|r| r.get("target").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        targets.contains(&"127.0.0.1"),
        "report for 127.0.0.1 missing: {targets:?}"
    );
    assert!(
        targets.contains(&"127.0.0.2"),
        "report for 127.0.0.2 missing: {targets:?}"
    );
}

#[test]
fn diagnose_cli_includes_doh_resolver_evidence() {
    // `diagnose --doh` must fold the DoH answers into the DNS observations
    // (visible in the evidence stack) and probe the DoH-resolved address.
    // The fixture's DoH answer is 192.0.2.77 (TEST-NET, unroutable), so the
    // probes fail cleanly while the diagnosis still renders.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            "host.example",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "500",
        ])
        .output()
        .expect("run diagnose --doh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --doh should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("192.0.2.77"),
        "DoH-resolved record missing from evidence: {stdout}"
    );
    assert!(stdout.contains("Diagnosis"), "diagnoses missing: {stdout}");
}

#[test]
fn diagnose_cli_tls_version_forces_protocol() {
    // `diagnose --tls-version 1.3` scopes the whole pipeline (TLS + http1 +
    // http2 phases) to a forced protocol version against the local fixture —
    // proving the flag threads through the full diagnostic pipeline. (http3
    // is QUIC/TLS 1.3 only and deliberately unaffected.)
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr,
            "--insecure",
            "--tls-version",
            "1.3",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run diagnose --tls-version 1.3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --tls-version 1.3 should exit 0: {stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("TLSv1.3"),
        "expected a forced TLSv1.3 row in the diagnose output: {stdout}"
    );
    assert!(stdout.contains("HTTPS"), "HTTP evidence missing: {stdout}");
}

#[test]
fn diagnose_cli_includes_dot_resolver_evidence() {
    // `diagnose --dot` must fold the DoT answers into the DNS observations
    // (visible in the evidence stack) and probe the DoT-resolved address.
    // The fixture's DoT answer is 192.0.2.77 (TEST-NET, unroutable), so the
    // probes fail cleanly while the diagnosis still renders.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = fixture.dot_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            "host.example",
            "--dot",
            &endpoint,
            "--insecure",
            "--timeout",
            "500",
        ])
        .output()
        .expect("run diagnose --dot");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --dot should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("192.0.2.77"),
        "DoT-resolved record missing from evidence: {stdout}"
    );
    assert!(stdout.contains("Diagnosis"), "diagnoses missing: {stdout}");
}

#[test]
fn probe_cli_http2_repeats_fixture_via_protocol_flag() {
    // End-to-end: `probe --protocol http2 --insecure` repeats HTTP/2 against
    // the self-signed fixture and aggregates 3 successes.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &addr,
            "--protocol",
            "http2",
            "--count",
            "3",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol http2");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe --protocol http2 should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Repeated probes"),
        "repeated-probe heading missing: {stdout}"
    );
    assert!(stdout.contains("success:  3"), "expected 3 successes: {stdout}");
}

#[test]
fn probe_cli_csv_export_renders_rows() {
    // `probe --csv` emits a header + one row per destination carrying the
    // aggregated `--count` latency/failure stats, so a connectivity-health
    // sweep loads into a spreadsheet.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["probe", &addr, "--count", "3", "--csv", "--timeout", "2000"])
        .output()
        .expect("run probe --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("host,destination,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,jitter_ms,failures"),
        "CSV header: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains(&format!("{addr},3,1.0000,"))),
        "expected a 3/3 success row for {addr}: {stdout}"
    );
}

#[test]
fn http_cli_report_shows_certificate_and_covers_verdict() {
    // The HTTPS human report must surface the serving certificate and the
    // SAN-coverage verdict (parity with `tls`), not just TLS/ALPN. Against the
    // fixture (whose self-signed cert covers localhost/127.0.0.1) an `http`
    // probe presented as `localhost` must show `covers localhost: yes`.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http", &addr, "--sni", "localhost", "--insecure", "--timeout", "2000"])
        .output()
        .expect("run http --sni localhost");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --sni localhost should exit 0: {stdout}
{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("cert : "),
        "http report must show the certificate row: {stdout}"
    );
    assert!(
        stdout.contains("covers localhost: yes"),
        "http report must show the SAN-coverage verdict: {stdout}"
    );
}

#[test]
fn http_cli_csv_export_renders_status_rows() {
    // `http --csv` (and http2/http3) emit a header + one row per destination
    // with the response status/protocol — an HTTP fleet sweep loads into a
    // spreadsheet.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http", &addr, "--insecure", "--csv", "--timeout", "2000"])
        .output()
        .expect("run http --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some(
            "host,destination,protocol,status,location,body_bytes,ttfb_ms,latency_ms,sni,version,cipher,alpn,subject,issuer,not_after_utc,failure"
        ),
        "CSV header: {stdout}"
    );
    assert!(
        lines.any(|l| l.starts_with("127.0.0.1,") && l.contains(",200,")),
        "expected a row with status 200: {stdout}"
    );
}

#[test]
fn http_cli_csv_exposes_negotiated_tls_details() {
    // The HTTPS probes embed the negotiated TLS handshake in each observation,
    // so the HTTP CSV must surface it (version/cipher/ALPN/cert, mirroring
    // `tls --csv`) — an HTTPS fleet sweep shouldn't lose that evidence.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    for cmd in ["http", "http2", "http3"] {
        let dest = if cmd == "http3" {
            fixture.udp_addr().to_string()
        } else {
            addr.clone()
        };
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([cmd, &dest, "--insecure", "--csv", "--timeout", "2000"])
            .output()
            .unwrap_or_else(|e| panic!("run {cmd} --csv: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{cmd} --csv should exit 0: {stdout}
{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("version,cipher,alpn,subject,issuer,not_after_utc"),
            "{cmd} --csv must carry the TLS header: {stdout}"
        );
        // The fixture negotiates TLS with a populated cipher and a cert whose
        // subject names the fixture — assert the negotiated row carries them.
        assert!(
            stdout.contains(",TLSv1.3,") || stdout.contains(",TLSv1.2,"),
            "{cmd} --csv must expose the negotiated TLS version: {stdout}"
        );
        // HTTP/1.1 and HTTP/2 carry the full certificate summary in their
        // embedded observation; HTTP/3's QUIC summary is minimal (version +
        // ALPN only), so only the TCP-based probes must expose the subject.
        if cmd != "http3" {
            assert!(
                stdout.contains("subject=") || stdout.contains("CN="),
                "{cmd} --csv must expose the certificate subject: {stdout}"
            );
        }
    }
}

#[test]
fn http_cli_insecure_probes_self_signed_fixture() {
    // End-to-end: the real binary with --insecure must talk to the self-signed
    // fixture over HTTP/2 (http2 tcp listener) without a certificate error.
    // A multi-thread runtime keeps the fixture's server tasks polled while the
    // subprocess runs on this (main) thread.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http2", &addr.to_string(), "--insecure", "--timeout", "2000"])
        .output()
        .expect("run http2 --insecure");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http2 --insecure should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("200"), "expected a 200 response: {stdout}");
    assert!(stdout.contains("HTTP/2"), "expected HTTP/2: {stdout}");

    // The same command without --insecure must fail against the self-signed
    // fixture (proving the flag actually controls validation).
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http2", &addr.to_string(), "--timeout", "2000"])
        .output()
        .expect("run http2 without --insecure");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("certificate") || stdout.contains("failed") || !out.status.success(),
        "without --insecure the self-signed cert must be rejected: {stdout}"
    );
}

#[test]
fn http_cli_includes_body_content_snippet() {
    // The fixture's ordinary route serves a 2-byte body ("ok"). The CLI report
    // must surface that content (human `body content:` line) and the JSON
    // observation must carry the `body_snippet` field.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http2", &addr, "--insecure", "--timeout", "2000"])
        .output()
        .expect("run http2 --insecure");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http2 --insecure should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("body content: ok"),
        "small body snippet must be captured: {stdout}"
    );

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http2", &addr, "--insecure", "--json", "--timeout", "2000"])
        .output()
        .expect("run http2 --insecure --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"body_snippet\": \"ok\""),
        "json must carry the body snippet: {stdout}"
    );
}

#[test]
fn http_output_body_writes_full_body_to_file() {
    // `--output-body FILE` must persist the actual response body verbatim (not
    // just the 1 KiB snippet) for the http/http2/http3 probes, so a WAF page /
    // API error body is inspectable without a re-run in curl. The fixture's
    // ordinary route serves a small "ok" body.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    for (cmd, dest_addr) in [
        ("http", fixture.tcp_addr().to_string()),
        ("http2", fixture.tcp_addr().to_string()),
        ("http3", fixture.udp_addr().to_string()),
    ] {
        let dir = std::env::temp_dir();
        let out_path = dir.join(format!("ip-tools-output-body-{cmd}-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&out_path);
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([
                cmd,
                &dest_addr,
                "--insecure",
                "--output-body",
                out_path.to_str().unwrap(),
                "--timeout",
                "2000",
            ])
            .output()
            .unwrap_or_else(|e| panic!("run {cmd} --output-body: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{cmd} --output-body should exit 0: {stdout}
{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let written = std::fs::read_to_string(&out_path)
            .unwrap_or_else(|e| panic!("read {cmd} output body file {out_path:?}: {e}"));
        assert_eq!(written, "ok", "{cmd} must write the full body verbatim to the file");
        let _ = std::fs::remove_file(&out_path);
    }
}

#[test]
fn http_cli_truncates_large_body_snippet() {
    // `big.invalid` streams 2 MiB of 'x'. The captured snippet must be capped
    // at BODY_SNIPPET_BYTES and carry the explicit truncation marker.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http", &addr, "--sni", "big.invalid", "--insecure", "--timeout", "2000"])
        .output()
        .expect("run http --sni big.invalid");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http big.invalid should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let snippet_line = stdout
        .lines()
        .find(|l| l.contains("body content:"))
        .expect("a body content line must be present");
    assert!(
        snippet_line.ends_with('…'),
        "large body snippet must be truncated with …: {stdout}"
    );
}

#[test]
fn http_cli_sends_request_body_through_echo() {
    // `--body` must reach the server on the wire: the `echo.invalid` fixture
    // echoes the request body back, and the probe's body snippet shows it.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--sni",
            "echo.invalid",
            "--body",
            "cli-body-7fa3",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http --body");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --body should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("cli-body-7fa3"),
        "the --body must reach the server and be echoed back: {stdout}"
    );
}

#[test]
fn http_cli_body_reads_from_file_and_stdin() {
    // `--body @<file>` reads the request body from a file and `--body -` reads
    // it from stdin — both must reach the echo route and be echoed back.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let path = std::env::temp_dir().join(format!("ip-tools-body-test-{}.txt", std::process::id()));
    std::fs::write(&path, b"file-body-9d2c").expect("write body file");
    let file_arg = format!("@{}", path.display());
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--sni",
            "echo.invalid",
            "--body",
            &file_arg,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http --body @file");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --body @file should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("file-body-9d2c"),
        "the file body must reach the server and be echoed back: {stdout}"
    );
    let _ = std::fs::remove_file(&path);

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--sni",
            "echo.invalid",
            "--body",
            "-",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .write_stdin("stdin-body-4ab1")
        .output()
        .expect("run http --body -");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --body - should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("stdin-body-4ab1"),
        "the stdin body must reach the server and be echoed back: {stdout}"
    );
}

#[test]
fn diagnose_cli_sends_request_body_through_echo() {
    // `diagnose --body` threads the body into the HTTP evidence phase; the
    // echo route's response must carry it in the JSON evidence.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr,
            "--sni",
            "echo.invalid",
            "--body",
            "diag-body-5c1",
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run diagnose --body --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --body should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("diag-body-5c1"),
        "the --body must appear in the diagnose HTTP evidence: {stdout}"
    );
}

#[test]
fn diagnose_cli_csv_export_renders_diagnosis_rows() {
    // `diagnose --csv` emits a header + one row per diagnosis for a host,
    // so a sweep's verdicts load straight into a spreadsheet.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr, "--insecure", "--csv", "--timeout", "1500"])
        .output()
        .expect("run diagnose --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("host,severity,category,confidence,summary"),
        "CSV header: {stdout}"
    );
    let some_row = lines.any(|l| l.starts_with("127.0.0.1,"));
    assert!(some_row, "expected a per-host diagnosis row: {stdout}");
}

#[test]
fn diagnose_cli_multiple_targets_render_each_and_emit_json_array() {
    // `diagnose` accepts multiple targets (a fleet sweep): each host runs the
    // full pipeline, human output shows every host's report, and `--json`
    // emits a single array (one report per host) rather than one object.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr1 = fixture.tcp_addr().to_string();
    let host1 = "127.0.0.1".to_string(); // report target has no port
    let addr2 = "127.0.0.2".to_string();
    let host2 = "127.0.0.2".to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr1, &addr2, "--insecure", "--timeout", "1500"])
        .output()
        .expect("run diagnose with two targets");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target diagnose should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("DNS {host1}")) && stdout.contains(&format!("DNS {host2}")),
        "each target's report must render: {stdout}"
    );

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr1, &addr2, "--insecure", "--json", "--timeout", "1500"])
        .output()
        .expect("run multi-target diagnose --json");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "multi-target diagnose --json should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("diagnose --json must parse");
    let reports = parsed.as_array().expect(">1 target must yield a JSON array");
    assert_eq!(reports.len(), 2, "expected 2 reports: {stdout}");
    let targets: Vec<&str> = reports
        .iter()
        .filter_map(|r| r.get("target").and_then(serde_json::Value::as_str))
        .collect();
    assert!(
        targets.contains(&host1.as_str()),
        "report for {host1} missing: {targets:?}"
    );
    assert!(
        targets.contains(&host2.as_str()),
        "report for {host2} missing: {targets:?}"
    );
}

#[test]
fn diagnose_cli_strict_aggregates_across_targets() {
    // `--strict` is aggregated across hosts: one unhealthy target (a refused
    // TCP connect on 127.0.0.1:443) makes the whole sweep exit non-zero.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr1 = fixture.tcp_addr().to_string();
    let addr2 = "127.0.0.1".to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr1,
            &addr2,
            "--insecure",
            "--strict",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run multi-target diagnose --strict");
    assert!(
        !out.status.success(),
        "an unhealthy target must fail --strict: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn diagnose_surfaces_a_redirect_observation() {
    // The diagnostic engine must surface a 3xx redirect as a first-class
    // observation (captive portal / login wall / moved domain / middleware
    // rewrite), rather than reporting the host Healthy. The fixture's
    // `redirect.invalid` route answers 302 with a Location; hitting the
    // fixture's IP literal with `--sni redirect.invalid` reaches that route,
    // and the diagnose human output must name the redirect — not silently
    // pass the host as healthy.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr.to_string(),
            "--sni",
            "redirect.invalid",
            "--insecure",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose against the redirect route");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose should not fail hard on a redirect: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("redirected"),
        "diagnose should raise a redirect diagnosis: {stdout}"
    );
    assert!(
        stdout.contains("redirect.invalid/landed"),
        "redirect diagnosis should name the Location target: {stdout}"
    );
}

#[test]
fn http_cli_sni_override_reaches_the_http_host_header() {
    // `--sni` must present the chosen name as the HTTP `Host` header while
    // still connecting to the target's resolved addresses. The fixture routes
    // by request host (`redirect.invalid` -> 302 with a Location), so probing
    // the fixture's *IP literal* with `--sni redirect.invalid --insecure`
    // must hit the redirect route: proof the override changed what actually
    // went out on the wire, not just a reported label.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr.to_string(), // an IP literal target
            "--sni",
            "redirect.invalid",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http --sni");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --sni should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("302"),
        "the fixture's redirect.invalid route (keyed on the Host header) must fire: {stdout}"
    );
    assert!(
        stdout.contains("redirect.invalid"),
        "output should show the presented SNI/host: {stdout}"
    );
}

#[test]
fn tls_cli_sni_override_presents_chosen_name_and_validates() {
    // `tls <ip> --sni localhost` connects to the literal IP but handshakes
    // with SNI=localhost. The fixture's self-signed certificate covers
    // `localhost` and `127.0.0.1`, so with `--insecure` the handshake must
    // complete and the JSON must surface the *overridden* SNI — not the
    // literal destination. This is the "probe this IP as if it were that
    // hostname" pattern the `--sni` flag implements.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "tls",
            &addr.to_string(),
            "--sni",
            "localhost",
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run tls --sni");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "tls --sni should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"sni\": \"localhost\""),
        "observation must record the overridden SNI: {stdout}"
    );
    assert!(
        stdout.contains("\"success\": true"),
        "the handshake to the fixture IP presenting localhost must succeed: {stdout}"
    );
}

#[test]
fn probe_cli_sni_override_aggregates_under_presented_host() {
    // `probe --protocol http --sni redirect.invalid` against the fixture's IP
    // literal must repeat against the redirect route (Host-header keyed) and
    // report successes — the override carries through the repeated protocol.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &addr.to_string(),
            "--protocol",
            "http",
            "--sni",
            "redirect.invalid",
            "--count",
            "3",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol http --sni");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe http --sni should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("success:  3"),
        "all repeated probes under the presented host should succeed: {stdout}"
    );
}

#[test]
fn http_cli_path_requests_the_given_endpoint() {
    // `--path` must change what is requested on the wire. The fixture serves
    // a canned DNS-over-HTTPS response only for requests whose path starts
    // with `/dns-query` (routed by path in `run_tcp_server`), so requesting
    // that path from the real binary must surface the DoH response (a
    // non-"ok" body) rather than the ordinary route.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr.to_string(),
            "--path",
            "/dns-query",
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http --path");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --path should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The observation must record the requested path.
    assert!(
        stdout.contains("\"path\": \"/dns-query\""),
        "observation must record the requested path: {stdout}"
    );
    // The DoH route responds 200 with the canned message; the plain route
    // also 200s but with a 2-byte "ok" body — distinguish by body size
    // (DOH_RESPONSE is longer).
    assert!(
        stdout.contains("\"body_bytes\":"),
        "json must carry the body size: {stdout}"
    );
    assert!(
        !stdout.contains("\"body_bytes\": 2"),
        "the /dns-query route must be served (not the 2-byte plain body): {stdout}"
    );
}

#[test]
fn http_cli_default_path_is_root() {
    // Without `--path`, the request must target `/` (the observation records
    // the default path and the ordinary route's 2-byte body is served).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http", &addr.to_string(), "--insecure", "--json", "--timeout", "2000"])
        .output()
        .expect("run http without --path");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"path\": \"/\""),
        "default observation path must be /: {stdout}"
    );
    assert!(
        stdout.contains("\"body_bytes\": 2"),
        "the default / route serves the 2-byte body: {stdout}"
    );
}

#[test]
fn http_cli_header_reaches_server_on_the_wire() {
    // `--header 'x-fixture-marker: present'` must actually send the header:
    // the fixture answers 202 only when it sees that header, so a 202 (rather
    // than the ordinary 200) proves the header reached the server over both
    // the TCP (http1/http2) and QUIC (http3) paths.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let tcp = fixture.tcp_addr();
    let udp = fixture.udp_addr();

    for protocol in ["http", "http2"] {
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([
                protocol,
                &tcp.to_string(),
                "--header",
                "x-fixture-marker: present",
                "--insecure",
                "--json",
                "--timeout",
                "2000",
            ])
            .output()
            .expect("run with --header");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{protocol} --header should exit 0: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("\"status\": 202"),
            "{protocol} must have sent the header (202 expected): {stdout}"
        );
    }

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http3",
            &udp.to_string(),
            "--header",
            "x-fixture-marker: present",
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http3 with --header");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http3 --header should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"status\": 202"),
        "http3 must have sent the header (202 expected): {stdout}"
    );
}

#[test]
fn http_cli_header_reads_from_file_and_stdin() {
    // `--header @<file>` and `--header -` (stdin) read NAME:VALUE lines; the
    // marker line still answers 202, proving those headers reach the server.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr().to_string();

    let path = std::env::temp_dir().join(format!("ip-tools-header-test-{}.txt", std::process::id()));
    std::fs::write(&path, b"x-fixture-marker: present\n").expect("write header file");
    let file_arg = format!("@{}", path.display());
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--header",
            &file_arg,
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http --header @file");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --header @file should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"status\": 202"),
        "the file header must reach the server (202 expected): {stdout}"
    );
    let _ = std::fs::remove_file(&path);

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr,
            "--header",
            "-",
            "--insecure",
            "--json",
            "--timeout",
            "2000",
        ])
        .write_stdin("x-fixture-marker: present\n")
        .output()
        .expect("run http --header -");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --header - should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"status\": 202"),
        "the stdin header must reach the server (202 expected): {stdout}"
    );
}

#[test]
fn http_cli_rejects_malformed_header() {
    // A `--header` without `NAME:VALUE` (or with an empty name) is a caller
    // mistake and must fail with a clear error, not be silently dropped.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "http",
            &addr.to_string(),
            "--header",
            "no-colon-here",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run http with a malformed --header");
    assert!(
        !out.status.success(),
        "a malformed --header must be rejected: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NAME:VALUE"),
        "the error must explain the expected form: {stderr}"
    );
}

#[test]
fn http_probes_record_response_headers() {
    // The fixture answers every ordinary route with a `server:
    // ip-tools-fixture` header; the probes must record it (and the JSON must
    // carry it) so server-software evidence survives in the observation.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let tcp = fixture.tcp_addr();

    for protocol in ["http", "http2"] {
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([protocol, &tcp.to_string(), "--insecure", "--json", "--timeout", "2000"])
            .output()
            .expect("run with header recording");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{protocol} should exit 0: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("\"server\""),
            "{protocol} JSON must carry the response headers: {stdout}"
        );
        assert!(
            stdout.contains("ip-tools-fixture"),
            "{protocol} must record the server header value: {stdout}"
        );
    }
}

#[test]
fn http3_probe_records_response_headers() {
    // The same header-recording guarantee on the QUIC path.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let udp = fixture.udp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http3", &udp.to_string(), "--insecure", "--json", "--timeout", "2000"])
        .output()
        .expect("run http3 with header recording");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http3 should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("\"server\""),
        "http3 JSON must carry the response headers: {stdout}"
    );
    assert!(
        stdout.contains("ip-tools-fixture"),
        "http3 must record the server header value: {stdout}"
    );
}

#[test]
fn diagnose_cli_request_flags_scope_http_evidence() {
    // `diagnose --header x-fixture-marker: present` must scope the HTTP phase
    // to a request carrying that header: the fixture answers 202 only when it
    // sees the marker, so the diagnose output must show a 202 HTTP row (proof
    // the header reached the server through the full pipeline), alongside the
    // other evidence phases.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr.to_string(),
            "--header",
            "x-fixture-marker: present",
            "--insecure",
            "--path",
            "/",
            "--method",
            "GET",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose with request flags");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --header should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("202"),
        "the HTTP phase must carry the marker header (202 expected): {stdout}"
    );
    assert!(stdout.contains("HTTPS"), "HTTP evidence missing: {stdout}");
    assert!(stdout.contains("Diagnosis"), "diagnoses missing: {stdout}");
}
