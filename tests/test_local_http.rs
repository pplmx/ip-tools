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
        ip_tools::report::render_tls(&ip_tools::style::Style::plain(), std::slice::from_ref(&obs))
            .contains("covers localhost: yes"),
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
async fn plain_probe_gets_200_from_cleartext_fixture() {
    // `probe_plain` must speak plaintext HTTP/1.1 (no TLS handshake): against
    // the fixture's plain listener it gets a 200 with no `tls` observation and
    // the recorded server header — the same request over TLS would fail.
    let fixture = FixtureServer::start().await;
    let obs = http::probe_plain(fixture.plain_addr(), "localhost", "GET", "/", &[], None, timeout()).await;
    assert!(obs.failure.is_none(), "plain probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/1.1"));
    assert!(
        obs.headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("server") && v == "ip-tools-plain"),
        "expected the cleartext server header: {obs:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_repeat_aggregates_cleartext_http() {
    // `probe::http_repeat_plain` repeatedly probes plaintext HTTP/1.1 and
    // aggregates success + status: against the fixture's plain listener all
    // attempts succeed with a stable 200.
    let fixture = FixtureServer::start().await;
    let r = probe::http_repeat_plain(fixture.plain_addr(), "localhost", "GET", "/", &[], None, 3, timeout()).await;
    assert_eq!(r.failures, 0, "plaintext repeat should be all-success: {r:?}");
    assert_eq!(r.successes, 3, "expected 3/3 success: {r:?}");
    assert_eq!(
        r.status_counts.iter().find(|s| s.status == 200).map(|s| s.count),
        Some(3),
        "expected 200x3 status distribution: {r:?}"
    );
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

/// `--max-body-bytes` must be a *strict* bound: the reported `body_bytes`
/// equals the cap exactly for every protocol (not the cap plus a whole frame),
/// and a response body larger than the cap is detected as capped, not as
/// complete.
#[tokio::test(flavor = "multi_thread")]
async fn max_body_bytes_is_a_strict_bound_for_all_protocols() {
    let fixture = FixtureServer::start().await;
    let cap = 128u64;

    let h1 = http::probe_insecure_with_version_output(
        fixture.tcp_addr(),
        "big.invalid",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        tls::TlsProtocol::Auto,
        cap,
        None,
    )
    .await;
    assert_eq!(h1.body_bytes, Some(cap), "http1 must stop exactly at the cap: {h1:?}");

    let h2 = http2::probe_insecure_with_version_output(
        fixture.tcp_addr(),
        "big.invalid",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        tls::TlsProtocol::Auto,
        cap,
        None,
    )
    .await;
    assert_eq!(h2.body_bytes, Some(cap), "http2 must stop exactly at the cap: {h2:?}");

    let h3 = http3::probe_insecure_output(
        fixture.udp_addr(),
        "big.invalid",
        "GET",
        "/",
        &[],
        None,
        timeout(),
        cap,
        None,
    )
    .await;
    assert_eq!(h3.body_bytes, Some(cap), "http3 must stop exactly at the cap: {h3:?}");
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

#[test]
fn probe_repeat_counts_a_stalled_body_as_a_failure() {
    // A server that answers 200 but never completes the body must not fold
    // into the repeat aggregate as `success: 100%` with the latency pushed at
    // the full `--timeout` wall-clock (the single-shot layer reports
    // `body: incomplete (timed out)`). Each stalled attempt is a failed
    // exchange, so `--expect-rate 1 --expect-status 2xx` gates the run
    // non-zero instead of asserting the endpoint green.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    // The stall route is served by the TLS listener (the cleartext listener
    // has no StalledBody arm), so probe over TLS with `--insecure` (the
    // fixture cert is self-signed) and route by the overridden Host header.
    let tls = fixture.tcp_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &tls,
            "--protocol",
            "http",
            "--insecure",
            "--header",
            "host: stall.invalid",
            "--count",
            "3",
            "--timeout",
            "800",
            "--expect-rate",
            "1",
            "--expect-status",
            "2xx",
        ])
        .output()
        .expect("run probe --expect-rate against a stall server");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a body-stalling endpoint must not pass --expect-rate 1: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("success:  0"),
        "the aggregate must report zero successful exchanges: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("failure:  3"),
        "every stalled attempt must be bucketed as a failure: {stdout}\n{stderr}"
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

/// A server that sends headers and then trickles body bytes forever (a fresh
/// chunk every <timeout period) must not bypass the probe's wall-clock bound:
/// the body read is one operation bounded by `--timeout`, so an endless
/// slow-drip stream is cut off as an incomplete response instead of stalling
/// the probe indefinitely. The bound is generous relative to the response head
/// (so the head reliably arrives even under parallel test load) yet the head
/// still comes first — it is the endless drip that the deadline must cut off.
#[tokio::test(flavor = "current_thread")]
async fn slow_dripping_body_is_bounded_by_the_probe_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let dripper = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        // Signal readiness once the accept loop is actually running, so the
        // probe never races the handler under parallel test load.
        let _ = ready_tx.send(());
        while let Ok((stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut stream = stream;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100000\r\n\r\n")
                    .await;
                // A new body chunk every 300 ms, forever. A per-frame-reset
                // timeout would treat each read as fresh and never fire.
                let mut n: u64 = 0;
                loop {
                    let chunk = format!("{n:064}\n").into_bytes();
                    n += 1;
                    if stream.write_all(&chunk).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });
        }
    });
    let _ = ready_rx.await;

    // Each drip (300 ms) is well inside the bound (3 s), yet the body never
    // completes — only the absolute deadline can stop the probe, which is
    // exactly the regression being pinned.
    let bound = Duration::from_secs(3);
    let start = std::time::Instant::now();
    let obs = http::probe_plain(addr, "localhost", "GET", "/", &[], None, bound).await;
    let elapsed = start.elapsed();

    assert_eq!(obs.status, Some(200), "headers received: {obs:?}");
    assert_eq!(obs.body_bytes, None, "an endless slow-drip body is incomplete: {obs:?}");
    // The 300ms-per-chunk body never ends; the probe must stop near the
    // --timeout bound (plus a grace), not track the endless stream.
    assert!(
        elapsed < Duration::from_secs(6),
        "the probe must stop near --timeout, not track an endless stream (elapsed {elapsed:?})"
    );
    dripper.abort();
}

/// An explicit `--header 'host: ...'` must replace the default Host header
/// on the wire (RFC 7230 §5.4 rejects a request carrying two Hosts), not
/// stack a second one under the probe's own host. Verified against a raw
/// socket so the actual request bytes are asserted.
#[tokio::test(flavor = "current_thread")]
async fn explicit_host_header_overrides_the_default_on_the_wire() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(1);
    let server = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        if let Ok((mut stream, _peer)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
                .await
                .map_or(0, |r| r.unwrap_or(0));
            let _ = sent_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned()).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await;
        }
    });

    let obs = http::probe_plain(
        addr,
        "default.example",
        "GET",
        "/",
        &[("host", "vhost.example"), ("x-custom", "1")],
        None,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(obs.status, Some(200), "probe should complete: {obs:?}");
    assert!(obs.failure.is_none(), "probe must not fail: {obs:?}");

    let request = tokio::time::timeout(Duration::from_secs(3), sent_rx.recv())
        .await
        .expect("server should report the request")
        .expect("channel open");
    let header_lines: Vec<&str> = request
        .lines()
        .filter(|l| l.contains(':') && !l.starts_with("GET "))
        .collect();
    let hosts: Vec<&str> = header_lines
        .iter()
        .filter(|l| l.to_ascii_lowercase().starts_with("host:"))
        .copied()
        .collect();
    assert_eq!(
        hosts,
        vec!["host: vhost.example"],
        "exactly one Host header, overridden by --header host: request was:\n{request}"
    );
    assert!(
        request.contains("x-custom: 1"),
        "non-host custom headers must still be sent:\n{request}"
    );
    server.abort();
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
    // A handshake that stalls past the bound is a TLS-layer timeout, exposed
    // as `TlsHandshake` (message says "timed out") so the diagnostics engine
    // does not double-count it as an HTTP-layer error on h1/h2 rows.
    assert_eq!(
        obs.failure.as_ref().map(|f| f.kind),
        Some(ip_tools::FailureKind::TlsHandshake),
        "expected a TLS handshake timeout: {obs:?}"
    );
    assert!(
        obs.failure.as_ref().expect("failure").message.contains("timed out"),
        "the stall must be spelled out in the message: {obs:?}"
    );

    let obs = http::probe(addr, "localhost", "GET", "/", &[], None, Duration::from_millis(500)).await;
    assert_eq!(
        obs.failure.as_ref().map(|f| f.kind),
        Some(ip_tools::FailureKind::TlsHandshake),
        "an h1-over-TLS handshake stall must not read as an HTTP-layer timeout: {obs:?}"
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
    assert!(
        stdout.contains("ttl 60s"),
        "the canned DoH answer's TTL (60s) should be surfaced: {stdout}"
    );
}

#[test]
fn dns_cli_csv_carries_record_ttl() {
    // `dns --csv` must carry the record TTL on single-shot rows so the
    // spreadsheet export is consistent with the human/JSON TTL feature
    // (parity with how the probe status distribution reached --csv).
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
            "--csv",
        ])
        .output()
        .expect("run dns --doh --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --doh --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.lines().next()
            == Some(
                "host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures,ttl,records"
            ),
        "CSV header should include ttl and records: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("host.example,") && l.contains(",60,")),
        "the single-shot DoH row should carry the 60s TTL field: {stdout}"
    );
    assert!(
        stdout.contains("192.0.2.77") && stdout.contains("2001:db8::77"),
        "the single-shot DoH rows should carry the resolved A and AAAA records: {stdout}"
    );
}

#[test]
fn dns_cli_ptr_reverse_lookup_uses_auto_built_reverse_zone() {
    // `dns --record-type PTR <ip>` auto-builds the reverse-zone name
    // (RFC 1035 `in-addr.arpa`) from the literal and issues a PTR query. The
    // fixture's canned PTR endpoint answers `192.0.2.77` with `host.example`,
    // so the resolved pointer must surface, labeled by the target IP (not the
    // reverse-zone name).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-ptr-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "192.0.2.77",
            "--record-type",
            "PTR",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --record-type PTR --doh");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --record-type PTR should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("host.example"),
        "the PTR record (host.example) should surface: {stdout}"
    );
    assert!(
        stdout.contains("192.0.2.77"),
        "the target IP should label the observation: {stdout}"
    );
    assert!(
        stdout.contains("PTR"),
        "the PTR record type should be labeled: {stdout}"
    );
}

#[test]
fn dns_cli_ptr_repeat_honors_count() {
    // `dns --record-type PTR <ip> --count N` must aggregate N reverse lookups
    // like every other record type rather than silently ignoring `--count`:
    // the repeat row reports the user's IP target with attempts=N.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-ptr-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "192.0.2.77",
            "--record-type",
            "PTR",
            "--count",
            "3",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run dns --record-type PTR --count 3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --record-type PTR --count 3 should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Repeated DNS 192.0.2.77"),
        "the repeat report must label the target IP: {stdout}"
    );
    assert!(
        stdout.contains(&endpoint) && stdout.contains("PTR"),
        "the DoH PTR repeat row must render: {stdout}"
    );
    assert!(
        stdout.contains("attempts: 3"),
        "--count 3 must be honored with 3 attempts: {stdout}"
    );
    assert!(
        stdout.contains("success:  3 (100.0%)"),
        "3 canned DoH PTR lookups should all succeed: {stdout}"
    );
}

#[test]
fn dns_cli_reads_targets_from_file_and_stdin() {
    // A fleet-sweep target list can come from a file (`@path`, with blank lines
    // and `#` comments skipped) or stdin (`-`), parity with `--header`/`--body`.
    use std::io::Write;
    let path = std::env::temp_dir().join(format!("ip-tools-targets-{}.txt", std::process::id()));
    let mut f = std::fs::File::create(&path).expect("create target file");
    writeln!(f, "# fleet sweep\n1.1.1.1\n\n8.8.8.8\n").expect("write target file");

    let from_file = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", &format!("@{}", path.display())])
        .output()
        .expect("run dns @file");
    let _ = std::fs::remove_file(&path);
    let file_out = String::from_utf8_lossy(&from_file.stdout);
    assert!(
        from_file.status.success(),
        "dns @file should exit 0: {file_out}\n{}",
        String::from_utf8_lossy(&from_file.stderr)
    );
    assert!(
        file_out.contains("1.1.1.1") && file_out.contains("8.8.8.8"),
        "both file targets must resolve (comments/blanks skipped): {file_out}"
    );

    let from_stdin = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["dns", "-"])
        .write_stdin("1.1.1.1\n8.8.8.8\n")
        .output()
        .expect("run dns - (stdin)");
    let stdin_out = String::from_utf8_lossy(&from_stdin.stdout);
    assert!(
        from_stdin.status.success(),
        "dns - (stdin) should exit 0: {stdin_out}\n{}",
        String::from_utf8_lossy(&from_stdin.stderr)
    );
    assert!(
        stdin_out.contains("1.1.1.1") && stdin_out.contains("8.8.8.8"),
        "both stdin targets must resolve: {stdin_out}"
    );
}

#[test]
fn diagnose_reverse_surfaces_ptr_evidence() {
    // `diagnose <ip> --reverse` adds reverse-DNS (PTR) evidence for an
    // IP-literal target. Against the fixture's canned PTR endpoint the
    // operator sees the hostname rDNS maps the address to (`host.example`),
    // which identifies what they are probing.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-ptr-query", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            "192.0.2.77",
            "--reverse",
            "--doh",
            &endpoint,
            "--insecure",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose --reverse");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --reverse should exit 0 (absent PTR / probe failures are observations): {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("host.example"),
        "reverse PTR evidence (host.example) must surface: {stdout}"
    );
    assert!(
        stdout.contains("192.0.2.77") && stdout.contains("PTR"),
        "the PTR evidence should be labeled by the target IP and type: {stdout}"
    );
}

#[test]
fn diagnose_reverse_applies_to_hostname_targets() {
    // `--reverse` must not be silently ignored for a hostname target: it
    // reverses each resolved address. The fixture's `/dns-query` resolves
    // `host.example` to 192.0.2.77 and `/dns-ptr-query` answers that address's
    // PTR, so the reverse evidence (`host.example` from a PTR row) must appear.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.tcp_addr();
    let forward = format!("https://{addr}/dns-query");
    let rev = format!("https://{addr}/dns-ptr-query");

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            "host.example",
            "--reverse",
            "--doh",
            &forward,
            "--doh",
            &rev,
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run diagnose hostname --reverse");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose hostname --reverse should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("PTR") && stdout.contains("host.example"),
        "hostname --reverse must surface the PTR evidence (not be silently ignored): {stdout}"
    );
    assert!(
        stdout.contains("192.0.2.77"),
        "the reversed address should be labeled: {stdout}"
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
fn dns_cli_doh_reports_no_records_for_a_nodata_answer() {
    // A NOERROR answer with zero wanted-type records (NODATA) must surface as
    // a `no A records found for ...` failure observation — the same verdict
    // the resolver-backed path reports via hickory's NoRecordsFound. On a
    // mixed run (system resolver + --doh) the same host would otherwise show
    // SYSTEM=failure next to DOH=success, and --strict / repeat aggregation
    // would disagree by resolver.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let endpoint = format!("https://{}/dns-empty", fixture.tcp_addr());

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "dns",
            "host.example",
            "--doh",
            &endpoint,
            "--insecure",
            "--record-type",
            "A",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run dns --doh against a NODATA endpoint");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --doh should still exit 0 (an error is an observation): {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("no A records found for host.example"),
        "a NODATA answer must report the no-records verdict: {stdout}"
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
        Some(
            "host,resolver,record_type,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,failures,ttl,records"
        ),
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
fn dns_cli_repeat_csv_carries_min_ttl() {
    // `dns --count N --csv` repeat rows must carry the minimum record TTL
    // (parity with single-shot rows): the fixture's canned DoH answer has a
    // 60s TTL, so a `--count 3` repeat row aggregates attempts>1 and still
    // surfaces `ttl=60`.
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
            "--count",
            "3",
            "--csv",
        ])
        .output()
        .expect("run dns --doh --count 3 --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "dns --doh --count 3 --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.lines().any(|l| l.contains(",3,1.0000") && l.contains(",60,")),
        "the repeat CSV row should aggregate 3 attempts and carry ttl=60: {stdout}"
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
fn probe_http_repeat_surfaces_status_distribution() {
    // `probe --protocol http --count N` must surface the observed HTTP status
    // distribution (the fixture's Normal route answers 200) so status flapping
    // is visible in a stability repeat, not just transport pass/fail counts.
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
            "http",
            "--count",
            "3",
            "--insecure",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol http --count 3");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe --protocol http should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("success:  3"),
        "expected 3 successful exchanges: {stdout}"
    );
    assert!(
        stdout.contains("200x3"),
        "the HTTP status distribution (200x3) must be surfaced: {stdout}"
    );
    // The server-response latency must be surfaced separately from total
    // latency: a `ttfb` block with the populated min/p50.
    assert!(
        stdout.contains("    ttfb:\n") && stdout.contains("p50:"),
        "the HTTP repeat must surface the ttfb latency block: {stdout}"
    );
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
        Some("host,destination,attempts,success_rate,latency_p50_ms,latency_p95_ms,latency_max_ms,jitter_ms,ttfb_p50_ms,ttfb_p95_ms,ttfb_max_ms,failures,statuses"),
        "CSV header: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains(&format!("{addr},3,1.0000,"))),
        "expected a 3/3 success row for {addr}: {stdout}"
    );
    // A transport (tcp/tls) repeat has no TTFB signal: the three ttfb cells
    // stay empty (blank cells before `,failures`) rather than a fabricated 0.
    // A transport (tcp/tls) repeat has no TTFB signal: the three ttfb cells
    // (columns 9..11) stay empty rather than a fabricated 0, and the row
    // closes with `failures=0` + empty statuses (13 columns total).
    assert!(
        stdout.lines().any(|l| {
            let cols: Vec<&str> = l.split(',').collect();
            cols.len() == 13
                && cols.get(8).is_some_and(|c| c.is_empty())
                && cols.get(9..11).is_some_and(|c| c.iter().all(|v| v.is_empty()))
        }),
        "transport repeat row should leave the ttfb cells empty: {stdout}"
    );
}

#[test]
fn probe_http_csv_export_includes_statuses() {
    // `probe --protocol http --csv` must carry the HTTP status distribution
    // (the fixture's Normal route answers 200) in its own column, so a
    // spreadsheet repeat-probe load reveals statuses, not just pass/fail.
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
            "http",
            "--count",
            "3",
            "--insecure",
            "--csv",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol http --csv");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe --protocol http --csv should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.lines().any(|l| l.contains("200x3")),
        "the HTTP status distribution must appear in the CSV: {stdout}"
    );
    // The repeated HTTP row must also carry the server-response latency
    // (TTFB) columns — a stability sweep in a spreadsheet needs the
    // slow-to-respond signal separate from total latency.
    assert!(
        stdout.contains("ttfb_p50_ms,ttfb_p95_ms,ttfb_max_ms"),
        "the probe HTTP CSV header must carry the TTFB columns: {stdout}"
    );
    // A data row must have 13 columns (header parity: ...jitter_ms,
    // ttfb_p50/95/max_ms, failures, statuses) and end `...,0,200x3` with the
    // three ttfb cells (9..11) populated.
    assert!(
        stdout.lines().any(|l| {
            let cols: Vec<&str> = l.split(',').collect();
            cols.len() == 13
                && cols.last() == Some(&"200x3")
                && cols.get(8).is_some_and(|c| !c.is_empty())
                && cols.get(9).is_some_and(|c| !c.is_empty())
                && cols.get(10).is_some_and(|c| !c.is_empty())
        }),
        "the HTTP repeat CSV row must carry non-empty ttfb cells: {stdout}"
    );
}

#[test]
fn probe_cli_plain_repeats_cleartext_http() {
    // `probe --protocol http --plain` repeatedly probes cleartext HTTP/1.1
    // (no TLS handshake) and aggregates the status/latency — a plaintext HTTP
    // health/stability sweep. Against the fixture's plain listener it must
    // report 3/3 success (stable 200) rather than a TLS handshake failure.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.plain_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &addr,
            "--protocol",
            "http",
            "--count",
            "3",
            "--plain",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol http --plain");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "probe --protocol http --plain should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("100.0%") && stdout.contains("success:  3"),
        "the plaintext HTTP repeat should be all-success: {stdout}"
    );
    assert!(
        stdout.contains("200x3"),
        "the plaintext HTTP status distribution (200x3) must appear: {stdout}"
    );

    // --plain only makes sense for cleartext HTTP, so a non-http protocol
    // must be rejected with a clear error.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &addr,
            "--protocol",
            "tls",
            "--count",
            "2",
            "--plain",
            "--timeout",
            "2000",
        ])
        .output()
        .expect("run probe --protocol tls --plain");
    assert!(
        !out.status.success(),
        "probe --plain with a non-http protocol must fail: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn diagnose_cli_plain_probes_cleartext_http_end_to_end() {
    // The full pipeline with --plain must observe a cleartext endpoint
    // truthfully: without --plain it would raise a false "TLS handshake fails
    // where TCP connects" verdict (the fixture's plain listener does no TLS),
    // but with --plain it skips the TLS phase and probes HTTP/1.1 over
    // cleartext, so the endpoint is seen as healthy.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.plain_addr().to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr, "--plain", "--count", "2", "--timeout", "2000"])
        .output()
        .expect("run diagnose --plain");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --plain should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The cleartext HTTP phase must observe the 200 response.
    assert!(
        stdout.contains("200"),
        "diagnose --plain should see the cleartext 200: {stdout}"
    );
    assert!(
        stdout.contains("server: ip-tools-plain") || stdout.contains("body content"),
        "the cleartext response (headers/body) must surface: {stdout}"
    );

    // Without --plain the same endpoint must be diagnosed as TLS-failing (the
    // plain listener does no handshake) — proving --plain is what changes the
    // observation, not the fixture.
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr, "--insecure", "--timeout", "2000"])
        .output()
        .expect("run diagnose without --plain");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TLS handshake fails where TCP connects"),
        "without --plain the plaintext endpoint must be TLS-failing: {stdout}"
    );
}

#[test]
fn diagnose_cli_ipv4_and_ipv6_scope_the_pipeline_to_one_family() {
    // `--ipv4`/`--ipv6` scope the whole diagnosis (all phases) to one address
    // family — parity with tcp/tls/http/http2/http3/probe. The fixture's
    // plain listener binds the IPv4 loopback, so `--ipv4` probes it (cleartext
    // 200, and no AddressFamily verdict: only one family's observations are
    // present, so the cross-family asymmetry rule stays silent), while
    // `--ipv6` filters the literal's address pool to nothing and the usual
    // no-address failure fires. Passing both flags is a parse error.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.plain_addr().to_string();

    let run = |extra: &[&str]| {
        Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args(["diagnose", &addr, "--plain", "--timeout", "2000"])
            .args(extra)
            .output()
            .expect("run diagnose family scope")
    };

    let out = run(&["--ipv4", "--count", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --ipv4 should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("200"),
        "diagnose --ipv4 must probe the v4 loopback's cleartext 200: {stdout}"
    );
    assert!(
        !stdout.contains("AddressFamily"),
        "a family-scoped diagnosis must not raise the cross-family AddressFamily verdict: {stdout}"
    );

    let out = run(&["--ipv6"]);
    assert!(
        !out.status.success(),
        "diagnose --ipv6 on an IPv4 literal must fail (no address of that family)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The target resolves (it is a literal); the error is that the --ipv6
    // scope empties the address pool — not a misleading "did not resolve".
    assert!(
        stderr.contains("--ipv6 scope leaves no IPv6 addresses"),
        "--ipv6 must report the family-scoped empty pool: {stderr}"
    );
    assert!(
        !stderr.contains("did not resolve"),
        "--ipv6 on a resolving target must not claim resolution failed: {stderr}"
    );

    // clap enforces the mutual exclusion (`--ipv4 --ipv6` is a parse error).
    let failed = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["diagnose", &addr, "--ipv4", "--ipv6"])
        .assert()
        .failure();
    let err = String::from_utf8_lossy(&failed.get_output().stderr).to_string();
    assert!(
        err.contains("cannot be used with") || err.contains("conflicts"),
        "--ipv4 and --ipv6 must conflict at parse: {err}"
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
            "host,destination,protocol,status,location,body_bytes,ttfb_ms,latency_ms,sni,version,cipher,alpn,subject,issuer,not_after_utc,sans,covers,headers,body_snippet,failure"
        ),
        "CSV header: {stdout}"
    );
    assert!(
        lines.any(|l| l.starts_with("127.0.0.1,") && l.contains(",200,")),
        "expected a row with status 200: {stdout}"
    );
    assert!(
        stdout.contains("server: ip-tools-fixture"),
        "the http --csv row should carry the observed response headers (the fixture sets `server: ip-tools-fixture`): {stdout}"
    );
    assert!(
        stdout.contains("body content") || stdout.contains(",ok,") || stdout.contains("body_snippet"),
        "the http --csv row should carry the response body snippet: {stdout}"
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
fn http_cli_plain_probes_cleartext_http() {
    // End-to-end: the real binary with --plain must probe a plaintext HTTP/1.1
    // server (no TLS handshake at all). The fixture's plain listener serves
    // `200 ok` with a `server: ip-tools-plain` header — the same request over
    // TLS would fail with a handshake error, so --plain is what observes the
    // cleartext endpoint truthfully.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr = fixture.plain_addr();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["http", &addr.to_string(), "--plain", "--timeout", "2000"])
        .output()
        .expect("run http --plain");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "http --plain should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("200"), "expected a 200 response: {stdout}");
    assert!(
        stdout.contains("HTTP/1.1"),
        "expected HTTP/1.1 over plaintext: {stdout}"
    );
    assert!(
        stdout.contains("server: ip-tools-plain") || stdout.contains("body content"),
        "expected the cleartext response (headers/body) to surface: {stdout}"
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
        Some("host,severity,category,confidence,summary,evidence,possible_causes"),
        "CSV header: {stdout}"
    );
    let some_row = lines.any(|l| l.starts_with("127.0.0.1,"));
    assert!(some_row, "expected a per-host diagnosis row: {stdout}");
    // A verdict carries its evidence + possible causes (the "why") so a
    // spreadsheet sweep keeps the reasoning, e.g. the fixture's QUIC verdict.
    assert!(
        stdout.contains("QUIC/HTTP3 fails while TCP+HTTPS succeeds")
            && stdout.contains("TCP path OK; UDP/QUIC path failed")
            && stdout.contains("QUIC disabled / not offered by server"),
        "expected the diagnosis row to carry its evidence and possible causes: {stdout}"
    );
    // The severity/category/confidence cells use the JSON spellings (HIGH,
    // total_connectivity_loss, ...) — not Debug's `High`/`TotalConnectivityLoss`
    // — so a CSV row pivots against `diagnose --json` output.
    assert!(
        !stdout.contains("TotalConnectivityLoss") && !stdout.contains(",High,") && !stdout.contains(",Medium,"),
        "diagnose --csv must use JSON enum spellings, not Debug's: {stdout}"
    );
}

#[test]
fn diagnose_flags_http_status_flapping_on_transport_healthy_path() {
    // `diagnose` must surface HTTP status flapping: the fixture's `flap.invalid`
    // route alternates 200/503 per request, so a repeated HTTP probe succeeds
    // at the transport layer every time yet sees both response classes. TCP
    // pass/fail alone would report stable connectivity, so the flapping verdict
    // is the user-visible signal that the backend is flapping.
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
            "flap.invalid",
            "--insecure",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose against flapping route");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("HTTP status flapping") && stdout.contains("flapping / degraded backend"),
        "the flapping diagnosis (and its possible cause) must surface: {stdout}"
    );
}

#[test]
fn diagnose_count_controls_the_stability_repeat() {
    // `diagnose --count N` sizes the stability phase's repeated attempts per
    // address (both the TCP transport repeat and the HTTP status repeat).
    // Against the flapping fixture, a single attempt (`--count 1`) cannot
    // observe both 200 and 503, so the flapping verdict must NOT fire — while
    // the default 3 (or a larger `--count`) does. This proves the flag is
    // actually threaded through the repeat phase, not ignored.
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
            "flap.invalid",
            "--insecure",
            "--count",
            "1",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose --count 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose --count 1 should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("HTTP status flapping"),
        "a single attempt cannot observe status flapping, so --count 1 must suppress the verdict: {stdout}"
    );

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr,
            "--sni",
            "flap.invalid",
            "--insecure",
            "--count",
            "5",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run diagnose --count 5");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("HTTP status flapping"),
        "a 5-attempt stability repeat should observe 200/503 flapping: {stdout}"
    );
}

#[test]
fn diagnose_flags_latency_instability_on_stable_transport() {
    // `diagnose` must surface latency instability: the fixture's
    // `slowflap.invalid` route keeps a stable 200 status but alternates fast /
    // slow (~120 ms) responses, so a repeated HTTP probe succeeds every attempt
    // with the same status yet shows a long p95-vs-p50 tail. Transport
    // pass/fail and status classes both stay quiet — only the latency
    // distribution reveals the flapping backend.
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
            "slowflap.invalid",
            "--insecure",
            "--timeout",
            "3000",
        ])
        .output()
        .expect("run diagnose against slow-flapping route");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "diagnose should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Latency instability") && stdout.contains("only the latency tail is long"),
        "the latency-instability diagnosis (and its evidence) must surface: {stdout}"
    );
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
fn diagnose_multiple_targets_preserve_input_order_under_concurrency() {
    // A concurrent fleet sweep (`--concurrency N`) must still render reports
    // in the given target order: `parallel_map` completes out of order, so the
    // runner re-sorts by input index. Probe two targets concurrently and check
    // the first target's report block precedes the second's in the output.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr1 = fixture.tcp_addr().to_string();
    let host1 = "127.0.0.1".to_string();
    let addr2 = "127.0.0.2".to_string();
    let host2 = "127.0.0.2".to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "diagnose",
            &addr1,
            &addr2,
            "--insecure",
            "--concurrency",
            "4",
            "--timeout",
            "1500",
        ])
        .output()
        .expect("run concurrent multi-target diagnose");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "concurrent multi-target diagnose should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let p1 = stdout
        .find(&format!("DNS {host1}"))
        .expect("first target's report must render");
    let p2 = stdout
        .find(&format!("DNS {host2}"))
        .expect("second target's report must render");
    assert!(p1 < p2, "target order must be preserved under --concurrency: {stdout}");
}

#[test]
fn probe_sweep_preserves_input_order_under_concurrency() {
    // The shared per-protocol probe sweep (`run_probe_flow`, used by tcp/tls/
    // http/http2/http3/probe) also runs targets concurrently under
    // `--concurrency` and must re-sort reports back to the given target order.
    // A multi-target `tcp` sweep labels each target block with its host, so we
    // assert the first target's label precedes the second's in the output.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());
    let addr1 = fixture.tcp_addr().to_string();
    let host1 = "127.0.0.1".to_string();
    let addr2 = "127.0.0.2".to_string();
    let host2 = "127.0.0.2".to_string();

    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args(["tcp", &addr1, &addr2, "--concurrency", "4", "--timeout", "1500"])
        .output()
        .expect("run concurrent tcp sweep");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "concurrent tcp sweep should exit 0: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let p1 = stdout
        .find(&format!("{host1}:"))
        .expect("first target's label must render");
    let p2 = stdout
        .find(&format!("{host2}:"))
        .expect("second target's label must render");
    assert!(
        p1 < p2,
        "probe sweep target order must be preserved under --concurrency: {stdout}"
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

// ---------------------------------------------------------------------------
// --expect-status / --expect-contains: user-asserted response checks
//
// The HTTP-family probes (`http`, `http2`, `http3`) accept an asserted
// response shape: `--expect-status SPEC` (exact code or `2xx` class) and
// `--expect-contains NEEDLE` (substring of the bounded body snippet). Every
// per-address observation must satisfy the assertions; the run exits non-zero
// with an `expectation violated: <dest> ...` stderr line when any does not,
// independent of `--strict`. The report on stdout is untouched.
// ---------------------------------------------------------------------------

/// Run the ip-tools binary's `HTTP`-family probe with extra args against the
/// fixture and return (`exit_ok`, stdout, stderr).
fn run_http_probe(fixture: &FixtureServer, sub: &str, extra: &[&str]) -> (bool, String, String) {
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([sub, &fixture.tcp_addr().to_string(), "--insecure", "--timeout", "1500"])
        .args(extra)
        .output()
        .expect("run http-family probe with expectations");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn http_cli_expect_status_gates_exit_code() {
    // The default fixture route answers 200. `--expect-status` must gate the
    // exit code: an exact code and a class both pass, a mismatched code fails
    // with a stderr verdict naming the destination and the expected value.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-status", "200"]);
    assert!(ok, "--expect-status 200 should pass on a 200: {stderr}");

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-status", "2xx"]);
    assert!(ok, "--expect-status 2xx should pass on a 200: {stderr}");

    let (ok, stdout, stderr) = run_http_probe(&fixture, "http", &["--expect-status", "403"]);
    assert!(!ok, "--expect-status 403 must fail on a 200");
    assert!(
        stdout.contains("200"),
        "the report (stdout) still renders the actual status: {stdout}"
    );
    assert!(
        stderr.contains("expectation violated:") && stderr.contains("expected 403"),
        "the violation verdict must name the destination and expectation: {stderr}"
    );
}

#[test]
fn http_cli_expect_contains_gates_exit_code() {
    // The default fixture body is `ok`. `--expect-contains` must gate the exit
    // code on the bounded snippet presence.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-contains", "ok"]);
    assert!(ok, "--expect-contains ok should pass on body 'ok': {stderr}");

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-contains", "deploy-live"]);
    assert!(!ok, "--expect-contains deploy-live must fail on body 'ok'");
    assert!(
        stderr.contains("expectation violated:") && stderr.contains("missing \"deploy-live\""),
        "the violation verdict must name the missing needle: {stderr}"
    );
}

#[test]
fn http_cli_expect_composes_status_and_contains() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-status", "200", "--expect-contains", "ok"]);
    assert!(ok, "both assertions satisfied on a 200 'ok' response: {stderr}");

    let (ok, _, stderr) = run_http_probe(
        &fixture,
        "http",
        &["--expect-status", "200", "--expect-contains", "gone"],
    );
    assert!(!ok, "a failing needle must fail the run even with matching status");
    assert!(
        stderr.contains("expected 200") || stderr.contains("missing \"gone\""),
        "the verdict should mention at least the violating assertion: {stderr}"
    );
}

#[test]
fn http_cli_expect_applies_to_a_redirected_response() {
    // `--sni redirect.invalid` routes the request to a 302 + Location. The
    // asserted status class gates the exit: 3xx passes on a 302, 2xx fails —
    // the redirect is recorded, never followed.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    let (ok, stdout, stderr) = run_http_probe(
        &fixture,
        "http",
        &["--sni", "redirect.invalid", "--expect-status", "3xx"],
    );
    assert!(ok, "--expect-status 3xx should pass on a 302: {stderr}");
    assert!(stdout.contains("302"), "the report must show the actual 302: {stdout}");

    let (ok, _, stderr) = run_http_probe(
        &fixture,
        "http",
        &["--sni", "redirect.invalid", "--expect-status", "2xx"],
    );
    assert!(!ok, "--expect-status 2xx must fail on a 302");
    assert!(stderr.contains("status 302 (expected 2xx)"), "{stderr}");
}

#[test]
fn http_cli_expect_rejects_malformed_specs_at_parse() {
    // A typo in the expectation must fail fast with a clear error instead of
    // silently passing or failing on every run. Default probe behavior
    // (no --expect at all) is unaffected.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    for bad in ["20x", "0xx", "999"] {
        let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-status", bad]);
        assert!(!ok, "--expect-status {bad} must be rejected");
        assert!(
            stderr.contains("invalid --expect-status"),
            "--expect-status {bad} should error clearly: {stderr}"
        );
    }

    let (ok, _, stderr) = run_http_probe(&fixture, "http", &["--expect-contains", ""]);
    assert!(!ok, "--expect-contains '' must be rejected");
    assert!(
        stderr.contains("cannot be an empty string"),
        "empty needle should error clearly: {stderr}"
    );

    // A run with no expectation flags still exits 0 (default byte-identical
    // behavior preserved).
    let (ok, _, _) = run_http_probe(&fixture, "http", &[]);
    assert!(ok, "no --expect flags leaves default exit semantics untouched");
}

#[test]
fn http2_and_http3_cli_expect_status_gate_exit_code() {
    // Parity across the three HTTP stacks: the same asserted-status verdict
    // applies to the HTTP/2 and HTTP/3 probes.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    for (sub, addr) in [
        ("http2", fixture.tcp_addr().to_string()),
        ("http3", fixture.udp_addr().to_string()),
    ] {
        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([sub, &addr, "--insecure", "--timeout", "1500", "--expect-status", "200"])
            .output()
            .expect("run http-family probe with expectation");
        assert!(
            out.status.success(),
            "{sub} --expect-status 200 should pass on a 200: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let out = Command::cargo_bin("ip-tools")
            .expect("ip-tools binary")
            .args([sub, &addr, "--insecure", "--timeout", "1500", "--expect-status", "403"])
            .output()
            .expect("run http-family probe with expectation");
        assert!(!out.status.success(), "{sub} --expect-status 403 must fail on a 200");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("expectation violated:"),
            "{sub} violation verdict missing: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// `probe --expect-status` / `--expect-rate`: assertions on the repeated probe
//
// The single-shot `--expect-*` above gates one response's shape. `probe`
// aggregates `--count` attempts per address and gates on the *aggregate*
// (DEC-075): the observed HTTP status distribution must stay within the
// accepted set, and the aggregate success rate must meet a threshold — the
// stability dimension a single response can never cover.

/// Run `probe --protocol http` against the fixture with the given extra args.
fn run_probe_expect(fixture: &FixtureServer, extra: &[&str]) -> (bool, String, String) {
    let out = Command::cargo_bin("ip-tools")
        .expect("ip-tools binary")
        .args([
            "probe",
            &fixture.tcp_addr().to_string(),
            "--insecure",
            "--timeout",
            "2000",
        ])
        .args(extra)
        .output()
        .expect("run repeated probe with expectations");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn probe_cli_expect_status_gates_the_http_repeat_distribution() {
    // The default fixture route answers 200 on every attempt, so a 200/2xx
    // status assertion must pass; a mismatched code or class must fail on
    // stderr, naming the destination and the offending statuses.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    let (ok, _, stderr) = run_probe_expect(
        &fixture,
        &["--protocol", "http", "--count", "6", "--expect-status", "200"],
    );
    assert!(ok, "--expect-status 200 should pass on an all-200 repeat: {stderr}");

    let (ok, _, stderr) = run_probe_expect(
        &fixture,
        &["--protocol", "http", "--count", "6", "--expect-status", "2xx"],
    );
    assert!(ok, "--expect-status 2xx should pass on an all-200 repeat: {stderr}");

    let (ok, _, stderr) = run_probe_expect(
        &fixture,
        &["--protocol", "http", "--count", "6", "--expect-status", "404"],
    );
    assert!(!ok, "--expect-status 404 must fail on an all-200 repeat");
    assert!(
        stderr.contains("expectation violated:"),
        "a violation verdict must name the destination: {stderr}"
    );

    // A redirect host answers 302 on every attempt: the 3xx class passes, and
    // a 2xx assertion fails on the observed distribution.
    let (ok, _, stderr) = run_probe_expect(
        &fixture,
        &[
            "--protocol",
            "http",
            "--count",
            "4",
            "--sni",
            "redirect.invalid",
            "--expect-status",
            "3xx",
        ],
    );
    assert!(ok, "--expect-status 3xx should pass on an all-302 repeat: {stderr}");

    let (ok, _, stderr) = run_probe_expect(
        &fixture,
        &[
            "--protocol",
            "http",
            "--count",
            "4",
            "--sni",
            "redirect.invalid",
            "--expect-status",
            "2xx",
        ],
    );
    assert!(!ok, "--expect-status 2xx must fail on an all-302 repeat");
    assert!(
        stderr.contains("302x4"),
        "the violation must show the offending status distribution: {stderr}"
    );
}

#[test]
fn probe_cli_expect_rate_gates_the_http_repeat_aggregate() {
    // Every attempt against the fixture completes, so the aggregate success
    // rate is 1.0: a reliability threshold at or below 100% must pass and
    // leave the default exit semantics untouched.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let fixture = rt.block_on(FixtureServer::start());

    for rate in ["0.5", "1", "100%"] {
        let (ok, _, stderr) =
            run_probe_expect(&fixture, &["--protocol", "http", "--count", "6", "--expect-rate", rate]);
        assert!(
            ok,
            "--expect-rate {rate} should pass when every attempt succeeds: {stderr}"
        );
    }
}
