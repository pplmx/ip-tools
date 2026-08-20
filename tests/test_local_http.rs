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
use ip_tools::tcp;
use ip_tools::test_support::FixtureServer;
use ip_tools::tls;
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
}

#[tokio::test(flavor = "multi_thread")]
async fn http1_probe_gets_200_from_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = http::probe_with_roots(fixture.tcp_addr(), "localhost", "GET", timeout(), &fixture.roots).await;
    assert!(obs.failure.is_none(), "http1 probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/1.1"));
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_probe_gets_200_from_local_fixture() {
    let fixture = FixtureServer::start().await;
    let obs = http2::probe_with_roots(fixture.tcp_addr(), "localhost", "GET", timeout(), &fixture.roots).await;
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
    let obs = http3::probe_with_roots(fixture.udp_addr(), "localhost", "GET", timeout(), &fixture.roots).await;
    assert!(obs.failure.is_none(), "http3 probe failed: {:?}", obs.failure);
    assert_eq!(obs.status, Some(200), "expected 200 over QUIC: {obs:?}");
    assert_eq!(obs.protocol.as_deref(), Some("HTTP/3"), "expected HTTP/3: {obs:?}");
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
    let h1 = http::probe_insecure(fixture.tcp_addr(), "localhost", "GET", timeout()).await;
    assert_eq!(h1.status, Some(200), "http1 insecure: {h1:?}");
    let h2 = http2::probe_insecure(fixture.tcp_addr(), "localhost", "GET", timeout()).await;
    assert_eq!(h2.status, Some(200), "http2 insecure: {h2:?}");
    assert_eq!(h2.protocol.as_deref(), Some("HTTP/2"));
    let h3 = http3::probe_insecure(fixture.udp_addr(), "localhost", "GET", timeout()).await;
    assert_eq!(h3.status, Some(200), "http3 insecure: {h3:?}");
    assert_eq!(h3.protocol.as_deref(), Some("HTTP/3"));
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
