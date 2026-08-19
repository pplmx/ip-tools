//! Integration tests for the probe pipeline against a fully local TLS/HTTP
//! fixture (self-signed cert + HTTP/1.1, HTTP/2 and HTTP/3 servers).
//!
//! Deterministic: no external network. Enabled by
//! `cargo test --features test-server`.
#![cfg(feature = "test-server")]

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
