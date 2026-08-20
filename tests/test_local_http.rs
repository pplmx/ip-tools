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

// --- repeated HTTP probing (probe --protocol) ---------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn http_repeat_against_fixture_aggregates_all_protocols() {
    let fixture = FixtureServer::start().await;
    let c = 3usize;
    let h1 = probe::http_repeat(fixture.tcp_addr(), "localhost", "GET", c, timeout(), true).await;
    assert_eq!(h1.successes, c, "http1 repeat should be all-success: {h1:?}");
    let h2 = probe::http2_repeat(fixture.tcp_addr(), "localhost", "GET", c, timeout(), true).await;
    assert_eq!(h2.successes, c, "http2 repeat should be all-success: {h2:?}");
    let h3 = probe::http3_repeat(fixture.udp_addr(), "localhost", "GET", c, timeout(), true).await;
    assert_eq!(h3.successes, c, "http3 repeat should be all-success: {h3:?}");
    assert_eq!(h3.latency.count, c, "http3 repeat should yield latency samples");
    assert!(h3.failure_counts.is_empty());
}

// --- HTTP/3 error paths (QUIC handshake/black-hole UDP) ---------------------

#[tokio::test(flavor = "multi_thread")]
async fn http3_probe_times_out_against_silent_udp_socket() {
    // A bound-but-silent UDP socket accepts the QUIC client's packets and
    // never answers: the handshake must time out (our wall-clock bound), not
    // hang forever or report success.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent udp");
    let addr = sock.local_addr().expect("silent udp addr");

    let obs = http3::probe(addr, "localhost", "GET", Duration::from_millis(600)).await;
    assert!(obs.failure.is_some(), "silent UDP must not report success: {obs:?}");
    let failure = obs.failure.as_ref().expect("expected a timeout failure");
    assert_eq!(
        failure.kind,
        ip_tools::FailureKind::Timeout,
        "unexpected kind: {failure:?}"
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

    let obs = http3::probe(addr, "localhost", "GET", Duration::from_millis(800)).await;
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

    let obs = http::probe(addr, "localhost", "GET", Duration::from_millis(500)).await;
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
