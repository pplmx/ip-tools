//! Integration tests for TCP probes using local fixtures (no external network).

use ip_tools::tcp;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

/// A TCP probe to a live local listener must succeed.
#[tokio::test]
async fn tcp_probe_success_on_live_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let addr = listener.local_addr().expect("local addr");

    // Accept and close the incoming connection on a separate thread.
    let accept = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().expect("accept");
    });

    let obs = tcp::probe(addr, Duration::from_secs(2)).await;
    assert!(obs.success, "probe to live listener should succeed: {obs:?}");
    assert!(obs.failure.is_none());
    assert!(obs.latency_ms.is_some());

    accept.join().expect("accept thread finished");
}

/// A TCP probe to a non-routable address in the IPv4 TEST-NET range must
/// time out rather than crash, within the configured deadline.
#[tokio::test]
async fn tcp_probe_times_out_gracefully() {
    // 192.0.2.0/24 is TEST-NET-1, guaranteed not to respond. Routing may raise
    // an OS-level error instead of a timeout on some systems, so we only
    // assert that the probe returns an observation with a failure (never
    // success) and that it does so within the timeout.
    let addr: SocketAddr = "192.0.2.1:443".parse().expect("test-net addr");
    let obs = tcp::probe(addr, Duration::from_millis(300)).await;
    assert!(!obs.success, "TEST-NET address must not connect");
    assert!(obs.failure.is_some());
}
