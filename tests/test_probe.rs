//! Integration tests for repeated probing against a local fixture.

use ip_tools::probe;
use std::net::TcpListener;
use std::time::Duration;

/// Repeated TCP probes to a live local listener all succeed and yield a
/// non-empty latency distribution with no failures.
#[tokio::test]
async fn tcp_repeat_to_live_listener_is_all_success() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local listener");
    let addr = listener.local_addr().expect("local addr");

    // Accept and close each incoming connection on a separate thread, so the
    // single-threaded tokio test runtime is never blocked.
    let acceptor = std::thread::spawn(move || {
        for _ in 0..8 {
            let _ = listener.accept();
        }
    });

    let result = probe::tcp_repeat(addr, 8, Duration::from_secs(2)).await;
    assert_eq!(result.attempts, 8);
    assert_eq!(result.successes, 8);
    assert_eq!(result.failures, 0);
    assert!((result.success_rate - 1.0).abs() < f64::EPSILON);
    assert!(result.latency.count == 8, "8 latency samples expected");
    assert!(result.latency.min.is_some());
    assert!(result.failure_counts.is_empty());
    acceptor.join().expect("acceptor thread finished");
}

/// Repeated TCP probes to a non-routable TEST-NET address always fail, so the
/// failure path (rate 0, no latency samples) is verified deterministically.
#[tokio::test]
async fn tcp_repeat_to_unroutable_address_is_all_failure() {
    let addr = "192.0.2.1:443".parse().expect("TEST-NET addr");
    let result = probe::tcp_repeat(addr, 4, Duration::from_millis(300)).await;
    assert_eq!(result.attempts, 4);
    assert_eq!(result.successes, 0);
    assert_eq!(result.failures, 4);
    assert!((result.success_rate - 0.0).abs() < f64::EPSILON);
    assert_eq!(result.latency.count, 0);
    assert!(!result.failure_counts.is_empty());
}
