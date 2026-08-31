//! TCP connectivity probes.
//!
//! Each probe is a single `connect()` to one destination socket address with
//! an explicit, configurable timeout. Failure modes are classified into
//! distinct categories (timeout, refused, reset, unreachable, …) — they are
//! never collapsed together.

use crate::model::{FailureKind, ProbeError, TcpObservation};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// Perform a single TCP connect probe to `destination`, bounded by `timeout`.
///
/// # Examples
///
/// ```no_run
/// use ip_tools::tcp;
/// use std::net::SocketAddr;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
/// let obs = tcp::probe(addr, Duration::from_secs(2)).await;
/// println!("reachable={} latency_ms={:?}", obs.success, obs.latency_ms);
/// # });
/// ```
///
/// Returns the observation; it never returns an `Err` — failures are captured
/// inside the observation as a classified [`ProbeError`].
pub async fn probe(destination: SocketAddr, timeout: Duration) -> TcpObservation {
    let start = Instant::now();
    let outcome = tokio::time::timeout(timeout, TcpStream::connect(destination)).await;

    match outcome {
        Ok(Ok(_stream)) => TcpObservation {
            destination,
            success: true,
            latency_ms: Some(start.elapsed().as_millis() as u64),
            failure: None,
        },
        Ok(Err(e)) => {
            let kind = classify_io_error(&e);
            TcpObservation {
                destination,
                success: false,
                latency_ms: None,
                failure: Some(ProbeError {
                    kind,
                    message: e.to_string(),
                }),
            }
        }
        Err(_elapsed) => TcpObservation {
            destination,
            success: false,
            latency_ms: None,
            failure: Some(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("connect to {destination} timed out after {timeout:?}"),
            }),
        },
    }
}

/// Classify an OS I/O error into a [`FailureKind`].
///
/// Standard `ErrorKind` covers refused/reset/timeout. Unreachable conditions
/// have no stable `ErrorKind`, so they are recovered from the raw OS error
/// code (Linux and macOS values).
///
/// The neighbouring local-stack denial codes — "no local source address for
/// this family/scope" (EADDRNOTAVAIL), "address family not supported"
/// (EAFNOSUPPORT), "host is down" (EHOSTDOWN), and local egress policy
/// denials (EACCES/EPERM) — are folded into the local-unreachable kinds on
/// the same grounds the engine documents for ENETUNREACH/EHOSTUNREACH: they
/// are reported by the local stack *before any packet is sent to the
/// destination*, so they are evidence about the host's own addressing/routing
/// state, not about the destination path. Keeping them out of `Other` lets
/// the diagnostic engine's local-condition exclusions (which match these two
/// kinds) avoid raising a false HIGH total-loss verdict or a false `--strict`
/// failure that would blame the destination.
pub(crate) fn classify_io_error(e: &std::io::Error) -> FailureKind {
    use FailureKind::{ConnectionRefused, ConnectionReset, HostUnreachable, NetworkUnreachable, Other, Timeout};
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => ConnectionRefused,
        std::io::ErrorKind::ConnectionReset => ConnectionReset,
        std::io::ErrorKind::TimedOut => Timeout,
        _ => match e.raw_os_error() {
            // ENETUNREACH: 101 = Linux, 64 = macOS. EADDRNOTAVAIL: 99 = Linux,
            // 49 = macOS ("cannot assign requested address" — no usable local
            // source address, e.g. a global-scope IPv6 connect from a host with
            // only link-local/loopback). EAFNOSUPPORT: 97 = Linux, 47 = macOS
            // (address family not supported on this host). All are local-stack
            // conditions emitted before any packet is sent.
            Some(101 | 64 | 99 | 49 | 97 | 47) => NetworkUnreachable,
            // EHOSTUNREACH: 113 = Linux, 65 = macOS. EHOSTDOWN: 112 = Linux
            // (kernel ARP/ND says the host is down; macOS's EHOSTDOWN (64)
            // collides with its ENETUNREACH (64) above — both local, so the
            // collision is harmless). EACCES / EPERM (13 / 1, both platforms):
            // local egress policy denied the connect (SELinux/seccomp/container
            // firewall) — the local stack refused before any packet was sent.
            Some(113 | 65 | 112 | 13 | 1) => HostUnreachable,
            // ETIMEDOUT
            Some(110) => Timeout,
            // ECONNRESET
            Some(104) => ConnectionReset,
            // ECONNREFUSED
            Some(111) => ConnectionRefused,
            _ => Other,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32) -> std::io::Error {
        std::io::Error::from_raw_os_error(code)
    }

    #[test]
    fn classifies_refused_by_kind() {
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "r");
        assert_eq!(classify_io_error(&e), FailureKind::ConnectionRefused);
    }

    #[test]
    fn classifies_reset_by_kind() {
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "r");
        assert_eq!(classify_io_error(&e), FailureKind::ConnectionReset);
    }

    #[test]
    fn classifies_timeout_by_kind() {
        let e = std::io::Error::new(std::io::ErrorKind::TimedOut, "t");
        assert_eq!(classify_io_error(&e), FailureKind::Timeout);
    }

    #[test]
    fn classifies_unreachable_by_os_code() {
        assert_eq!(classify_io_error(&err(101)), FailureKind::NetworkUnreachable);
        // macOS variant of ENETUNREACH (the 134 arm previously masked its gap).
        assert_eq!(classify_io_error(&err(64)), FailureKind::NetworkUnreachable);
        assert_eq!(classify_io_error(&err(113)), FailureKind::HostUnreachable);
        assert_eq!(classify_io_error(&err(65)), FailureKind::HostUnreachable);
        assert_eq!(classify_io_error(&err(110)), FailureKind::Timeout);
        assert_eq!(classify_io_error(&err(104)), FailureKind::ConnectionReset);
        assert_eq!(classify_io_error(&err(111)), FailureKind::ConnectionRefused);
    }

    #[test]
    fn unknown_os_error_is_other() {
        assert_eq!(classify_io_error(&err(9999)), FailureKind::Other);
    }

    #[test]
    fn classifies_local_stack_denials_as_local_unreachability() {
        // EADDRNOTAVAIL (no local source address for this family/scope),
        // EAFNOSUPPORT (family unsupported), EHOSTDOWN and the egress-policy
        // codes EACCES/EPERM are all reported by the local stack before any
        // packet is sent — they must classify as local-unreachable (not
        // `Other`), or the diagnostic engine would read them as destination
        // path failures and raise a false HIGH total-loss verdict.
        assert_eq!(classify_io_error(&err(99)), FailureKind::NetworkUnreachable); // EADDRNOTAVAIL
        assert_eq!(classify_io_error(&err(49)), FailureKind::NetworkUnreachable); // EADDRNOTAVAIL (macOS)
        assert_eq!(classify_io_error(&err(97)), FailureKind::NetworkUnreachable); // EAFNOSUPPORT
        assert_eq!(classify_io_error(&err(47)), FailureKind::NetworkUnreachable); // EAFNOSUPPORT (macOS)
        assert_eq!(classify_io_error(&err(112)), FailureKind::HostUnreachable); // EHOSTDOWN
        assert_eq!(classify_io_error(&err(13)), FailureKind::HostUnreachable); // EACCES (egress policy)
        assert_eq!(classify_io_error(&err(1)), FailureKind::HostUnreachable); // EPERM (egress policy)
    }
}
