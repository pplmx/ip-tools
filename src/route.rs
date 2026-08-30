//! Route diagnostics (traceroute).
//!
//! This is the one truly platform-gated probe family. The current
//! implementation is **Linux-only** and requires privileges to open a raw
//! ICMP socket (i.e. `CAP_NET_RAW` / root). On other platforms or without
//! privileges it returns a clear error rather than pretending to work.
//!
//! A missing hop does *not* imply packet loss: routers routinely deprioritize
//! or filter TTL-expired responses, so the report records `lost` hops without
//! over-interpreting them.

use crate::model::{LatencyStats, LatencySummary};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// One hop in a route.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RouteHop {
    /// Time-to-live of this hop (1-based).
    pub ttl: u8,
    /// Router address responding for this hop, if any.
    pub addr: Option<IpAddr>,
    /// Reverse hostname of the router, if resolvable.
    pub hostname: Option<String>,
    /// Round-trip time in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Whether this hop produced no reply within the timeout.
    pub lost: bool,
}

/// Configuration for a traceroute run.
#[derive(Debug, Clone, Copy)]
pub struct TracerouteConfig {
    /// Maximum number of hops to try.
    pub max_hops: u8,
    /// Per-probe timeout.
    pub timeout: Duration,
    /// Probes sent per hop (for loss estimation).
    pub probes_per_hop: u8,
}

impl Default for TracerouteConfig {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout: Duration::from_secs(1),
            probes_per_hop: 3,
        }
    }
}

/// Aggregated observations for one TTL across a [`traceroute_repeat`] run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteHopStats {
    /// Time-to-live of this hop (1-based).
    pub ttl: u8,
    /// How many of the repeated runs this hop answered in (0 = every run lost).
    pub answered: u16,
    /// Distinct router addresses observed across the runs (empty if never answered).
    pub addrs: Vec<IpAddr>,
    /// Best-effort reverse hostname of the reported address, when resolvable.
    pub hostname: Option<String>,
    /// Round-trip latency distribution across the answered runs.
    pub rtt: LatencySummary,
    /// Whether more than one distinct router address was observed at this hop
    /// — the path (or a load-balanced next-hop) changed between runs.
    pub path_changed: bool,
}

/// The result of repeating a traceroute: per-hop aggregates over `runs` traces.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RouteRepeat {
    /// Number of traces aggregated.
    pub runs: usize,
    /// Per-hop aggregates in TTL order (the union of hops seen across runs).
    pub hops: Vec<RouteHopStats>,
}

/// Fold per-run hop lists into per-hop aggregates.
///
/// Pure, so unit-testable without a raw ICMP socket. A hop that answered in
/// some runs and was lost in others counts toward `answered` with the
/// latencies it produced; a hop never seen in a run is simply absent.
#[must_use]
pub fn aggregate_runs(hops_by_run: &[Vec<RouteHop>]) -> RouteRepeat {
    let mut by_ttl: BTreeMap<u8, (u16, Vec<IpAddr>, Option<String>, LatencyStats)> = BTreeMap::new();
    for run in hops_by_run {
        for hop in run {
            let entry = by_ttl
                .entry(hop.ttl)
                .or_insert_with(|| (0, Vec::new(), None, LatencyStats::default()));
            if hop.lost {
                continue;
            }
            entry.0 += 1;
            if let Some(addr) = hop.addr {
                if !entry.1.contains(&addr) {
                    entry.1.push(addr);
                }
            }
            if let Some(ms) = hop.rtt_ms {
                entry.3.push(ms);
            }
            if let Some(name) = &hop.hostname {
                if entry.2.is_none() && !name.is_empty() {
                    entry.2 = Some(name.clone());
                }
            }
        }
    }
    let runs = hops_by_run.len();
    let hops = by_ttl
        .into_iter()
        .map(|(ttl, (answered, addrs, hostname, latency))| RouteHopStats {
            ttl,
            answered,
            path_changed: addrs.len() > 1,
            addrs,
            hostname,
            rtt: latency.summarize(),
        })
        .collect();
    RouteRepeat { runs, hops }
}

/// Repeat a traceroute `count` times and aggregate the per-hop observations.
///
/// A single unstable hop (a flapping next-hop, a load-balanced router, BGP /
/// MPLS churn) becomes visible instead of whichever address answered last.
/// `count` is clamped to at least 1; `count == 1` yields the single-trace
/// shape (one address per answered hop, no path-change signal).
///
/// # Errors
///
/// Returns an error string when route diagnostics are unsupported on the
/// platform or the raw ICMP socket cannot be opened (the same gating as
/// [`traceroute`]).
pub fn traceroute_repeat(target: IpAddr, cfg: TracerouteConfig, count: usize) -> Result<RouteRepeat, String> {
    let mut runs = Vec::with_capacity(count.max(1));
    for _ in 0..count.max(1) {
        runs.push(traceroute(target, &cfg)?);
    }
    Ok(aggregate_runs(&runs))
}

/// Perform a UDP/ICMP traceroute to `target`, returning per-hop observations.
///
/// # Errors
///
/// Returns an error string when route diagnostics are unsupported on the
/// platform or the raw ICMP socket cannot be opened.
pub fn traceroute(target: IpAddr, cfg: &TracerouteConfig) -> Result<Vec<RouteHop>, String> {
    #[cfg(target_os = "linux")]
    {
        traceroute_linux(target, cfg)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target, cfg);
        Err("route diagnostics are currently supported only on Linux".to_string())
    }
}

#[cfg(target_os = "linux")]
fn traceroute_linux(target: IpAddr, cfg: &TracerouteConfig) -> Result<Vec<RouteHop>, String> {
    let IpAddr::V4(_) = target else {
        return Err("route diagnostics are currently IPv4-only on Linux".to_string());
    };

    // RAII guard so the raw ICMP socket is closed even on early-return error
    // paths (bind/set_ttl failures), not just on the happy path.
    let icmp_fd = RawSocket(open_icmp_socket()?);
    let mut hops = Vec::new();

    for ttl in 1..=cfg.max_hops {
        let mut hop = RouteHop {
            ttl,
            addr: None,
            hostname: None,
            rtt_ms: None,
            lost: true,
        };

        for probe in 0..cfg.probes_per_hop {
            // Bind a fresh UDP socket per probe; its local port is embedded in
            // the ICMP echo so replies can be matched to the right probe.
            let udp = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
                Ok(u) => u,
                Err(e) => return Err(format!("failed to bind UDP probe socket: {e}")),
            };
            // The local port is embedded in each probe so ICMP replies can be
            // matched back; if it cannot be read (a just-bound socket going
            // half-dead) the match below could never succeed, so fail loudly
            // instead of silently losing every hop with `map_or(0, ..)`.
            let local_port = match udp.local_addr() {
                Ok(a) => a.port(),
                Err(e) => return Err(format!("failed to read UDP probe socket port: {e}")),
            };
            if let Err(e) = udp.set_ttl(u32::from(ttl)) {
                return Err(format!("failed to set TTL {ttl}: {e}"));
            }
            let probe_dest = SocketAddr::new(target, 33_434 + u16::from(probe));
            // A failed send is a local transport error (e.g. the socket went
            // dead), not "the hop timed out": fail loudly so the run does not
            // spin the full per-hop timeout on a probe that never left.
            if let Err(e) = udp.send_to(&[0u8; 8], probe_dest) {
                return Err(format!("failed to send traceroute probe to {probe_dest}: {e}"));
            }

            // Read ICMP replies until we match this probe, or time out.
            let start = std::time::Instant::now();
            let deadline = start + cfg.timeout;
            let mut buf = [0u8; 512];
            while std::time::Instant::now() < deadline {
                match recv_icmp(icmp_fd.0, &mut buf, deadline) {
                    Ok(None) => break, // timeout
                    Ok(Some((src, inner_udp_src))) => {
                        if inner_udp_src == local_port {
                            hop.addr = Some(src);
                            hop.rtt_ms = Some(start.elapsed().as_millis() as u64);
                            hop.lost = false;
                            break;
                        }
                    }
                    Err(_) => {}
                }
            }
            // The hop answered: sending the remaining probes is wasted work —
            // routers commonly rate-limit TTL-exceeded replies, so the extra
            // probes would each spin the full timeout for no new information.
            if !hop.lost {
                break;
            }
        }

        hops.push(hop);
        // Terminate once the destination itself answered (port-unreachable).
        let last = hops.last().expect("hop pushed");
        if last.addr == Some(target) && !last.lost {
            break;
        }
    }

    Ok(hops)
}

/// Owns a raw socket fd and closes it on drop (RAII).
#[cfg(target_os = "linux")]
struct RawSocket(i32);

#[cfg(target_os = "linux")]
impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Open a raw ICMP socket with a receive timeout for non-blocking reads.
#[cfg(target_os = "linux")]
fn open_icmp_socket() -> Result<i32, String> {
    use libc::{setsockopt, socket, timeval, AF_INET, IPPROTO_ICMP, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO};
    use std::io;

    let fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if fd < 0 {
        return Err(format!(
            "failed to open raw ICMP socket (requires root/CAP_NET_RAW): {}",
            io::Error::last_os_error()
        ));
    }
    let tv = timeval {
        tv_sec: 0,
        tv_usec: 100_000, // 100ms poll granularity; the caller enforces the deadline
    };
    unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<timeval>() as u32,
        );
    }
    Ok(fd)
}

/// Receive one ICMP reply, returning `(source_ip, inner_udp_source_port)` or
/// `None` on timeout. Returns the source IP directly from the socket address.
#[cfg(target_os = "linux")]
fn recv_icmp(fd: i32, buf: &mut [u8], deadline: std::time::Instant) -> std::io::Result<Option<(IpAddr, u16)>> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    loop {
        // Use a short non-blocking receive so we can respect the deadline.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
                (&raw mut addr).cast::<libc::sockaddr>().cast(),
                &raw mut addr_len,
            )
        };
        if n > 0 {
            let src_ip_raw = u32::from_be(addr.sin_addr.s_addr);
            let src = IpAddr::V4(Ipv4Addr::from(src_ip_raw));
            if let Some((_t, src_port)) = parse_icmp_udp_src(buf, n as usize) {
                return Ok(Some((src, src_port)));
            }
            continue;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock || err.kind() == std::io::ErrorKind::TimedOut {
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            continue;
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        return Err(err);
    }
}

/// Parse an ICMP reply and return the offending datagram's UDP source port.
///
/// Layout: `outer IP header` + `ICMP header (8)` + `offending IP header` + `UDP`.
#[cfg(target_os = "linux")]
fn parse_icmp_udp_src(buf: &[u8], len: usize) -> Option<(u8, u16)> {
    if len < 28 {
        return None;
    }
    let outer_ihl = ((buf[0] & 0x0f) as usize) * 4;
    if outer_ihl + 8 > len {
        return None;
    }
    let icmp_type = buf[outer_ihl];
    // Time-exceeded (11) and destination-unreachable (3) echo the offending
    // datagram; anything else (e.g. echo-reply) we ignore.
    if icmp_type != 11 && icmp_type != 3 {
        return None;
    }
    let inner_start = outer_ihl + 8;
    if inner_start + 20 > len {
        return None;
    }
    let inner_ihl = ((buf[inner_start] & 0x0f) as usize) * 4;
    let udp_start = inner_start + inner_ihl;
    if udp_start + 4 > len {
        return None;
    }
    let src_port = u16::from_be_bytes([buf[udp_start], buf[udp_start + 1]]);
    Some((icmp_type, src_port))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::parse_icmp_udp_src;

    fn build_icmp_time_exceeded(inner_udp_src: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Outer IP header (IHL=5 => 20 bytes).
        p.push(0x45); // version 4, IHL 5
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // ICMP: type 11 (time exceeded), code 0, then 6 unused bytes.
        p.push(11);
        p.push(0);
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // Inner IP header (IHL=5).
        p.push(0x45);
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Inner UDP header: src port, dst port, len, checksum.
        p.extend_from_slice(&inner_udp_src.to_be_bytes());
        p.extend_from_slice(&[0x82, 0x9a, 0, 8, 0, 0]);
        p
    }

    #[test]
    fn parses_inner_udp_source_port() {
        let p = build_icmp_time_exceeded(0x1234);
        assert_eq!(parse_icmp_udp_src(&p, p.len()), Some((11, 0x1234)));
    }

    #[test]
    fn parses_destination_unreachable_as_the_final_hop_reply() {
        // ICMP type 3 (destination unreachable — the port-unreachable reply
        // the proxied destination sends) is the branch that terminates the
        // trace at the final hop (route.rs:226 comment). It must parse like a
        // time-exceeded hop, carrying the same inner UDP source port, with the
        // type surfaced so the traceroute recognizes the end.
        let mut p = build_icmp_time_exceeded(0x1234);
        p[20] = 3; // type: destination unreachable
        assert_eq!(parse_icmp_udp_src(&p, p.len()), Some((3, 0x1234)));
    }

    #[test]
    fn rejects_non_icmp_types() {
        let mut p = build_icmp_time_exceeded(0x1234);
        p[20] = 0; // echo reply
        assert_eq!(parse_icmp_udp_src(&p, p.len()), None);
        // A redirect (type 5) also carries no offending datagram to act on.
        p[20] = 5;
        assert_eq!(parse_icmp_udp_src(&p, p.len()), None);
    }

    #[test]
    fn rejects_short_buffers() {
        assert_eq!(parse_icmp_udp_src(&[0u8; 8], 8), None);
    }
}

#[cfg(test)]
mod repeat_tests {
    use super::aggregate_runs;
    use crate::RouteHop;

    fn hop(ttl: u8, addr: Option<&str>, rtt_ms: Option<u64>, lost: bool) -> RouteHop {
        RouteHop {
            ttl,
            addr: addr.map(|s| s.parse().unwrap()),
            hostname: None,
            rtt_ms,
            lost,
        }
    }

    #[test]
    fn stable_path_aggregates_a_single_router() {
        let runs = vec![
            vec![
                hop(1, Some("192.0.2.1"), Some(3), false),
                hop(2, Some("192.0.2.2"), Some(9), false),
            ],
            vec![
                hop(1, Some("192.0.2.1"), Some(5), false),
                hop(2, Some("192.0.2.2"), Some(11), false),
            ],
        ];
        let rep = aggregate_runs(&runs);
        assert_eq!(rep.runs, 2);
        assert_eq!(rep.hops.len(), 2);
        let h1 = &rep.hops[0];
        assert_eq!(h1.ttl, 1);
        assert_eq!(h1.answered, 2);
        assert_eq!(h1.addrs, vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]);
        assert!(!h1.path_changed, "a stable router must not flag a path change");
        assert_eq!(h1.rtt.count, 2);
        assert_eq!(h1.rtt.min, Some(3));
        assert_eq!(h1.rtt.max, Some(5));
    }

    #[test]
    fn divergent_path_lists_both_routers_and_flags_change() {
        let runs = vec![
            vec![hop(1, Some("192.0.2.1"), Some(2), false)],
            vec![hop(1, Some("192.0.2.9"), Some(4), false)],
        ];
        let rep = aggregate_runs(&runs);
        assert_eq!(rep.hops.len(), 1);
        let h = &rep.hops[0];
        assert_eq!(h.answered, 2);
        assert_eq!(h.addrs.len(), 2);
        assert!(h.path_changed, "two distinct routers must flag a path change");
        assert_eq!(h.rtt.min, Some(2));
        assert_eq!(h.rtt.max, Some(4));
    }

    #[test]
    fn lost_hops_count_answered_and_stay_empty() {
        // Hop 1 answered in run 1 but was lost in run 2; hop 2 was lost in both.
        let runs = vec![
            vec![hop(1, Some("192.0.2.1"), Some(3), false), hop(2, None, None, true)],
            vec![hop(1, None, None, true), hop(2, None, None, true)],
        ];
        let rep = aggregate_runs(&runs);
        assert_eq!(rep.hops.len(), 2);
        let h1 = &rep.hops[0];
        assert_eq!(h1.answered, 1, "hop answered in one of two runs");
        assert_eq!(h1.addrs, vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]);
        assert_eq!(h1.rtt.count, 1);
        let h2 = &rep.hops[1];
        assert_eq!(h2.answered, 0, "a fully-lost hop never answers");
        assert!(h2.addrs.is_empty());
    }

    #[test]
    fn runs_with_different_hop_sets_union_by_ttl() {
        // Run 1 terminated at hop 2 (destination answered); run 2 saw hop 1 only.
        let runs = vec![
            vec![
                hop(1, Some("192.0.2.1"), Some(2), false),
                hop(2, Some("192.0.2.2"), Some(3), false),
            ],
            vec![hop(1, Some("192.0.2.1"), Some(1), false)],
        ];
        let rep = aggregate_runs(&runs);
        assert_eq!(rep.hops.len(), 2, "both hops are in the union");
        assert_eq!(rep.hops[0].answered, 2);
        assert_eq!(rep.hops[1].answered, 1, "hop 2 only answered in the first run");
    }
}
