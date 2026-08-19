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

    let icmp_fd = open_icmp_socket()?;
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
            let local_port = udp.local_addr().map(|a| a.port()).unwrap_or(0);
            if let Err(e) = udp.set_ttl(ttl as u32) {
                return Err(format!("failed to set TTL {ttl}: {e}"));
            }
            let probe_dest = SocketAddr::new(target, 33_434 + probe as u16);
            let _ = udp.send_to(&[0u8; 8], probe_dest);

            // Read ICMP replies until we match this probe, or time out.
            let start = std::time::Instant::now();
            let deadline = start + cfg.timeout;
            let mut buf = [0u8; 512];
            while std::time::Instant::now() < deadline {
                match recv_icmp(icmp_fd, &mut buf, deadline) {
                    Ok(None) => break, // timeout
                    Ok(Some((src, inner_udp_src))) => {
                        if inner_udp_src == local_port {
                            hop.addr = Some(src);
                            hop.rtt_ms = Some(start.elapsed().as_millis() as u64);
                            hop.lost = false;
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        hops.push(hop);
        // Terminate once the destination itself answered (port-unreachable).
        let last = hops.last().expect("hop pushed");
        if last.addr == Some(target) && !last.lost {
            break;
        }
    }

    unsafe { libc::close(icmp_fd) };
    Ok(hops)
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
            &tv as *const timeval as *const _,
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
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr as *mut _,
                &mut addr_len,
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
/// Layout: [outer IP header][ICMP header (8)][offending IP header][UDP].
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
    fn rejects_non_icmp_types() {
        let mut p = build_icmp_time_exceeded(0x1234);
        p[20] = 0; // echo reply
        assert_eq!(parse_icmp_udp_src(&p, p.len()), None);
    }

    #[test]
    fn rejects_short_buffers() {
        assert_eq!(parse_icmp_udp_src(&[0u8; 8], 8), None);
    }
}
