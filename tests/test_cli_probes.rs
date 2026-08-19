//! Integration tests for the probe-family and diagnose CLI subcommands
//! against fully local listeners. Deterministic: no external network, no
//! privileges required.
//!
//! These cover the thin `cli/*` handler wrappers (`tcp`, `tls`, `http`,
//! `http2`, `http3`, `probe`, `dns`, `diagnose`, `route`) that the probe
//! engine itself cannot test in-process.

use assert_cmd::Command;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::thread;

/// Bind a plain TCP listener on the loopback that accepts connections.
/// Returns its socket address; a background thread consumes them (accepted
/// connections are dropped immediately, so clients see a reset, not a hang).
fn local_tcp_listener() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let addr = listener.local_addr().expect("listener address");
    thread::spawn(move || while listener.accept().is_ok() {});
    addr
}

/// A minimal in-process DNS server answering A / AAAA queries for any name
/// with the configured addresses (mirrors the unit-test responder in dns.rs).
fn local_dns_server(ipv4: &[&str], ipv6: &[&str]) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind dns server");
    let addr = sock.local_addr().expect("dns server address");
    let ipv4: Vec<IpAddr> = ipv4.iter().map(|a| a.parse().unwrap()).collect();
    let ipv6: Vec<IpAddr> = ipv6.iter().map(|a| a.parse().unwrap()).collect();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            if let Some(resp) = response(&buf[..n], &ipv4, &ipv6) {
                let _ = sock.send_to(&resp, peer);
            }
        }
    });
    addr
}

/// Build a standard DNS response to one A/AAAA query.
fn response(query: &[u8], ipv4: &[IpAddr], ipv6: &[IpAddr]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let id = [query[0], query[1]];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    loop {
        let len = *query.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        pos += len;
    }
    let question = &query[12..pos + 4];
    let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);
    let answers: Vec<IpAddr> = match qtype {
        1 => ipv4.to_vec(),
        28 => ipv6.to_vec(),
        _ => Vec::new(),
    };
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&qdcount.to_be_bytes());
    let ancount = u16::try_from(answers.len()).expect("fewer than 65536 answers");
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(question);
    for ip in &answers {
        out.extend_from_slice(&[0xC0, 0x0C]);
        let (type_code, rdlen): (u16, u16) = if ip.is_ipv4() { (1, 4) } else { (28, 16) };
        out.extend_from_slice(&type_code.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&rdlen.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
        }
    }
    Some(out)
}

fn cmd() -> Command {
    Command::cargo_bin("ip-tools").expect("ip-tools binary")
}

fn stdout(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn stderr(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

#[test]
fn tcp_cli_reports_pass_and_json() {
    let addr = local_tcp_listener();
    let out = stdout(&cmd().args(["tcp", &addr.to_string()]).assert().success());
    assert!(out.contains("PASS"), "tcp CLI should report PASS: {out}");

    let out = stdout(&cmd().args(["tcp", &addr.to_string(), "--json"]).assert().success());
    assert!(
        out.contains("\"success\": true"),
        "json output must carry success payload: {out}"
    );
}

#[test]
fn tls_cli_reports_failure_against_plain_listener() {
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args(["tls", &addr.to_string(), "--timeout", "800"])
            .assert()
            .success(),
    );
    // TCP connects but the TLS handshake cannot complete: the CLI must report
    // a failure rather than crash.
    assert!(out.contains("TLS handshake"), "tls CLI header missing: {out}");
}

#[test]
fn http_cli_probes_fail_against_plain_listener() {
    let addr = local_tcp_listener();
    for sub in ["http", "http2", "http3"] {
        let out = stdout(
            &cmd()
                .args([sub, &addr.to_string(), "--timeout", "800"])
                .assert()
                .success(),
        );
        assert!(
            out.contains("HTTPS") || out.contains("failed") || out.contains("timed out"),
            "{sub} CLI should render a probe report: {out}"
        );
    }
}

#[test]
fn probe_cli_repeats_and_aggregates() {
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args(["probe", &addr.to_string(), "--count", "3", "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("Repeated probes"), "probe heading missing: {out}");
    assert!(out.contains("success:  3"), "expected 3 successes: {out}");
}

#[test]
fn dns_cli_resolves_via_custom_local_server() {
    let server = local_dns_server(&["192.0.2.77"], &["2001:db8::77"]);
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("192.0.2.77"), "A record missing: {out}");
    assert!(out.contains("2001:db8::77"), "AAAA record missing: {out}");

    // --ipv6 queries AAAA only.
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--ipv6",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("2001:db8::77"), "AAAA with --ipv6 missing: {out}");
    assert!(!out.contains("192.0.2.77"), "--ipv6 must not include A: {out}");
}

#[test]
fn dns_cli_rejects_invalid_server() {
    let err = stderr(
        &cmd()
            .args(["dns", "example.com", "--server", "not-an-ip"])
            .assert()
            .failure(),
    );
    assert!(err.contains("Error"), "invalid server must error: {err}");
}

#[test]
fn diagnose_cli_runs_full_pipeline_against_listener() {
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args(["diagnose", &addr.to_string(), "--timeout", "400"])
            .assert()
            .success(),
    );
    assert!(out.contains("TCP connect"), "diagnose should show TCP phase: {out}");
    assert!(out.contains("Diagnosis"), "diagnose should render diagnoses: {out}");
}

#[test]
fn route_cli_rejects_ipv6_target() {
    // The route traceroute is IPv4-only on Linux; the v6 guard must error
    // deterministically rather than attempt a raw socket.
    let err = stderr(
        &cmd()
            .args(["route", "::1", "--max-hops", "2", "--timeout", "300"])
            .assert()
            .failure(),
    );
    assert!(err.contains("IPv4"), "expected IPv4-only guard error: {err}");
}

#[test]
fn route_cli_runs_or_errors_gracefully_on_loopback() {
    // On a privileged runner the traceroute runs and renders hops; on an
    // unprivileged runner it must fail with a clear "requires root/CAP_NET_RAW"
    // style error. Either way the process must not panic.
    let assert = cmd()
        .args([
            "route",
            "127.0.0.1",
            "--max-hops",
            "3",
            "--probes-per-hop",
            "1",
            "--timeout",
            "300",
        ])
        .assert();
    let code = assert.get_output().status.code().unwrap_or(-999);
    let text = format!("{}\n{}", stdout(&assert), stderr(&assert));
    if code == 0 {
        assert!(text.contains("Traceroute"), "expected traceroute output: {text}");
    } else {
        assert!(
            text.to_lowercase().contains("icmp") || text.contains("root"),
            "unprivileged route must explain it needs ICMP/root: {text}"
        );
    }
}

#[test]
fn invalid_target_produces_clean_error() {
    let err = stderr(&cmd().args(["tcp", "1.2.3.4.5"]).assert().failure());
    assert!(err.contains("Error"), "invalid target must error: {err}");
}
