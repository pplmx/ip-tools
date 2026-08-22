//! Integration tests for the probe-family and diagnose CLI subcommands
//! against fully local listeners. Deterministic: no external network, no
//! privileges required.
//!
//! These cover the thin `cli/*` handler wrappers (`tcp`, `tls`, `http`,
//! `http2`, `http3`, `probe`, `dns`, `diagnose`, `route`) that the probe
//! engine itself cannot test in-process.

use assert_cmd::Command;
use predicates::str::contains;
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
fn tcp_cli_csv_export_renders_rows() {
    // `tcp --csv` emits a header + one row per destination with reachability,
    // latency and failure kind — a fleet TCP sweep loads into a spreadsheet.
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args(["tcp", &addr.to_string(), "--csv", "--timeout", "800"])
            .assert()
            .success(),
    );
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("host,destination,success,latency_ms,failure"));
    assert!(
        lines.any(|l| l.starts_with(&format!("127.0.0.1,{addr},1,"))),
        "expected a reachable row for {addr}: {out}"
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
    // Each failed probe must keep and render its protocol identity, so the
    // HTTP/1.1, HTTP/2 and HTTP/3 rows are distinguishable on a failing host.
    let expected = [("http", "HTTP/1.1"), ("http2", "HTTP/2"), ("http3", "HTTP/3")];
    for (sub, protocol) in expected {
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
        assert!(
            out.contains(protocol),
            "{sub} failure must keep its protocol label ({protocol}): {out}"
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
fn probe_cli_protocol_tls_accepts_and_reports_failures_on_plain_listener() {
    // `probe --protocol tls` must be accepted by the CLI and aggregate TLS
    // handshakes. Against a plain TCP listener the handshake fails, so the
    // report shows a classified failure, not a crash or a misleading success.
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--protocol",
                "tls",
                "--count",
                "2",
                "--timeout",
                "800",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("Repeated probes"), "probe heading missing: {out}");
    assert!(out.contains("attempts: 2"), "expected 2 attempts: {out}");
    assert!(out.contains("failure:  2"), "expected 2 failures: {out}");
}

#[test]
fn probe_cli_rejects_zero_count() {
    // `--count 0` would probe nothing yet render a vacuous "0 attempts, 0.0%
    // success" report and exit 0; a count of zero is a caller mistake and must
    // fail with a clear error instead (matching how `route` never runs zero
    // probes per hop).
    let addr = local_tcp_listener();
    cmd()
        .args(["probe", &addr.to_string(), "--count", "0", "--timeout", "800"])
        .assert()
        .failure()
        .stderr(contains("--count"));
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
fn dns_cli_record_type_selects_a_single_record_type() {
    let server = local_dns_server(&["192.0.2.77"], &["2001:db8::77"]);

    // `--record-type A` restricts the query to A (no AAAA row).
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--record-type",
                "A",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("192.0.2.77"), "A (via --record-type) missing: {out}");
    assert!(
        !out.contains("2001:db8::77"),
        "--record-type A must exclude AAAA: {out}"
    );

    // `--record-type CNAME` queries a new type; the A-only responder yields
    // no CNAME answers but the run succeeds (query plumbed without error).
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--record-type",
                "CNAME",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(
        !out.contains("192.0.2.77"),
        "--record-type CNAME must not show A: {out}"
    );

    // CAA and SRV are accepted record types (the A-only responder returns no
    // answers for them, but the query runs cleanly).
    for rt in ["CAA", "SRV"] {
        let out = stdout(
            &cmd()
                .args([
                    "dns",
                    "host.example",
                    "--server",
                    &server.to_string(),
                    "--record-type",
                    rt,
                    "--timeout",
                    "1200",
                ])
                .assert()
                .success(),
        );
        assert!(!out.contains("192.0.2.77"), "--record-type {rt} must not show A: {out}");
    }

    // Unknown and conflicting values are rejected.
    cmd()
        .args([
            "dns",
            "host.example",
            "--server",
            &server.to_string(),
            "--record-type",
            "BOGUS",
        ])
        .assert()
        .failure();
    cmd()
        .args([
            "dns",
            "host.example",
            "--server",
            &server.to_string(),
            "--record-type",
            "A",
            "--ipv6",
        ])
        .assert()
        .failure();
}

#[test]
fn dns_cli_count_repeats_and_aggregates_latency_stats() {
    let server = local_dns_server(&["192.0.2.77"], &[]);
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--count",
                "5",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("Repeated DNS"), "repeat heading missing: {out}");
    assert!(out.contains("host.example"), "host label missing: {out}");
    assert!(
        out.contains("success:  5 (100.0%)"),
        "all five resolutions should aggregate as success: {out}"
    );
    assert!(out.contains("attempts: 5"), "attempt count wrong: {out}");
    assert!(out.contains("p50:"), "latency stats missing: {out}");
}

#[test]
fn dns_cli_count_of_one_keeps_single_shot_output() {
    let server = local_dns_server(&["192.0.2.77"], &[]);
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--count",
                "1",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    // A single query is the ordinary per-resolver address report, not the
    // repeat aggregation — `--count 1` must not switch output mode.
    assert!(out.contains("DNS host.example"), "single-shot header missing: {out}");
    assert!(out.contains("192.0.2.77"), "A record missing: {out}");
    assert!(!out.contains("Repeated DNS"), "--count 1 must stay single-shot: {out}");
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
fn diagnose_cli_uses_custom_resolver_dns_observations() {
    // diagnose --server must query the custom resolver so the DNS observations
    // that feed the engine include resolver disagreement (previously only the
    // system resolver was queried). A fake local DNS server supplies A
    // 192.0.2.77.
    let dns_server = local_dns_server(&["192.0.2.77"], &[]);
    let out = stdout(
        &cmd()
            .args([
                "diagnose",
                "host.example",
                "--server",
                &dns_server.to_string(),
                "--timeout",
                "400",
            ])
            .assert()
            .success(),
    );
    // The custom resolver's DNS observation must appear in the report...
    assert!(out.contains("192.0.2.77"), "custom-resolver DNS record missing: {out}");
    // ...and the diagnoses rendered regardless of the (unroutable TEST-NET)
    // probe outcome.
    assert!(out.contains("Diagnosis"), "diagnoses missing: {out}");
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
    // The full evidence stack must be rendered in text mode, not only
    // DNS + TCP + verdicts (TLS/HTTP/probe phases may report failures
    // against a plain listener but must still appear).
    assert!(out.contains("TLS handshake"), "diagnose should show TLS phase: {out}");
    assert!(out.contains("HTTPS"), "diagnose should show HTTP phases: {out}");
    assert!(
        out.contains("Repeated probes"),
        "diagnose should show probe phase: {out}"
    );
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
    let lower = text.to_lowercase();
    if code == 0 {
        assert!(text.contains("Traceroute"), "expected traceroute output: {text}");
    } else {
        // Linux without privileges -> ICMP/root error; non-Linux -> the
        // "supported only on Linux" gate. Either way it must not panic.
        assert!(
            lower.contains("icmp") || lower.contains("root") || lower.contains("linux"),
            "route must explain it needs ICMP/root (linux) or is unsupported: {text}"
        );
    }
}

#[test]
fn invalid_target_produces_clean_error() {
    let err = stderr(&cmd().args(["tcp", "1.2.3.4.5"]).assert().failure());
    assert!(err.contains("Error"), "invalid target must error: {err}");
}

#[test]
fn probe_cli_resolves_via_custom_dns_server() {
    // `--server` must steer resolution for the probe commands, not just
    // `dns`/`diagnose`: the only address for the reserved `.example` hostname
    // comes from the custom DNS server (the system resolver returns NXDOMAIN),
    // and that address is what gets probed.
    let dns_server = local_dns_server(&["127.0.0.1"], &[]);
    let listener = local_tcp_listener();
    let target = format!("host.example:{}", listener.port());
    let out = stdout(
        &cmd()
            .args(["tcp", &target, "--server", &dns_server.to_string(), "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("PASS"), "tcp via custom resolver should PASS: {out}");

    // The same steering applies to the repeated-probe subcommand (shared flow).
    let out = stdout(
        &cmd()
            .args([
                "probe",
                &target,
                "--server",
                &dns_server.to_string(),
                "--count",
                "2",
                "--timeout",
                "800",
            ])
            .assert()
            .success(),
    );
    assert!(
        out.contains("127.0.0.1") && out.contains("success:  2"),
        "probe via custom resolver should show 2 successes on the custom address: {out}"
    );
}

#[test]
fn probe_cli_rejects_invalid_server() {
    let err = stderr(
        &cmd()
            .args(["tcp", "example.com", "--server", "not-an-ip"])
            .assert()
            .failure(),
    );
    assert!(err.contains("Error"), "invalid server must error: {err}");
}

/// A loopback TCP port that nothing is listening on (bound then dropped).
fn closed_loopback_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind probe port");
    l.local_addr().expect("probe port addr")
}

#[test]
fn tcp_cli_probes_bracketed_ipv6_literal() {
    // Bracket-form IPv6 targets (as produced by the `[::1]:port` syntax) must
    // resolve to the literal and be probed, instead of being sent to a DNS
    // resolver. Skipped when the platform has no IPv6 loopback.
    let Ok(listener) = TcpListener::bind("[::1]:0") else {
        eprintln!("skipping: no IPv6 loopback available");
        return;
    };
    let addr = listener.local_addr().expect("v6 listener address");
    std::thread::spawn(move || while listener.accept().is_ok() {});
    // SocketAddr's Display is already bracket-form: `[::1]:1234`.
    let out = stdout(
        &cmd()
            .args(["tcp", &addr.to_string(), "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("PASS"), "bracketed IPv6 target should PASS: {out}");

    // The TLS command must also accept a bracketed IPv6 literal (SNI handling
    // exists, but the request-build must not fail on the bracket form).
    let out = stdout(
        &cmd()
            .args(["tls", &addr.to_string(), "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("TLS handshake"), "tls CLI header missing: {out}");
}

#[test]
fn tcp_cli_ipv4_and_ipv6_filter_the_probed_family() {
    // `--ipv4`/`--ipv6` restrict a sweep to one address family. Against the
    // IPv4 loopback, `--ipv4` reaches the listener and `--ipv6` filters it to
    // no addresses (exit 0, no probe output); passing both is a parse error.
    let addr = local_tcp_listener();

    let out = stdout(
        &cmd()
            .args(["tcp", &addr.to_string(), "--ipv4", "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("PASS"), "--ipv4 should probe the v4 loopback: {out}");

    let out = stdout(
        &cmd()
            .args(["tcp", &addr.to_string(), "--ipv6", "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(!out.contains("PASS"), "--ipv6 must filter out the IPv4 loopback: {out}");

    cmd()
        .args(["tcp", &addr.to_string(), "--ipv4", "--ipv6"])
        .assert()
        .failure();
}

#[test]
fn strict_exits_nonzero_only_when_probe_fails() {
    // A failed probe is an observation: by default the CLI still exits 0...
    let closed = closed_loopback_port();
    cmd()
        .args(["tcp", &closed.to_string(), "--timeout", "400"])
        .assert()
        .success();

    // ...but `--strict` turns any failed probe into a non-zero exit.
    let err = stderr(
        &cmd()
            .args(["tcp", &closed.to_string(), "--timeout", "400", "--strict"])
            .assert()
            .failure(),
    );
    assert!(err.contains("failed"), "strict failure should be reported: {err}");

    // When every probe completes, --strict must still exit 0.
    let ok = local_tcp_listener();
    cmd()
        .args(["tcp", &ok.to_string(), "--timeout", "800", "--strict"])
        .assert()
        .success();

    // The repeated-probe subcommand shares the strict semantic (any failed
    // attempt exits non-zero).
    cmd()
        .args([
            "probe",
            &closed.to_string(),
            "--strict",
            "--count",
            "2",
            "--timeout",
            "400",
        ])
        .assert()
        .failure();
    cmd()
        .args(["probe", &ok.to_string(), "--strict", "--count", "2", "--timeout", "800"])
        .assert()
        .success();
}

#[test]
fn dns_strict_exits_nonzero_only_when_a_lookup_fails() {
    // A failed DNS lookup is an observation: without --strict the CLI exits 0
    // even when the (custom) resolver cannot answer. `host.example` never
    // resolves, so the custom server failure is guaranteed regardless of the
    // environment's system resolver.
    let closed = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind closed udp port");
        s.local_addr().expect("closed udp addr")
    };
    let base = [
        "dns",
        "host.example",
        "--server",
        &closed.to_string(),
        "--timeout",
        "400",
    ];
    cmd().args(base.iter().copied()).assert().success();

    // ...but `--strict` turns any failed lookup into a non-zero exit.
    let err = stderr(&cmd().args(base.iter().copied().chain(["--strict"])).assert().failure());
    assert!(err.contains("failed"), "dns --strict should report failures: {err}");
}

#[test]
fn diagnose_strict_exits_nonzero_only_when_anomaly_diagnosed() {
    // A closed loopback port is a deterministic local anomaly: diagnose raises
    // a loss diagnosis but (without --strict) the CLI still exits 0...
    let closed = closed_loopback_port();
    cmd()
        .args(["diagnose", &closed.to_string(), "--timeout", "400"])
        .assert()
        .success();

    // ...while `--strict` makes any non-`Healthy` diagnosis a non-zero exit.
    let err = stderr(
        &cmd()
            .args(["diagnose", &closed.to_string(), "--timeout", "400", "--strict"])
            .assert()
            .failure(),
    );
    assert!(err.contains("anomaly diagnosis"), "diagnose --strict: {err}");
}

#[test]
fn route_strict_exits_nonzero_only_on_lost_hops() {
    // Privileged: loopback traceroute completes with no lost hops, so
    // --strict exits 0. Unprivileged (or non-Linux): the traceroute fails
    // cleanly with the ICMP/root/linux explanation, which is also a non-zero
    // exit. Either way the process must not panic.
    let assert = cmd()
        .args([
            "route",
            "127.0.0.1",
            "--max-hops",
            "1",
            "--probes-per-hop",
            "1",
            "--timeout",
            "300",
            "--strict",
        ])
        .assert();
    let code = assert.get_output().status.code().unwrap_or(-999);
    let text = format!("{}\n{}", stdout(&assert), stderr(&assert));
    let lower = text.to_lowercase();
    if code == 0 {
        assert!(text.contains("Traceroute"), "expected traceroute output: {text}");
    } else {
        assert!(
            lower.contains("icmp") || lower.contains("root") || lower.contains("linux"),
            "route must explain it needs ICMP/root (linux) or is unsupported: {text}"
        );
    }
}

#[test]
fn diagnose_cli_sni_presents_chosen_hostname_against_listener() {
    // `diagnose <ip> --sni host` must accept the flag and present the chosen
    // name as SNI (and HTTP Host) while still targeting the literal address —
    // the whole diagnosis is scoped to "how does this address behave as that
    // hostname". Against a plain TCP listener the TLS/HTTP phases fail, but
    // the failure rows must name the overridden SNI/host, not the literal.
    // (The full-name-to-wire proof lives in the fixture-gated
    // `http_cli_sni_override_reaches_the_http_host_header` test.)
    let addr = local_tcp_listener();
    let out = stdout(
        &cmd()
            .args([
                "diagnose",
                &addr.to_string(),
                "--sni",
                "host.example",
                "--timeout",
                "400",
            ])
            .assert()
            .success(),
    );
    assert!(
        out.contains("host.example"),
        "diagnose --sni should surface the presented name in output: {out}"
    );
    assert!(out.contains("Diagnosis"), "diagnoses missing: {out}");
    // The literal address should still be the destination being probed.
    assert!(
        out.contains(&addr.ip().to_string()),
        "the targeted literal address must remain the destination: {out}"
    );
}
