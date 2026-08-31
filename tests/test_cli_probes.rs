//! Integration tests for the probe-family and diagnose CLI subcommands
//! against fully local listeners. Deterministic: no external network, no
//! privileges required.
//!
//! These cover the thin `cli/*` handler wrappers (`tcp`, `tls`, `http`,
//! `http2`, `http3`, `probe`, `dns`, `diagnose`, `route`) that the probe
//! engine itself cannot test in-process.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
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

/// A minimal in-process DNS server answering every query with a single CNAME
/// whose target name embeds a raw ANSI ESC byte (`\x1b[31mEVIL`) — the wire
/// arranges for `dns`'s hand-rolled `read_name` decoder to pass a control byte
/// through; the report must escape it, never emit a live terminal sequence.
fn cname_escape_server() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind dns server");
    let addr = sock.local_addr().expect("dns server address");
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf) {
            if let Some(resp) = cname_response(&buf[..n]) {
                let _ = sock.send_to(&resp, peer);
            }
        }
    });
    addr
}

/// Build a DNS answer: one CNAME whose target is the label
/// `ESC [ 3 1 m E V I L` (9 bytes) then root.
fn cname_response(query: &[u8]) -> Option<Vec<u8>> {
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
    let target: Vec<u8> = {
        let mut t = vec![9u8];
        t.extend_from_slice(&[0x1b, b'[', b'3', b'1', b'm', b'E', b'V', b'I', b'L']);
        t.push(0u8); // root
        t
    };
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&id);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // one answer
    out.extend_from_slice(&[0u8; 4]); // ns, ar counts
    out.extend_from_slice(question);
    out.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer to qname
    out.extend_from_slice(&5u16.to_be_bytes()); // CNAME
    out.extend_from_slice(&[0, 1]); // IN
    out.extend_from_slice(&60u32.to_be_bytes()); // ttl
    let rdlen = u16::try_from(target.len()).expect("short target");
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(&target);
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
fn probe_flow_family_scope_empty_pool_fails_cleanly() {
    // `tcp --ipv6` on an IPv4-only hostname resolves the A record but the
    // scope empties the address pool. It must fail with a message naming the
    // scope — not silently exit 0 with zero probes and an empty report.
    let server = local_dns_server(&["192.0.2.77"], &[]);
    let assert = cmd()
        .args([
            "tcp",
            "host.example",
            "--server",
            &server.to_string(),
            "--ipv6",
            "--timeout",
            "1200",
        ])
        .assert()
        .failure();
    let err = stderr(&assert);
    assert!(
        err.contains("scope leaves no IPv6 addresses"),
        "--ipv6 must name the family-scoped empty pool: {err}"
    );
    // The plain run (both families, one address) still probes and reports that
    // address — scope-empty stays scoped-only.
    let out = stdout(
        &cmd()
            .args([
                "tcp",
                "host.example",
                "--server",
                &server.to_string(),
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(
        out.contains("192.0.2.77"),
        "unscoped run must still show the resolved address: {out}"
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
fn stdin_conflict_fails_fast_without_consuming_stdin() {
    // `target -` / `--header -` / `--body -` all read the same stdin; asking
    // for more than one must fail up front — the header parser runs before the
    // target list, so without the guard it would eat the user's target lines
    // and report them as malformed headers.
    cmd()
        .args(["http", "-", "--header", "-"])
        .write_stdin("1.1.1.1\n")
        .assert()
        .failure()
        .stderr(contains("only one input may come from stdin"));
    cmd()
        .args(["probe", "-", "--body", "-"])
        .write_stdin("x\n")
        .assert()
        .failure()
        .stderr(contains("only one input may come from stdin"));
    // A single stdin consumer still works (target list from stdin).
    let addr = local_tcp_listener();
    cmd()
        .args(["http", "-"])
        .write_stdin(format!("{addr}\n"))
        .assert()
        .success();
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
fn probe_cli_rejects_http_request_flags_for_non_http_protocols() {
    // `--method`/`--path`/`--header`/`--body` are silently ignored by the
    // tcp/tls protocol arms (no HTTP request is sent), and `--tls-version`
    // means nothing to a tcp repeat. Those mismatches must fail fast with a
    // clear error instead of appearing to be honored.
    let addr = local_tcp_listener();
    // The default-shaped values (`--method GET`, `--path /`, `--tls-version
    // auto`) are explicit-but-equal-to-default: an operator passing them
    // still believes they take effect, so they must be rejected too — the
    // earlier value-comparison against the defaults let exactly these slip
    // through silently.
    let cases: &[(&str, &str, &str)] = &[
        ("tls", "--path", "/x"),
        ("tcp", "--method", "HEAD"),
        ("tls", "--header", "x-test: 1"),
        ("tcp", "--body", "x"),
        ("tcp", "--tls-version", "1.2"),
        ("tcp", "--method", "GET"),
        ("tls", "--path", "/"),
        ("tcp", "--tls-version", "auto"),
    ];
    for (protocol, flag, value) in cases {
        let assert = cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--protocol",
                protocol,
                "--count",
                "2",
                "--timeout",
                "800",
                flag,
                value,
            ])
            .assert()
            .failure();
        let err = stderr(&assert);
        assert!(
            err.contains("only apply to --protocol http|http2|http3")
                || err.contains("only applies to --protocol tls|http|http2|http3"),
            "{flag} with --protocol {protocol} must fail with a protocol-scope error: {err}"
        );
    }
    // The HTTP-family protocols legitimately accept these flags.
    cmd()
        .args([
            "probe",
            &addr.to_string(),
            "--protocol",
            "http",
            "--count",
            "2",
            "--timeout",
            "800",
            "--path",
            "/",
            "--method",
            "GET",
        ])
        .assert()
        .success();
}

#[test]
fn probe_cli_rejects_tls_version_for_http3() {
    // QUIC is always TLS 1.3, so `--tls-version` on the http3 repeat is
    // meaningless: it would otherwise run silently as 1.3 while the operator
    // believes they pinned 1.2 (the standalone `http3` subcommand does not
    // even define the flag). It must fail fast with a clear scope error.
    let addr = local_tcp_listener();
    for value in ["1.2", "1.3", "auto"] {
        let assert = cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--protocol",
                "http3",
                "--count",
                "2",
                "--timeout",
                "800",
                "--tls-version",
                value,
            ])
            .assert()
            .failure();
        let err = stderr(&assert);
        assert!(
            err.contains("--tls-version does not apply to --protocol http3"),
            "--tls-version {value} with --protocol http3 must be rejected: {err}"
        );
    }
}

#[test]
fn probe_cli_rejects_sni_for_a_tcp_repeat() {
    // `--sni` names a TLS/SNI identity; a bare `tcp` repeat has no handshake,
    // so the flag used to be silently ignored (exit 0) while the standalone
    // `tcp` command rejects `--sni` at argument parse — the same silent
    // swallow the method/path/header/body guard fixed. It must fail fast,
    // while `--sni` stays valid on the TLS-over-TCP protocols.
    let addr = local_tcp_listener();
    cmd()
        .args([
            "probe",
            &addr.to_string(),
            "--protocol",
            "tcp",
            "--sni",
            "vhost.example",
            "--count",
            "2",
            "--timeout",
            "800",
        ])
        .assert()
        .failure()
        .stderr(contains("--sni does not apply to --protocol tcp"));
}

#[test]
fn probe_cli_rejects_insecure_for_a_tcp_repeat() {
    // `--insecure` disables certificate verification — meaningless where there
    // is no handshake. The standalone `tcp` subcommand doesn't define the flag,
    // so `probe --protocol tcp --insecure` used to run a plain TCP repeat
    // silently (exit 0). It must fail fast, while `--insecure` stays valid on
    // the TLS-over-TCP protocols.
    let addr = local_tcp_listener();
    cmd()
        .args([
            "probe",
            &addr.to_string(),
            "--protocol",
            "tcp",
            "--insecure",
            "--count",
            "2",
            "--timeout",
            "800",
        ])
        .assert()
        .failure()
        .stderr(contains("--insecure does not apply to --protocol tcp"));
}

#[test]
fn http_cli_rejects_an_invalid_path_at_parse() {
    // The request-target must be a non-empty origin-form path (RFC 9110
    // §3.2): an empty or whitespace-carrying `--path` otherwise sinks into
    // the probe as a bogus "could not build http request" observation that
    // exits 0 like a network failure — the same class `--method` guards.
    let addr = local_tcp_listener();
    for (path, needle) in [
        ("", "non-empty request path"),
        ("/a b", "whitespace or control characters"),
        ("/healthz", ""),
    ] {
        let assert = cmd().args(["http", &addr.to_string(), "--path", path]).assert();
        if path == "/healthz" {
            // A valid origin-form path still parses (the probe then fails at
            // the TLS layer as an observation, which is exit 0).
            assert.success().stderr(contains("request path").not());
        } else {
            assert.failure().stderr(contains(needle));
        }
    }
}

#[test]
fn http_cli_rejects_an_invalid_method_at_parse() {
    // An HTTP method is a `token` (RFC 9110 §9.1): a value with a space is a
    // paste/quoting accident that must fail at argument parse — not deep
    // inside the probe, where it would surface as a bogus "could not build
    // http request" observation and exit 0 like a network failure.
    let addr = local_tcp_listener();
    cmd()
        .args(["http", &addr.to_string(), "--method", "FOO BAR"])
        .assert()
        .failure()
        .stderr(contains("'FOO BAR' is not a valid HTTP method"));
    // Valid methods still parse (the local plaintext listener makes the TLS
    // probe fail as an observation, which is exit 0 without --strict — the
    // point is that the method itself is accepted at parse).
    cmd()
        .args(["http", &addr.to_string(), "--method", "PATCH"])
        .assert()
        .success()
        .stderr(contains("not a valid HTTP method").not());
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
fn probe_cli_rejects_zero_timeout() {
    // `--timeout 0` can never mean "no timeout" — every consumer converts it
    // straight into a `Duration` bound, so a zero renders a nonsense "timed
    // out after 0ns" report and exits 0. Like `--count 0`, it is a caller
    // mistake and must fail at argument parse instead of producing a report
    // that looks like a real measurement.
    let addr = local_tcp_listener();
    cmd()
        .args(["probe", &addr.to_string(), "--count", "2", "--timeout", "0"])
        .assert()
        .failure()
        .stderr(contains("--timeout"));
    // The prior behavior produced a clean "TCP connect" report and exited 0.
    // A zero timeout stays rejected even where a real probe would be instant.
    cmd()
        .args(["tcp", &addr.to_string(), "--timeout", "0"])
        .assert()
        .failure()
        .stderr(contains("--timeout"));
}

#[test]
fn http_cli_output_body_does_not_truncate_an_artifact_on_a_doomed_run() {
    // A run whose target fails to resolve produces no body — so it must not
    // truncate a previous valid capture at the `--output-body` path. Before
    // the fix the pre-flight `File::create` ran whenever the flag was present,
    // destroying the artifact even though `dest_count == 0` and the run below
    // fails loudly with "did not resolve".
    let tmp = std::env::temp_dir().join(format!("ip-tools-doomed-output-{}.html", std::process::id()));
    std::fs::write(&tmp, "PREVIOUS CAPTURE").expect("write prior artifact");
    cmd()
        .args([
            "http",
            "no-such-host-round32.invalid",
            "--output-body",
            tmp.to_str().unwrap(),
            "--timeout",
            "800",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("did not resolve"));
    assert_eq!(
        std::fs::read_to_string(&tmp).expect("artifact still readable"),
        "PREVIOUS CAPTURE",
        "a doomed run must leave the prior artifact untouched"
    );
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn http_cli_rejects_output_body_across_a_multi_target_sweep() {
    // `--output-body` writes one file per probe; a multi-target sweep would
    // race every host's body onto the same path (last finisher wins), so it
    // must fail up front like other contradictory flag combinations instead
    // of silently writing whichever host finished last.
    let tmp = std::env::temp_dir().join(format!("ip-tools-multi-output-{}.html", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    cmd()
        .args([
            "http",
            "127.0.0.1",
            "127.0.0.2",
            "--output-body",
            tmp.to_str().unwrap(),
            "--timeout",
            "800",
        ])
        .assert()
        .failure()
        .stderr(contains("--output-body").and(contains("single target")));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn http_cli_rejects_output_body_for_a_single_dual_address_target() {
    // The multi-target guard counts *targets*, but a single hostname that
    // resolves to several addresses (dual-stack A + AAAA) gets past it and
    // would still race the addresses' bodies into the one file (last finisher
    // wins, silently). The post-resolution destination-count guard must fail
    // fast — before any probe writes — even when those addresses are
    // unroutable on this host.
    let dns = local_dns_server(&["127.0.0.1"], &["::1"]);
    let tmp = std::env::temp_dir().join(format!("ip-tools-race-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    cmd()
        .args([
            "http",
            "dual.example",
            "--server",
            &dns.to_string(),
            "--output-body",
            tmp.to_str().unwrap(),
            "--timeout",
            "300",
        ])
        .assert()
        .failure()
        .stderr(contains("would race all bodies into one file"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn http_cli_rejects_unwritable_output_body_before_probing() {
    // `--output-body` is an operator-requested artifact: a path the probe
    // cannot write (missing directory) used to surface only as a stderr
    // `Warning:` while the run still exited 0 — a capture-enabled health
    // check silently losing its file with a green exit. The path is now
    // pre-created (and its writability verified) before any probe runs, so
    // an unwritable path fails the run up front.
    let addr = local_tcp_listener();
    let bad = std::env::temp_dir()
        .join(format!("ip-tools-nowhere-{}.bin", std::process::id()))
        .join("body.bin");
    cmd()
        .args([
            "http",
            &addr.to_string(),
            "--output-body",
            bad.to_str().unwrap(),
            "--timeout",
            "800",
        ])
        .assert()
        .failure()
        .stderr(contains("--output-body cannot write"));
}

#[test]
fn probe_cli_expect_rate_passes_at_or_above_threshold() {
    // Every connect to a live local listener succeeds (aggregate success rate
    // 1.0), so a reliability threshold at or below 1.0 must pass and exit 0.
    // `--expect-rate` is the repeated probe's assertion on the aggregate
    // (DEC-075): a single-shot could never gate "reliably 100%".
    let addr = local_tcp_listener();
    for rate in ["1", "0.97", "50%", "100%"] {
        cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--count",
                "3",
                "--timeout",
                "800",
                "--expect-rate",
                rate,
            ])
            .assert()
            .success();
    }
}

#[test]
fn probe_cli_expect_rate_fails_below_threshold() {
    // `127.0.0.1:1` is a closed port, so every connect is refused and the
    // aggregate success rate is 0; a 100% threshold must gate the exit code
    // non-zero and name the destination on stderr with the observed rate.
    cmd()
        .args([
            "probe",
            "127.0.0.1:1",
            "--count",
            "4",
            "--timeout",
            "800",
            "--expect-rate",
            "1",
        ])
        .assert()
        .failure()
        .stderr(contains("expectation violated:").and(contains("success rate")));
}

#[test]
fn probe_cli_rejects_invalid_expect_rate() {
    // A zero threshold would make every run pass vacuously, a value above the
    // valid range is a caller mistake about the grammar, and malformed text is
    // a typo — all must fail fast with a clear parse error rather than
    // silently gating nothing (like the single-shot `--expect-status` specs).
    let addr = local_tcp_listener();
    for bad in ["0", "2", "abc", "0%"] {
        cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--count",
                "2",
                "--timeout",
                "800",
                "--expect-rate",
                bad,
            ])
            .assert()
            .failure()
            .stderr(contains("invalid --expect-rate"));
    }
}

#[test]
fn probe_cli_expect_status_requires_an_http_protocol() {
    // `--expect-status` asserts an observed HTTP status distribution; a tcp
    // repeat carries none, so it is a call-time error, not a silent no-op.
    let addr = local_tcp_listener();
    cmd()
        .args([
            "probe",
            &addr.to_string(),
            "--protocol",
            "tcp",
            "--count",
            "2",
            "--timeout",
            "800",
            "--expect-status",
            "200",
        ])
        .assert()
        .failure()
        .stderr(contains("--expect-status").and(contains("http")));
}

#[test]
fn probe_cli_notes_ignored_resolvers_for_ip_literal_targets() {
    // An IP-literal target is probed directly, so `--doh`/`--dot`/`--server`
    // are never consulted — but an operator who configured an encrypted
    // resolver (believing it was in play) previously got a silent no-op while
    // the `dns` subcommand printed a note for the same flags. The probe
    // commands must say so (once), and stay silent when no resolver is set.
    let out = cmd()
        .args([
            "tcp",
            "127.0.0.1:1",
            "--doh",
            "https://127.0.0.1/dns-query",
            "--timeout",
            "300",
        ])
        .output()
        .expect("probe an IP literal with --doh");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a refused literal is an observation, exit 0: {stderr}"
    );
    assert!(
        stderr.contains("--server/--doh/--dot are ignored for an IP-literal target"),
        "the ignored-resolver note must appear: {stderr}"
    );
    let out = cmd()
        .args(["tcp", "127.0.0.1:1", "--timeout", "300"])
        .output()
        .expect("bare literal");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("ignored for an IP-literal target"),
        "no resolver configured -> no note: {stderr}"
    );
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
fn dns_cli_multi_server_rows_are_deterministically_ordered() {
    // Two `--server` resolvers: `resolve()` collects from a `HashMap` of
    // resolvers in completion order (both nondeterministic per process), so
    // before the deterministic re-sort the row order in the JSON `resolver`
    // field flipped across identical runs. Two fresh runs of the same command
    // must now emit byte-identical *resolver sequences* (latency values still
    // vary run to run, so only the row order is compared).
    let server_a = local_dns_server(&["192.0.2.71"], &[]);
    let server_b = local_dns_server(&["192.0.2.72"], &[]);
    let run = || {
        let out = stdout(
            &cmd()
                .args([
                    "dns",
                    "host.example",
                    "--server",
                    &server_a.to_string(),
                    "--server",
                    &server_b.to_string(),
                    "--record-type",
                    "A",
                    "--json",
                    "--timeout",
                    "1200",
                ])
                .assert()
                .success(),
        );
        let value: serde_json::Value = serde_json::from_str(&out).expect("dns --json must parse");
        value.as_array().map_or_else(
            || vec![value["resolver"].to_string()],
            |rows| rows.iter().map(|r| r["resolver"].to_string()).collect(),
        )
    };
    assert_eq!(run(), run(), "multi-resolver rows must not flip between runs");
    // Both custom resolvers must be present and stable — the system resolver
    // row is deliberately not counted: it is skipped when the host has no
    // usable system resolver (a stripped container), so an exact row count
    // would make the test environment-brittle rather than more precise.
    let r = run();
    assert!(r.len() >= 2, "at least the two custom resolvers: {r:?}");
    for s in [&server_a.to_string(), &server_b.to_string()] {
        assert!(
            r.iter().any(|row| row.contains(s.as_str())),
            "missing resolver {s}: {r:?}"
        );
    }
}

#[test]
fn dns_cli_escapes_control_bytes_in_wire_decoded_names() {
    // A CNAME answer whose target label begins with a raw ANSI ESC byte must
    // render escaped — never as a live terminal sequence — on BOTH resolution
    // paths. This exercises the `--server`/hickory path (which already
    // octal-escapes, spelling the ESC `\033` and other hostname-unsafe bytes
    // like `[` as `\[`); the DoH/DoT hand-rolled wire path is pinned by the
    // fixture-gated `dns_cli_doh_escapes_control_bytes_in_wire_decoded_names`
    // test, whose `read_name` decoder previously passed the raw byte through.
    let server = cname_escape_server();
    let human = stdout(
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
        !human.contains('\u{1b}'),
        "human report must not carry a raw ESC: {human:?}"
    );
    assert!(
        human.contains("\\033\\[31mEVIL"),
        "ESC must render as hickory's octal escape: {human}"
    );

    let csv = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--record-type",
                "CNAME",
                "--csv",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(!csv.contains('\u{1b}'), "CSV must not carry a raw ESC: {csv:?}");
    assert!(csv.contains("\\033\\[31mEVIL"), "CSV records cell must escape: {csv}");
}

#[test]
fn dns_cli_no_records_error_is_human_readable() {
    // A host that has A records but no AAAA records (the responder answers
    // NOERROR with zero AAAA answers) must surface a plain
    // "no AAAA records found for ..." message — not hickory's internal
    // Debug dump (`no records found for Query { name: Name("host.example."),
    // query_type: AAAA, query_class: IN }`) that used to leak into the report.
    let server = local_dns_server(&["192.0.2.77"], &[]);
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
    assert!(
        out.contains("no AAAA records found for host.example"),
        "the no-records reason should read as plain text: {out}"
    );
    assert!(
        !out.contains("Query {") && !out.contains("Name("),
        "hickory's internal Query/Name Debug must not leak into the report: {out}"
    );
}

#[test]
fn dns_cli_notes_an_ignored_target_port_on_stderr() {
    // DNS queries a resolver, never the target's own port, so a `host:port`
    // target's port is silently dropped by resolution. That must not happen
    // with no indication: an operator aiming at a custom resolver port would
    // believe the query used it. A non-default-port target gets a stderr note;
    // a bare hostname (or its default-port spelling) stays silent.
    let server = local_dns_server(&["192.0.2.77"], &["2001:db8::77"]);
    let err = stderr(
        &cmd()
            .args([
                "dns",
                "host.example:5353",
                "--server",
                &server.to_string(),
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(
        err.contains("ignoring the :5353 port of host.example"),
        "a non-default target port must be noted on stderr: {err}"
    );
    // A bare hostname carries no note.
    let err = stderr(
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
    assert!(
        !err.contains("ignoring the :"),
        "a bare hostname must not trigger the port note: {err}"
    );
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
fn dns_cli_ipv4_is_the_a_only_shorthand() {
    let server = local_dns_server(&["192.0.2.77"], &["2001:db8::77"]);

    // `--ipv4` is the shorthand for `--record-type A`: A-only, no AAAA row.
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--ipv4",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(out.contains("192.0.2.77"), "A (via --ipv4) missing: {out}");
    assert!(!out.contains("2001:db8::77"), "--ipv4 must exclude AAAA: {out}");

    // `--ipv4` and `--ipv6` are mutually exclusive (like every other command).
    cmd()
        .args(["dns", "host.example", "--ipv4", "--ipv6"])
        .assert()
        .failure();
    // `--ipv4` also conflicts with `--record-type` (both pick the A record set).
    cmd()
        .args(["dns", "host.example", "--ipv4", "--record-type", "A"])
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
fn dns_cli_repeat_json_serializes_success_rate() {
    // `dns --count --json` must carry the same `success_rate` field as
    // `probe --json`: the DNS repeat aggregate's headline metric used to be a
    // Rust-only method, so JSON consumers got a different schema for the same
    // logical metric across the two repeat commands.
    let server = local_dns_server(&["192.0.2.77"], &[]);
    let out = stdout(
        &cmd()
            .args([
                "dns",
                "host.example",
                "--server",
                &server.to_string(),
                "--count",
                "3",
                "--record-type",
                "A",
                "--json",
                "--timeout",
                "1200",
            ])
            .assert()
            .success(),
    );
    assert!(
        out.contains("\"success_rate\": 1.0"),
        "the repeat JSON must serialize the success rate: {out}"
    );
    assert!(
        out.contains("\"attempts\": 3"),
        "the repeat JSON must still carry attempts: {out}"
    );
}

#[test]
fn dns_cli_rejects_count_zero() {
    // `dns --count 0` used to silently degrade to a single-shot lookup and
    // exit 0, the one probe command not aligned with probe/route/diagnose's
    // "never probe zero times" rejection. Now rejected at argument parse —
    // the same `--count <N>: must be at least 1` (and exit 2) channel the
    // sibling `--timeout`/`--concurrency` nonzero parsers use, so identical
    // zero-input mistakes exit identically.
    let server = local_dns_server(&["192.0.2.77"], &[]);
    let assert = cmd()
        .args(["dns", "host.example", "--server", &server.to_string(), "--count", "0"])
        .assert()
        .failure()
        .code(2);
    let err = stderr(&assert);
    assert!(
        err.contains("must be at least 1"),
        "dns --count 0 must fail with the shared parse message: {err}"
    );
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
    // IPv4 loopback, `--ipv4` reaches the listener; `--ipv6` filters the pool
    // to nothing, which must NOW be a scoped-empty failure (this scope
    // formerly exited 0 with zero probes and an empty report); passing both is
    // a parse error.
    let addr = local_tcp_listener();

    let out = stdout(
        &cmd()
            .args(["tcp", &addr.to_string(), "--ipv4", "--timeout", "800"])
            .assert()
            .success(),
    );
    assert!(out.contains("PASS"), "--ipv4 should probe the v4 loopback: {out}");

    let assert = cmd()
        .args(["tcp", &addr.to_string(), "--ipv6", "--timeout", "800"])
        .assert()
        .failure();
    let err = stderr(&assert);
    assert!(
        err.contains("scope leaves no IPv6 addresses"),
        "--ipv6 must report the scoped-empty pool, not quietly succeed: {err}"
    );

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
    let text = format!("{}\n{}", stdout(&assert), stderr(&assert));
    let lower = text.to_lowercase();
    if lower.contains("icmp") || lower.contains("root") || lower.contains("linux") {
        // Unprivileged or unsupported platform: the process must explain that
        // it needs ICMP/root on Linux (which it just did in `text`).
    } else {
        // The traceroute ran. It always prints the `Traceroute` header, even
        // when every hop is lost — and `--strict` then exits non-zero with an
        // "N route hop(s) lost" line (no ICMP/root mention). So a completed
        // run must show the traceroute header to be a genuine run.
        assert!(
            text.contains("Traceroute"),
            "route must either explain it needs ICMP/root or emit traceroute output: {text}"
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

#[test]
fn probe_family_cli_rejects_an_empty_target_list() {
    // An `@file` that parsed to zero entries (empty, or only blank/# lines) is
    // a caller mistake: probing nothing renders an empty report and would exit
    // 0 — a silent false-pass for a script/CI sweep. It must fail fast the same
    // way `--count 0` and the family-scope-empty case do.
    let tmp = std::env::temp_dir().join(format!("ip-tools-empty-{}.txt", std::process::id()));
    std::fs::write(&tmp, "# nothing to probe\n\n").expect("write empty target file");
    for sub in ["tcp", "tls", "http", "probe"] {
        cmd()
            .args([sub, &format!("@{}", tmp.display())])
            .assert()
            .failure()
            .stderr(contains("no targets to probe"));
    }
    // Empty stdin (`-`) behaves the same.
    cmd()
        .args(["tcp", "-"])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(contains("no targets to probe"));
    let _ = std::fs::remove_file(&tmp);
}

#[test]
fn dns_and_diagnose_cli_reject_an_empty_target_list() {
    let tmp = std::env::temp_dir().join(format!("ip-tools-empty2-{}.txt", std::process::id()));
    std::fs::write(&tmp, "").expect("write empty target file");
    for sub in ["dns", "diagnose"] {
        cmd()
            .args([sub, &format!("@{}", tmp.display())])
            .assert()
            .failure()
            .stderr(contains("no targets to probe"));
    }
    let _ = std::fs::remove_file(&tmp);
}

#[cfg(target_os = "linux")]
#[test]
fn probe_family_cli_surfaces_a_lost_output_as_failure() {
    // A genuine stdout write failure (redirected to a full disk) must be a
    // failure, not a silent exit 0 with the report lost: an ENOSPC on
    // `/dev/full` is the opposite of the closed-pipe case (`... | head`,
    // which stays success). The run completes; the report never lands.
    use std::process::{Command as StdCommand, Stdio};
    let addr = local_tcp_listener();
    let full = std::fs::File::create("/dev/full").expect("open /dev/full");
    let out = StdCommand::new(env!("CARGO_BIN_EXE_ip-tools"))
        .args(["tcp", &addr.to_string(), "--timeout", "800"])
        .stdout(Stdio::from(full))
        .output()
        .expect("run tcp with stdout redirected to a full device");
    assert_eq!(out.status.code(), Some(1), "a lost report must exit 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("failed to write report to stdout"),
        "the lost-report reason must be on stderr: {err}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn completions_cli_surfaces_a_lost_output_as_failure() {
    // `completions zsh` writes "disposable shell script" output, but a lost
    // script (ENOSPC to a full disk) is a failure, not the panic
    // `clap_complete::generate` produced on any writer error (exit 101). The
    // script is buffered in memory and emitted through the same EPIPE-tolerant
    // writer as the reports, so a full device exits 1 with the reason.
    use std::process::{Command as StdCommand, Stdio};
    let full = std::fs::File::create("/dev/full").expect("open /dev/full");
    let out = StdCommand::new(env!("CARGO_BIN_EXE_ip-tools"))
        .args(["completions", "zsh"])
        .stdout(Stdio::from(full))
        .output()
        .expect("run completions with stdout redirected to a full device");
    assert_eq!(out.status.code(), Some(1), "a lost completion script must exit 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("failed to write"),
        "the lost-script reason must be on stderr: {err}"
    );
}

#[test]
fn probe_family_cli_rejects_json_with_csv() {
    // `--json` and `--csv` both name the output format; the render chain used
    // to silently honor CSV and drop the JSON. The rejection is exit 2 on the
    // same channel as the other contradictory-flag pairs, in EITHER flag
    // position: `--json` is global, so when it precedes the subcommand name
    // the subcommand-local clap conflict is not evaluated against it — that
    // position is caught by the handlers' `ensure_json_csv_not_both` with the
    // identical clap `ArgumentConflict` error (regression pinned after round
    // 30 found the pre-subcommand position silently dropping the JSON).
    let addr = local_tcp_listener();
    for sub in ["tcp", "tls", "http", "probe", "dns", "route", "diagnose"] {
        for position in [
            &[sub, &addr.to_string(), "--json", "--csv"][..],
            &["--json", sub, &addr.to_string(), "--csv"][..],
        ] {
            cmd()
                .args(position)
                .assert()
                .failure()
                .code(2)
                .stderr(contains("cannot be used with"));
        }
    }
}

#[test]
fn probe_family_cli_rejects_zero_concurrency() {
    // `--concurrency 0` used to be silently clamped to 1; every sibling
    // option fails fast on 0, so it must too.
    let addr = local_tcp_listener();
    for sub in ["tcp", "http", "probe", "dns", "diagnose"] {
        cmd()
            .args([sub, &addr.to_string(), "--concurrency", "0"])
            .assert()
            .failure()
            .stderr(contains("must be at least 1"));
    }
}

#[test]
fn route_cli_rejects_a_run_count_above_u16_max() {
    // The per-hop `answered` aggregate is a u16; a `--count` above 65535 would
    // wrap a busy hop to "0 runs answered" (false 100% loss), so it is
    // rejected up front instead of silently corrupting the aggregate.
    cmd()
        .args([
            "route",
            "127.0.0.1",
            "--count",
            "65536",
            "--max-hops",
            "1",
            "--timeout",
            "300",
        ])
        .assert()
        .failure()
        .stderr(contains("at most 65535"));
}

#[test]
fn tcp_failure_json_contract_serializes_the_failure_object() {
    // A failed probe's `--json` must serialize the classified failure as
    // `"failure": {"kind": "<snake_case>", "message": ...}` — the most
    // scripting-critical surface of the JSON output. Every other JSON test
    // parses into an untyped Value and never pins this, so this is the
    // contract test that catches a future kind rename or field change.
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = l.local_addr().expect("listener addr");
        drop(l); // nothing listens now: connect => ECONNREFUSED
        addr
    };
    let out = cmd()
        .args(["tcp", &addr.to_string(), "--json", "--timeout", "800"])
        .assert()
        .success();
    let stdout = stdout(&out);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("tcp --json must parse");
    let obs = value.as_array().and_then(|a| a.first()).expect("single observation");
    let failure = obs.get("failure").expect("a refused probe must carry a failure object");
    assert_eq!(
        failure.get("kind").and_then(serde_json::Value::as_str),
        Some("connection_refused"),
        "FailureKind must serialize snake_case: {failure}"
    );
    assert!(
        failure
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| !m.is_empty()),
        "the failure message must be present and non-empty: {failure}"
    );
}

#[test]
fn diagnose_and_route_cli_reject_zero_run_parameters() {
    // `diagnose --count 0` and every route zero-run guard (--count, --max-hops,
    // --probes-per-hop, --timeout, --concurrency) fail fast at argument parse
    // (exit 2) on the shared nonzero-parser channel — a zero repeat would
    // render a vacuous report, and the same mistake class must be one exit code
    // across the whole subcommand.
    let addr = local_tcp_listener();
    cmd()
        .args(["diagnose", &addr.to_string(), "--count", "0", "--timeout", "800"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("must be at least 1"));
    for zero in ["count", "max-hops", "probes-per-hop", "timeout"] {
        cmd()
            .args(["route", "127.0.0.1", &format!("--{zero}"), "0", "--timeout", "300"])
            .assert()
            .failure()
            .code(2)
            .stderr(contains("must be at least 1"));
    }
}

#[test]
fn concurrency_above_the_cap_is_noted_on_stderr() {
    // `--concurrency 1000` runs bounded by the hard MAX_CONCURRENCY cap; an
    // operator who asked for 1000 must be told the run uses 256, not discover
    // the clamp from a slower-than-expected sweep. Within the cap stays silent.
    let addr = local_tcp_listener();
    let err = stderr(
        &cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--count",
                "1",
                "--concurrency",
                "1000",
                "--timeout",
                "500",
            ])
            .assert()
            .success(),
    );
    assert!(
        err.contains("--concurrency 1000 is capped at 256"),
        "an over-cap --concurrency must be noted: {err}"
    );
    let err = stderr(
        &cmd()
            .args([
                "probe",
                &addr.to_string(),
                "--count",
                "1",
                "--concurrency",
                "100",
                "--timeout",
                "500",
            ])
            .assert()
            .success(),
    );
    assert!(
        !err.contains("capped at"),
        "a within-cap --concurrency stays silent: {err}"
    );
}
