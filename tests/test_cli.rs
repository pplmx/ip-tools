use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn test_get_subcommand_outputs_ip() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.arg("get")
        .assert()
        .success()
        .stdout(contains(".").or(contains(":")));
}

#[test]
fn test_list_subcommand_outputs_interfaces() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.arg("list")
        .assert()
        .success()
        .stdout(contains(":").and(contains(" ")));
}

#[test]
fn test_no_subcommand_exits_with_error() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.assert().failure();
}

#[test]
fn test_rejected_old_flag_get_ip() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["get", "--ip"])
        .assert()
        .failure()
        .stderr(contains("unexpected argument"));
}

#[test]
fn test_rejected_old_flag_list_all() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["list", "--all"])
        .assert()
        .failure()
        .stderr(contains("unexpected argument"));
}

#[test]
fn test_get_json_output() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    let output = cmd.arg("get").arg("--json").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(value["ip"].is_string(), "JSON output should contain 'ip' string field");
}

#[test]
fn test_list_json_output() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    let output = cmd.arg("list").arg("--json").assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(value.is_array(), "JSON output should be an array");
    let interfaces = value.as_array().unwrap();
    assert!(!interfaces.is_empty(), "at least one interface in JSON output");
    for iface in interfaces {
        assert!(iface["name"].is_string(), "each entry should have 'name' string");
        assert!(iface["ip"].is_string(), "each entry should have 'ip' string");
    }
}

#[test]
fn test_get_json_global_flag() {
    // --json as a global flag before the subcommand should also work
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    let output = cmd.args(["--json", "get"]).assert().success();
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(value["ip"].is_string());
}

#[test]
fn test_help_flag_shows_usage() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("list").and(contains("get")));
}

#[test]
fn test_help_lists_diagnostic_subcommands() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.arg("--help").assert().success().stdout(
        contains("dns")
            .and(contains("tcp"))
            .and(contains("tls"))
            .and(contains("http"))
            .and(contains("http2"))
            .and(contains("http3"))
            .and(contains("probe"))
            .and(contains("route"))
            .and(contains("diagnose")),
    );
}

#[test]
fn test_each_diagnostic_subcommand_rejects_missing_target() {
    for sub in [
        "dns", "tcp", "tls", "http", "http2", "http3", "probe", "route", "diagnose",
    ] {
        let mut cmd = Command::cargo_bin("ip-tools").unwrap();
        cmd.arg(sub).assert().failure();
    }
}

#[test]
fn test_dns_literal_target_reports_the_address_itself() {
    // `dns 1.1.1.1` must not ask the resolver to look up a *name* "1.1.1.1."
    // (which answers "no records found"): an IP literal is already an address,
    // so its identity is reported directly and deterministically (no network).
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["dns", "1.1.1.1"])
        .assert()
        .success()
        .stdout(contains("1.1.1.1 (0 ms)").and(contains("no records found").not()));
}

#[test]
fn test_dns_literal_target_with_strict_exits_zero() {
    // A literal target is trivially "resolved" (it is its own address), so
    // `--strict` must not treat it as a failed lookup.
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["dns", "1.1.1.1", "--strict"]).assert().success();
}

#[test]
fn test_dns_bracketed_ipv6_literal_reports_the_address_itself() {
    // Bracket-form IPv6 literals (`[::1]`, as accepted by target parsing) are
    // addresses too, not names to resolve.
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["dns", "[::1]"])
        .assert()
        .success()
        .stdout(contains("::1 (0 ms)"));
}

#[test]
fn test_dns_literal_forward_lookup_notes_an_ignored_resolver() {
    // `dns 1.1.1.1 --server …` reports the literal straight from the address
    // and never touches the configured resolver — but the PTR branch *does*
    // use it, so the same flags do opposite things by record type. The note
    // (mirroring the `--count`-literal and `host:port`-port notes) must
    // surface on stderr while the forward lookup still succeeds, and stay
    // absent when no resolver is configured.
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["dns", "1.1.1.1", "--server", "127.0.0.1:53"])
        .assert()
        .success()
        .stdout(contains("1.1.1.1 (0 ms)"))
        .stderr(contains(
            "--server/--doh/--dot are ignored for an IP-literal forward lookup",
        ));
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.args(["dns", "1.1.1.1"])
        .assert()
        .success()
        .stderr(contains("ignored for an IP-literal forward lookup").not());
}

#[test]
fn test_piped_human_output_has_no_ansi_escapes() {
    // assert_cmd pipes stdout, so this exercises the non-TTY gate: the human
    // renderer must color only for a terminal and never leak escapes into a
    // pipe (a failure token like "connection refused" would be red on a TTY).
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    let output = cmd.args(["tcp", "127.0.0.1:1"]).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        !stdout.contains('\u{1b}'),
        "piped human output must be plain (no ANSI escapes): {stdout:?}"
    );
    assert!(
        stdout.contains("connection refused"),
        "refused row expected: {stdout:?}"
    );
}

#[test]
fn test_json_and_csv_output_never_carry_ansi_escapes() {
    // JSON and CSV go through their own serializers, which must never be
    // touched by the color gate even when a failure is being reported.
    for (format, args) in [
        ("--json", vec!["tcp", "--json", "127.0.0.1:1"]),
        ("--csv", vec!["probe", "--csv", "--count", "1", "127.0.0.1:1"]),
    ] {
        let mut cmd = Command::cargo_bin("ip-tools").unwrap();
        let output = cmd.args(&args).assert().success();
        let stdout = String::from_utf8_lossy(&output.get_output().stdout);
        assert!(
            !stdout.contains('\u{1b}'),
            "{format} output must never carry ANSI escapes: {stdout:?}"
        );
    }
}

#[test]
fn completions_subcommand_generates_for_each_supported_shell() {
    // `completions <shell>` must emit a real script that names every
    // subcommand — the generated output is the user-visible contract, and it
    // is driven off the live clap tree so a new flag/subcommand shows up
    // automatically. Missing or unknown shells are clean errors.
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = Command::cargo_bin("ip-tools")
            .unwrap()
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{shell} completions must succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            text.len() > 200,
            "{shell} completions look empty ({len} bytes)",
            len = text.len()
        );
        for sub in ["dns", "tcp", "tls", "http", "probe", "route", "diagnose"] {
            assert!(text.contains(sub), "{shell} completions must name the {sub} subcommand");
        }
    }
    Command::cargo_bin("ip-tools")
        .unwrap()
        .arg("completions")
        .assert()
        .failure();
    Command::cargo_bin("ip-tools")
        .unwrap()
        .args(["completions", "tcsh"])
        .assert()
        .failure();
}

#[test]
fn completions_output_survives_an_early_closing_pipe() {
    // A `completions zsh | head` (a pager, a preview) closes stdout early;
    // that must not panic with a BrokenPipe backtrace — the script is
    // disposable output. Close the read end mid-stream while the child may
    // still be writing, then require a clean exit.
    use std::io::Read;
    // powershell generates the largest script (~38 KiB), keeping the child
    // likely to still be writing when the read end is closed.
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ip-tools"))
        .args(["completions", "powershell"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn completions");
    let mut buf = [0u8; 1];
    {
        let mut out = child.stdout.take().expect("piped stdout");
        // Read a little of the script, then drop the pipe while the child is
        // (very likely) still writing — the pre-BrokenPipe behavior panicked.
        let _ = out.read(&mut buf);
        drop(out);
    }
    let status = child.wait().expect("wait for completions");
    assert_eq!(
        status.code(),
        Some(0),
        "an early-closing pipe must leave completions exit 0, not panic: {status}"
    );
}
