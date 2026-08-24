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
