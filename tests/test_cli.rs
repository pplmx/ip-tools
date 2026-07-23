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
