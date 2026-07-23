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
        .stdout(contains(":").and(contains("\t")));
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
fn test_help_flag_shows_usage() {
    let mut cmd = Command::cargo_bin("ip-tools").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(contains("list").and(contains("get")));
}
