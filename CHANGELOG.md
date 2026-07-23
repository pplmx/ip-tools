# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
|- Add editorconfig
|- Add renovate.json
|- Add a badge for [Rust GitHub Template](https://rust-github.github.io/)
|- Add CLI integration tests covering get, list, no-subcommand, flag rejection, and help output
|- Add assert_cmd and predicates as dev dependencies
|- Add pre-publish test step to cargo publish in CD workflow
|- Add husky-rs git hooks (pre-commit, commit-msg, pre-push) for local fmt/clippy/test enforcement
|- Add unit tests for IpToolsError (Display, source, From, Send+Sync) to improve coverage
|- Add coverage enforcement step to CI (`cargo llvm-cov --fail-under-lines 80`)
|- Document coverage testing with cargo-llvm-cov in CONTRIBUTING.md

### Changed
|- Remove cli.yml
|- Remove redundant dependabot.yml — Renovate handles all dependency updates
|- Update clap to v4
|- Replace clap_derive with clap_builder
|- Replace CARGO_API_KEY with CARGO_REGISTRY_TOKEN
|- Refactor `get_local_ip` and `list_net_ifs` to return `Result` instead of panicking
|- Print errors to stderr and exit with non-zero status on failure
|- Add `ExitCode` return from CLI entry point
|- Replace placeholder tests with meaningful integration tests
|- Add benchmarks for `get_local_ip` and `list_net_ifs`
|- Modernize CD workflow: replace deprecated `actions-rs/toolchain` and `actions-rs/cargo` with `dtolnay/rust-toolchain` and direct `cargo` commands
|- Modernize audit workflow: replace deprecated `actions-rs/audit-check` with `cargo install cargo-audit` and direct `cargo audit`
|- Improve README with actual usage examples for `get` and `list` subcommands
|- Update clap from `~4.5.0` to `~4.6.0` (4.5.61 -> 4.6.4)
|- Update clap_builder to 4.6.2
|- Remove redundant `--ip` flag from `get` subcommand and `--all` flag from `list` subcommand
|- Use Display format instead of Debug format for IP addresses in CLI output
|- Fix list output format from tab-separated to `name: ip`
|- Fix misleading doc comments on `get_local_ip` and `list_net_ifs` to clarify they return `Result`
|- Inline format arguments (e.g., `{e}` instead of `{}`, `e`) in string formatting

### Fixed
|- Fix broken checkbox format in bug report and feature request issue templates
|- Fix clippy command in CONTRIBUTING.md to match CI (`-D warnings`)
|- Fix README example output to match actual `name: ip` format (was tab-separated)
|- Run tests before `cargo publish` to prevent untested code from being published to crates.io

## [v0.1.0] - 2022-08-02

### Added
|- initial release
|- add clap for command line arguments
