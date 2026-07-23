# Contribution guidelines

First off, thank you for considering contributing to ip-tools.

If your contribution is not straightforward, please first discuss the change you
wish to make by creating a new issue before making the change.

## Reporting issues

Before reporting an issue on the
[issue tracker](https://github.com/pplmx/ip-tools/issues),
please check that it has not already been reported by searching for some related
keywords.

## Pull requests

Try to do one pull request per change.

### Updating the changelog

Update the changes you have made in
[CHANGELOG](https://github.com/pplmx/ip-tools/blob/main/CHANGELOG.md)
file under the **Unreleased** section.

Add the changes of your pull request to one of the following subsections,
depending on the types of changes defined by
[Keep a changelog](https://keepachangelog.com/en/1.1.0/):

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

If the required subsection does not exist yet under **Unreleased**, create it!

## Developing

### Set up

This is no different than other Rust projects.

```shell
git clone https://github.com/pplmx/ip-tools
cd ip-tools
cargo test
```

Git hooks (via husky-rs) are automatically installed on `cargo build`.
They enforce the same checks as CI: `cargo fmt --check` and `cargo clippy` on
commit, conventional commit messages, and full tests on push.
To skip hooks for a commit, use `HUSKY=0 git commit`.

### Useful Commands

- Build and run release version:

  ```shell
  cargo build --release && cargo run --release
  ```

- Run Clippy:

  ```shell
  cargo clippy --all-targets --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery
  ```

- Run all tests:

  ```shell
  cargo test --all-features --workspace
  ```

- Check to see if there are code formatting issues

  ```shell
  cargo fmt --all --check
  ```

- Format the code in the project

  ```shell
  cargo fmt --all
  ```

- Check code coverage (requires [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)):

  ```shell
  cargo llvm-cov --all-features --workspace
  ```

  CI enforces a minimum of 80% line coverage via `--fail-under-lines 80`.
  Generate an HTML report for detailed inspection with
  `cargo llvm-cov --all-features --workspace --html`.
