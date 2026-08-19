# ip-tools justfile — network tool with library + binary
default:
    @just --list

# Install dev tools and set up git hooks
init:
    uv tool install prek
    uv tool install rumdl
    uv tool install ruff
    git config core.hooksPath .husky
    @echo "Hooks installed. prek available: run 'prek run --all-files' to test."

# Build release binary
build:
    cargo build --release

# Run all tests
test:
    cargo test --all-features --workspace

# Format check (CI style)
fmt-check:
    cargo fmt --all --check

# Run clippy (CI style, matches project pedantic/nursery standards)
clippy:
    cargo clippy --all-targets --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery

# Check documentation (CI style)
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --examples

# Run doctests (/// examples in src/lib.rs)
doctest:
    cargo test --doc --workspace --all-features

# Run coverage check
coverage:
    cargo llvm-cov --all-features --workspace --fail-under-lines 80

# Run benchmarks
bench:
    cargo bench --workspace

# Quick read-only checks (local loop)
quick: fmt-check clippy doc-check doctest test

# Full CI gate
ci: quick coverage msrv audit deny public-api-check

# MSRV check
msrv:
    cargo +1.88 check --all-targets --all-features --workspace

# Check public API hasn't changed (fails if baseline differs)
# Compared as text against `api-baseline.txt` (-sss = simplified, low-noise
# output). `cargo public-api diff` with no args compares against the last
# *published* version instead, which is wrong before a release.
public-api-check:
    cargo public-api --manifest-path Cargo.toml -sss | diff -u - api-baseline.txt || (echo "Public API changed. Run 'just public-api-baseline' to update." && false)

# Regenerate public API baseline (run after intentional API changes)
public-api-baseline:
    cargo public-api --manifest-path Cargo.toml -sss > api-baseline.txt

# Auto-fix clippy + format
fix:
    cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery
    cargo fmt --all

# Security audit
audit:
    cargo audit

# Dependency policy check
deny:
    cargo deny check

# Clean build artifacts
clean:
    cargo clean
