_help:
    just -l

# Run all unit tests using nextest.
@test:
    cargo nextest run --workspace --all-targets --future-incompat-report
    cargo nextest run -p zerolease-store-postgres --manifest-path crates/zerolease-store-postgres/Cargo.toml  --run-ignored ignored-only --future-incompat-report

# Run the fuzz tests against the wireline protocol.
@fuzz:
    cargo +nightly fuzz run fuzz_read_frame -- -max_total_time=60
    cargo +nightly fuzz run fuzz_protocol_deser -- -max_total_time=60
    cargo +nightly fuzz run fuzz_domain_scope -- -max_total_time=60

# Run all the tests.
all-tests: test fuzz

# Get a code coverage report using llvm-cov.
@coverage:
    cargo llvm-cov --all-targets --workspace --summary-only

# Run the nightly formatter.
@fmt:
    cargo +nightly fmt

# Run the same checks we run in CI. Requires nightly.
@ci: test fmt
    cargo clippy --workspace --all-targets
    cargo clippy -p zerolease-store-postgres --manifest-path crates/zerolease-store-postgres/Cargo.toml
    cargo test --doc
    cargo test --doc -p zerolease-store-postgres --manifest-path crates/zerolease-store-postgres/Cargo.toml

# Install required tools
@setup:
    brew tap ceejbot/tap
    brew install cargo-nextest tomato semver-bump cargo-llvm-cov
    rustup install nightly

# Tag a new version for release.
version BUMP:
    #!/usr/bin/env bash
    set -e
    current=$(tomato get workspace.package.version Cargo.toml)
    version=$(semver-bump {{ BUMP }} "$current")
    tomato set workspace.package.version "$version" Cargo.toml &> /dev/null
    tomato set package.version "$version" crates/zerolease-store-postgres/Cargo.toml &> /dev/null
    cargo generate-lockfile
    git commit Cargo.{toml,lockfile} crates/zerolease-store-postgres/Cargo.{toml,lockfile} -m "v${version}"
    git tag "v${version}"
    echo "Release tagged for version v${version}"

# publish to crates.io
@release:
    cargo publish
