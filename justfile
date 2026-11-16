set positional-arguments

# No recipe passes --workspace: Cargo ignores -p next to it, and this virtual workspace
# has no default-members, so Cargo already selects every member when no -p is given.

# List recipes.
default:
    @just --list

# Format Rust under crates/ (vendor/ excluded) and the Python scripts.
fmt:
    git ls-files 'crates/*.rs' ':!crates/vendor/**' | xargs rustfmt --edition 2021
    uv tool run ruff@0.17.3 format scripts

# Check formatting as CI does, without rewriting files.
fmt-check:
    git ls-files 'crates/*.rs' ':!crates/vendor/**' | xargs rustfmt --check --edition 2021
    uv tool run ruff@0.17.3 format --check scripts

# Clippy with warnings denied, as CI runs it: default features, all features, each crate alone.
clippy *args:
    cargo clippy --all-targets -q --message-format=short "$@" -- -D warnings
    cargo clippy --all-targets --all-features -q --message-format=short "$@" -- -D warnings
    for crate in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'); do \
        cargo clippy -p "$crate" --all-targets -q --message-format=short "$@" -- -D warnings || exit 1; \
    done

# Apply Clippy's suggested fixes, also in a dirty worktree.
fix *args:
    cargo clippy --fix --allow-dirty --all-targets -q --message-format=short "$@"

# Clippy, the Python lint script and typos.
lint: clippy
    scripts/lint/python.sh
    typos

# A test behind a cargo feature runs with the `args` of its entry in the `features` matrix
# of .github/workflows/ci.yml, e.g. `just test -p jeth-core --features secp-inline`.
# Workspace tests as CI runs them; arguments narrow the run, e.g. `just test -p jeth-core`.
test *args:
    cargo nextest run --cargo-quiet --locked --no-fail-fast "$@"

# Build jeth-host (the jeth CLI) in release mode, e.g. `just build --features secp-inline`.
build *args:
    cargo build -q --message-format=short --release -p jeth-host "$@"

# Run the jeth CLI in release mode, e.g. `just jeth bench`.
jeth *args:
    cargo run -q --message-format=short --release -p jeth-host -- "$@"

# Expanded-cycle counts over the frozen block set, e.g. `just cycles --tree ../other-checkout`.
cycles *args:
    cargo run -q --message-format=short --release -p jeth-host -- cycles run "$@"
