## Contributing flow

branch → PR → CI green (`.github/workflows/ci.yml`) → merge; no direct pushes to main.

CI: first-party rustfmt, Clippy and `cargo nextest run --workspace` (Jolt is a public
git dependency pinned by rev), typos, and Python lint.
`~/.git-hooks/pre-commit` runs Clippy with `-D warnings` and the workspace lint
policy; its repository hook runs the Python gate when Python or lint config is staged.

- Rust: `cargo clippy -q --workspace --all-targets --message-format=short -j 6 -- -D warnings`
- Formatting: `git ls-files 'crates/*.rs' ':!crates/vendor/**' | xargs rustfmt --check --edition 2021`
- Python: `scripts/lint/python.sh` (Ruff 0.15.7 check + format check via uv)
- Spelling: `typos`
- Hook: `scripts/pre-commit.sh` (runs when relevant files are staged)

Vendor crates are excluded. Guest lint: skip; guest built only via Jolt CLI.
For Rust behavior changes, run the affected tests locally with
`cargo nextest run --cargo-quiet -p <crate>` before opening a PR.
