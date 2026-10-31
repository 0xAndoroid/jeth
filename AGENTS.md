## Contributing flow

branch → PR → CI green (`.github/workflows/ci.yml`) → merge; no direct pushes to main.

CI: first-party rustfmt, Clippy and `cargo nextest run --workspace` (Jolt is a public
git dependency pinned by rev), typos, and Python lint.
`~/.git-hooks/pre-commit` runs Clippy with `-D warnings` and the workspace lint
policy; its repository hook runs the Python gate when Python or lint config is staged.

The root `justfile` wraps these commands; `just` lists its recipes.

- Rust: `just clippy -j 6`; `just fix` applies Clippy's suggested fixes
- Formatting: `just fmt-check` (rustfmt on `crates/` minus `crates/vendor/`, Ruff format on `scripts/`); `just fmt` rewrites
- Python: `scripts/lint/python.sh` (Ruff 0.15.7 check + format check via uv)
- Spelling: `typos`
- All linters: `just lint` (Clippy, `scripts/lint/python.sh`, `typos`)
- Host CLI: `just build` builds `jeth-host` in release mode; `just jeth <subcommand>` builds and runs it
- Hook: `scripts/pre-commit.sh` (runs when relevant files are staged)

Vendor crates are excluded. Guest lint: skip; guest built only via Jolt CLI.
For Rust behavior changes, run the affected tests locally with
`just test -p <crate>` before opening a PR.
