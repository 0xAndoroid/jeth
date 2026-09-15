## Contributing flow

branch → PR → CI green (`.github/workflows/ci.yml`) → merge; no direct pushes to main.

CI runs on GitHub-hosted runners and covers `rustfmt --check` (first-party
crates, `crates/vendor/` excluded) and `typos` only. The workspace has path
dependencies on a local jolt worktree, so a full build is not possible in CI:
run `cargo check`/`cargo test` and the guest build locally before opening a PR.
