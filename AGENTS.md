## Contributing flow

branch → PR → CI green (`.github/workflows/ci.yml`) → merge; no direct pushes to main.

CI runs `rustfmt --check` (first-party crates, `crates/vendor/` excluded), `typos`,
and `cargo nextest run --workspace` (host unit tests; the guest crate is not a
workspace member and is only built via the `jolt` CLI). The test job clones the
jolt worktree the path deps point at from `0xAndoroid/jolt-private` using the
`JOLT_PRIVATE_DEPLOY_KEY` secret, so fork PRs cannot run it. Bumping the jolt
rev in Cargo.toml requires bumping `JOLT_REV` in `ci.yml` too. Run the guest
build locally before opening a PR.
