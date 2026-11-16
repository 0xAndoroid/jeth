## Contributing flow

branch → PR → CI green (`.github/workflows/ci.yml`) → merge; no direct pushes to main.

CI: first-party rustfmt, Clippy and `cargo nextest run --workspace` (Jolt is a public
git dependency pinned by rev), typos, and Python lint.
`~/.git-hooks/pre-commit` runs Clippy with `-D warnings` and the workspace lint
policy; its repository hook runs the Python gate when Python or lint config is staged.

The root `justfile` wraps these commands; `just` lists its recipes.

- Rust: `just clippy -j 6`; `just fix` applies Clippy's suggested fixes
- Formatting: `just fmt-check` (rustfmt on `crates/` minus `crates/vendor/`, Ruff format on `scripts/`); `just fmt` rewrites
- Python: `scripts/lint/python.sh` (Ruff 0.17.3 check + format check via uv)
- Spelling: `typos`
- All linters: `just lint` (Clippy, `scripts/lint/python.sh`, `typos`)
- Host CLI: `just build` builds `jeth-host` in release mode; `just jeth <subcommand>` builds and runs it
- Hook: `scripts/pre-commit.sh` (runs when relevant files are staged)

Vendor crates are excluded from fmt and Clippy. Guest lint: skip; guest built only via Jolt CLI.
For Rust behavior changes, run the affected tests locally with
`just test -p <crate>` before opening a PR.

## Review

Every review of a PR or diff, fork PRs included, checks the diff for comment bloat and
test bloat: a PR adds no comment that [Comments](#comments) deletes and no test that
[Tests](#tests) leaves out.

- Read every comment and test the diff adds or changes; list each instance as a finding with its `file:line`. It is fixed before merge; on a fork PR the contributor fixes it.
- The Comments and Tests rules and this check cover all jeth-written code, including jeth's changes inside `crates/vendor/`; the fmt and Clippy exclusions do not exempt them. Text imported unchanged from an upstream release is out of scope, so the diff against upstream stays readable: leave upstream comments and tests as they are unless a jeth change alters what they describe or assert.
- A PR that claims a cycle win cites expanded-cycle counts over the frozen block set: the Cycles workflow's table (job summary or `cycles` artifact), or `just cycles` for base and head at one checkout path (RESULTS.md → Cycle-count harness). An ad hoc run is not evidence.

## Comments

A comment must carry information the code cannot; when unsure, leave it out.

- Keep license headers, directives a tool reads, and public API docs that state a contract beyond the signature.
- Keep an invariant the types cannot express, naming where it is enforced; a why-not note that prevents reintroducing a known bug; a pointer to non-local coupling, such as the `[patch]` tables mirrored in the root and `crates/guest` manifests.
- Keep soundness or security reasoning, `SAFETY:` on every `unsafe` block (Clippy denies an undocumented one), and behavior forced by an external dependency, platform or protocol.
- Keep an algorithm explanation with its paper, EIP or spec link where one exists; an issue or RFC link only when it explains a constraint; a TODO only as `TODO(#issue)`.
- Delete narration of code or assertions, section banners, commented-out code, stale descriptions, history and migration notes, restated signatures and end markers.
- Fix confusing code with names, types or structure, not a comment; a cleanup pass only flags it. Update or delete a comment when the behavior it describes changes.

## Lint suppressions

- Suppress in source only a style, pedantic or naming lint, as `#[expect(<lint>, reason = "...")]`: the workspace denies `#[allow]` (`clippy::allow_attributes`). A reviewer verifies the reason against the code; a reason that is only stated is a finding.
- Never suppress a correctness, safety, suspicious, complexity, perf or restriction lint, which covers every lint the root `Cargo.toml` denies; fix the code.
- A test-only exemption (`unwrap_used`, `expect_used`, `panic` in tests) goes in Clippy configuration (`allow-unwrap-in-tests`, `allow-expect-in-tests`, `allow-panic-in-tests` in `clippy.toml`), not in a source attribute.
- In `scripts/`, a `# noqa` follows the same classes and names its rule code and reason.

## Tests

- Test public contract or API behavior, a regression pinned to a fixed bug (name its issue or fixing commit), an invariant or property the types cannot express, wire or format compatibility (fixtures, golden files), and security or soundness.
- Never delete or weaken such a test to make a change pass; change it only when its contract changes. A test that may guard a past bug stays even when its bug link cannot be confirmed; report the missing evidence.
- Write about one focused test per stated behavior, each with a failure signal no existing test gives; search existing tests first. Not every low-impact edit needs a test, and missing branch coverage alone is not a missing test.
- Assert against independent ground truth: spec vectors (EIP-152, RIP-7212, Wycheproof), an upstream reference implementation (`sha3`, `sha2`, `k256`, arkworks, revm), mainnet block data under `fixtures/` (a block input; pinned header hashes, state roots and receipts roots), or an algebraic property. Never a second in-repo implementation of the rule under test.
- Leave out implementation mirrors (mock-everything tests, internal-call assertions, expected values recomputed with the logic under test), tests whose only failure mode is a refactor, more cases of one path with different literals and no distinct failure signal, assertions on log text or ordering no contract requires, and self-validation of one small change. Different boundaries, failure modes, fixed bugs or contracts are not duplicates.
- Keep no old-vs-new equivalence test and no `#[cfg(test)]` copy of superseded code as the oracle; transition validation belongs in the PR, not the suite.
- Before handoff, remove scaffolding: development probes, `#[ignore]` tests with no stated run condition, diagnostic counters, and any parity or benchmark harness written to validate one change. A diagnostic worth keeping becomes a `jeth` subcommand or a script under `scripts/` with a documented command.
- `crates/guest` is `test = false`: its `#[cfg(test)]` modules run only through `crates/guest/native-tests`, which includes each tested module by `#[path]`. Add a new tested guest module there; run them with `just test --manifest-path crates/guest/native-tests/Cargo.toml`.
- CI's `riscv64` job runs the lib tests of `crates/vendor/{foldhash,hashbrown,alloy-primitives,revm-interpreter,zeth-mpt}` and `crates/guest/native-tests` on `riscv64gc-unknown-linux-musl` under qemu; no other job runs them, and native runs skip their `target_arch = "riscv64"` code. Test jeth's changes in those crates with unit tests (the job passes `--lib`). No CI job runs tests in `crates/vendor/ark-ff` or `crates/vendor/alloy-eip7702`.
