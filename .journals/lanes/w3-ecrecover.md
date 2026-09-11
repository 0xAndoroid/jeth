---
created: 2026-09-04
updated: 2026-09-04
tags: [jeth, benchmark]
---
# Wave 3: deferred ecrecover

Base: campaign-2x @ 6d1665ca3edf8d4a5387ca56f147b9ee44a7d4a4.
Isolated branch: w3-ecrecover. Jolt: read-only main-2026-09-04 pin.
Phase 1: deferred transaction/precompile/7702 recovery; in-guest sighash unchanged.
Soundness: [w3-ecrecover-soundness.md](w3-ecrecover-soundness.md).

## Verification

- Workspace nextest: 13/13, including eight new batch tests.
- Native baseline and batched validation: three matching block hashes and gas totals.
- Self traces: 3/3, no block regression. Self-only gates per Sep 4 17:39 directive.
- Diagnostic only (earlier GLV candidate, before redundant scalar conversion removal): the already-started 25905788 trusted trace passed at 116,818,996 rows
  (18.7884 c/g; baseline 130,189,227 rows). No further trusted runs requested.
- Source data: input.bin and witness.json symlinks; meta.json copied. All 45 source-file SHA-256 hashes unchanged.

## Implementation decisions

- Canonical finite Q or the sole identity sentinel; every advised outcome joins the batch.
  False failure and false finite-key claims both create nonzero residuals.
- Checked square-root/nonresidue certificates replace R decompression exponentiation.
- One-shot keccak for the full fixed-width tuple transcript and indexed challenges;
  alloy's incremental Keccak256 does not use the native-keccak hook.
- One end-of-validation Pippenger MSM with the SDK's checked GLV scalar split. The SDK's point-add implementation is retained;
  a coordinate-difference rewrite cost 116,198 extra rows on 25905788 and was removed.
- Recovery batching also removes bytewise comparisons within the old transaction
  verifier; those rows are not all included in the 110.9M direct-symbol curve pool.

## Phase 1 self-verifying ledger

| Block | Base rows | Batch rows | c/g | Δ c/g | MSM rows | Entire batch check |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 1,026,896,402 | 947,352,797 | 21.4202 | -1.7985 | 44,320,036 | 50,848,533 |
| 25905786 | 504,204,199 | 466,097,451 | 17.6860 | -1.4460 | 25,842,465 | 29,293,733 |
| 25905788 | 163,174,014 | 149,798,764 | 24.0927 | -2.1512 | 13,418,140 | 14,929,134 |

Three-block gas-weighted: **22.0612 → 20.3551 c/g**, Δ -1.7061;
131,025,603 rows removed (7.73%). This is the three-block subset,
not the campaign ten-block aggregate.

The estimated −2.0/−1.7/−3.1 c/g was not reached: the full batch check
costs 50.85M/29.29M/14.93M rows, materially above the research estimate.
No unverified recovery outcomes were accepted to meet a row target.

## N1 follow-up sizing

Phase 1 leaves **13,515,448 / 8,979,420 / 1,857,427 rows** in the entire
transaction-signature phase (781/786/788), with **3,079 / 2,153 / 301** keccak
permutations still required. The previously estimated 15–25M N1 saving exceeds
the entire remaining 781 signing phase. At 3,087 rows per permutation alone,
less than 4.02M / 2.34M / 0.93M rows remain for *all* non-keccak work, including
range/curve checks, key hashing glue, allocation, and batch insertion. RLP
serialization is only a subset. No sighash-slicing implementation is included:
legacy EIP-155 v/chain-id rewriting and typed-envelope framing need a separate
binding audit for this smaller residual. Phase 1 ships independently.

## Reproduction

Build/test commands, serialized under an atomic mkdir lock at
`/tmp/jeth-w3-cargo.lock` (release with `rmdir`):

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-w3-ecrecover
export JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt
cargo nextest run --cargo-quiet --workspace --features jeth-host/secp-inline
cargo build -q --message-format=short --release -p jeth-host --features secp-inline
```

The release CLI's `run-native --input data/<block>/input.bin` exercises batched
recovery. A default-feature host build retains the independent stateless/k256
path. Baseline native parity used the existing campaign-2x binary (built Sep 4).

`trace --input data/<block>/input.bin` builds and runs the self-verifying
compute/proven ELF pair; add `--trusted-digests` for trusted witness digests.
After each pair exists, `--skip-build` avoids further Cargo calls. Guest ELF
outputs have the isolated `jeth-w3-ecrecover-guest-*` prefix.

The `recovery_msm` and `recovery_batch` marker totals include real and virtual
rows. Only the second marker occurrence (proven pass) belongs in the ledger.
Raw logs: `/tmp/jeth-w3-ecrecover-<block>-{self,trusted}.log`.
Native logs: `/tmp/jeth-w3-ecrecover-native-{baseline-,}<block>.log`.
Trace JSONs: local `data/<block>/trace-summary{,-trusted}.json`.
