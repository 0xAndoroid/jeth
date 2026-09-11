---
created: 2026-09-04
updated: 2026-09-04
tags: [jeth, audit]
---
# Deferred ecrecover soundness

Status: native tests and three-block self-verifying traces passed. Phase 1 only; signing-message construction unchanged.

## Statement and bindings

For each structurally admissible recovery, the guest appends `(R,z,r,s,Q)` and
checks `sum_i lambda_i (s_i R_i - z_i G - r_i Q_i) = O` before constructing a
successful `ValidationResult`. The group is secp256k1's prime-order group of order
n. Every nonzero r has an inverse, so one tuple has exactly one valid Q, including
Q=O when recovery must fail.

- Transaction r/s/parity and sighash come from the RLP-decoded input block;
  `tx.signature_hash()` still computes the hash in guest. Consensus transaction-root
  and block-hash checks retain their existing bindings. EIP-2 low-s is checked
  before appending. Supplied transaction public keys must have the 04 prefix,
  canonical coordinates, satisfy the curve equation, and be nonidentity.
- EVM messages/signatures come from the actually executed precompile calldata;
  EIP-7702 messages still come from `Authorization::signature_hash()` in guest.
  These values may depend on earlier advised addresses. That adaptivity does not
  bypass the batch: any first false recovery creates a nonzero equation residual.
- Revm still enforces the 32-byte v word exactly equal to 27 or 28. The shared
  recovery routine accepts recovery IDs 0..3, rejects noncanonical or zero r/s,
  and rejects r+n overflow or r+n >= p. High-s normalization flips parity, leaving
  sR invariant. The authorization low-s gate is unchanged.
- R.x is determined by r and recovery-ID bit 1; its y is canonical, checked
  against x^3+7, and parity-selected by recovery-ID bit 0. The square-root advice
  replaces exponentiation only. Invalid-x advice must supply a nonzero square
  root of -(x^3+7). Since p=3 mod 4, -1 is a nonsquare, so this is a certificate
  that x^3+7 is a nonsquare. A forged rejection certificate panics immediately.
- Advised recovery Q uses eight canonical coordinate limbs. A finite Q must
  satisfy the curve equation; (0,0) is the sole identity/failure sentinel.
  Finite advice yields keccak(x_be||y_be)[12..]; identity advice yields immediate
  recovery failure. Both outcomes append the complete tuple for verification.

## Why an identity failure needs deferred verification

`r=G.x, R=G, s=1, z=1` passes every range and R-curve check but recovers O.
Therefore range/point prechecks do **not** fully decide k256's failure set.
A failure sentinel is necessary for exact semantics without guest scalar
multiplication. Claiming failure for a successful recovery gives residual
`sR-zG != O`; claiming a finite point for an identity recovery gives residual
`-rQ != O`. Either is rejected by the same batch check. No unverified failure is
silently omitted. A false transaction key can only cause a panic or a failed batch.

## Fiat-Shamir transcript

The guest first fixes the whole ordered list, then computes:

```
T = keccak("jeth/recovery-batch/v1/tuples" || count_u64le || tuples)
lambda_i = OS2IP(keccak("jeth/recovery-batch/v1/challenge" || T || i_u64le)) mod n
```

Each tuple has fixed length 224 bytes: R (8 little-endian u64 limbs), original
32-byte message, r (4 limbs), normalized s (4 limbs), Q (8 limbs). R includes the
normalization parity flip. The scalar z in the MSM is the original message
integer modulo n, computed in guest. Keeping the unreduced message in T also
binds two distinct prehashes that reduce to the same scalar. Identity has one
canonical encoding. The count, order, all coordinates, scalars, and messages
are absorbed; there are no omitted advice-selected fields or ambiguous lengths.
Challenges are derived only after execution fixes every tuple. No challenge is
made available to execution that chooses later Q values.

## Algebra and probability

For a fixed transcript with at least one nonzero residual, fix all coefficients
except one attached to a nonzero residual. At most one value in Fr makes the sum
zero. A full 256-bit hash reduced modulo n gives any field value probability at
most 2/2^256; zero coefficients are permitted and covered by this bound. In the
random-oracle model, a prover trying q distinct complete transcripts has at most
approximately 2q/2^256 success probability, plus hash-collision probability.
This is not an information-theoretic assertion that deterministic Fiat-Shamir
has a fixed 2^-128 failure rate against unlimited attempts; the target is the
usual 128-bit computational security, including transcript collision resistance.
No assumption that EVM output/state-root equality authenticates Q is needed.

The final MSM uses unsigned fixed windows, canonical Fr arithmetic, and the
existing secp256k1 point operations. Its GLV split uses the pinned SDK's
`glv_decompose`: the guest validates both sign words, reconstructs signed 128-bit
magnitudes k1/k2, and checks `k = k1 + mu*k2 (mod n)` before using them, where mu
is the fixed endomorphism eigenvalue. Thus `kP = k1*P + k2*endomorphism(P)`;
forged decomposition advice spoils the proof. This is one Pippenger MSM over
the split terms, not a separate verification per recovery. All finite curve
points are in the prime-order subgroup (cofactor 1).

## Output paths

Both `validate_mainnet` and `validate_recovered` call `recovery_batch::verify`
under `secp-inline` immediately before constructing `ValidationResult`.
All three guest entry points route through `run_validation` and
`validate_recovered`. Existing early errors are `Result::Err` and are converted
to panic by the guest; they produce no `ValidationResult`. Structurally invalid
precompile and authorization recoveries return failure during execution, not
an early block output. The identity-failure tuple remains in the batch.
A failed assertion or nonidentity MSM panics before output; a panic cannot prove
the guest's successful-output statement. Native batch state is thread-local;
the single-hart guest state has no interrupts or reentrant batch calls.

## Relation to prior work

The randomized sum uses the standard modified/recoverable-ECDSA batching idea;
Ethereum's recovery parity supplies the nonce point selection. The application
here requires authenticating recovery failure as well as finite recovered keys.
See [Batch Verification of Modified ECDSA Signatures](https://eprint.iacr.org/2026/663)
for NMVR/HSS randomization of modified ECDSA. The argument above is for this
implementation, not a claim that the cited paper proves this guest integration.

## Verification evidence

Workspace nextest: 13/13, eight new batch tests. Edge vectors cover r/s zero
and out of range, r+n overflow and r+n=p, both R parities, nonresidue rejection, zero and
noncanonical messages, identity recovery, high-s precompile acceptance, the
EIP-2 low-s rejection, and EVM v-word rejection. Malformed, identity, and off-curve transaction keys
are rejected. Dedicated forged finite-key and
forged failure-sentinel cases panic at the batch check. Count/order and all five
tuple components are mutated in transcript tests. Both MSM window sizes match
independent k256 recovery. Native block hashes/gas match baseline 3/3; proven
self traces match 3/3 with no row regression. See [row ledger](w3-ecrecover.md).
