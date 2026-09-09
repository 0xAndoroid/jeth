# Wave 3 small-bore probes @ 6d1665c

Native execution key-hash calls (account + storage only):

| Block | Address total | Unique | Repeat % | Slot total | Unique | Repeat % | Combined repeat % |
|---|---:|---:|---:|---:|---:|---:|---:|
| 25905781 | 4301 | 1469 | 65.85 | 2832 | 2221 | 21.57 | 48.27 |
| 25905786 | 2146 | 797 | 62.86 | 1349 | 1017 | 24.61 | 48.10 |
| 25905788 | 597 | 222 | 62.81 | 375 | 309 | 17.60 | 45.37 |

Address repeats exceed 40%; slot repeats do not. Native validation passed all three blocks. Counts are exact preimages at SparseState::account/storage, before any cache. The earlier ~16,433 storage-call estimate used return-address sampling of a function with internal calls; it overcounts the actual 2,832 slot-key hashes on 781. Raw probes: /tmp/jeth-w3-smallbore/.

The same probes through native recover_block + validate_recovered (the guest validation loop) match every count above; all three outputs pass consensus.

## Address memo candidate

Private `SparseState` address→digest memo, `AddressMap<B256>` (hashbrown open
addressing with alloy's fixed-byte Fx hasher), initial capacity witness.state.len()/8.
No advice; entries are computed by keccak, and no digest is supplied externally.
Both self and trusted modes use the same cache per the parent accounting ruling.
Slot hashing remains direct because its repeats fail the 40% gate.

781 inclusive call-cost probe (host-only PC/return-PC tracking; guest unchanged):
2,832 hits cost 1,174,787 rows total = **414.826 rows/hit**, max 526;
1,469 misses cost 6,399,710 rows total = 4,356.508 rows/miss, max 4,513.
A miss is distinguished by execution of native_keccak256 before returning.
The hit/miss counts agree exactly with the native preimage counter.
Assembly emits byte loads for the 20-byte Address before Fx hashing.

The candidate clears the parent's ≥8M net-row floor on 781 (8,839,900 saved),
but exceeds the original ≲200-row memo-hit budget. No extra optimization attempted.
Candidate patch retained at /tmp/jeth-w3-smallbore/candidate-a.patch.

## Three-block candidate ledger

| Block | Mode | Base rows | Memo rows | Saved rows | Base perms | Memo perms | Saved perms = hits |
|---|---|---:|---:|---:|---:|---:|---:|
| 25905781 | self | 1,026,896,402 | 1,018,056,502 | 8,839,900 | 122,629 | 119,797 | 2,832 |
| 25905781 | trusted | 827,710,368 | 818,870,467 | 8,839,901 | 62,694 | 59,862 | 2,832 |
| 25905786 | self | 504,204,199 | 500,044,490 | 4,159,709 | 61,960 | 60,611 | 1,349 |
| 25905786 | trusted | 403,320,374 | 399,160,664 | 4,159,710 | 31,537 | 30,188 | 1,349 |
| 25905788 | self | 163,174,014 | 162,018,688 | 1,155,326 | 19,910 | 19,535 | 375 |
| 25905788 | trusted | 130,189,227 | 129,033,900 | 1,155,327 | 9,989 | 9,614 | 375 |

All six candidate traces passed and had no row regression. Block hash and gas
match baseline in each mode. Native parity: 3/3. `cargo nextest run --cargo-quiet
--release`: 6/6 passed, including the deterministic 1,024-random-address test
(two passes, direct digest comparison on every call; test-only recomputation path).

Permutation accounting: reveal and signature counters are unchanged. The first
post_root counter drops by 2,832 / 1,349 / 375; post_root's own delta and the final
validation tail are unchanged. Cache calls occur only in account/storage reads,
so these are execution-phase savings, in both variants. No per-tx-only counter
capture was needed to establish the delta.

**Final decision: KEEP address memo under the parent's final net-row ruling.**
The binding floor is ≥8M saved rows on 781, with net-positive results on 786/788
and no regression in either mode; all six ledger entries pass. The parent waived
the earlier ≲200-row hit-cost ceiling. The measured implementation and its
random-preimage equality test are retained unchanged; host probes are removed.
Slot memo remains killed at the repeat-rate probe.

Follow-up only: unaligned byte loads in AddressMap/Fx hashing; aligned-word rework
could roughly halve hit cost (estimate, not measured). No hasher tuning in this lane.

## Reproduction

Use 6d1665c and its production-library inputs. Lane data linked input.bin and
witness.json without writing through either link; meta.json and summaries local.
Host CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-w3-smallbore; the host's private
guest target constant was temporarily changed to jeth-w3-smallbore-guest (restored
before handoff). JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt.
Explicit cargo/jolt builds after the lock ruling acquired /tmp/jeth-w3-cargo.lock
atomically. Global pre-commit hooks unexpectedly ran fmt/clippy without that lock
on the documentation commits; both passed. This exception was logged as a papercut.

Raw logs: /tmp/jeth-w3-smallbore/{block}-{base,a}-{self,trusted}.log,
{block}-{guest-native-probe,native-probe,a-native}.log, 781-address-profile.log,
nextest-a.log. Machine-readable summaries: data/{block}/smallbore-{base,a}-{self,trusted}.json.
