# Wave 3 Item B: memcmp caller probe — kill

Base: 6d1665c, production-library inputs. Exact RV64IMAC row attribution on
25905781: 1,026,896,402 total rows, 29,930,376 memcmp rows.

| Caller | Rows | Share |
|---|---:|---:|
| recover::inline_verify_pubkey | 17,091,825 | 57.11% |
| crypto::mul_4x128 | 3,774,051 | 12.61% |
| post-state account sorting | 695,100 | 2.32% |
| ark field inverse | 608,922 | 2.03% |
| All remaining callers | 7,760,478 | 25.93% |

The 781 run made 368,529 length-32 memcmp calls. Of these, 368,518 (99.997%)
had both operands 8-byte aligned. The dominant two callers made 228,263 and
50,337 length-32 calls respectively, all aligned 0/0. Length-20 calls: 31,732.
These are exact register observations at memcmp entry, not sampled estimates.

`llvm-nm` finds only `memcmp`: `memcmp_impl` is inlined into that C-ABI symbol.
Thus `profile --rows --callers-of memcmp` captures the word-wise override itself.
Its existing co-aligned fast path already runs for essentially every fixed-32 call.

Decision: kill with redirect to the batch-verification lane. Its removal of the inline secp verification path also removes the dominant 69.72% of memcmp rows; include these rows in that lane’s non-overlapping ledger. Kill the proposed trie/map call-site or alignment repair. The dominant
cost is secp inline arithmetic, not trie walking or map probing. Changing upstream
field arithmetic or adding a general memcmp specialization is a separate candidate;
the existing alignment fast path needs no repair.
No production code change, therefore no permutation change attributable to Item B.

Raw caller/alignment log: /tmp/jeth-w3-smallbore/781-memcmp.log.
Temporary host-only register counters were removed before handoff.

## Item B baseline ledger

Item B is killed; Item A is retained under the final net-row ruling. The table
below is the 6d1665c baseline, not the final combined row count. Item B contributes
zero row or permutation delta. Final Item-A measurements and parity/test evidence are in
[w3-smallbore.md](w3-smallbore.md).

| Block | Self rows | Trusted rows | Self perms | Trusted perms |
|---|---:|---:|---:|---:|
| 25905781 | 1,026,896,402 | 827,710,368 | 122,629 | 62,694 |
| 25905786 | 504,204,199 | 403,320,374 | 61,960 | 31,537 |
| 25905788 | 163,174,014 | 130,189,227 | 19,910 | 9,989 |
