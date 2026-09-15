#!/bin/zsh
# 10-block gate: trace every block with the final tree (p256-inline ON); compare hash/perms with data/<b>/trace-summary.json.
set -uo pipefail
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-a-p256 JETH_GUEST_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-a-p256-guest JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-amber-nolane/release/jolt
WT=/Volumes/Dev/worktrees/jeth/inlines-a-p256
cd $WT
grep -n "jeth-core = " crates/guest/Cargo.toml
mkdir -p /tmp/opcg-p256/tenblock
JETH=/tmp/opcg-p256/bin/jeth-after
cp $CARGO_TARGET_DIR/release/jeth $JETH
for b in 25905781 25905782 25905783 25905784 25905785 25905786 25905787 25905788 25905789 25905790; do
  date; echo "== $b"
  $JETH trace --input /tmp/opcg-p256/blocks/$b/input.bin --skip-build > /tmp/opcg-p256/tenblock/$b.log 2>&1; echo "exit=$?"
  cp /tmp/opcg-p256/blocks/$b/trace-summary.json /tmp/opcg-p256/tenblock/$b-summary.json
  grep -E "rows|perms|block_hash|hash" /tmp/opcg-p256/tenblock/$b.log | tail -6
done
date; echo TENBLOCK-DONE
