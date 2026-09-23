#!/bin/zsh
# usage: build_guest_side.sh <side>  — build the four guest ELF flavours into target/guest-<side>-* in parallel
side=$1
unset CARGO_TARGET_DIR
JOLT=/Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt
PREFIX=/Volumes/Dev/worktrees/jeth/inlines-b-bls/target/guest-$side
cd /Volumes/Dev/worktrees/jeth/inlines-b-bls/crates/guest
for spec in "validate_block|guest|1" "validate_block-compute_advice|guest,compute_advice|" "validate_block-pertx|guest,pertx|" "validate_block-pertx-compute_advice|guest,pertx,compute_advice|"; do
  dir=${spec%%|*}; rest=${spec#*|}; feats=${rest%%|*}; sym=${rest#*|}
  ( export JOLT_FUNC_NAME=validate_block; [ -n "$sym" ] && export JOLT_BACKTRACE=1
    start=$(date +%s)
    $JOLT build -p jeth-guest --backtrace off --stack-size 33554432 --heap-size 1610612736 -- --release --target-dir $PREFIX-$dir --features $feats > /Volumes/Dev/jeth-scratch/inlines-b-bls/logs/build-$side-$dir.log 2>&1
    echo "$dir exit=$? $(( $(date +%s) - start ))s" >> /Volumes/Dev/jeth-scratch/inlines-b-bls/logs/build-$side-summary.log ) &
done
wait
cat /Volumes/Dev/jeth-scratch/inlines-b-bls/logs/build-$side-summary.log
