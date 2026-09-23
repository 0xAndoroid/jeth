#!/bin/zsh
# usage: profile_block.sh <side> <block>  — exact-row symbol attribution with target/guest-<side>
set -e
side=$1; block=$2
unset CARGO_TARGET_DIR
export JETH_GUEST_TARGET_DIR=/Volumes/Dev/worktrees/jeth/inlines-b-bls/target/guest-$side
export JOLT_PATH=/Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt
cd /Volumes/Dev/worktrees/jeth/inlines-b-bls
target/release/jeth profile --input /Volumes/Dev/jeth-scratch/inlines-b-bls/data/$block/input.bin --rows --top 60 --skip-build \
  --entries 'mul_assign,square_in_place,sum_of_products,add_assign,sub_assign,double_in_place,neg_in_place,inverse,bls12_381,kzg,QuadExtField' \
  > /Volumes/Dev/jeth-scratch/inlines-b-bls/logs/profile$block-$side.log 2>&1
echo "exit=$?"
