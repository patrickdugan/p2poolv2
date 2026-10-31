#!/usr/bin/env bash
# Build the M1 and M2 workspace in a native Linux directory (WSL: not /mnt/*, which is slow).
#
# Usage: bash research/zk_clearing/bitvm/scripts/build.sh <work dir> [cargo test args...]
#
# 1. BitVM c620dbf is cloned into <work>/BitVM-c620dbf (from $BITVM_SRC if set, a local clone
#    or URL, else GitHub) and patches/0001-bitvm-18-public-inputs.patch is applied. With
#    ZKC_PUBS=1 (M3, accounting16x4_hashed) patches/0002-bitvm-1-public-input.patch is applied
#    on top, setting NUM_PUBS back to 1.
# 2. research/zk_clearing is copied to <work>/src, with vendor/BitVM linked to that checkout.
# 3. cargo build --release, then cargo test --release. Cargo.lock is seeded from BitVM's lock
#    file the first time and copied back into the repository.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZK="$(dirname "$HERE")"
WORK="$(mkdir -p "${1:?usage: build.sh <work dir>}" && cd "$1" && pwd)"
shift
BITVM_REV=c620dbf
BITVM="$WORK/BitVM-$BITVM_REV"

case "${ZKC_PUBS:-18}" in
  18) PATCHES=(0001-bitvm-18-public-inputs.patch) ;;
  1) PATCHES=(0001-bitvm-18-public-inputs.patch 0002-bitvm-1-public-input.patch) ;;
  *) echo "ZKC_PUBS must be 18 (M1) or 1 (M3)"; exit 2 ;;
esac

if [ "$(cat "$BITVM/.zkc-patched" 2>/dev/null)" != "${PATCHES[*]}" ]; then
  rm -rf "$BITVM"
  git clone -q --no-checkout "${BITVM_SRC:-https://github.com/BitVM/BitVM}" "$BITVM"
  git -C "$BITVM" -c core.autocrlf=false checkout -q "$BITVM_REV"
  for patch in "${PATCHES[@]}"; do
    git -C "$BITVM" apply "$HERE/patches/$patch"
  done
  echo "${PATCHES[*]}" > "$BITVM/.zkc-patched"
fi

mkdir -p "$WORK/src"
rm -rf "$WORK/src/zk_clearing"
(cd "$ZK/.." && tar --exclude=target --exclude=vendor --exclude=__pycache__ -cf - zk_clearing) | tar -xf - -C "$WORK/src"
mkdir -p "$WORK/src/zk_clearing/bitvm/vendor"
ln -sfn "$BITVM" "$WORK/src/zk_clearing/bitvm/vendor/BitVM"

cd "$WORK/src/zk_clearing/bitvm"
[ -f Cargo.lock ] || cp "$BITVM/Cargo.lock" Cargo.lock
export CARGO_TARGET_DIR="$WORK/target"
cargo build --release
cargo test --release "$@"
cp Cargo.lock "$HERE/Cargo.lock"
echo "built: $CARGO_TARGET_DIR/release/zkc-convert $CARGO_TARGET_DIR/release/zkc-m1 $CARGO_TARGET_DIR/release/zkc-m2"
