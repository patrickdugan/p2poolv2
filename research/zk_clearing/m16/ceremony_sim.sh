#!/usr/bin/env bash
# A simulated multi-party Groth16 phase 2, closed by a Bitcoin block hash fixed in advance.
#
# Usage:
#   bash ceremony_sim.sh contribute <circuit.r1cs> <phase-1 .ptau> <contributors> <beacon height> <out dir>
#   bash ceremony_sim.sh finish     <circuit.r1cs> <phase-1 .ptau> <beacon block hash> <out dir>
#
# `contribute` first writes the beacon height to <out>/transcript.txt, so the beacon is named
# before any contribution exists. It then runs `snarkjs groth16 setup` and one contribution per
# contributor. Each contributor is its own Linux user (zkc-contrib-<i>, created if missing) with
# its own home directory:
#   - it reads the previous zkey from a hand-off directory;
#   - it contributes with 64 bytes of its own /dev/urandom, held in a shell variable and never
#     written to disk;
#   - it writes the next zkey and its contribution hash to the hand-off directory, and deletes
#     its copies.
# The setup is sound if any one contributor destroyed its entropy. Here the contributors share
# a machine and an administrator, so this run shows the procedure, not independence.
#
# `finish` applies the beacon (the hash of the block at the height named in the transcript,
# 2^10 iterations), runs `snarkjs zkey verify` over the whole chain against the circuit and the
# phase-1 file, and exports the verifying key.
#
# Needs node and snarkjs where every contributor can run them: ZKC_CEREMONY_TOOLS (default
# /opt/zkc-ceremony) holds node/ and node_modules/ (copied there by `contribute` from NODE_DIR
# and SNARKJS_MODULES).
set -euo pipefail

MODE="${1:?usage: ceremony_sim.sh contribute|finish ...}"
TOOLS="${ZKC_CEREMONY_TOOLS:-/opt/zkc-ceremony}"
NODE="$TOOLS/node/bin/node"
SNARKJS=("$NODE" "$TOOLS/node_modules/snarkjs/build/cli.cjs")
strip() { sed 's/\x1b\[[0-9;]*m//g'; }

case "$MODE" in
contribute)
  R1CS="$(realpath "${2:?r1cs}")"; PTAU="$(realpath "${3:?ptau}")"; N="${4:?contributors}"; HEIGHT="${5:?beacon height}"
  OUT="$(mkdir -p "${6:?out dir}" && cd "$6" && pwd)"
  NAME="$(basename "$R1CS" .r1cs)"
  if [ ! -x "$NODE" ]; then
    mkdir -p "$TOOLS"
    cp -a "${NODE_DIR:?set NODE_DIR to a node install}" "$TOOLS/node"
    cp -a "${SNARKJS_MODULES:?set SNARKJS_MODULES to a node_modules with snarkjs}" "$TOOLS/node_modules"
    chmod -R a+rX "$TOOLS"
  fi
  {
    echo "ceremony for $NAME, r1cs sha256 $(sha256sum "$R1CS" | cut -d' ' -f1)"
    echo "phase 1: $(basename "$PTAU"), sha256 $(sha256sum "$PTAU" | cut -d' ' -f1)"
    echo "beacon: the hash of testnet4 block $HEIGHT, named $(date -u +%FT%TZ) before any contribution"
  } > "$OUT/transcript.txt"
  HANDOFF="$OUT/handoff"
  mkdir -p "$HANDOFF"
  chmod 1777 "$HANDOFF"
  "${SNARKJS[@]}" groth16 setup "$R1CS" "$PTAU" "$HANDOFF/${NAME}_0.zkey" > /dev/null
  chmod a+r "$HANDOFF/${NAME}_0.zkey"
  for i in $(seq 1 "$N"); do
    user="zkc-contrib-$i"
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
    start=$(date +%s.%N)
    # The contributor's own shell: its entropy lives only in this process.
    su - "$user" -c "set -euo pipefail
      cp '$HANDOFF/${NAME}_$((i - 1)).zkey' ~/in.zkey
      entropy=\$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
      '$NODE' '$TOOLS/node_modules/snarkjs/build/cli.cjs' zkey contribute ~/in.zkey ~/out.zkey --name='contributor $i ($user)' -e=\"\$entropy\" > ~/contribution.log
      unset entropy
      cp ~/out.zkey '$HANDOFF/${NAME}_$i.zkey'
      chmod a+r '$HANDOFF/${NAME}_$i.zkey'
      sed 's/\x1b\[[0-9;]*m//g' ~/contribution.log | grep -A4 'Contribution Hash' > '$HANDOFF/contribution_$i.txt'
      rm -f ~/in.zkey ~/out.zkey ~/contribution.log"
    rm -f "$HANDOFF/${NAME}_$((i - 1)).zkey"
    printf 'contribution %d by %s (uid %s): %s s\n' "$i" "$user" "$(id -u "$user")" "$(awk -v a="$start" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')" | tee -a "$OUT/transcript.txt"
    tr -s ' ' < "$HANDOFF/contribution_$i.txt" | tr '\n' ' ' | cut -c1-220 | tee -a "$OUT/transcript.txt"; echo | tee -a "$OUT/transcript.txt"
  done
  echo "contributions done; waiting for the beacon block $HEIGHT" | tee -a "$OUT/transcript.txt"
  ;;
finish)
  R1CS="$(realpath "${2:?r1cs}")"; PTAU="$(realpath "${3:?ptau}")"; BEACON="${4:?beacon block hash}"
  OUT="$(cd "${5:?out dir}" && pwd)"
  NAME="$(basename "$R1CS" .r1cs)"
  last="$(ls "$OUT/handoff/${NAME}"_*.zkey | sort -t_ -k3 -n | tail -1)"
  echo "beacon block hash: $BEACON" >> "$OUT/transcript.txt"
  "${SNARKJS[@]}" zkey beacon "$last" "$OUT/$NAME.zkey" "$BEACON" 10 -n="testnet4 block hash beacon" > /dev/null
  "${SNARKJS[@]}" zkey verify "$R1CS" "$PTAU" "$OUT/$NAME.zkey" | strip > "$OUT/verify.log"
  grep -q "ZKey Ok!" "$OUT/verify.log" || { echo "zkey verify FAILED"; tail -20 "$OUT/verify.log"; exit 1; }
  "${SNARKJS[@]}" zkey export verificationkey "$OUT/$NAME.zkey" "$OUT/verification_key.json" > /dev/null
  {
    echo "zkey verify: ZKey Ok!"
    grep -E "contribution #|Beacon generator|^\s+[0-9a-f]{8} [0-9a-f]{8}" "$OUT/verify.log" | head -60
    echo "verifying key sha256: $(sha256sum "$OUT/verification_key.json" | cut -d' ' -f1)"
  } | tee -a "$OUT/transcript.txt"
  ;;
*) echo "mode must be contribute or finish"; exit 2 ;;
esac
