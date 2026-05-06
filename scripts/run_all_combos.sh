#!/bin/bash
# Run all 10 (config, fst_dim_pow2) combinations end-to-end.
# Output goes to outputs/<cpu_tag>_<DB_SIZE_MB>MB/.
#
# This script edits database_constants.h between runs to flip FST_DIM_POW2 and
# DB_SIZE_MB, then restores both at the end.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEADER="$PROJECT_DIR/src/includes/database_constants.h"

# --- Tunables (overridable via env) ---
DB_SIZE_MB="${DB_SIZE_MB:-1024}"   # database size for all runs
EXPERIMENTS="${EXPERIMENTS:-5}"    # passed to run.py -n
WARMUP="${WARMUP:-3}"              # passed to run.py -w

# --- CPU tag for the output folder ---
CPU_RAW=$(awk -F': *' '/^model name/ {print $2; exit}' /proc/cpuinfo)
CPU_TAG=$(echo "$CPU_RAW" | tr '[:upper:]' '[:lower:]' \
                          | sed -E 's/\(r\)|\(tm\)|cpu|@.*//g' \
                          | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g')
OUT_DIR="$PROJECT_DIR/outputs/${CPU_TAG}_${DB_SIZE_MB}MB"
mkdir -p "$OUT_DIR"

echo "==> Output: $OUT_DIR"
echo "==> CPU:    $CPU_RAW"
echo "==> DB:     ${DB_SIZE_MB} MB, n=${EXPERIMENTS}, w=${WARMUP}"

# --- Snapshot originals so we can restore on exit ---
ORIG_DB=$(grep -E '^\s*constexpr size_t DB_SIZE_MB' "$HEADER" | head -1)
ORIG_POW2=$(grep -E '^\s*constexpr bool FST_DIM_POW2' "$HEADER" | head -1)
trap 'sed -i "s/^\s*constexpr size_t DB_SIZE_MB = .*/${ORIG_DB}/" "$HEADER"; \
      sed -i "s/^\s*constexpr bool FST_DIM_POW2 = .*/${ORIG_POW2}/" "$HEADER"; \
      echo "[restore] reverted DB_SIZE_MB and FST_DIM_POW2"' EXIT

# --- Set DB size for this entire script run ---
sed -i "s/^\s*constexpr size_t DB_SIZE_MB = .*/  constexpr size_t DB_SIZE_MB = ${DB_SIZE_MB};/" "$HEADER"

# --- Save STREAM bandwidth baseline (if available) ---
STREAM_BIN="${STREAM_BIN:-/u/yuec12/stream_ispc/build/stream_ispc}"
if [[ -x "$STREAM_BIN" ]]; then
  echo "==> Recording STREAM bandwidth"
  "$STREAM_BIN" > "$OUT_DIR/00_stream_ispc.txt" 2>&1 || true
fi
lscpu > "$OUT_DIR/00_lscpu.txt" 2>&1 || true

# --- Run all combos ---
CONFIGS=(k1 k2_mp k2_rns n4096_k2_mp n4096_k2_rns)
POW2_VALS=(true false)

cd "$PROJECT_DIR"
for POW2 in "${POW2_VALS[@]}"; do
  sed -i "s/^\s*constexpr bool FST_DIM_POW2 = .*/  constexpr bool FST_DIM_POW2 = ${POW2};/" "$HEADER"
  for CFG in "${CONFIGS[@]}"; do
    OUT_FILE="${OUT_DIR}/${CFG}_pow2_${POW2}.txt"
    echo "==== ${CFG} pow2=${POW2}  →  ${OUT_FILE}"
    rm -rf build
    python3 run.py -c "$CFG" -n "$EXPERIMENTS" -w "$WARMUP" \
                   -o "$OUT_FILE"
  done
done

echo "==> DONE. Files in $OUT_DIR:"
ls -1 "$OUT_DIR"
