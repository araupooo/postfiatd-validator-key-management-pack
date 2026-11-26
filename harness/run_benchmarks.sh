#!/bin/sh
# run_benchmarks.sh — re-run this pack's key measurements fresh in its
# own harness (liboqs 0.14.0, single thread) and write the unedited
# output to $MEASUREMENT_OUTDIR (default outputs/).
#
# What is re-run here (all single-threaded):
#   bench_sig     ML-DSA-44/65/87 + SLH-DSA-SHA2-128s/128f sign/verify
#                 (32-byte message, and 225-byte validator-manifest
#                 payload — the smallest live manifest observed)
#   hybrid_bench  Ed25519 + ML-DSA-44 dual-signature (manifest envelope)
#   classical_speed.sh  OpenSSL Ed25519 / ECDSA P-256 baseline
#   manifest_size_model.py  PQ manifest sizes from the live inventory
#
# liboqs source: LIBOQS_SRC, or ~/liboqs when it exists and its HEAD is
# the pinned 0.14.0 commit 94b421ebb82405c843dba4e9aa521a56ee5a333d,
# otherwise a fresh clone of tag 0.14.0 into .deps/liboqs (network).
# The build directory is LIBOQS_BUILD_DIR, default $LIBOQS_SRC/build.
set -eu
cd "$(dirname "$0")/.."
PACK_DIR="$(pwd)"
PINNED_LIBOQS_COMMIT="94b421ebb82405c843dba4e9aa521a56ee5a333d"
OUTDIR="${MEASUREMENT_OUTDIR:-outputs}"

if [ -n "${LIBOQS_SRC:-}" ]; then
    LIBOQS_SRC_DIR="$LIBOQS_SRC"
elif [ -d "$HOME/liboqs" ] && [ "$(git -C "$HOME/liboqs" rev-parse HEAD 2>/dev/null || echo none)" = "$PINNED_LIBOQS_COMMIT" ]; then
    LIBOQS_SRC_DIR="$HOME/liboqs"
else
    LIBOQS_SRC_DIR="$PACK_DIR/.deps/liboqs"
    if [ ! -d "$LIBOQS_SRC_DIR" ]; then
        echo "[step] liboqs not found locally; cloning tag 0.14.0..."
        git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC_DIR"
    fi
fi
LIBOQS_BUILD="${LIBOQS_BUILD_DIR:-$LIBOQS_SRC_DIR/build}"
echo "[step] liboqs source: $LIBOQS_SRC_DIR"
echo "[step] liboqs commit: $(git -C "$LIBOQS_SRC_DIR" rev-parse HEAD)"
if [ "$(git -C "$LIBOQS_SRC_DIR" rev-parse HEAD)" != "$PINNED_LIBOQS_COMMIT" ]; then
    echo "ERROR: liboqs HEAD is not the pinned 0.14.0 commit $PINNED_LIBOQS_COMMIT"
    exit 1
fi
echo "[step] liboqs commit check: PASS (pinned 0.14.0)"
if [ ! -f "$LIBOQS_BUILD/lib/liboqs.a" ]; then
    echo "[step] building liboqs (one-time, a few minutes)..."
    cmake -S "$LIBOQS_SRC_DIR" -B "$LIBOQS_BUILD" -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release -DOQS_DIST_BUILD=OFF
    cmake --build "$LIBOQS_BUILD" -j 2
    echo "[step] liboqs build: PASS"
else
    echo "[step] liboqs library present: $LIBOQS_BUILD/lib/liboqs.a"
fi

mkdir -p "$OUTDIR"
echo "[step] compiling bench_sig..."
cc -O2 -I"$LIBOQS_SRC_DIR/src" -I"$LIBOQS_BUILD/include" \
    harness/bench_sig.c -L"$LIBOQS_BUILD/lib" -loqs -lcrypto -o harness/bench_sig
echo "[step] compiling hybrid_bench..."
cc -O2 -I"$LIBOQS_SRC_DIR/src" -I"$LIBOQS_BUILD/include" \
    harness/hybrid_bench.c -L"$LIBOQS_BUILD/lib" -loqs -lcrypto -o harness/hybrid_bench
echo "[step] harnesses compiled: PASS"

LOG="$OUTDIR/benchmark-pq.log"
{
    echo "=== pq-signature benchmark run ==="
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "liboqs: 0.14.0 (open-quantum-safe/liboqs, tag 0.14.0)"
    echo "message: fixed 32-byte vector (256-bit digest length, mirrors postfiatd sha512Half)"
    echo "threads: 1"
    echo "verify_budget_sec: 5"
    echo "sign_budget_sec: 5 (capped at 25 sign iterations per algorithm)"
    echo ""
} > "$LOG"
# liboqs 0.14.0 does not register the FIPS 205 names (SLH-DSA-SHA2-128s);
# the same parameter sets are registered under their SPHINCS+ names.
for pair in "ML-DSA-44|ML-DSA-44" "ML-DSA-65|ML-DSA-65" "ML-DSA-87|ML-DSA-87" \
        "SLH-DSA-SHA2-128s|SPHINCS+-SHA2-128s-simple" "SLH-DSA-SHA2-128f|SPHINCS+-SHA2-128f-simple"; do
    label="${pair%%|*}"; alg="${pair##*|}"
    echo "[step] bench_sig $label (32-byte message, liboqs name $alg)..."
    echo "--- $label ---" >> "$LOG"
    ./harness/bench_sig "$alg" 5 5 >> "$LOG" 2>&1 || { echo "FAILED: bench_sig $label (see $LOG)"; exit 1; }
    echo "[step] bench_sig $label: PASS"
done
{
    echo ""
    echo "=== pq-signature benchmark, 225-byte validator-manifest payload ==="
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "message: fixed 225-byte validator-manifest payload (repeating pattern; 225 B is the smallest live manifest observed in data/key_inventory.json)"
    echo ""
} >> "$LOG"
for pair in "ML-DSA-44|ML-DSA-44" "SLH-DSA-SHA2-128f|SPHINCS+-SHA2-128f-simple"; do
    label="${pair%%|*}"; alg="${pair##*|}"
    echo "[step] bench_sig $label (225-byte payload)..."
    echo "--- $label (225-byte payload) ---" >> "$LOG"
    ./harness/bench_sig "$alg" 5 5 225 >> "$LOG" 2>&1 || { echo "FAILED: bench_sig $label 225 (see $LOG)"; exit 1; }
    echo "[step] bench_sig $label 225-byte: PASS"
done
echo "[step] benchmark-pq.log written"

HLOG="$OUTDIR/hybrid_dual_sig_bench.log"
{
    echo "=== hybrid dual-signature benchmark ==="
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "liboqs: 0.14.0 (commit 94b421ebb82405c843dba4e9aa521a56ee5a333d)"
    echo "classical half: Ed25519 via OpenSSL EVP"
    echo "manifest: fixed 225-byte validator-manifest payload"
    echo "threads: 1"
    echo "verify_budget_sec: 5"
    echo "sign_budget_sec: 5 (capped at 50 sign iterations per hybrid)"
    echo ""
} > "$HLOG"
echo "[step] running hybrid_bench (Ed25519 + ML-DSA-44 dual signature)..."
./harness/hybrid_bench 5 5 >> "$HLOG" 2>&1 || { echo "FAILED: hybrid benchmark (see $HLOG)"; exit 1; }
echo "[step] hybrid_dual_sig_bench.log written: PASS"
echo "[step] running classical_speed.sh..."
sh harness/classical_speed.sh "$OUTDIR"
echo "[step] benchmark-classical.log written: PASS"
echo "[step] probing FIPS 205 name registration (expected: not registered)..."
./harness/bench_sig "SLH-DSA-SHA2-128s" 1 1 > "$OUTDIR/negative_fips205_names.log" 2>&1 || true
echo "[step] negative_fips205_names.log written: PASS"
echo "[step] running manifest size model (from vendored live inventory)..."
python3 scripts/manifest_size_model.py
echo "[step] manifest size model written: PASS"
echo "[step] writing environment.txt..."
sh harness/environment.sh "$OUTDIR" "$PINNED_LIBOQS_COMMIT"
echo "[step] all benchmarks complete"
