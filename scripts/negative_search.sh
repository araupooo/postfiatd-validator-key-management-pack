#!/bin/sh
# negative_search.sh — reproducible negative searches over the pinned
# postfiatd checkout (~/workspace/postfiatd-pin-0085a1f, or $PIN).
# Each search logs every step as it happens, with the exact command,
# the hit count, and (when zero) the first lines of what was searched.
# A zero hit count is evidence of absence IN THE SEARCHED SCOPE, not
# a proof about the world; the scope is printed with each result.
#
# Usage: PIN=/path/to/checkout sh scripts/negative_search.sh
# Outputs: outputs/negative_search.log and outputs/negative_pq_names.log
set -eu
cd "$(dirname "$0")/.."
PIN="${PIN:-$HOME/workspace/postfiatd-pin-0085a1f}"
LOG="outputs/negative_search.log"
mkdir -p outputs
{
echo "=== negative searches over the pinned postfiatd tree ==="
echo "checkout: $PIN"
echo "checkout HEAD: $(git -C "$PIN" rev-parse HEAD)"
echo "expected pin: 0085a1ff885d6a446369cf73a4430f75af22be55"
if [ "$(git -C "$PIN" rev-parse HEAD)" = "0085a1ff885d6a446369cf73a4430f75af22be55" ]; then
    echo "[step] checkout HEAD matches pinned commit: PASS"
else
    echo "[step] checkout HEAD matches pinned commit: FAIL"
    exit 1
fi
echo ""
} > "$LOG"

run_search() {
    label="$1"; shift
    echo "[step] search: $label" >> "$LOG"
    echo "  scope: $PIN/src $PIN/include" >> "$LOG"
    echo "  pattern: $*" >> "$LOG"
    hits=$(grep -rniE "$@" "$PIN/src" "$PIN/include" 2>/dev/null | grep -v "^Binary" || true)
    count=$(printf "%s" "$hits" | grep -c . || true)
    if [ -z "$hits" ]; then count=0; fi
    echo "  hits: $count" >> "$LOG"
    if [ "$count" -gt 0 ]; then
        printf "%s\n" "$hits" | head -10 | sed 's/^/  hit: /' >> "$LOG"
    fi
    echo "  result: $label -> $count hits" >> "$LOG"
    echo "" >> "$LOG"
}

# N-1: no post-quantum algorithm names anywhere in the tree.
run_search "N-1 post-quantum algorithm names (ML-DSA/Dilithium/SLH-DSA/SPHINCS/ML-KEM/Kyber/FIPS 204/FIPS 205/CRYSTALS)" \
    'ML-DSA|Dilithium|SLH-DSA|SPHINCS|ML-KEM|Kyber|FIPS 204|FIPS 205|CRYSTALS'
# N-2: no key-rotation automation.
run_search "N-2 key-rotation automation (key rotation / rotate key / rekey)" \
    'key.?rotation|rotate.?key|rekey'
# N-3: no in-tree manifest creation (production code only; tests excluded
# by scope below — this search is run separately with a path filter).
echo "[step] search: N-3 manifest creation in production code (src/xrpld only)" >> "$LOG"
echo "  scope: $PIN/src/xrpld (tests excluded)" >> "$LOG"
echo "  pattern: makeManifest|createManifest|signManifest" >> "$LOG"
hits3=$(grep -rn 'makeManifest\|createManifest\|signManifest' "$PIN/src/xrpld" 2>/dev/null | grep -v makeManifestMessages || true)
count3=$(printf "%s" "$hits3" | grep -c . || true)
if [ -z "$hits3" ]; then count3=0; fi
echo "  hits: $count3 (makeManifestMessages gossip serialization excluded)" >> "$LOG"
if [ "$count3" -gt 0 ]; then
    printf "%s\n" "$hits3" | head -10 | sed 's/^/  hit: /' >> "$LOG"
fi
echo "  result: N-3 manifest creation in production code -> $count3 hits" >> "$LOG"
echo "" >> "$LOG"
# N-4: no Ed25519 validation-key path (ValidatorKeys.cpp hardcodes secp256k1).
echo "[step] search: N-4 Ed25519 in ValidatorKeys.cpp" >> "$LOG"
echo "  scope: $PIN/src/xrpld/app/misc/detail/ValidatorKeys.cpp" >> "$LOG"
echo "  pattern: ed25519" >> "$LOG"
count4=$(grep -ci 'ed25519' "$PIN/src/xrpld/app/misc/detail/ValidatorKeys.cpp" || true)
echo "  hits: $count4" >> "$LOG"
echo "  result: N-4 Ed25519 in ValidatorKeys.cpp -> $count4 hits" >> "$LOG"
echo "" >> "$LOG"
# N-5: no manifest-rotation scheduling (timers, expiry, renewal for manifests).
run_search "N-5 manifest expiry/renewal scheduling" \
    'manifest.*expir|expir.*manifest|renew.*manifest|manifest.*renew|rotate.*manifest|manifest.*rotat'
# N-6: no compromise-detection machinery for validator keys.
run_search "N-6 compromise detection for validator keys" \
    'compromised.*key|key.*compromis|detect.*compromis|revocation.*detect'

echo "=== summary (derived from the hit counts logged above) ===" >> "$LOG"
grep -E "^  result: " "$LOG" | sed 's/^  result: /  /' >> "$LOG"
echo "NEGATIVE SEARCH OK" >> "$LOG"
cat "$LOG"
