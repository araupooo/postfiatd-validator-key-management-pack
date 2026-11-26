#!/usr/bin/env python3
"""check_measurements.py — structural check of a measurement run.

Reads the measurement logs in $MEASUREMENT_OUTDIR (default outputs/)
and the vendored live inventory + size model, and verifies structure,
not absolute rates (rates vary by machine; see docs/FAILURE_MODES.md):
  - every algorithm block present in benchmark-pq.log, controls PASS,
    measured lengths equal to the FIPS/liboqs parameter table;
  - dual-signature envelopes 2,484 B (ML-DSA-44) and 17,152 B
    (SLH-DSA-128f), controls C-1..C-5 PASS for both;
  - classical Ed25519 + P-256 ECDSA baseline present;
  - the FIPS-205-name probe log matches the vendored evidence
    (ALGORITHM_NOT_ENABLED) — note: the probe log contains a
    timestamp, so reproduce compares structure, not bytes;
  - live inventory: 25 validators, all master keys Ed25519 (ED
    prefix), all signing keys secp256k1 (02/03 prefix), every parsed
    manifest field table sums to its manifest byte length, every
    sequence >= 1;
  - size model: current variant reproduces the measured mean manifest
    size within 1 byte; every variant's arithmetic re-derives from
    the parameter table and the inventory means.

Exit 0 with "CHECK OK" only when every check passes. Prints one
verbose [step] line per check as it runs.
"""
import json
import os
import re
import sys

OUTDIR = os.environ.get("MEASUREMENT_OUTDIR", "outputs")
PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(name):
    p = os.path.join(OUTDIR, name)
    if not os.path.isfile(p):
        print(f"[FAIL] missing log: {p}")
        sys.exit(1)
    return open(p).read()


def check(cond, label):
    print(f"[step] {label}: {'PASS' if cond else 'FAIL'}")
    if not cond:
        sys.exit(1)


SIG_LENGTHS = {
    "ML-DSA-44": (2420, 1312),
    "ML-DSA-65": (3309, 1952),
    "ML-DSA-87": (4627, 2592),
    "SPHINCS+-SHA2-128s-simple": (7856, 32),
    "SPHINCS+-SHA2-128f-simple": (17088, 32),
}

pq = read("benchmark-pq.log")
for alg, (sig_len, pk_len) in SIG_LENGTHS.items():
    check(f"algorithm: {alg}" in pq, f"benchmark-pq block present: {alg}")
    check(f"length_signature: {sig_len}" in pq, f"{alg} signature length {sig_len} B")
    check(f"length_public_key: {pk_len}" in pq, f"{alg} public-key length {pk_len} B")
check(pq.count("control_valid_signature_verifies: PASS") >= 7,
      "benchmark-pq controls: valid verifies (7 blocks)")
check(pq.count("control_tampered_signature_rejected: PASS") >= 7,
      "benchmark-pq controls: tampered rejects (7 blocks)")
check("--- ML-DSA-44 (225-byte payload) ---" in pq,
      "benchmark-pq 225-byte payload block present")
check("--- SLH-DSA-SHA2-128f (225-byte payload) ---" in pq,
      "benchmark-pq 225-byte SLH-DSA block present")

dual = read("hybrid_dual_sig_bench.log")
check("hybrid_signature_len: 2484" in dual,
      "dual-sig envelope 2484 B (64 Ed25519 + 2420 ML-DSA-44)")
check("hybrid_signature_len: 17152" in dual,
      "dual-sig envelope 17152 B (64 Ed25519 + 17088 SLH-DSA-128f)")
check(dual.count("control C-1: PASS") == 2, "dual-sig control C-1 PASS (both hybrids)")
check(dual.count("control C-2: PASS") == 2, "dual-sig control C-2 PASS (both hybrids)")
check(dual.count("control C-3: PASS") == 2, "dual-sig control C-3 PASS (both hybrids)")
check(dual.count("control C-4: PASS") == 2, "dual-sig control C-4 PASS (both hybrids)")
check(dual.count("control C-5: PASS") == 2, "dual-sig control C-5 PASS (both hybrids)")
check("hybrid_verify_ops_per_sec:" in dual, "dual-sig verify rate present")

classical = read("benchmark-classical.log")
check(re.search(r"EdDSA \(Ed25519\)\s+[\d.]+s\s+[\d.]+s\s+[\d.]+\s+[\d.]+", classical) is not None,
      "benchmark-classical Ed25519 sign/verify rates present")
check("256 bits ecdsa" in classical or "256 bit ecdsa" in classical,
      "benchmark-classical P-256 ECDSA section present")

probe = read("negative_fips205_names.log")
check("result: ALGORITHM_NOT_ENABLED" in probe,
      "FIPS 205 name probe: SLH-DSA-SHA2-128s not registered")

# Live inventory structure (vendored data, not re-probed).
inv_path = os.path.join(PACK, "data", "key_inventory.json")
inv = json.load(open(inv_path))
vals = inv["validators"]
check(len(vals) == 25, "live inventory: 25 validators")
check(inv["vl_sequence"] == 31, "live inventory: VL sequence 31")
for v in vals:
    check(v["master_key_type"] == "Ed25519", f"validator {v['index']}: master key Ed25519")
    check(v["signing_key_type"] == "secp256k1", f"validator {v['index']}: signing key secp256k1")
    check(v["sequence"] >= 1, f"validator {v['index']}: sequence >= 1")
    total = sum(f["total_bytes"] for f in v["fields"])
    check(total == v["manifest_bytes"],
          f"validator {v['index']}: field table sums to manifest bytes")
    by_name = {f["field"]: f for f in v["fields"]}
    check(by_name["sfMasterSignature"]["value_bytes"] == 64,
          f"validator {v['index']}: master signature 64 B")
    check(by_name["sfSignature"]["value_bytes"] in (70, 71),
          f"validator {v['index']}: ephemeral DER signature 70-71 B")
check(sum(1 for v in vals if v["sequence"] > 1) == 16,
      "live inventory: 16 of 25 validators rotated (seq > 1)")

# Size model arithmetic (re-derived here from the parameter table).
model = json.load(open(os.path.join(PACK, "data", "manifest_size_model.json")))
mean_total = model["inventory"]["mean_manifest_bytes"]
mean_der = model["inventory"]["mean_der_ephemeral_sig_bytes"]
fixed = model["inventory"]["fixed_part_bytes"]
check(abs(model["variants"]["current"]["manifest_bytes"] - mean_total) < 1.0,
      "size model: current variant reproduces measured mean within 1 B")
for name, (pk, sig) in (("pq_both_ML-DSA-44", (1312, 2420)),
                        ("pq_both_ML-DSA-65", (1952, 3309)),
                        ("pq_both_ML-DSA-87", (2592, 4627)),
                        ("pq_both_SLH-DSA-128s", (32, 7856)),
                        ("pq_both_SLH-DSA-128f", (32, 17088))):
    v = model["variants"][name]
    # VL length prefix: 1 byte base; +1 when a value exceeds 192 bytes,
    # +2 when it exceeds 12480 bytes (3-byte prefix).
    extra = sum((0 if x <= 192 else 1 if x <= 12480 else 2)
                for x in (pk, pk, sig, sig))
    expected = round(fixed + 2 * pk + 2 * sig + extra)
    check(v["manifest_bytes"] == expected,
          f"size model: {name} arithmetic {expected} B")
    check(abs(v["ratio_vs_current"] - expected / mean_total) < 0.01,
          f"size model: {name} ratio consistent")

# Hybrid dual (PFQS v1 envelope): composite pk 1344 B per slot,
# envelope signature 2492 B per slot, +1 length-prefix byte per VL
# field whose value exceeds 192 bytes (all four do).
dual_v = model["variants"]["hybrid_dual_mldsa44"]
extra_dual = sum((0 if x <= 192 else 1 if x <= 12480 else 2)
                 for x in (1344, 1344, 2492, 2492))
expected_dual = round(fixed + 2 * 1344 + 2 * 2492 + extra_dual)
check(dual_v["manifest_bytes"] == expected_dual,
      f"size model: hybrid dual ML-DSA-44 arithmetic {expected_dual} B")
check(abs(dual_v["ratio_vs_current"] - expected_dual / mean_total) < 0.01,
      "size model: hybrid dual ratio consistent")

print("CHECK OK")
