#!/usr/bin/env python3
"""manifest_size_model.py — post-quantum validator-manifest size model.

Derives the serialized size of a validator manifest under each
signature scheme from the LIVE inventory (data/key_inventory.json):
every live manifest was parsed field by field (scripts/parse_manifest.py),
so the model starts from measured field sizes, not from a guess.

Model (per manifest, bytes):
  size = FIXED + master_pk + signing_pk + master_sig + ephemeral_sig
         + EXTRA_LEN_PREFIX
  FIXED = field headers (7 B: one byte per field, two for
          sfMasterSignature) + VL length-prefix base (5 B, one per VL
          field) + sfSequence value (4 B) + domain value (mean live
          domain length). Measured from the inventory: mean total
          234.6 B - mean pk values (33 + 33) - mean sig values
          (64 master + mean DER ephemeral) = FIXED.
  EXTRA_LEN_PREFIX = +1 for each VL field whose value exceeds 192
          bytes: the rippled VL length prefix grows from 1 byte to 2
          bytes (193..12480 range). A 33-byte public key stays 1 byte;
          a 1,312-byte ML-DSA public key or a 2,420-byte signature costs
          one extra byte each.

Algorithm parameter table (liboqs 0.14.0 / FIPS 204 Table 2 /
FIPS 205; verified against benchmark-pq.log by
scripts/check_measurements.py):
  ML-DSA-44  pk 1312  sig 2420
  ML-DSA-65  pk 1952  sig 3309
  ML-DSA-87  pk 2592  sig 4627
  SLH-DSA-128s  pk 32  sig 7856
  SLH-DSA-128f  pk 32  sig 17088
  Ed25519    pk 33    sig 64
  secp256k1  pk 33    sig DER 70-72 (measured mean from inventory)
  PFQS v1 envelope (docs/PQ_MIGRATION.md): 8-byte header + 64 B Ed25519
          + 2420 B ML-DSA-44 = 2492 B per signature; composite public
          key 33 + 1312 = 1345 B per key slot.

Writes data/manifest_size_model.json. Deterministic: re-running it
regenerates the file byte-identically from the vendored inventory.

Usage: python3 scripts/manifest_size_model.py
"""
import json
import os

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (public-key bytes, signature bytes) per scheme, from FIPS 204/205
# and liboqs 0.14.0 headers; checked against benchmark-pq.log.
PARAMS = {
    "Ed25519": (33, 64),
    "secp256k1": (33, None),  # signature is variable DER; mean measured below
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
    "SLH-DSA-128s": (32, 7856),
    "SLH-DSA-128f": (32, 17088),
}


def len_prefix_extra(value_bytes: int) -> int:
    """Extra length-prefix bytes vs the 1-byte base, for a VL field."""
    if value_bytes <= 192:
        return 0
    if value_bytes <= 12480:
        return 1
    return 2


def main():
    inv = json.load(open(os.path.join(PACK, "data", "key_inventory.json")))
    vals = inv["validators"]
    n = len(vals)
    print(f"[step] inventory: {n} validators, VL sequence {inv['vl_sequence']}")

    totals = [v["manifest_bytes"] for v in vals]
    mean_total = sum(totals) / n
    der = [f["value_bytes"] for v in vals for f in v["fields"]
           if f["field"] == "sfSignature"]
    mean_der = sum(der) / len(der)
    domains = [len(v["domain"] or "") for v in vals]
    mean_domain = sum(domains) / n
    print(f"[step] mean manifest size: {mean_total:.2f} B "
          f"(min {min(totals)}, max {max(totals)})")
    print(f"[step] mean ephemeral DER signature: {mean_der:.2f} B "
          f"(values {sorted(set(der))})")
    print(f"[step] mean domain length: {mean_domain:.2f} B "
          f"(min {min(domains)}, max {max(domains)})")

    # FIXED = mean total - pk values - sig values (all measured).
    fixed = mean_total - 33 - 33 - 64 - mean_der
    print(f"[step] FIXED part: {fixed:.2f} B "
          f"(headers 7 + len-prefix base 5 + sequence 4 + mean domain "
          f"{mean_domain:.2f})")
    assert abs(fixed - (7 + 5 + 4 + mean_domain)) < 0.01, "FIXED mismatch"

    def model(master_scheme, ephemeral_scheme, master_sig=None, eph_sig=None):
        mpk, msig = PARAMS[master_scheme]
        epk, esig = PARAMS[ephemeral_scheme]
        if master_sig is not None:
            msig = master_sig
        if eph_sig is not None:
            esig = eph_sig
        extra = (len_prefix_extra(mpk) + len_prefix_extra(epk)
                 + len_prefix_extra(msig) + len_prefix_extra(esig))
        size = fixed + mpk + epk + msig + esig + extra
        return round(size), extra

    variants = {}
    # Current deployment: Ed25519 master, secp256k1 ephemeral (DER mean).
    size, extra = model("Ed25519", "secp256k1", eph_sig=mean_der)
    variants["current"] = {
        "label": "Current: Ed25519 master + secp256k1 ephemeral",
        "master_pk": 33, "signing_pk": 33,
        "master_sig": 64, "ephemeral_sig": round(mean_der, 2),
        "extra_len_prefix_bytes": extra,
        "manifest_bytes": size,
        "ratio_vs_current": 1.0,
    }
    print(f"[step] current model: {size} B (measured mean {mean_total:.2f} B)")
    assert abs(size - mean_total) < 1.0, "current model does not reproduce the measured mean"

    for pq in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
               "SLH-DSA-128s", "SLH-DSA-128f"):
        size, extra = model(pq, pq)
        mpk, msig = PARAMS[pq]
        variants[f"pq_both_{pq}"] = {
            "label": f"Full PQ: {pq} master + {pq} ephemeral",
            "master_pk": mpk, "signing_pk": mpk,
            "master_sig": msig, "ephemeral_sig": msig,
            "extra_len_prefix_bytes": extra,
            "manifest_bytes": size,
            "ratio_vs_current": round(size / mean_total, 2),
        }
        print(f"[step] {pq} both: {size} B "
              f"({size / mean_total:.1f}x current)")

    # Hybrid dual signature (PFQS v1 envelope): 8-byte header + 64 B
    # Ed25519 + 2420 B ML-DSA-44 = 2492 B per signature; composite
    # public key 32 + 1312 = 1344 B per key slot (raw keys, no 0xED prefix;
#          hybrid_bench.log hybrid_public_key_len: 1344). All four VL fields
    # exceed 192 bytes, so each costs one extra length-prefix byte.
    dual_extra = 4
    dual_size = round(fixed + 1344 + 1344 + 2492 + 2492 + dual_extra)
    variants["hybrid_dual_mldsa44"] = {
        "label": "Hybrid dual Ed25519+ML-DSA-44 (PFQS v1 envelope, both signatures)",
        "master_pk": 1344, "signing_pk": 1344,
        "master_sig": 2492, "ephemeral_sig": 2492,
        "extra_len_prefix_bytes": dual_extra,
        "manifest_bytes": dual_size,
        "ratio_vs_current": round(dual_size / mean_total, 2),
    }
    print(f"[step] hybrid dual ML-DSA-44: {dual_size} B "
          f"({dual_size / mean_total:.1f}x current)")

    # Staged hybrids: only one half migrates.
    size, extra = model("ML-DSA-44", "secp256k1", eph_sig=mean_der)
    variants["hybrid_master_only_mldsa44"] = {
        "label": "Staged: ML-DSA-44 master only, secp256k1 ephemeral",
        "master_pk": 1312, "signing_pk": 33,
        "master_sig": 2420, "ephemeral_sig": round(mean_der, 2),
        "extra_len_prefix_bytes": extra,
        "manifest_bytes": size,
        "ratio_vs_current": round(size / mean_total, 2),
    }
    print(f"[step] master-only ML-DSA-44: {size} B")
    size, extra = model("Ed25519", "ML-DSA-44")
    variants["hybrid_ephemeral_only_mldsa44"] = {
        "label": "Staged: Ed25519 master, ML-DSA-44 ephemeral only",
        "master_pk": 33, "signing_pk": 1312,
        "master_sig": 64, "ephemeral_sig": 2420,
        "extra_len_prefix_bytes": extra,
        "manifest_bytes": size,
        "ratio_vs_current": round(size / mean_total, 2),
    }
    print(f"[step] ephemeral-only ML-DSA-44: {size} B")

    # Gossip impact: 25 manifests per validator-list greeting set,
    # and the untrusted-manifest cache bound (1000, Manifest.h:283).
    current_total = round(mean_total * n)
    model_out = {
        "inventory": {
            "validators": n,
            "vl_sequence": inv["vl_sequence"],
            "mean_manifest_bytes": round(mean_total, 2),
            "min_manifest_bytes": min(totals),
            "max_manifest_bytes": max(totals),
            "mean_der_ephemeral_sig_bytes": round(mean_der, 2),
            "mean_domain_bytes": round(mean_domain, 2),
            "fixed_part_bytes": round(fixed, 2),
        },
        "variants": variants,
        "gossip_impact": {
            "validators": n,
            "current_25_manifests_bytes": current_total,
            "mldsa44_25_manifests_bytes": variants["pq_both_ML-DSA-44"]["manifest_bytes"] * n,
            "slh128f_25_manifests_bytes": variants["pq_both_SLH-DSA-128f"]["manifest_bytes"] * n,
            "untrusted_cap_manifests": 1000,
            "current_1000_manifests_bytes": round(mean_total * 1000),
            "mldsa44_1000_manifests_bytes": variants["pq_both_ML-DSA-44"]["manifest_bytes"] * 1000,
        },
    }
    out = os.path.join(PACK, "data", "manifest_size_model.json")
    with open(out, "w") as f:
        json.dump(model_out, f, indent=2)
        f.write("\n")
    print(f"[step] model written to data/manifest_size_model.json")
    print("MODEL OK")


if __name__ == "__main__":
    main()
