# Manifest Format and Size Model

## The format (pinned source)

A validator manifest is a serialized `STObject` (`sfGeneric`) with
this template (`src/xrpld/app/misc/detail/Manifest.cpp:59-82`):

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| sfPublicKey (master) | VL | required | 33-byte public key |
| sfMasterSignature | VL | required | signature with the master key |
| sfSequence | UINT32 | required | sequence number |
| sfVersion | UINT16 | default (0) | only version 0 is understood (`Manifest.cpp:90-93`) |
| sfDomain | VL | optional | validated only as a well-formed TOML domain (`:109-113`) |
| sfSigningPubKey | VL | optional | the ephemeral signing key |
| sfSignature | VL | optional | signature with the ephemeral key |

Regular manifests must contain a signing key and its signature;
revocation manifests must not (`Manifest.cpp:117-149`). The signing
and master keys cannot be the same (`:145-149`).

Verification (`Manifest::verify`, `Manifest.cpp:196-213`) checks two
signatures: the ephemeral signature (unless revoked), then the master
signature, both over the `HashPrefix::manifest` domain-separated blob
(`HashPrefix::manifest`, `include/xrpl/protocol/HashPrefix.h:84`).
Revocation is sequence `0xFFFFFFFF` (`Manifest.cpp:235-241`).

## The size model

Script: `scripts/manifest_size_model.py`. Machine data:
`data/manifest_size_model.json`. The model starts from the measured
live inventory (mean manifest 234.6 B, mean DER ephemeral signature
70.52 B, mean domain 18.08 B) and the FIPS/liboqs parameter table.

Per manifest, in bytes:

```
size = FIXED + master_pk + signing_pk + master_sig + ephemeral_sig
       + EXTRA_LEN_PREFIX
FIXED = 34.08 (field headers 7 + VL length-prefix base 5
        + sfSequence value 4 + mean domain 18.08)
EXTRA_LEN_PREFIX = +1 per VL field whose value exceeds 192 bytes
        (length prefix grows 1 -> 2 bytes); +2 per field whose value
        exceeds 12,480 bytes (3-byte prefix)
```

Sanity check: the model reproduces the measured mean exactly
(current variant 235 B vs measured mean 234.6 B).

## Variant table ([SIMULATED])

| Variant | Manifest bytes | Ratio vs current |
|---------|---------------|------------------|
| Current: Ed25519 master + secp256k1 ephemeral | 235 | 1.0x |
| ML-DSA-44, both halves | 7,502 | 32.0x |
| ML-DSA-65, both halves | 10,560 | 45.0x |
| ML-DSA-87, both halves | 14,476 | 61.7x |
| SLH-DSA-128s, both halves | 15,812 | 67.4x |
| SLH-DSA-128f, both halves | 34,278 | 146.1x |
| Hybrid dual Ed25519+ML-DSA-44 (PFQS v1) | 7,710 | 32.9x |
| Staged: ML-DSA-44 master only | 3,872 | 16.5x |
| Staged: ML-DSA-44 ephemeral only | 3,865 | 16.5x |

## Gossip impact ([SIMULATED])

- 25 manifests (one greeting set): current 5,865 B; ML-DSA-44
  187,550 B; SLH-DSA-128f 856,950 B.
- Untrusted-manifest cache bound (1000, `Manifest.h:283`): current
  234,600 B; ML-DSA-44 7,502,000 B.

## Encoding detail

SLH-DSA-128f signatures (17,088 B) exceed the 12,480-byte two-byte
VL length limit, so they need 3-byte length prefixes — two extra
bytes per such field instead of one. Every other variant stays
within the two-byte range. This is a property of the VL encoding,
not of the signature scheme, and it is accounted for in the model
(`len_prefix_extra` in `scripts/manifest_size_model.py`).

## PFQS v1 envelope (byte-exact)

The hybrid signature envelope used in the size model fixes every
byte (see `docs/PQ_MIGRATION.md` for the full layout):

| Offset | Length | Content |
|--------|--------|---------|
| 0 | 1 | version = 0x01 |
| 1 | 1 | scheme id = 0x01 (Ed25519 + ML-DSA-44) |
| 2 | 1 | mode = 0x00 (both halves required) |
| 3 | 5 | reserved, must be 0x00 |
| 8 | 64 | Ed25519 signature |
| 72 | 2,420 | ML-DSA-44 signature |

Total 2,492 B per signature. The composite public key is 1,344 B
(32 B raw Ed25519 + 1,312 B ML-DSA-44; `hybrid_bench.log`
`hybrid_public_key_len: 1344`). Unspecified bytes: none — the
envelope is fully specified. Open decisions D-01..D-05 are labelled
in `data/roadmap.json`, not hidden inside the format.
