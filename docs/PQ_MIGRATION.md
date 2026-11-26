# Post-Quantum Migration

## Where validator keys stand today

- Master keys: Ed25519 (live: 25/25). Signing keys: secp256k1
  (live: 25/25). Both are classical; zero PQ names exist in the
  pinned tree (negative search N-1: 0 hits).
- The signing key is hardcoded to secp256k1 in three places
  (K-01). The manifest format is version-locked to 0 (K-07).
- Fresh measurements (liboqs 0.14.0, single thread, this pack):
  ML-DSA-44 verify 25,714.1/s, sign 8,715.6/s; ML-DSA-65 verify
  16,161.5/s; ML-DSA-87 verify 11,459.4/s; SLH-DSA-128s verify
  2,571.4/s, sign 3.6/s; SLH-DSA-128f verify 920.1/s, sign 70.0/s.
  Classical baseline: Ed25519 verify 6,784.0/s; P-256 ECDSA verify
  10,557.5/s (proxy for secp256k1, see U-01).
- Verification is not the bottleneck: ML-DSA-44 verifies 3.8x
  faster than Ed25519. Signing is: SLH-DSA-128s signs at 3.6/s.
  Prefer ML-DSA-44 for validator keys.

## PFQS v1 hybrid envelope (byte-exact)

Each signature slot in a hybrid manifest carries this envelope
(2,492 B total). There are no unspecified bytes.

| Offset | Length | Content |
|--------|--------|---------|
| 0 | 1 | version = 0x01 |
| 1 | 1 | scheme id = 0x01 (Ed25519 + ML-DSA-44) |
| 2 | 1 | mode = 0x00 (both halves required; a verifier MUST reject if either half fails) |
| 3 | 5 | reserved, must be 0x00 (a verifier MUST reject any non-zero byte) |
| 8 | 64 | Ed25519 signature |
| 72 | 2,420 | ML-DSA-44 signature |

Composite public key per slot: 1,344 B (32 B raw Ed25519 +
1,312 B ML-DSA-44; `hybrid_dual_sig_bench.log`
`hybrid_public_key_len: 1344`). Measured dual-signature
performance: verify 4,440.2/s, sign 7,113.9/s, controls C-1..C-5
PASS (`hybrid_dual_sig_bench.log:15-51`). The dual SLH-DSA-128f
variant (17,152 B signature, verify 762.7/s) is measured but not
recommended: it is 2.2x the size of the ML-DSA-44 dual for a slower
verify.

Legacy-verifier behavior during stage 1 (one half migrated): a
legacy verifier that understands only the classical half verifies
the classical half and ignores the PQ half — it does NOT fail
closed. That is the staged-migration trade-off, stated plainly:
during the transition, a quantum adversary can forge the classical
half alone. Stage 1 must be time-boxed, with a published date after
which verifiers require both halves (mode 0x00 enforced).

## Staged plan

1. **Master-first (recommended):** migrate the master key to
   ML-DSA-44 first (manifest 3,872 B, 16.5x). The master key is the
   long-lived key; retiring it sooner matters more than the 7-byte
   size difference vs ephemeral-first (3,865 B).
2. **Ephemeral second:** migrate the signing key (manifest 7,710 B,
   32.9x once both halves are dual).
3. **Full PQ (optional, later):** pure ML-DSA-44 manifests are
   7,502 B; pure SLH-DSA-128f is 34,278 B and is not recommended
   (size + signing latency + the 3-byte VL length-prefix detail).
4. **Format versioning first:** define manifest version 1 (D-01)
   before minting any PQ key, with a dual-version acceptance window.

## Open decisions (labelled, not hidden)

- **D-01:** Manifest version 1 field layout: which PQ algorithms are permitted per key slot.
- **D-02:** Master-first vs ephemeral-first (this pack recommends master-first).
- **D-03:** Gossip/cache budget for PQ manifests (1000 unlisted manifests = 7.5 MB at ML-DSA-44).
- **D-04:** Manifest expiry length, if any.
- **D-05:** Whether `validation_create` stays admin-only RPC or moves to a dedicated offline tool.
