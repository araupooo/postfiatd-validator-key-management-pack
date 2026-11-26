# Claim Index

Every substantive claim in this pack, with its evidence. Labels:

- **[MEASURED]** — re-run fresh in this pack's own harness (liboqs 0.14.0, single thread), observed live on the testnet on 2026-11-26, or read directly from the pinned source with a file:line citation.
- **[SIMULATED]** — the output of a model (the manifest size model in `scripts/manifest_size_model.py`), not a measurement.
- **[UNSUPPORTED]** — a claim this pack could not verify; it is recorded, not endorsed.

Findings (judgements) live in `docs/REMEDIATION.md` and `docs/RISK_REGISTER.md`, never here. Pinned postfiatd revision throughout: `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10). Machine: single thread; see `outputs/environment.txt`. Every risk-register finding carries a `source_ref` field naming its anchor (pinned file:line or vendored log line).

## A. Fresh measurements (this pack, re-run 2026-11-26)

### A1. Post-quantum signatures — `outputs/benchmark-pq.log`

| ID | Claim | Evidence |
|----|-------|----------|
| M-01 | [MEASURED] ML-DSA-44: verify 25,714.134/s, sign 8,715.630/s (32-byte message, 5 s budgets) | `benchmark-pq.log` (`--- ML-DSA-44 ---`, `verify_ops_per_sec: 25714.134` :27, `sign_ops_per_sec: 8715.630` :31) |
| M-02 | [MEASURED] ML-DSA-65: verify 16,161.519/s, sign 5,447.113/s | `benchmark-pq.log` (`--- ML-DSA-65 ---`, :56, :60) |
| M-03 | [MEASURED] ML-DSA-87: verify 11,459.444/s, sign 5,156.079/s | `benchmark-pq.log` (`--- ML-DSA-87 ---`, :85, :89) |
| M-04 | [MEASURED] SLH-DSA-SHA2-128s: verify 2,571.394/s, sign 3.616/s | `benchmark-pq.log` (`--- SLH-DSA-SHA2-128s ---`, :114, :118) |
| M-05 | [MEASURED] SLH-DSA-SHA2-128f: verify 920.075/s, sign 70.018/s | `benchmark-pq.log` (`--- SLH-DSA-SHA2-128f ---`, :142, :146) |
| M-06 | [MEASURED] On a 225-byte validator-manifest payload: ML-DSA-44 verify 25,447.939/s, sign 8,858.931/s | `benchmark-pq.log` (`--- ML-DSA-44 (225-byte payload) ---`, :176, :180) |
| M-07 | [MEASURED] On a 225-byte validator-manifest payload: SLH-DSA-SHA2-128f verify 963.118/s, sign 74.293/s | `benchmark-pq.log` (`--- SLH-DSA-SHA2-128f (225-byte payload) ---`, :205, :209) |
| M-08 | [MEASURED] Signature sizes: ML-DSA-44 2,420 B; ML-DSA-65 3,309 B; ML-DSA-87 4,627 B; SLH-DSA-128s 7,856 B; SLH-DSA-128f 17,088 B. Public-key sizes: ML-DSA-44 1,312 B; ML-DSA-65 1,952 B; ML-DSA-87 2,592 B; SLH-DSA-128s/f 32 B | `benchmark-pq.log` (`length_signature` / `length_public_key` per block: :15/:17, :44/:46, :73/:75, :102/:104, :130/:132); FIPS 204 Table 2; FIPS 205 |
| M-09 | [MEASURED] Every algorithm's controls passed: a valid signature verifies, a tampered signature is rejected | `benchmark-pq.log` (`control_valid_signature_verifies: PASS`, `control_tampered_signature_rejected: PASS` per block, 7 blocks) |
| M-10 | [MEASURED] liboqs 0.14.0 does not register the FIPS 205 names (SLH-DSA-SHA2-128s): the probe returns ALGORITHM_NOT_ENABLED; the same parameter sets are registered under their SPHINCS+ names | `outputs/negative_fips205_names.log` (`result: ALGORITHM_NOT_ENABLED`) |

### A2. Hybrid dual signatures — `outputs/hybrid_dual_sig_bench.log`

| ID | Claim | Evidence |
|----|-------|----------|
| M-11 | [MEASURED] Dual Ed25519 + ML-DSA-44: combined signature 2,484 B, composite public key 1,344 B, verify 4,440.248/s, sign 7,113.913/s; controls C-1..C-5 PASS | `hybrid_dual_sig_bench.log` (`--- hybrid: Ed25519 + ML-DSA-44 ---` :15, `hybrid_signature_len: 2484` :23, `hybrid_public_key_len: 1344` :24, verify :47, sign :51, controls :30/:33/:37/:40/:43) |
| M-12 | [MEASURED] Dual Ed25519 + SLH-DSA-SHA2-128f: combined signature 17,152 B, composite public key 64 B, verify 762.663/s, sign 69.776/s; controls C-1..C-5 PASS | `hybrid_dual_sig_bench.log` (`--- hybrid: Ed25519 + SLH-DSA-SHA2-128f ---` :56, `hybrid_signature_len: 17152` :64, `hybrid_public_key_len: 64` :65, verify :88, sign :92, controls :71/:74/:78/:81/:84) |
| M-13 | [MEASURED] PFQS v1 envelope: 8-byte header + 64 B Ed25519 + 2,420 B ML-DSA-44 = 2,492 B per signature (envelope, not the bare 2,484 B concatenation) | `docs/PQ_MIGRATION.md` (envelope layout, byte-exact); `hybrid_dual_sig_bench.log:23` (bare concatenation 2,484 B) |

### A3. Classical baseline — `outputs/benchmark-classical.log`

| ID | Claim | Evidence |
|----|-------|----------|
| M-14 | [MEASURED] Ed25519 (OpenSSL 3.0.13): sign 18,679.0/s, verify 6,784.0/s | `benchmark-classical.log:12` (`253 bits EdDSA (Ed25519) ... 18679.0 6784.0`) |
| M-15 | [MEASURED] P-256 ECDSA (OpenSSL 3.0.13, nistp256): sign 29,361.5/s, verify 10,557.5/s — this is the classical-ECDSA proxy for secp256k1, NOT a secp256k1 rate (see U-01) | `benchmark-classical.log:68` (`256 bits ecdsa (nistp256) ... 29361.5 10557.5`) |

### A4. Live testnet validator inventory — `outputs/live_manifest_probe.log`, `data/key_inventory.json`

Probed 2026-11-26 (VL fetched 02:14 UTC; manifests via `https://rpc.testnet.postfiat.org`, method `manifest`). Script: `scripts/live_manifest_probe.py`.

| ID | Claim | Evidence |
|----|-------|----------|
| L-01 | [MEASURED] Testnet validator list sequence 31, 25 validators, VL format version 2, expiration 892052157 | `live_manifest_probe.log:6,8` (`VL sequence: 31`, `validators listed: 25`); `outputs/live_vl_raw.json` |
| L-02 | [MEASURED] All 25 master keys are Ed25519 (66 hex chars, ED prefix); all 25 signing keys are secp256k1 (02/03 prefix) | `live_manifest_probe.log:215-216` (`master key types: ['Ed25519']`, `signing key types: ['secp256k1']`); `data/key_inventory.json` |
| L-03 | [MEASURED] Manifest sequences observed: 1 (9 validators), 2 (3), 3 (1), 4 (2), 5 (4), 6 (2), 7 (3), 13 (1). Maximum 13. 16 of 25 validators have rotated at least once; 9 never rotated | `live_manifest_probe.log:214` (`sequences observed: [1, 2, 3, 4, 5, 6, 7, 13]`); `data/key_inventory.json` |
| L-04 | [MEASURED] Manifest sizes: min 225 B, max 246 B, mean 234.6 B. Ephemeral DER signatures 70 B (12 validators) or 71 B (13). Domains present on 25/25, lengths 8-29 chars, mean 18.08 | `data/key_inventory.json`; `data/manifest_size_model.json` (`inventory` section) |
| L-05 | [MEASURED] Every live manifest parses field-by-field with the STObject parser and the field totals sum exactly to the manifest byte length (25/25 PASS) | `live_manifest_probe.log` (per-validator `field totals sum ... : PASS`); `scripts/parse_manifest.py` |
| L-06 | [MEASURED] Example parsed manifest (validator 1, seq 1, domain `app.w.ai`): sfSequence 4 B, sfPublicKey 33 B (ED4D42...), sfSigningPubKey 33 B (0206793A...), sfSignature 71 B DER, sfDomain 8 B, sfMasterSignature 64 B; total 225 B | `live_manifest_probe.log` validator 1 block; `scripts/parse_manifest.py` |
| L-07 | [MEASURED] The public testnet RPC refuses `validators`, `peers`, and `validator_list_sites` (HTTP 403, body `Forbidden`); the `manifest` method works | `live_manifest_probe.log:9-11` |
| L-08 | [MEASURED] VL publisher master key is Ed25519 (ED3F1E0DA736FCF99BE2880A60DBD470715C0E04DD793FB862236B070571FC09E2) | `live_manifest_probe.log:5`; `outputs/live_vl_raw.json` |

### A5. Negative searches — `outputs/negative_search.log`

| ID | Claim | Evidence |
|----|-------|----------|
| N-01 | [MEASURED] Zero post-quantum algorithm names in `src/` + `include/` of the pinned tree (ML-DSA/Dilithium/SLH-DSA/SPHINCS/ML-KEM/Kyber/FIPS 204/FIPS 205/CRYSTALS) | `negative_search.log:11` (`N-1 ... -> 0 hits`) |
| N-02 | [MEASURED] Zero key-rotation automation in `src/xrpld` + `src/libxrpl` (key rotation / rotate key / rekey) | `negative_search.log:17` (`N-2 ... -> 0 hits`) |
| N-03 | [MEASURED] Zero manifest creation in production code (`src/xrpld`): no makeManifest/createManifest/signManifest; the only manifest builder is the test helper `makeManifestString` (`src/test/app/Manifest_test.cpp:106`) / `makeManifest` (:193) | `negative_search.log:23` (`N-3 ... -> 0 hits`) |
| N-04 | [MEASURED] Zero `ed25519` mentions in `ValidatorKeys.cpp`: validation keys are secp256k1-only | `negative_search.log:29` (`N-4 ... -> 0 hits`) |
| N-05 | [MEASURED] Manifest expiry/renewal search: 3 hits, all benign — two test-helper names (`manifest_flood_test.cpp:201,232`, a `rotation` variable) and one unrelated discard timer (`PeerImp.cpp:725`, `manifestDiscard_.expired()`) | `negative_search.log:38` (`N-5 ... -> 3 hits`, hits listed :32-36) |
| N-06 | [MEASURED] Compromise-detection search: 2 hits, both prose in the `Manifest.h` doc comment (:40, :66); no detection code | `negative_search.log:46` (`N-6 ... -> 2 hits`, hits listed :42-44) |

## B. Simulated (model outputs) — `data/manifest_size_model.json`

The model starts from the measured live inventory (mean manifest 234.6 B, mean DER ephemeral signature 70.52 B, mean domain 18.08 B) and the FIPS/liboqs parameter table; see `scripts/manifest_size_model.py` and `docs/MANIFEST_FORMAT.md`. Ratios are against the measured mean 234.6 B.

| ID | Claim | Evidence |
|----|-------|----------|
| S-01 | [SIMULATED] Full-PQ manifest sizes: ML-DSA-44 7,502 B (32.0x), ML-DSA-65 10,560 B (45.0x), ML-DSA-87 14,476 B (61.7x), SLH-DSA-128s 15,812 B (67.4x), SLH-DSA-128f 34,278 B (146.1x) | `manifest_size_model.json` (`variants.pq_both_*`) |
| S-02 | [SIMULATED] Hybrid dual Ed25519+ML-DSA-44 (PFQS v1 envelope): 7,710 B (32.9x). Staged hybrids: master-only ML-DSA-44 3,872 B (16.5x); ephemeral-only ML-DSA-44 3,865 B (16.5x) | `manifest_size_model.json` (`variants.hybrid_*`) |
| S-03 | [SIMULATED] Gossip impact for 25 manifests: current 5,865 B; ML-DSA-44 187,550 B; SLH-DSA-128f 856,950 B. Untrusted-cache bound (1000 manifests): current 234,600 B; ML-DSA-44 7,502,000 B | `manifest_size_model.json` (`gossip_impact`) |
| S-04 | [SIMULATED] SLH-DSA-128f signatures (17,088 B) exceed the 12,480-byte two-byte VL length limit and need 3-byte length prefixes (+2 bytes per such field instead of +1) | `manifest_size_model.json` (`variants.pq_both_SLH-DSA-128f.extra_len_prefix_bytes` = 4); `scripts/manifest_size_model.py` (`len_prefix_extra`) |

## C. Unsupported

| ID | Claim | Evidence |
|----|-------|----------|
| U-01 | [UNSUPPORTED] secp256k1 ECDSA verify rate on this machine: not measured. The P-256 ECDSA numbers (M-15) are a same-construction proxy, not secp256k1 rates; libsecp256k1 throughput is not claimed | `docs/FAILURE_MODES.md` (FM-07) |
| U-02 | [UNSUPPORTED] Rotation cadence and policy per validator: unobservable. Only the current sequence number is visible; when a rotation happened and why is not recorded anywhere public | `docs/FAILURE_MODES.md` (FM-08) |
| U-03 | [UNSUPPORTED] Whether any validator master key has ever been compromised: unobservable. No revocation manifest for any listed validator was observed (all 25 manifests are non-revoked, seq < 0xFFFFFFFF), but absence of an observed revocation is not proof no compromise occurred | `docs/FAILURE_MODES.md` (FM-09) |
