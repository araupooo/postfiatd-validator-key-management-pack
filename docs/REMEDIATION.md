# Remediation

Each finding from `data/risk_register.json` with its fix. Every finding
carries a `source_ref` field in the register naming its anchor (pinned
file:line or vendored log line). Severity first, then exploitability.
The single most valuable fix is S0-1 (route key generation away from
the command line); the second is S0-2 (rehearse master-key revocation).

## Priority order

1. **S0-1 stop secret leakage in key generation (K-06)** — the only in-tree key-generation path warns in its own source that secrets on the command line leak via shell history and `ps`.
2. **S0-2 rehearse master-key revocation (K-02)** — the revocation path is terminal and has no runbook; a compromise with no rehearsed response is a longer outage.
3. **S0-3 ship an in-tree manifest tool (K-04, K-05)** — rotation is manual and manifest creation exists only in tests.

## validator-identity-and-manifests

### K-09 — LOW: Mixed key types: Ed25519 master, secp256k1 ephemeral

- **Rank:** 9 of 16 · **Exploitability:** Medium · **Origin:** live inventory
- **Source ref:** data/key_inventory.json (25/25 master Ed25519, 25/25 signing secp256k1); Manifest.cpp:196-213
- **Fix:** In the PQ migration, replace both halves together (see docs/PQ_MIGRATION.md). Do not migrate one half and leave the other classical: a manifest verified by two algorithms has two failure modes, and a half-migrated manifest is only as strong as its classical half.

### K-10 — LOW: Manifests never expire: no timestamp or expiry field

- **Rank:** 10 of 16 · **Exploitability:** Low · **Origin:** source
- **Source ref:** src/xrpld/app/misc/detail/Manifest.cpp:59-82,411
- **Fix:** Add an optional not-valid-after to manifest version 1 (open decision D-04). Until then, treat sequence numbers as the only freshness signal and alert on validators whose sequence has not advanced.

### K-11 — LOW: Domain is unauthenticated free text

- **Rank:** 11 of 16 · **Exploitability:** Low · **Origin:** source + live
- **Source ref:** src/xrpld/app/misc/detail/Manifest.cpp:109-113; data/key_inventory.json
- **Fix:** Do not treat the domain as identity evidence. If a domain is relied upon for anything (display, contact), verify control of it out-of-band; the in-tree check only confirms the string is a well-formed TOML domain.

### K-12 — LOW: Public RPC refuses validator-inventory methods

- **Rank:** 12 of 16 · **Exploitability:** Low · **Origin:** live probe
- **Source ref:** outputs/live_manifest_probe.log:9-11
- **Fix:** Publish validator inventory through the node (or document the publisher VL file as the canonical source). Monitoring that depends on `validators`/`peers` RPCs silently gets nothing today.

### K-13 — LOW: getSigningKey falls back to the master key when no manifest is known

- **Rank:** 13 of 16 · **Exploitability:** Low · **Origin:** source
- **Source ref:** src/xrpld/app/misc/detail/Manifest.cpp:310-320; ValidatorList.cpp:2072-2075
- **Fix:** No code change needed for trusted validators (the trusted-set path asserts a manifest exists). Document the fallback as intentional legacy behavior; do not rely on it for new deployments.

## key-generation

### K-01 — HIGH: Validation keys are secp256k1-only, hardcoded in three places

- **Rank:** 1 of 16 · **Exploitability:** High · **Origin:** source
- **Source ref:** src/xrpld/app/misc/detail/ValidatorKeys.cpp:47,84-85; src/xrpld/rpc/handlers/ValidationCreate.cpp:54,58
- **Fix:** Parameterize `ValidatorKeys`, `generateSecretKey`/`derivePublicKey` call sites, and `validation_create` over `KeyType` instead of hardcoding `KeyType::secp256k1`. This is the precondition for any PQ validator key: without it, no config change can migrate a validator.

### K-06 — MEDIUM: validation_create invites secret leakage via shell history and ps

- **Rank:** 6 of 16 · **Exploitability:** Medium · **Origin:** source
- **Source ref:** src/xrpld/rpc/detail/RPCCall.cpp:1100-1103
- **Fix:** Route secrets through a file or stdin, never the command line; document the file path as the only supported input. `validation_create` is admin-only today, which bounds the exposure to operators — keep it that way (open decision D-05).

## key-rotation-and-revocation

### K-02 — HIGH: Master-key compromise is terminal

- **Rank:** 2 of 16 · **Exploitability:** High · **Origin:** source
- **Source ref:** src/xrpld/app/misc/Manifest.h:66-76; src/xrpld/app/misc/detail/Manifest.cpp:235-241
- **Fix:** Publish and rehearse a revocation runbook now, while no compromise is active: who decides, who signs the 0xFFFFFFFF revocation manifest, how the validator list is updated, how every node is told. A terminal mechanism with no rehearsed response is an outage waiting for a decision.

### K-04 — MEDIUM: No key-rotation automation: rotation is fully manual

- **Rank:** 4 of 16 · **Exploitability:** High · **Origin:** source + live
- **Source ref:** outputs/negative_search.log (N-2: 0; N-5: 3 benign); data/key_inventory.json (9/25 seq 1)
- **Fix:** Ship an in-tree manifest minting/rotation tool (productize the test helper `makeManifestString`, `src/test/app/Manifest_test.cpp:106`), with sequence management, and document a recommended rotation cadence. Track sequence numbers per validator and alert on staleness.

### K-05 — MEDIUM: Manifest creation exists only in tests

- **Rank:** 5 of 16 · **Exploitability:** Medium · **Origin:** source
- **Source ref:** outputs/negative_search.log (N-3: 0); src/test/app/Manifest_test.cpp:106,193
- **Fix:** Same as K-04: the rotation tool is the fix. External/offline tooling that is not in this tree cannot be audited here; bring it in-tree or publish and version it.

### K-07 — MEDIUM: Manifest version is pinned to 0 with no upgrade path

- **Rank:** 7 of 16 · **Exploitability:** Low · **Origin:** source
- **Source ref:** src/xrpld/app/misc/detail/Manifest.cpp:72,90-93
- **Fix:** Define manifest version 1 (open decision D-01) with a PQ-capable field layout and a dual-version acceptance window, before any PQ key is minted. A version bump with no migration design is a flag day.

### K-08 — MEDIUM: Untrusted-manifest cache bound (1000) is not size-aware

- **Rank:** 8 of 16 · **Exploitability:** Low · **Origin:** source + model
- **Source ref:** src/xrpld/app/misc/Manifest.h:282-284; data/manifest_size_model.json
- **Fix:** Make the bound size-aware (open decision D-03) and set a gossip budget for PQ manifests before migration: at ML-DSA-44 a full cache is ~7.5 MB and a 25-manifest greeting set is 187,550 B vs 5,865 B today.

### K-14 — MEDIUM: Full-PQ manifests are 32-146x current size

- **Rank:** 14 of 16 · **Exploitability:** Medium · **Origin:** model
- **Source ref:** data/manifest_size_model.json
- **Fix:** Stage the migration (docs/PQ_MIGRATION.md): master-only ML-DSA-44 first (3,872 B, 16.5x), then the ephemeral half. Do not jump to full PQ (7,502 B) or SLH-DSA-128f (34,278 B) without a gossip budget. Note the encoding detail: SLH-DSA-128f signatures cross the 12,480-byte VL length boundary and need 3-byte length prefixes.

### K-15 — INFO: Live rotation is uneven: 16 of 25 rotated, 9 never rotated

- **Rank:** 15 of 16 · **Exploitability:** Low · **Origin:** live
- **Source ref:** data/key_inventory.json
- **Fix:** No code fix. Publish rotation policy per validator and track sequence numbers; a validator that has never rotated is not necessarily at risk, but its rotation path is untested.

## compromise-detection-and-recovery

### K-03 — HIGH: No compromise detection for validator keys anywhere in-tree

- **Rank:** 3 of 16 · **Exploitability:** Medium · **Origin:** source
- **Source ref:** outputs/negative_search.log (N-6: 2 hits, both doc prose)
- **Fix:** Add manifest/validation anomaly monitoring: unexpected sequence jumps, duplicate ephemeral keys across master keys, new master keys appearing for known validators, validations signed by keys with no manifest. Detection must come from monitoring, not from an operator happening to notice.

## post-quantum-readiness

### K-16 — LOW: PQ verification is fast enough; PQ signing is the bottleneck

- **Rank:** 16 of 16 · **Exploitability:** Low · **Origin:** fresh measurement
- **Source ref:** outputs/benchmark-pq.log; outputs/hybrid_dual_sig_bench.log; outputs/benchmark-classical.log
- **Fix:** No fix needed for verification (ML-DSA-44 verifies at 25,714.1/s, 3.8x Ed25519). Plan signing capacity instead: SLH-DSA-128s signs at 3.6/s — a validator that signs manifests rarely can tolerate it, but any high-frequency signing path cannot. Prefer ML-DSA-44 for validator keys (sign 8,715.6/s).
