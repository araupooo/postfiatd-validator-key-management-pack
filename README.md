# Postfiatd Validator Key-Management Evidence Pack

Evidence pack assessing validator identity and manifests, key
generation, rotation, revocation, compromise detection and recovery,
and post-quantum migration for postfiatd, pinned to postfiatd
revision `0085a1ff885d6a446369cf73a4430f75af22be55` (2026-10-10) and
liboqs 0.14.0 (commit `94b421ebb82405c843dba4e9aa521a56ee5a333d`).

## Headline findings

- **16 findings: 3 HIGH, 6 MEDIUM, 6 LOW, 1 INFO** (`docs/RISK_REGISTER.md`, `data/risk_register.json`).
- **Overall score 1.4 / 5** (`docs/SCORECARD.md`). Compromise
  detection and recovery scores 0 — nothing detects compromise;
  master-key compromise is terminal by design.
- **Live inventory (2026-11-26):** 25 testnet validators, VL
  sequence 31. All 25 master keys Ed25519; all 25 signing keys
  secp256k1. 16 of 25 have rotated at least once (max sequence 13);
  9 never rotated. Mean manifest 234.6 B.
- **Fresh measurements (liboqs 0.14.0, single thread):** ML-DSA-44
  verify 25,714.1/s; SLH-DSA-128s sign 3.6/s; dual Ed25519+ML-DSA-44
  verify 4,440.2/s. PQ verification is fast enough; PQ signing is
  the bottleneck.
- **Size impact ([SIMULATED]):** full-PQ manifests are 32-146x
  current size (ML-DSA-44: 7,502 B; SLH-DSA-128f: 34,278 B). The
  staged hybrid (master-only ML-DSA-44) is 3,872 B.
- **PFQS v1 envelope is byte-exact** (8-byte header + 64 B Ed25519
  + 2,420 B ML-DSA-44 = 2,492 B per signature); open decisions
  D-01..D-05 are labelled explicitly in `data/roadmap.json`.

## Contents

- `docs/CLAIMS.md` — claim index ([MEASURED]/[SIMULATED]/[UNSUPPORTED]) with log:line citations.
- `docs/KEY_INVENTORY.md` — live testnet validator key inventory.
- `docs/MANIFEST_FORMAT.md` — manifest format and size model.
- `docs/KEY_LIFECYCLE.md` — generation, rotation, revocation, compromise.
- `docs/PQ_MIGRATION.md` — post-quantum migration design and staged plan.
- `docs/RISK_REGISTER.md`, `docs/REMEDIATION.md` — findings and fixes.
- `docs/SCORECARD.md`, `docs/ROADMAP.md` — scores and the S0-S4 roadmap.
- `docs/SOURCES.md`, `docs/REPRODUCTION.md`, `docs/FAILURE_MODES.md`.
- `data/` — key_inventory.json, manifest_size_model.json,
  risk_register.json (every finding carries a `source_ref` field),
  scorecard.json, roadmap.json, source_excerpts.json (16 excerpts).
- `harness/`, `scripts/` — benchmarks, probes, and checks.
- `outputs/` — unedited measurement logs and vendored live data.
- `SHA256SUMS`, `verify_digests.sh`, `reproduce.sh`,
  `.github/workflows/ci.yml`.

## Reproduce

```bash
bash reproduce.sh
```

Exit 0 with `REPRODUCE OK` means every check passed. Measurements
are re-run into a scratch directory (vendored logs are never
overwritten); digests are verified against `SHA256SUMS`. No
postfiatd checkout is required: source checks run against vendored
excerpts, with an optional `--pin` cross-check. See
`docs/REPRODUCTION.md`.
