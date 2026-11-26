# Remediation Roadmap

Staged S0-S4. Each stage names its fixes (finding IDs) and an exit
criterion. Machine data: `data/roadmap.json`. Open decisions D-01..D-05
are labelled explicitly in the roadmap data and in `docs/PQ_MIGRATION.md`.

## S0 — Stop the bleeding: secret handling + revocation readiness

- K-06: route `validation_create` through a file/stdin secret path; never accept secrets on the command line.
- K-02: publish a tested master-key revocation runbook (revocation manifest + list update) and rehearse it on testnet.
- **Exit:** a revocation can be published end-to-end on testnet within one hour of decision, without putting a secret on any command line.

## S1 — Make rotation real: tooling + policy

- K-04: ship an in-tree manifest minting/rotation tool (the test helper logic, productized) with sequence management.
- K-05: document the rotation procedure and a recommended cadence; publish each validator's rotation policy.
- K-15: track sequence numbers per validator and alert on staleness.
- **Exit:** any validator can rotate its ephemeral key with one command; rotation events are visible in the manifest sequence history.

## S2 — Detection: notice compromise before it is exploited

- K-03: add manifest/validation anomaly monitoring (unexpected sequence jumps, duplicate ephemeral keys, new master keys).
- K-10: add optional manifest expiry (not-valid-after) so stale manifests die without operator action.
- **Exit:** a compromised-key scenario is detected by monitoring, not by an operator happening to notice.

## S3 — Post-quantum design: version the format, stage the migration

- K-07: define manifest version 1 with a PQ-capable field layout and a dual-version acceptance window.
- K-01: parameterize `ValidatorKeys`/`validation_create` over key type instead of hardcoding secp256k1.
- K-14: adopt the staged hybrid (master-only ML-DSA-44 first, 3,872 B) before full PQ; set a gossip/cache budget for 7,502 B manifests.
- **Exit:** a version-1 manifest verifies on a test build; staged hybrid manifests stay within the gossip budget.

## S4 — Migrate and operate

- K-08: make the untrusted-manifest bound size-aware.
- K-09: complete the dual-key migration and retire secp256k1-only paths.
- K-11/K-12/K-13: authenticate domains where relied upon, publish validator inventory via the node, remove the master-key fallback.
- **Exit:** all testnet validators run PQ or hybrid manifests; secp256k1-only validation keys are gone.

## Open decisions

- **D-01:** Manifest version 1 field layout: which PQ algorithms are permitted per key slot (ML-DSA-44 only, or a small set). Status: open.
- **D-02:** Whether the master key migrates first or the ephemeral key migrates first (this pack recommends master-first; the size difference is a wash — 3,872 B vs 3,865 B — but master-first retires the long-lived key sooner). Status: open.
- **D-03:** Gossip/cache budget for PQ manifests: keep 1000 unlisted manifests (7.5 MB at ML-DSA-44) or lower the bound. Status: open.
- **D-04:** Manifest expiry length, if any (no expiry exists today; a value must be chosen before K-10 can ship). Status: open.
- **D-05:** Whether `validation_create` stays admin-only RPC or moves to a dedicated offline tool (the CLI-leak warning pushes toward offline). Status: open.
