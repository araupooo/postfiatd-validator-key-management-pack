# Risk Register

16 findings: 3 HIGH, 6 MEDIUM, 6 LOW, 1 INFO. Rank = severity first,
then exploitability. Every finding carries a `source_ref` field in
`data/risk_register.json` naming its anchor. Full text in
`docs/REMEDIATION.md`.

| Rank | ID | Severity | Exploitability | Title |
|------|----|----------|----------------|-------|
| 1 | K-01 | HIGH | High | Validation keys are secp256k1-only, hardcoded in three places |
| 2 | K-02 | HIGH | High | Master-key compromise is terminal: revocation permanently removes the validator |
| 3 | K-03 | HIGH | Medium | No compromise detection for validator keys anywhere in-tree |
| 4 | K-04 | MEDIUM | High | No key-rotation automation: rotation is fully manual |
| 5 | K-05 | MEDIUM | Medium | Manifest creation exists only in tests; production has no minting tool |
| 6 | K-06 | MEDIUM | Medium | validation_create invites secret leakage via shell history and ps |
| 7 | K-07 | MEDIUM | Low | Manifest version is pinned to 0 with no upgrade path |
| 8 | K-08 | MEDIUM | Low | Untrusted-manifest cache bound (1000) is not size-aware |
| 9 | K-09 | LOW | Medium | Mixed key types: Ed25519 master, secp256k1 ephemeral |
| 10 | K-10 | LOW | Low | Manifests never expire: no timestamp or expiry field |
| 11 | K-11 | LOW | Low | Domain is unauthenticated free text |
| 12 | K-12 | LOW | Low | Public RPC refuses validator-inventory methods |
| 13 | K-13 | LOW | Low | getSigningKey falls back to the master key when no manifest is known |
| 14 | K-14 | MEDIUM | Medium | Full-PQ manifests are 32-146x current size and cross a length-encoding boundary |
| 15 | K-15 | INFO | Low | Live rotation is uneven: 16 of 25 rotated, 9 never rotated |
| 16 | K-16 | LOW | Low | PQ verification is fast enough; PQ signing is the bottleneck |

Top 3 by rank: K-01 (secp256k1 hardcoded), K-02 (terminal revocation),
K-03 (no compromise detection).
