# Sources

## Primary sources

- **postfiatd** — pinned revision `0085a1ff885d6a446369cf73a4430f75af22be55`
  (2026-10-10, branch 1.0.9, tag `1.0.9`). All file:line citations
  in this pack are verified with `grep -n` against a local checkout
  of this revision; see `data/source_excerpts.json` (16 excerpts,
  E-01..E-16, verified verbatim by `scripts/check_excerpts.py
  --pin`). The pack does not require a postfiatd checkout to
  reproduce: checks run against the vendored excerpts.
- **liboqs 0.14.0** — commit `94b421ebb82405c843dba4e9aa521a56ee5a333d`,
  tag `0.14.0`. Fresh measurements in this pack were built from this
  tag. FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) parameter sizes
  match the measured values.
- **Live testnet** — validator list `https://postfiat.org/testnet_vl.json`
  (sequence 31, 25 validators) and manifests via
  `https://rpc.testnet.postfiat.org` (method `manifest`), probed
  2026-11-26. Raw responses vendored in `outputs/live_vl_raw.json`
  and `outputs/live_manifest_raw.json`.

## Prior packs re-used (numbers re-verified, not copied)

- PQ signature and hybrid benchmarks were re-run fresh in this
  pack's harness (`outputs/benchmark-pq.log`,
  `outputs/hybrid_dual_sig_bench.log`); the earlier packs'
  numbers were used only as a sanity cross-check (within a few
  percent on the same machine) and are not cited as evidence here.
- The live validator-list size (25 validators) and the quorum model
  (17 @ 67%) were confirmed again by the live probe in this pack.
- The PFQS v1 envelope (8-byte header + 64 B Ed25519 + 2,420 B
  ML-DSA-44 = 2,492 B) is carried from the consolidated PQ security
  pack and re-derived here from the fresh dual-signature bench
  (`hybrid_public_key_len: 1344`, `hybrid_signature_len: 2484`).

## Standards

- FIPS 204 (ML-DSA): public-key sizes 1,312 / 1,952 / 2,592 B,
  signature sizes 2,420 / 3,309 / 4,627 B.
- FIPS 205 (SLH-DSA): public-key size 32 B, signature sizes 7,856 B
  (128s) / 17,088 B (128f).

## Notes on line numbers

Every cited line number was taken from `grep -n` on the pinned
checkout. The excerpts in `data/source_excerpts.json` carry their
exact file:line ranges; `scripts/check_excerpts.py --pin` re-verifies
them against a real checkout when one is present.
