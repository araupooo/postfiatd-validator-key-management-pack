# Failure Modes

Ways this pack can be wrong, and what was done about each.

## FM-01 — Live probe hit a stale or cached VL file

- **Risk:** the VL file could have been cached between fetch and
  probe. **Mitigation:** the VL and all 25 manifests were fetched
  in one run (2026-11-26 02:14 UTC); the VL sequence (31) matches
  the sequence the manifests were checked against. The raw VL is
  vendored byte-identical in `outputs/live_vl_raw.json`.

## FM-02 — Benchmark numbers are machine-specific

- **Risk:** ops/s depend on CPU and load. **Mitigation:** single
  thread, 5 s budgets, environment recorded in
  `outputs/environment.txt`; the pack's claims are about relative
  magnitudes (ML-DSA-44 verifies ~3.8x Ed25519; SLH-DSA-128s signs
  at 3.6/s), not absolute rates. Reproduction re-runs the harness
  and compares within tolerance, not exactly.

## FM-03 — Classical baseline is not secp256k1

- **Risk:** the P-256 ECDSA numbers are read as secp256k1 rates.
  **Mitigation:** labelled [UNSUPPORTED] as U-01; the claim index
  states explicitly that M-15 is a same-construction proxy, not a
  secp256k1 rate. No secp256k1 throughput is claimed anywhere.

## FM-04 — Size model uses means, not per-validator values

- **Risk:** a validator with a long domain or a 72-byte DER
  signature would exceed the modelled mean. **Mitigation:** the
  model is anchored to the measured mean (234.6 B) and reproduces
  it exactly; the fixed part of the model separates domain length
  (18.08 B mean) from the rest, so a longer domain adds exactly its
  own length. The per-validator sizes are all in
  `data/key_inventory.json` for anyone who wants the worst case
  (246 B).

## FM-05 — SLH-DSA-128f length-prefix boundary

- **Risk:** a reader might apply the two-byte VL length prefix to
  a 17,088-byte signature. **Mitigation:** the model accounts for
  the 3-byte prefix (+2 bytes per SLH-DSA-128f field) and calls it
  out in `docs/MANIFEST_FORMAT.md` and claim S-04.

## FM-06 — Negative searches can miss obfuscated names

- **Risk:** a grep for "key rotation" misses a differently-named
  mechanism. **Mitigation:** six independent negative searches
  (N-1..N-6) with varied terms, plus manual reads of the
  surrounding files (Manifest.cpp in full, ValidatorKeys.cpp,
  ValidationCreate.cpp). The claim is "no automation found", not
  "no automation exists" — but the live evidence (9/25 never
  rotated) is consistent with manual-only rotation.

## FM-07 — secp256k1 verify rate is not measured (U-01)

- **Risk:** a reader compares ML-DSA-44 verify (25,714/s) with the
  P-256 ECDSA proxy (10,557/s) and concludes ML-DSA is 2.4x faster
  than secp256k1. **Mitigation:** U-01 labels the proxy explicitly;
  the comparison that IS claimed is ML-DSA-44 vs Ed25519 (both
  measured: 25,714 vs 6,784 = 3.8x).

## FM-08 — Rotation cadence is unobservable (U-02)

- **Risk:** sequence numbers are read as a rotation schedule.
  **Mitigation:** U-02 states the cadence is unobservable; the pack
  reports only the current sequence distribution (L-03) and does
  not infer when rotations happened.

## FM-09 — Absence of an observed revocation is not proof of safety (U-03)

- **Risk:** "no revocation observed" is read as "no compromise ever
  occurred". **Mitigation:** U-03 states this explicitly; the
  finding K-03 (no detection) exists precisely because compromise
  would be invisible.

## FM-10 — Reproduce overwrites vendored logs

- **Risk:** a re-run overwrites the evidence it is checking.
  **Mitigation:** `reproduce.sh` runs measurements into a scratch
  directory (`MEASUREMENT_OUTDIR`); vendored logs are never
  overwritten. The selfcheck log is excluded from `SHA256SUMS`
  (it embeds the digest output) and is verified by byte-identical
  regeneration.

## FM-11 — CI depends on a local checkout path

- **Risk:** a script greps a checkout that does not exist on the
  runner. **Mitigation:** all source checks run against vendored
  excerpts in `data/source_excerpts.json`; `--pin` is an optional
  silent cross-check only.
