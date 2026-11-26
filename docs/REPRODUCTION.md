# Reproduction

## Prerequisites

- Linux x86_64, gcc, make, cmake, git, python3, openssl.
- `liboqs` 0.14.0 is cloned by `harness/run_benchmarks.sh` into
  `.deps/` (tag `0.14.0`); no checkout of postfiatd is required.
- No network access is needed except the initial liboqs clone
  (and only for the harness build; the live probe already ran and
  its raw responses are vendored in `outputs/`).

## Reproduce everything

```bash
bash reproduce.sh
```

This runs, in order:

1. `scripts/check_excerpts.py` — verifies the 16 vendored source
   excerpts are self-consistent (and, with `--pin`, against a real
   postfiatd checkout if one is present at the pinned revision).
2. `scripts/check_measurements.py` — re-derives every measured
   number in `docs/CLAIMS.md` from the vendored logs and re-checks
   the size model against its inputs.
3. `harness/run_benchmarks.sh` — rebuilds the harness from
   liboqs 0.14.0 and re-runs all measurements into a scratch
   directory (never overwriting the vendored logs), then compares
   the fresh results with the vendored values within tolerance.
4. `bash verify_digests.sh` — verifies every file in the pack
   against `SHA256SUMS`.

Exit 0 with `REPRODUCE OK` means all four steps passed. The
self-check log is written to `outputs/reproduce_selfcheck.log`.
That log embeds the digest output, so it is excluded from
`SHA256SUMS` by design and is verified by byte-identical
regeneration instead.

## Verify digests only

```bash
bash verify_digests.sh
```

## Fresh-clone check

Clone this repository to a fresh directory, run `bash
reproduce.sh` there, and compare `outputs/reproduce_selfcheck.log`
with the vendored one: the digests and the selfcheck SHA-256 must
match. A postfiatd checkout must NOT be required: run with the
pinned checkout moved aside to prove it.

## CI

`.github/workflows/ci.yml` runs `bash reproduce.sh` on
`ubuntu-latest` with Python 3.12 and no secrets.
