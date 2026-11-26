#!/bin/sh
# verify_digests.sh — check every file listed in SHA256SUMS.
# Exits 0 only when every covered file matches its recorded hash.
# (SHA256SUMS itself and outputs/reproduce_selfcheck.log are excluded
# by design: the self-check log embeds the digest output and can
# never match its own recorded hash.)
set -eu
cd "$(dirname "$0")"
sha256sum -c SHA256SUMS
