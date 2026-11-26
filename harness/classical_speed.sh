#!/bin/sh
# classical_speed.sh — OpenSSL classical baseline (Ed25519 sign/verify,
# ECDSA sign/verify across OpenSSL's curve set, including P-256).
# Writes benchmark-classical.log into $1 (default outputs/). The two
# openssl runs are timed separately because the ECDSA curve sweep is
# slow on a throttled machine; total runtime is a few minutes at most.
#
# NOTE: postfiatd verifies validations with secp256k1 ECDSA via
# libsecp256k1 (src/libxrpl/protocol/PublicKey.cpp), which OpenSSL
# `speed` cannot measure directly on this build. The P-256 ECDSA
# numbers below are the measured classical-ECDSA proxy: same 256-bit
# ECDSA construction, different curve. They are labelled as P-256 in
# the log and in docs/CLAIMS.md, never presented as secp256k1 rates.
set -eu
OUTDIR="${1:-outputs}"
mkdir -p "$OUTDIR"
{
    echo "classical baseline: openssl speed (OpenSSL 3.0.13)"
    echo "command: timeout 60 openssl speed -elapsed -seconds 2 ed25519"
    timeout 60 openssl speed -elapsed -seconds 2 ed25519 2>&1
    echo "command: timeout 170 openssl speed -elapsed -seconds 2 ecdsa"
    timeout 170 openssl speed -elapsed -seconds 2 ecdsa 2>&1
    echo "note: P-256 ECDSA above is the classical-ECDSA proxy for secp256k1 (see header); Ed25519 is measured directly"
} > "$OUTDIR/benchmark-classical.log" 2>&1
echo "wrote $OUTDIR/benchmark-classical.log"
