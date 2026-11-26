#!/bin/sh
# environment.sh — record the machine/toolchain context of a measurement
# run into $1/environment.txt. No measured rates are written here, so
# this file is stable except for the timestamp line.
set -eu
OUTDIR="${1:-outputs}"
PINNED_LIBOQS_COMMIT="${2:-94b421ebb82405c843dba4e9aa521a56ee5a333d}"
mkdir -p "$OUTDIR"
{
    echo "machine: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "cpus: $(nproc)"
    echo "memory: $(free -m | awk '/^Mem:/ {print $2" MB total"}')"
    echo "os: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
    echo "openssl: $(openssl version)"
    echo "compiler: $(cc --version | head -1)"
    echo "liboqs: 0.14.0 commit $PINNED_LIBOQS_COMMIT"
    echo "liboqs build: liboqs 0.14.0 (see harness/run_benchmarks.sh for source resolution)"
    echo "postfiatd pin: 0085a1ff885d6a446369cf73a4430f75af22be55 (2026-10-10, version 1.0.9)"
    echo "threads: single thread for all benchmarks"
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$OUTDIR/environment.txt"
echo "wrote $OUTDIR/environment.txt"
