#!/usr/bin/env python3
"""check_excerpts.py — verify data/source_excerpts.json.

Without --pin: internal consistency only (line numbers sequential and
ascending within each excerpt, files and line ranges plausible, pin
field present).
With --pin <checkout>: every excerpt line is compared verbatim against
the checkout at the pinned commit (HEAD must equal the recorded pin);
any mismatch fails.

Usage:
    python3 scripts/check_excerpts.py
    python3 scripts/check_excerpts.py --pin ~/workspace/postfiatd-pin-0085a1f
"""
import argparse
import json
import os
import subprocess
import sys

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fail(msg):
    print(f"[FAIL] {msg}")
    sys.exit(1)


def step(msg):
    print(f"[step] {msg}: PASS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", default=None, help="pinned postfiatd checkout dir")
    args = ap.parse_args()

    path = os.path.join(PACK, "data", "source_excerpts.json")
    doc = json.load(open(path))
    pin = doc.get("pin")
    if not pin or len(pin) != 40:
        fail("pin field missing or not a full 40-char SHA")
    step("pin field present (40-char SHA)")

    excerpts = doc["excerpts"]
    if len(excerpts) < 1:
        fail("no excerpts")
    for ex in excerpts:
        lines = ex["lines"]
        nums = [l["line"] for l in lines]
        if nums != list(range(nums[0], nums[0] + len(nums))):
            fail(f"{ex['id']}: line numbers not sequential")
        if not ex["file"] or not ex.get("note"):
            fail(f"{ex['id']}: missing file or note")
    step(f"{len(excerpts)} excerpts internally consistent")

    if args.pin is None:
        print("CHECK OK (internal consistency; re-run with --pin to verify against a checkout)")
        return

    head = subprocess.run(["git", "-C", args.pin, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    if head != pin:
        fail(f"checkout HEAD {head} != pinned {pin}")
    step("checkout HEAD matches pinned commit")

    for ex in excerpts:
        fpath = os.path.join(args.pin, ex["file"])
        if not os.path.isfile(fpath):
            fail(f"{ex['id']}: file missing in checkout: {ex['file']}")
        srclines = open(fpath).read().splitlines()
        for l in ex["lines"]:
            n = l["line"]
            if n < 1 or n > len(srclines):
                fail(f"{ex['id']}: line {n} out of range in {ex['file']}")
            if srclines[n - 1] != l["text"]:
                fail(f"{ex['id']}: line {n} mismatch in {ex['file']}\n"
                     f"  excerpt: {l['text']!r}\n  source:  {srclines[n - 1]!r}")
        print(f"[step] {ex['id']} {ex['file']}:{ex['lines'][0]['line']}-{ex['lines'][-1]['line']} verbatim: PASS")
    print("CHECK OK (all excerpts verified verbatim against the pinned checkout)")


if __name__ == "__main__":
    main()
