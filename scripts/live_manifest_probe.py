#!/usr/bin/env python3
"""live_manifest_probe.py — live testnet validator key inventory.

Fetches the published testnet validator list from
https://postfiat.org/testnet_vl.json, decodes the VL blob, and for
every listed validator calls the public testnet RPC `manifest` method
(https://rpc.testnet.postfiat.org) with the validator's master public
key (base58 NodePublic form) to retrieve its live manifest. Each
manifest is parsed with scripts/parse_manifest.py into an exact field
table (public keys, sequence, domain, signature byte lengths).

Also probes the restricted RPC methods (validators, peers,
validator_list_sites) and records their responses — the public
endpoint refuses them, which bounds what a live inventory can see.

Every step is logged as it happens (verbose per-step lines), not only
a final summary. Outputs:
  outputs/live_vl_raw.json        — the fetched VL file, byte-identical
  outputs/live_manifest_raw.json  — raw RPC responses, one per validator
  outputs/live_manifest_probe.log — this run's verbose log
  data/key_inventory.json         — parsed inventory (25 validators)

This is a one-time live measurement: re-running it later may return a
different VL sequence if validators rotate. reproduce.sh does NOT
re-run this probe; it re-parses the vendored inventory and re-checks
the size model instead (scripts/check_measurements.py).

Usage: python3 scripts/live_manifest_probe.py   (run from the pack root)
"""
import base64
import hashlib
import json
import os
import sys
import urllib.request

PACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PACK, "scripts"))
from parse_manifest import parse  # noqa: E402

VL_URL = "https://postfiat.org/testnet_vl.json"
RPC_URL = "https://rpc.testnet.postfiat.org"

ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def log(msg):
    print(msg, flush=True)


def b58encode(payload: bytes) -> str:
    n = int.from_bytes(payload, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPHABET[r] + s
    pad = 0
    for c in payload:
        if c == 0:
            pad += 1
        else:
            break
    return ALPHABET[0] * pad + s


def node_public_b58(pubkey_hex: str) -> str:
    payload = bytes([28]) + bytes.fromhex(pubkey_hex)
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def rpc_call(method, params):
    body = json.dumps({"method": method, "params": params}).encode()
    req = urllib.request.Request(
        RPC_URL, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def main():
    outdir = os.path.join(PACK, "outputs")
    datadir = os.path.join(PACK, "data")
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(datadir, exist_ok=True)
    logpath = os.path.join(outdir, "live_manifest_probe.log")

    with open(logpath, "w") as logf:
        def step(msg):
            line = f"[step] {msg}"
            print(line, flush=True)
            logf.write(line + "\n")

        step("fetching validator list from " + VL_URL)
        with urllib.request.urlopen(VL_URL, timeout=30) as resp:
            vl_raw = resp.read()
        step(f"VL fetched: {len(vl_raw)} bytes, HTTP 200")
        with open(os.path.join(outdir, "live_vl_raw.json"), "wb") as f:
            f.write(vl_raw)
        step("VL saved to outputs/live_vl_raw.json (byte-identical)")
        vl = json.loads(vl_raw)
        step(f"VL format version: {vl.get('version')}")
        publisher_pk = vl.get("public_key", "")
        step(f"VL publisher master key: {publisher_pk} "
             f"(first byte {publisher_pk[:2]} = Ed25519)")
        blob = json.loads(base64.b64decode(vl["blobs_v2"][0]["blob"]))
        seq = blob["sequence"]
        validators = blob["validators"]
        step(f"VL sequence: {seq}")
        step(f"VL expiration: {blob.get('expiration')}")
        step(f"validators listed: {len(validators)}")

        # Restricted-method probes: bound what the public RPC exposes.
        for method in ("validators", "peers", "validator_list_sites"):
            status, body = rpc_call(method, [{}])
            step(f"RPC {method}: HTTP {status} body={body.strip()[:40]!r}")

        raw_responses = []
        inventory = []
        for i, v in enumerate(validators):
            mk_hex = v["validation_public_key"]
            mk_b58 = node_public_b58(mk_hex)
            step(f"validator {i + 1}/{len(validators)}: master {mk_hex[:12]}... "
                 f"-> base58 {mk_b58}")
            status, body = rpc_call("manifest", [{"public_key": mk_b58}])
            step(f"  RPC manifest HTTP {status}")
            resp = json.loads(body)
            raw_responses.append(resp)
            if resp.get("result", {}).get("status") != "success":
                step(f"  manifest RPC FAILED for {mk_b58}: {body[:200]}")
                raise SystemExit(1)
            details = resp["result"]["details"]
            manifest_b64 = resp["result"]["manifest"]
            raw_bytes = base64.b64decode(manifest_b64)
            step(f"  manifest: {len(raw_bytes)} bytes, seq={details['seq']}, "
                 f"domain={details.get('domain')!r}")
            fields = parse(raw_bytes)
            field_sum = sum(f["total_bytes"] for f in fields)
            step(f"  parsed fields: "
                 + ", ".join(f"{f['field']}={f['value_bytes']}B" for f in fields))
            step(f"  field totals sum {field_sum} == input {len(raw_bytes)}: "
                 f"{'PASS' if field_sum == len(raw_bytes) else 'FAIL'}")
            if field_sum != len(raw_bytes):
                raise SystemExit(1)
            by_name = {f["field"]: f for f in fields}
            master_pk = by_name["sfPublicKey"]["value_hex"]
            signing_pk = by_name["sfSigningPubKey"]["value_hex"]
            step(f"  master key type: {'Ed25519' if master_pk.startswith('ED') else 'secp256k1' if master_pk[:2] in ('02', '03') else 'UNKNOWN'} "
                 f"({master_pk[:2]}...)")
            step(f"  signing key type: {'Ed25519' if signing_pk.startswith('ED') else 'secp256k1' if signing_pk[:2] in ('02', '03') else 'UNKNOWN'} "
                 f"({signing_pk[:2]}...)")
            step(f"  master signature: {by_name['sfMasterSignature']['value_bytes']} B; "
                 f"ephemeral signature: {by_name['sfSignature']['value_bytes']} B (DER)")
            inventory.append({
                "index": i + 1,
                "validation_public_key_hex": mk_hex,
                "master_key_base58": mk_b58,
                "master_key_type": "Ed25519" if master_pk.startswith("ED") else "secp256k1",
                "signing_key_hex": signing_pk,
                "signing_key_type": "Ed25519" if signing_pk.startswith("ED") else "secp256k1",
                "ephemeral_key_base58": details.get("ephemeral_key"),
                "sequence": details["seq"],
                "domain": details.get("domain"),
                "manifest_bytes": len(raw_bytes),
                "manifest_base64": manifest_b64,
                "fields": fields,
            })

        with open(os.path.join(outdir, "live_manifest_raw.json"), "w") as f:
            json.dump(raw_responses, f, indent=2)
        step("raw RPC responses saved to outputs/live_manifest_raw.json")
        with open(os.path.join(datadir, "key_inventory.json"), "w") as f:
            json.dump({
                "source": VL_URL,
                "fetched": "2026-11-26",
                "vl_sequence": seq,
                "vl_expiration": blob.get("expiration"),
                "vl_publisher_master_key_hex": publisher_pk,
                "rpc": RPC_URL,
                "validators": inventory,
            }, f, indent=2)
        step("parsed inventory saved to data/key_inventory.json")
        seqs = sorted(set(x["sequence"] for x in inventory))
        step(f"sequences observed: {seqs}")
        step(f"master key types: {sorted(set(x['master_key_type'] for x in inventory))}")
        step(f"signing key types: {sorted(set(x['signing_key_type'] for x in inventory))}")
        step("LIVE PROBE OK")


if __name__ == "__main__":
    main()
