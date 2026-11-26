# Live Key Inventory

Live testnet validator key inventory, probed 2026-11-26. Script:
`scripts/live_manifest_probe.py`. Raw data: `outputs/live_vl_raw.json`
(the VL file, byte-identical), `outputs/live_manifest_raw.json` (raw
RPC responses), `data/key_inventory.json` (parsed inventory).
Verbose log: `outputs/live_manifest_probe.log`.

## Sources

- Validator list: `https://postfiat.org/testnet_vl.json` (VL format
  version 2, sequence 31, expiration 892052157, publisher master key
  ED3F1E0DA736FCF99BE2880A60DBD470715C0E04DD793FB862236B070571FC09E2 —
  Ed25519).
- Manifests: `https://rpc.testnet.postfiat.org`, method `manifest`,
  one call per validator, keyed by the validator's master public key
  in base58 NodePublic form.

## What the public RPC refuses

`validators`, `peers`, and `validator_list_sites` all return HTTP 403
with body `Forbidden` (`live_manifest_probe.log:9-11`). A live
inventory cannot be built from the node; it needs the publisher VL
file plus the `manifest` method, which works.

## Results (25 validators)

- **Master keys:** 25/25 Ed25519 (66 hex chars, ED prefix).
- **Signing (ephemeral) keys:** 25/25 secp256k1 (02/03 prefix).
- **Sequences:** 1 (9 validators), 2 (3), 3 (1), 4 (2), 5 (4), 6 (2),
  7 (3), 13 (1). Maximum 13. 16 of 25 have rotated at least once.
- **Manifest sizes:** min 225 B, max 246 B, mean 234.6 B.
- **Ephemeral signatures (DER):** 70 B (12), 71 B (13). Mean 70.52 B.
- **Master signatures:** 64 B (Ed25519) on all 25.
- **Domains:** present on 25/25; lengths 8-29 chars, mean 18.08.
  Examples: `app.w.ai`, `postfiat.live`, `pft.thedarkmatter.xyz`,
  `lc66validator.postfiatcn.org`, `iopo545454-del.github.io`.
- **Parsing:** every manifest parses field-by-field with
  `scripts/parse_manifest.py` and the field totals sum exactly to the
  manifest byte length (25/25 PASS).

## Example: validator 1 (parsed)

Manifest 225 bytes, sequence 1, domain `app.w.ai`:

| Field | Type | Value bytes |
|-------|------|-------------|
| sfSequence | UINT32 | 4 (value 1) |
| sfPublicKey (master) | VL | 33 (ED4D4244B734459A6D88DA611B2F2D94951181E422381AB078FAF75A41F0470A59) |
| sfSigningPubKey | VL | 33 (0206793AB8EAEAF8778C8C46C69155D7DE36D61469B5BBED67C17615CA5852750A) |
| sfSignature | VL | 71 (DER, secp256k1) |
| sfDomain | VL | 8 (`app.w.ai`) |
| sfMasterSignature | VL | 64 (Ed25519) |

Field headers add 7 bytes (one per field, two for sfMasterSignature);
VL length prefixes add 5 bytes (one per VL field); total 225 B.

## Reading

The mixed key types are the inventory's headline: the long-lived
master key is Ed25519 while the key that actually signs validations
is secp256k1. Any migration must replace both halves. Rotation
happens (16/25 rotated) but is uneven and unpolicied: nine validators
have never rotated, and the most-rotated validator is on sequence 13.
No revocation manifest was observed for any listed validator.
