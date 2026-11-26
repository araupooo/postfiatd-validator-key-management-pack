# Key Lifecycle: Generation, Rotation, Revocation, Compromise

## Generation

A validator's keys come from exactly two config paths, both
hardcoded to secp256k1 (`src/xrpld/app/misc/detail/ValidatorKeys.cpp`):

- `[validator_token]`: a base64 JSON token with `manifest` +
  `validation_secret_key`; the secret must be exactly 32 bytes
  (`Manifest.cpp:287-296`) and the derived public key must equal the
  manifest's signing key (`ValidatorKeys.cpp:47`, `:50-53`).
- `[validation_seed]`: a seed parsed from base58; the key is
  generated and derived as secp256k1 (`ValidatorKeys.cpp:84-85`).

Both paths cannot be configured at once (fatal,
`ValidatorKeys.cpp:31-36`). A third path, the `validation_create`
RPC/CLI command, also generates secp256k1 only
(`src/xrpld/rpc/handlers/ValidationCreate.cpp:54,58`) and is
admin-only (`:42-43`). Its own parser warns that secrets on the
command line leak via shell history and `ps`
(`src/xrpld/rpc/detail/RPCCall.cpp:1100-1103`).

Key sizes: secret keys are 32 bytes (`SecretKey.h:40`); public keys
are 33 bytes — secp256k1 compressed (lead 0x02/0x03), Ed25519 with a
0xED prefix + 32 bytes (`PublicKey.h:52-58,63-65`). Ed25519
signatures are exactly 64 bytes (`SecretKey.cpp:262-266`);
secp256k1 signatures are DER-serialized into a 72-byte buffer and
measure 70-72 bytes in practice (`SecretKey.cpp:284-290`; live mean
70.52 B).

## Rotation

Rotation is a new manifest with a higher sequence number, signed by
the master key (`Manifest.h:66-69`). The cache accepts a manifest
only when its sequence is strictly greater than the one known
(`Manifest.cpp:411`, disposition `stale` otherwise), and it refuses
a manifest that reuses a master key as an ephemeral key or vice
versa (`:449-455` badMasterKey, `:470-490` badEphemeralKey).

There is no automation: no rotation scheduler, expiry, or renewal
exists in the tree (negative searches N-2 and N-5), and manifest
creation exists only in the test helpers `makeManifestString`
(`src/test/app/Manifest_test.cpp:106`) and `makeManifest` (`:193`).
Live rotation does happen — 16 of 25 testnet validators have
rotated at least once (max sequence 13) — but 9 have never rotated,
and no validator publishes a rotation policy.

## Revocation

Revocation is a manifest with sequence `0xFFFFFFFF`
(`Manifest.cpp:235-241`). It carries no signing key and no signing
signature, and once accepted no higher sequence exists, so the
validator is permanently removed (`Manifest.h:66-76`). Revocations
can be loaded from the `[validator_key_revocation]` config entry
(`Manifest.cpp:659-682`) or received as gossip. A revoked publisher
also invalidates its validator lists
(`ValidatorList.cpp:1394-1398`).

## Compromise response

The documented response (`Manifest.h:66-76`): ephemeral compromise
-> new signing key pair + higher-sequence manifest signed by the
master key; master compromise -> revocation manifest. What is
missing is detection: nothing in-tree watches for compromise
(negative search N-6: the only two hits are prose in the doc
comment). The trusted set itself is safe against a missing manifest
— it contains only validators with non-revoked manifests, so a valid
signing key must exist (`ValidatorList.cpp:2072-2075`) — but a
compromised key that nobody notices keeps validating until someone
acts.
