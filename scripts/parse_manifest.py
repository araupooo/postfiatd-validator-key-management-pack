#!/usr/bin/env python3
"""parse_manifest.py — parse a serialized postfiatd validator manifest
(STObject binary form) into a field table with exact byte lengths.

Field codes (include/xrpl/protocol/detail/sfields.macro):
  sfPublicKey       VL     code 1
  sfSigningPubKey   VL     code 3
  sfSequence        UINT32 code 4
  sfSignature       VL     code 6
  sfDomain          VL     code 7
  sfMasterSignature VL     code 18
  sfVersion         UINT16 code 16

Field-header encoding (rippled SerialIter): one byte (type<<4)|field
when both are < 16; a zero nibble means the real value follows in the
next byte. VL length prefix: 1 byte when len <= 192, 2 bytes when
193 <= len <= 12480, else 3 bytes. UINT16 value: 2 bytes. UINT32: 4.

The parser is self-validating: it must consume exactly the whole
input, and every field it finds must be one of the manifest template
fields (src/xrpld/app/misc/detail/Manifest.cpp:59-82). Any leftover
byte or unknown field fails loudly instead of silently misreading.

Usage:
  python3 scripts/parse_manifest.py <base64-manifest>
  python3 scripts/parse_manifest.py --json <base64-manifest>
"""
import base64
import json
import sys

# (type_code, field_code) -> (name, kind)
FIELDS = {
    (7, 1): ("sfPublicKey", "VL"),
    (7, 3): ("sfSigningPubKey", "VL"),
    (2, 4): ("sfSequence", "UINT32"),
    (7, 6): ("sfSignature", "VL"),
    (7, 7): ("sfDomain", "VL"),
    (7, 18): ("sfMasterSignature", "VL"),
    (1, 16): ("sfVersion", "UINT16"),
}
TYPE_NAMES = {1: "UINT16", 2: "UINT32", 7: "VL"}


def parse(data: bytes):
    """Parse serialized STObject bytes; return a list of field dicts."""
    pos = 0
    fields = []
    while pos < len(data):
        start = pos
        b = data[pos]
        pos += 1
        type_code = b >> 4
        field_code = b & 0x0F
        if type_code == 0:
            if pos >= len(data):
                raise ValueError(f"truncated field header at byte {start}")
            type_code = data[pos]
            pos += 1
        if field_code == 0:
            if pos >= len(data):
                raise ValueError(f"truncated field header at byte {start}")
            field_code = data[pos]
            pos += 1
        key = (type_code, field_code)
        if key not in FIELDS:
            raise ValueError(
                f"unknown field type={type_code} code={field_code} at byte {start}"
            )
        name, kind = FIELDS[key]
        header_len = pos - start
        if kind == "VL":
            if pos >= len(data):
                raise ValueError(f"truncated VL length at byte {start}")
            l0 = data[pos]
            pos += 1
            if l0 <= 192:
                length = l0
                len_prefix = 1
            elif l0 <= 240:
                if pos >= len(data):
                    raise ValueError(f"truncated VL length at byte {start}")
                length = 193 + ((l0 - 193) << 8) + data[pos]
                pos += 1
                len_prefix = 2
            else:
                if pos + 1 >= len(data):
                    raise ValueError(f"truncated VL length at byte {start}")
                length = 12481 + ((l0 - 241) << 16) + (data[pos] << 8) + data[pos + 1]
                pos += 2
                len_prefix = 3
            if pos + length > len(data):
                raise ValueError(f"field {name} overruns input at byte {start}")
            value = data[pos:pos + length]
            pos += length
            fields.append({
                "field": name,
                "type": kind,
                "header_bytes": header_len,
                "length_prefix_bytes": len_prefix,
                "value_bytes": length,
                "total_bytes": pos - start,
                "value_hex": value.hex().upper(),
            })
        elif kind == "UINT32":
            if pos + 4 > len(data):
                raise ValueError(f"field {name} overruns input at byte {start}")
            value = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            fields.append({
                "field": name,
                "type": kind,
                "header_bytes": header_len,
                "length_prefix_bytes": 0,
                "value_bytes": 4,
                "total_bytes": pos - start,
                "value": value,
            })
        elif kind == "UINT16":
            if pos + 2 > len(data):
                raise ValueError(f"field {name} overruns input at byte {start}")
            value = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            fields.append({
                "field": name,
                "type": kind,
                "header_bytes": header_len,
                "length_prefix_bytes": 0,
                "value_bytes": 2,
                "total_bytes": pos - start,
                "value": value,
            })
    if pos != len(data):
        raise ValueError(f"parser stopped at {pos} of {len(data)} bytes")
    return fields


def main():
    as_json = False
    args = [a for a in sys.argv[1:] if a != "--json"]
    if "--json" in sys.argv[1:]:
        as_json = True
    if len(args) != 1:
        print("usage: parse_manifest.py [--json] <base64-manifest>", file=sys.stderr)
        sys.exit(2)
    data = base64.b64decode(args[0])
    fields = parse(data)
    if as_json:
        print(json.dumps({"total_bytes": len(data), "fields": fields}, indent=2))
        return
    print(f"total_bytes: {len(data)}")
    for f in fields:
        extra = ""
        if "value" in f:
            extra = f" value={f['value']}"
        elif f["field"] in ("sfPublicKey", "sfSigningPubKey"):
            extra = f" value={f['value_hex']}"
        print(f"  {f['field']}: type={f['type']} header={f['header_bytes']}B "
              f"len_prefix={f['length_prefix_bytes']}B value={f['value_bytes']}B "
              f"total={f['total_bytes']}B{extra}")
    print(f"sum of field totals: {sum(f['total_bytes'] for f in fields)} "
          f"(input {len(data)} bytes)")


if __name__ == "__main__":
    main()
