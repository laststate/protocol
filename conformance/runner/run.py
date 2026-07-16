#!/usr/bin/env python3
"""Validate golden vectors (stdlib only)."""

from __future__ import annotations

import binascii
import json
import struct
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KNOWN_FLAGS = 0x1F
HEADER = 24


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def load_hex(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    clean = "".join(c for c in text if c in "0123456789abcdefABCDEF")
    return binascii.unhexlify(clean)


def validate_tlvs(payload: bytes) -> None:
    off = 0
    while off < len(payload):
        if len(payload) - off < 4:
            raise ValueError("corrupt: tlv")
        t, n = struct.unpack_from("<HH", payload, off)
        off += 4
        if t == 0 or n > len(payload) - off:
            raise ValueError("corrupt: tlv")
        off += n


def validate(data: bytes) -> None:
    if len(data) > 4 << 20:
        raise ValueError("too_large")
    if len(data) < HEADER + 4:
        raise ValueError("corrupt: too short")
    if data[:4] != b"LSTP":
        raise ValueError("corrupt: magic")
    version, flags = data[4], data[7]
    if version != 1:
        raise ValueError("unsupported: version")
    if flags & ~KNOWN_FLAGS:
        raise ValueError("unsupported: flags")
    enc = bool(flags & 0x02)
    aead = bool(flags & 0x04)
    auth = bool(flags & 0x01)
    if enc != aead:
        raise ValueError("corrupt: flags")
    if aead and not auth:
        raise ValueError("corrupt: flags")
    meta = 28 if aead else 0
    auth_len = 16 if aead else (32 if auth else 0)
    payload_length = struct.unpack_from("<I", data, 16)[0]
    overhead = HEADER + meta + 4 + auth_len
    if len(data) != overhead + payload_length:
        raise ValueError("corrupt: size")
    if struct.unpack_from("<I", data, 20)[0] != crc32(data[:20]):
        raise ValueError("corrupt: header_crc")
    crc_off = HEADER + meta + payload_length
    if struct.unpack_from("<I", data, crc_off)[0] != crc32(data[HEADER:crc_off]):
        raise ValueError("corrupt: payload_crc")
    if not enc and not (flags & 0x10):
        validate_tlvs(data[HEADER + meta : crc_off])


def main() -> int:
    manifest = json.loads((ROOT / "test-vectors" / "manifest.json").read_text(encoding="utf-8"))
    failed = 0
    for item in manifest["vectors"]:
        path = ROOT / "test-vectors" / item["path"]
        raw = load_hex(path)
        expect = item["expect"]
        try:
            validate(raw)
            ok = expect == "valid"
            err = None
        except Exception as exc:  # noqa: BLE001
            ok = expect == "invalid"
            err = str(exc)
        if not ok:
            failed += 1
        print(f"{'PASS' if ok else 'FAIL'} {item['id']}: expect={expect} err={err}")
    print(f"\n{len(manifest['vectors']) - failed}/{len(manifest['vectors'])} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
