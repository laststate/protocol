#!/usr/bin/env python3
"""Validate golden vectors (stdlib only).

Structural conformance across the wire format: magic, version, flags,
length math, header/payload CRC-32, TLV shape, Latch Stream framing, and
LSAK control messages. Cryptographic tag verification (XChaCha20-Poly1305,
HMAC-SHA256) is performed by the reference Go codec tests against the
documented test keys in manifest.json; this runner proves the crypto
vectors are structurally well-formed (correct flags, sizes, and CRCs).
"""

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
MAX_ENVELOPE = 4 << 20
ACCEPTED_VERSIONS = (1, 2)


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
    if len(data) > MAX_ENVELOPE:
        raise ValueError("too_large")
    if len(data) < HEADER + 4:
        raise ValueError("corrupt: too short")
    if data[:4] != b"LSTP":
        raise ValueError("corrupt: magic")
    version, flags = data[4], data[7]
    if version not in ACCEPTED_VERSIONS:
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


def validate_stream(data: bytes) -> None:
    if len(data) < 8 + 4:
        raise ValueError("corrupt: stream too short")
    if data[:2] != b"LS":
        raise ValueError("corrupt: stream magic")
    if data[2] != 1 or data[3] != 0:
        raise ValueError("unsupported: stream version/flags")
    length = struct.unpack_from("<I", data, 4)[0]
    if len(data) != 8 + length + 4:
        raise ValueError("corrupt: stream length")
    envelope = data[8 : 8 + length]
    if struct.unpack_from("<I", data, 8 + length)[0] != crc32(envelope):
        raise ValueError("corrupt: stream crc")
    validate(envelope)


def validate_lsak(data: bytes, expect_event_id: int, expect_status: int) -> None:
    if len(data) != 12:
        raise ValueError("corrupt: lsak size")
    if data[:4] != b"LSAK":
        raise ValueError("corrupt: lsak magic")
    if data[4] != 1 or data[6:8] != b"\x00\x00":
        raise ValueError("corrupt: lsak version/reserved")
    event_id, status = struct.unpack_from("<I", data, 8)[0], data[5]
    if event_id != expect_event_id or status != expect_status:
        raise ValueError(f"corrupt: lsak content event={event_id} status={status}")


def main() -> int:
    manifest = json.loads((ROOT / "test-vectors" / "manifest.json").read_text(encoding="utf-8"))
    keys = {k["id"]: k for k in manifest.get("keys", [])}
    failed = 0
    for item in manifest["vectors"]:
        path = ROOT / "test-vectors" / item["path"]
        raw = load_hex(path)
        kind = item["kind"]
        try:
            if kind == "valid":
                validate(raw)
            elif kind == "invalid":
                try:
                    validate(raw)
                except Exception:  # noqa: BLE001
                    pass
                else:
                    raise ValueError("expected invalid but validated")
            elif kind == "crypto-aead":
                # Structural: a crypto vector must be a well-formed AEAD envelope.
                validate(raw)
                key = keys.get(item.get("key", ""))
                if key is None:
                    raise ValueError("missing key for crypto-aead vector")
            elif kind == "crypto-hmac":
                validate(raw)
                key = keys.get(item.get("key", ""))
                if key is None:
                    raise ValueError("missing key for crypto-hmac vector")
            elif kind == "stream":
                validate_stream(raw)
            elif kind == "lsak":
                validate_lsak(raw, item["event_id"], item["status"])
            else:
                raise ValueError(f"unknown kind {kind}")
            ok = True
            err = None
        except Exception as exc:  # noqa: BLE001
            ok = False
            err = str(exc)
        if not ok:
            failed += 1
        print(f"{'PASS' if ok else 'FAIL'} {item['id']}: kind={kind} err={err}")
    print(f"\n{len(manifest['vectors']) - failed}/{len(manifest['vectors'])} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
