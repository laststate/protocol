# Changelog

## Unreleased

- Register the additive Latch platform-context TLVs (16–22), including RV64
  CPU state, retained blackbox records, mission, time synchronization,
  provisioning, supervisor, and environment evidence.
- Add a golden vector covering the new context TLVs.

## 1.0.0

- LEP v1 wire format, framing, crypto device path, TLV registry 1–15
- Golden vectors (plain, invalid, stream, LSAK, crypto)
- Go reference codec
