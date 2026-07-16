# Last State Protocol (LEP)

Binary, versioned, transport-independent contract for firmware/hardware diagnostics between devices, gateways, and servers.

**v1.0.0** — [`VERSION`](VERSION)

When Latch, Relay, Trace, or third-party code disagree on bytes, **this repo wins**.

Relay and Trace keep local LEP codecs for deployment independence, but their CI
runs `test-vectors/` against those codecs (`PROTOCOL_VECTORS` / `TestProtocolVectors`).
Prefer changing this repo first, then bumping consumer codecs.

## Wire (summary)

| Item | Value |
|------|--------|
| Magic | `LSTP` (`4C 53 54 50`) |
| Endianness | little-endian |
| Header | 24 bytes |
| CRC | CRC-32/IEEE |
| Payload | TLV `u16 type` + `u16 length` + value |
| Flags | AUTH, ENC, AEAD, TRUNCATED, COMPRESSED (bit 4) |

Full layout: [`spec/lep-v1.md`](spec/lep-v1.md)

## Repository

```text
spec/                 Normative text (wire, framing, crypto, …)
registry/tlv-types.md All TLV byte layouts
test-vectors/         Golden hex
implementations/go/   Reference codec
conformance/runner/   Vector checker
```

| Doc | Topic |
|-----|--------|
| [spec/lep-v1.md](spec/lep-v1.md) | Header, flags, validation |
| [spec/integrity.md](spec/integrity.md) | CRC |
| [spec/identity.md](spec/identity.md) | Device / build identity |
| [spec/encryption.md](spec/encryption.md) | HMAC / XChaCha AEAD |
| [spec/compression.md](spec/compression.md) | Truncation vs zstd |
| [spec/framing.md](spec/framing.md) | Stream, COBS, LSAK, fragments |
| [spec/transports.md](spec/transports.md) | UART, TCP, HTTP, … |
| [spec/architectures.md](spec/architectures.md) | Arch codes, CPU/FAULT |
| [registry/tlv-types.md](registry/tlv-types.md) | All TLV byte layouts |
| [spec/compatibility.md](spec/compatibility.md) | Versioning |
| [spec/limits.md](spec/limits.md) | Size bounds |

## Not in this repo

Product code: HardFault handlers, SQLite spool, Trace UI, Probe PCB, cloud billing.

## Check

```bash
cd implementations/go && go test ./...
python conformance/runner/run.py
```

## License

Apache-2.0 — [`LICENSE`](LICENSE)
