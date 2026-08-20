# Last State Protocol (LEP)

Binary, versioned, transport-independent contract for firmware and hardware
diagnostics between devices, gateways, and servers.

[![CI](https://github.com/laststate/protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/laststate/protocol/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://img.shields.io/badge/go-reference-1.22+-007D9C.svg)](implementations/go)
[![Python Conformance](https://img.shields.io/badge/python-conformance-3.10+-3776AB.svg)](conformance)

**v1.1.0** — [`VERSION`](VERSION)

When Latch, Relay, Trace, or third-party code disagree on bytes, **this repo
wins**.

Relay and Trace keep local LEP codecs for deployment independence, but their CI
runs `test-vectors/` against those codecs (`PROTOCOL_VECTORS` /
`TestProtocolVectors`). Prefer changing this repo first, then bumping consumer
codecs.

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

## Try it

Validate the reference codec and golden vectors locally:

```sh
cd implementations/go && go vet ./... && go test ./...
python conformance/runner/run.py
```

To add a new golden vector or update the registry:

1. Edit [`registry/tlv-types.md`](registry/tlv-types.md) first.
2. Add or update hex vectors under [`test-vectors/`](test-vectors/).
3. Run the conformance runner; fix the codec if a vector no longer passes.
4. Update the [`CHANGELOG.md`](CHANGELOG.md) with a one-line note.

## Not in this repo

Product code: HardFault handlers, SQLite spool, Trace UI, Probe PCB, cloud
billing. Those live in [`latch`](https://github.com/laststate/latch),
[`relay`](https://github.com/laststate/relay), and the private Trace backend.

## Community and security

- [Contributing guide](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Support](SUPPORT.md)
- [Roadmap](ROADMAP.md) and [changelog](CHANGELOG.md)

Maintainers preparing a visibility change should complete the
[publication checklist](PUBLICATION.md).

## License

Apache-2.0 — [`LICENSE`](LICENSE)
