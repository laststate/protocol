# Security policy

Report suspected vulnerabilities through the repository's [private vulnerability
reporting form](https://github.com/laststate/protocol/security/advisories/new).
Do not open a public issue containing device keys, captured memory, exploit
details, or production endpoint credentials.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Earlier versions | No |

## Cryptographic design

CRC-32/IEEE detects corruption; it is not authentication. Authenticity requires
HMAC-SHA-256 or XChaCha20-Poly1305 with a 256-bit key, a 192-bit CSPRNG nonce,
and the full 128-bit tag. The fixed header, nonce, and `key_id` are
authenticated as AAD. HKDF-SHA-256 derives domain-separated, per-envelope keys
from the provisioned master key, `key_id`, sequence, and event ID. Decryption
authenticates before writing plaintext and comparisons are constant-time.

The older HMAC-SHA-256 envelope format remains supported for verification only
unless `allow_legacy_hmac` is explicitly enabled by the consumer. Raw ChaCha20
remains exposed for interoperability tests and must never be used alone for
application data.

## Provisioning requirements

- Provision a unique random 256-bit master key per device. Do not derive it
  from a serial number, MAC address, password, or firmware secret.
- Register a cryptographically secure random provider before enabling envelope
  or at-rest encryption.
- Increment `key_id` on every key rotation and retain old keys server-side only
  for the required migration window.
- Use verified TLS in addition to envelope encryption. Never set peer
  verification to optional in production.
- Treat dumps as sensitive even when encrypted. Apply exclusion, zeroing, or
  hashing before capture.

## Protocol safety requirements

- CRC detects corruption, not adversaries.
- Use HMAC or AEAD for authenticity and verify it before exposing TLVs.
- Bound all lengths before allocation or decompression.
- Treat unknown TLVs according to the compatibility rules; reject unknown flag
  bits and malformed framing.
- Never claim a vector is authenticated without the matching flag set.

## Assurance and limitations

The reference codec includes RFC known-answer vectors, negative/tamper tests,
and sanitizer runs. These checks do not replace an independent cryptographic
review, side-channel evaluation on the target MCU, secure provisioning review,
or product certification. Do not claim FIPS, Common Criteria, or PSA
certification based on this repository alone.
