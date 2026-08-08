# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Earlier versions | No |

## Reporting a vulnerability

Use the repository's [private security advisory form](https://github.com/laststate/protocol/security/advisories/new).
Do not open a public issue or include production captures, credentials, or keys.

Include the affected version, a minimal reproducer or vector, impact, and any
mitigation. Maintainers aim to acknowledge reports within five business days,
coordinate a fix, and agree on disclosure timing with the reporter.

## Protocol safety requirements

- CRC detects corruption, not adversaries.
- Use HMAC or AEAD for authenticity and verify it before exposing TLVs.
- Bound all lengths before allocation or decompression.
- Treat unknown TLVs according to the compatibility rules; reject unknown flag
  bits and malformed framing.
