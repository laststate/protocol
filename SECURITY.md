# Security

- CRC detects corruption, not adversaries.
- Use HMAC or AEAD for authenticity; verify before parsing TLVs.
- Bound all lengths before allocation.
- Report protocol-security issues privately to the maintainers before public disclosure.
