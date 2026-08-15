# Support

Use the channel that matches the request:

- **Integration questions and design ideas:** [GitHub Discussions](https://github.com/laststate/protocol/discussions).
- **Reproducible bugs and scoped feature requests:** [GitHub Issues](https://github.com/laststate/protocol/issues).
- **Security vulnerabilities or sensitive captured data:** follow [SECURITY.md](SECURITY.md) and use private vulnerability reporting.
- **Conduct concerns:** use the private process in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

When asking for an interoperability question, include the protocol version,
the relevant TLV type or framing detail, a minimal non-sensitive example, and
which consumer codec (Go, C, Rust, embedded) you are testing against. Remove
secrets, private endpoints, device identifiers, and captured customer memory.

The maintainer target is to acknowledge new issues and pull requests within 72
hours and triage them within seven days. This is not a commercial support SLA.

Wire-format questions should reference the current registry at
[`registry/tlv-types.md`](registry/tlv-types.md) and the specification files
under [`spec/`](spec/).
