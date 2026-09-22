# Predicate Credential System Documentation

Deeper material for the crate. The entry point is the repo root [`README.md`](../README.md); the
API documentation is generated from the sources (`cargo docs`, see the root README).

- [Operating a helper](./operating-a-helper.md) — what the operator of a helper has to decide
  and enforce around the library: predicates, policy, keys, root issuance.
- [Design notes](./design-notes.md) — how the implementation is put together and why, its
  limitations, and how it relates to the paper's boxes.
- [Encodings and interoperability](./encodings.md) — wire format, JSON (`serde` feature), IETF
  BBS bytes.
- [Testing and benchmarks](./testing-and-benchmarks.md) — what the suites cover, the gates, the
  benchmarks.
- [OpenVTC integration](./openvtc-integration.md) — where the library fits into OpenVTC, how
  the integration could look, and what is missing on both sides.
- [`katex-header.html`](./katex-header.html) — loaded by rustdoc to render the formulas of the
  API documentation.
