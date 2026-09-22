# Testing and Benchmarks

What the test suites cover, the checks a change has to pass, and the benchmarks.

## Test suites

Test helpers: the generic conformance flows (`cred::conformance`) and an
INSECURE hash-to-group oracle for curves without a hash-to-curve suite (`hash::testing`)
are compiled for the crate's own tests and behind the non-default cargo feature `test-utils`.
The crate lists itself as a dev-dependency with that feature, so `cargo test` enables it for
unit and integration tests alike; a normal build never contains them. The flows walk through
the way the construction box consumes a base and a tag (root signing, `Attest` / `VerifyAtt`,
`Prove` / `VerifyProof`, `Issue`, `Unblind`, `VerifyCred`, chaining), with negatives that each
hinge on one mechanism. `tests/credential_bases.rs` runs them for every compatible pair:
`Σ-PS`, `Σ-BBS` and `Σ-MAC` with `Tag_DDH` and with `Tag_DY`, `Σ-EQ` with `Tag_DDH`, each over
BLS12-381 and over BN254 (the latter with the insecure oracle where an oracle is needed), plus
the refusal of `Σ-EQ` with `Tag_DY`.

`tests/pcs_correctness.rs` runs the construction itself through its public API: Def.
"Correctness" with root issuance and chaining for every compatible pair and `k ∈ {1, 2, 5}`
(plus a run over BN254), the byte sizes of the comparison table, proof-gated issuance, and
negatives that each hinge on one verifier-side check (where the honest `prove` refuses to build
the offending proof, a cheating prover builds it from the public relation and context builders).
`tests/pcs_review_regressions.rs` holds the regression tests of a hostile review of the
construction: objects with group elements OUTSIDE the prime-order subgroup (rejected by every
decoder at every position, and by every verifier when they are built in memory), the root path
for threshold predicates, and what a helper key under two deployment labels does and does not
allow.

Three further suites were written independently of the construction's author, against its
public API only, for every compatible pair:

* `tests/pcs_soundness.rs`: the special-soundness extractor, run by rewinding the interactive
  protocol on exactly the relations `R_att` and `R_issue` that the proofs use (the extracted
  `usk` is the attester's, reproduces the tag, and `VerifyCred` accepts the credential for it;
  for `Σ-BBS` the signature is rebuilt from the extracted randomizers); simulated transcripts
  verify interactively but are rejected as Fiat-Shamir proofs; structural checks of what an
  attestation reveals; and Def. "Proof-gated issuance" exhaustively (every field of a valid proof
  mutated in turn, the number of mutants pinned). These are algebraic and structural evidence on
  seeded samples; they do not and cannot test computational indistinguishability or the
  reductions.
* `tests/pcs_adversarial.rs`: each known attack mounted against the real code and required to
  fail with the expected error: credential-free degenerate shows, the `Σ-EQ` key-reuse and
  forged-key-vector attacks, self-attestation and its disguises, a proof for a foreign context,
  the weak Fiat-Shamir attack (tag or shown credential chosen after the challenge), wrong
  attestation counts and threshold confusion, replay between the root path and the ordinary
  path, duplicate attesters, attestations grafted from another identifier, replay across
  deployments and helpers, policy violations, a malicious helper's pre-credentials, malformed
  helper keys, the undefined point of `Tag_DY`, and byte fuzzing of every encoding (no panics).
* `tests/serialization.rs`: round trips of every public type in both encodings, the byte sizes
  of the comparison table with their decomposition, rejection of trailing bytes, non-canonical
  scalars, points outside the prime-order subgroup and uncompressed encodings, and a pinned
  digest of the public parameters.

And per layer:

* `tests/sigma_protocol.rs`: the sigma layer on relations over `G_1`, `G_2`, `G_T` and mixtures
  of them: completeness, simulated transcripts, special soundness with shared variables, and the
  Fiat-Shamir transform.
* `tests/serde_json.rs` (`serde` feature): a join that travels as JSON end to end for every
  pair, strict decoding, and the JSON forms of secrets.
* `tests/bbs_ietf_interop.rs`: `Σ-BBS` under IETF parameters against the pinned dev-dependency
  `affinidi-bbs` 0.3.3, in both directions (see [Encodings](./encodings.md)).

All randomness in tests and benchmarks is seeded. The tests are evidence on sampled instances:
they check algebraic and structural facts, not computational indistinguishability and not the
reductions of the paper.

## Gates and benchmarks

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo test --doc
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps

cargo bench --bench kiprf                # Tag_DDH, Tag_DY
cargo bench --bench cred                 # Σ-PS, Σ-BBS, Σ-EQ, Σ-MAC
cargo bench --bench pcs                  # the construction, every public base/tag pair at k = 5
cargo bench --bench cred -- sigma-bbs    # one group (the filter is a regex)
cargo bench --bench cred -- --test       # only the size tables (every benchmark runs once)
```

Benchmarks (criterion, seeded inputs, BLS12-381). Each one first prints the SIZES of the objects
it handles, then measures the running times:

* `benches/kiprf.rs`, the key-injective PRFs: `TagKeyGen`, `TagEval` at an ordinary point and
  at the identity point `c_0`, `ValidTag`, the stand-alone proof for `R_Tag` and its verifier,
  and `H_2` alone (the hash to the curve that `Tag_DDH` pays per point and `Tag_DY` does not).
  Sizes: `pp_Tag`, key, tag, tag proof.
* `benches/cred.rs`, the credential bases: `Setup`, `KeyGen`, the key range check, `Sign`,
  `Verify`, `Com`, `BlindIssue`, `Unblind`, `ReRand`, the public checks of `VerifyPossess`, the
  possession proof and its verifier, for `Σ-PS`, `Σ-BBS`, `Σ-EQ` and the designated-verifier
  `Σ-MAC` (over `G_1` of BLS12-381, whereas the paper measures it over ristretto255). Sizes:
  parameters, keys, credential, `m_aux`, issuance encoding and state, pre-credential, shown
  credential, possession proof.
* `benches/pcs.rs`, the construction: `Attest`, `VerifyAtt`, `Prove`, `VerifyProof`, `Issue`,
  `Unblind` and `VerifyCred`. `Prove` and `VerifyProof` include `CheckAtts_P`, i.e. `k`
  attestation verifications; the paper's "prove" figure (the `k` attestations together with the
  subject's proof) corresponds to `k · attest + prove`. Sizes: `pp`, `hvk`, root request,
  pre-credential, credential, `att` and `π` (the last two are the comparison table's figures).

Timings depend on the machine, the compiler and the enabled features: record them with
`rustc --version` and the commit.
