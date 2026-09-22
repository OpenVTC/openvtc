# Encodings and Interoperability

The canonical wire format is the compressed arkworks encoding (module `serialization`), plus the
fixed-format compact codec of `pcs::codec` for attestations and issuance proofs, which reproduces
the byte sizes of the paper's comparison table. Two further representations exist.

## JSON (`serde` feature)

The canonical wire format stays the compressed arkworks encoding (`serialization`, and the
fixed-format compact codec for `att` and `π`). With the `serde` feature every protocol object
also has a JSON form (module `serialization`, "Text forms"): a value with a canonical encoding is
one multibase base58btc string (`z…`, the convention of a W3C Data Integrity `proofValue`), while `Predicate`,
`Attestation`, `IssuanceProof` and `RootRequest` are objects with camelCase members, e.g.
`{"tag":"z…","shown":"z…","phi":"z…","proof":"z…"}`, so that a policy engine can read the `phi`
of each attestation. Decoding is strict (base58btc only, validated canonical bytes, no trailing
bytes, no unknown members). Secrets (`UserSecretKey`, `IssuanceState`, `Credential`, signing
keys) have a JSON form too, meant for protected storage only. `tests/serde_json.rs` runs a join
that travels as JSON end to end for every pair.

## Interoperability with IETF BBS (`cred::bbs::ietf`)

Not part of the paper. `BBSPublicParams::ietf(interface, vk, header)` derives the generators
of `Σ-BBS` as the IETF ciphersuite BLS12-381-SHA-256 does (`h_0 := P_1 + domain·Q_1`, and
`h_1, h_2, h_3` := the generators that carry `usk`, `φ`, `ρ` in the core, the blind or the
pseudonym interface). Under these parameters a credential `(A, e)` and an IETF BBS signature
are the same object; `to_ietf_bytes` / `from_ietf_bytes` convert keys and credentials
(big-endian scalars). Because `h_0` depends on the helper's key and on the header, such a
deployment is set up with `PCS::setup_with_base_parameters` and received with
`PCS::from_public_parameters_with_base`.

`tests/bbs_ietf_interop.rs` checks this in both directions against `affinidi-bbs` 0.3.3, the
BBS crate of the Affinidi / OpenVTC stack (on `bls12_381_plus`); that crate is a pinned
dev-dependency and never part of a build of the library.

Compatible, and tested in both directions: core signatures over three messages, blind issuance,
and the pseudonym interface with signer entropy `0` (with non-zero entropy the certified key is
`usk + entropy`, not the `usk` behind `id`); the show of this crate on a credential they
signed; and the whole construction under IETF parameters with a helper key from their `keygen`.

Deliberately NOT implemented, so an attestation or an issuance proof of this crate is not an
IETF BBS proof, and their verifier does not accept ours:

* **Challenge and proof layout.** IETF `ProofGen` proves the same relation as the `Σ-BBS` show,
  but its challenge is `hash_to_scalar` over a fixed field order with RFC 9380
  `expand_message_xmd`, and its proof bytes have their own order with big-endian scalars. This
  crate uses the strong Fiat-Shamir transcript of `sigma::fiat_shamir` and the compact `(c, z)`
  codec. Closing the gap means adding an IETF challenge function and codec next to the existing
  ones; the sigma layer would be reused unchanged.
* **Messages.** IETF BBS signs byte strings mapped by `messages_to_scalars`
  (`cred::bbs::ietf::message_to_scalar` reproduces the map); the construction certifies scalars,
  and `φ = EncPred(f)` comes from this crate's `H_0`. A credential issued by `PCS::issue` is a
  valid IETF signature, but their byte-oriented `blind_verify` cannot be asked to check it.
* **Tags.** The IETF per-verifier pseudonym is `OP^{nym_secret}` with `OP` hashed from context
  bytes under the IETF domain separator; `Tag_DDH` is `H_2(s)^{usk}` with this crate's oracle.
  `kiprf::DDH<G, H>` is generic over the oracle, so an oracle with their domain separator would
  make the two coincide; none is included.
* **Scope.** `BBSPublicParams::ietf` fixes three messages and one committed message; selective
  disclosure over `L` messages is not part of `Σ-BBS`. Only BLS12-381-SHA-256 is covered.

A bridge between the two stacks must keep this crate's own public checks
(`verify_possess_public`, subgroup validation) on everything it receives.
