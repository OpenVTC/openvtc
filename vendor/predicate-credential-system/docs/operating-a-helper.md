# Operating a Helper

What the operator of a helper (the issuer of the construction) has to decide and enforce around
the library. The Rust example below is compiled by `cargo test --doc`.

The construction is as strong as the helper's admission decisions. The code enforces what the
protocol box enforces; the following is the helper operator's part. None of it is a statement of
the paper, whose model has one `pp`, one `hvk` and a policy `P` that is given.

* **Serve a closed set of predicates.** `issue(hvk, hsk, f, id, π)` issues under whatever `f` it
  is called with: `f` is the HELPER's input. A requester that may name `f` names its own
  threshold. With a threshold-1 predicate on offer, ONE credentialed user endorses any number of
  fresh keys of its own, and those keys then endorse a newcomer for a threshold-5 community
  (the regression tests run exactly this). Theorem "Predicate soundness" is not violated (a node
  of the tree has as many children as ITS predicate asks for), but the community's threshold
  means nothing. Decide which `(threshold, label)` pairs exist and refuse everything else before
  calling `issue`.
* **Do not run with the default policy.** `SetupParams::new` selects `P ≡ 1` (`AcceptAll`),
  under which an attestation counts whatever label `φ_j` it discloses: root credentials,
  credentials of a threshold-1 predicate, and ANY other credential under `hvk`. Use an allow
  list over the predicates of the deployment whose members may endorse, e.g.

  ```rust
  use ark_bls12_381::{Bls12_381, G1Projective};
  use predicate_credential_system::{
      cred::PS,
      hash::bls12_381::G1Hasher,
      kiprf::DDH,
      pcs::{AllowList, PCS, Predicate, PredicateCredentialSystem, SetupParams},
  };

  type Open = PCS<Bls12_381, PS<Bls12_381>, DDH<G1Projective, G1Hasher>>;
  type Helper = PCS<
      Bls12_381,
      PS<Bls12_381>,
      DDH<G1Projective, G1Hasher>,
      AllowList<ark_bls12_381::Fr>,
  >;

  # fn main() -> Result<(), predicate_credential_system::Error> {
  let pp = Open::setup(SetupParams::new(b"example.org/community".to_vec()))?;
  let f_root = Predicate::root(b"founders".to_vec());
  let f = Predicate::new(2, b"members".to_vec());
  // founders and members may endorse; nobody else, whatever else `hvk` has signed
  let policy = pp.allow_list([&f_root, &f])?;
  let helper = Helper::from_public_parameters(pp.public_parameters().clone(), policy)?;
  assert_eq!(helper.parameters_digest(), pp.parameters_digest());
  # Ok(())
  # }
  ```

  The policy is the verifier's own input and is not part of `pp` or of a proof, so users can
  keep `P ≡ 1`; the helper's policy decides.
* **One helper key per deployment label.** A credential of `Σ-PS` or `Σ-EQ` is a signature under
  `hvk` on `(usk, φ)` and nothing else (`pp_Σ` is empty; `Σ-BBS` differs, its generators are
  derived from the label). If one key pair served two labels, members of one deployment could
  attest in the other with their label `φ` as a bare scalar, and `P ≡ 1` would count them (an
  allow list would not). `helper_keygen` therefore records the digest of its `pp` inside `hsk`,
  and `issue` / `issue_root` return `InvalidKey` under another `pp`. `HelperSecretKey::new` lets
  you bind a key pair to a deployment yourself: bind it to one.
* **`issue_root` sits behind your admission check, and `f_root` is yours.** A root request proves
  that `C`, `id` and `T_0` are under one key which the requester knows. It says nothing about
  whether that key should be admitted: never expose `issue_root` as an endpoint that anybody
  can call, and never take `f_root` from the request (a requester that names its root predicate
  names its admission class, e.g. one that a community's allow list admits).
* **Attestations are standing endorsements and issuance is assumed sequential** (see
  [Limitations](./design-notes.md#limitations)): if one issuance per set of attestations is wanted, record the tag sets you
  have seen per `id`.
