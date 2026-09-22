# Design Notes

How the implementation is put together, and why. None of this changes what honest parties
compute. The code follows the paper's boxes step by step; the few places where it adds to them
are listed under [Relation to the paper](#relation-to-the-paper).

* Statements of proofs are linear relations over `G_1`, `G_2` and `G_T` with one shared variable
  space; a witness coordinate that occurs in several equations is one variable with one mask and
  one response (witness-preserving AND composition). `G_T` equations are kept in lazy
  pairing-product form, so proving and verifying cost one multi-pairing per equation and no
  exponentiation in `G_T`.
* Fiat-Shamir proofs are compact `(challenge, responses)` pairs. The challenge hashes the caller's
  context **and the complete statement** (every base and target) and the commitment; the test
  suite mounts the weak Fiat-Shamir attack (a tag or a shown credential chosen after the
  challenge) and checks that it fails.
* Decoding accepts the identity point and the zero scalar. Every non-degeneracy requirement of
  the paper is therefore an explicit check in the verifier of the corresponding relation. This
  includes verification KEYS: the possession verifier rejects a key under which its clauses do
  not depend on a certified value, and `CredentialBase::is_well_formed_key` is the membership
  test for the range of `KeyGen`, to be run once on a key received from elsewhere.
* The algorithms of `PCS` do not depend on how their inputs were built. `Attestation`,
  `IssuanceProof` and `RootRequest` have public fields, and arkworks offers unvalidated and
  uncompressed decoding; only validated compressed decoding (`from_bytes`, `from_compact_bytes`)
  guarantees that a value of type `E::G1` is on the curve and in the prime-order subgroup.
  Every algorithm that consumes an object of another party (`verify_attestation`,
  `verify_proof`, `issue`, the root path, `prove`, `attest`, `unblind`, `verify_cred`)
  therefore re-validates it first (`ark_serialize::Valid::check` on `hvk`, `id` and the whole
  object) and returns `Error::InvalidGroupElement` (`false`) otherwise. This is load-bearing:
  pairing equations do not see a component of small order in a `G_1` argument, and the Schnorr
  clause of a tag shifted by a point of order 3 (the cofactor of BLS12-381 `G_1` is divisible
  by 3) verifies after three attempts on average, so that without the check ONE attester
  passes the distinctness check as two and a requester passes self-exclusion with its own
  attestation. The regression tests mount both for every base. Decode with the validating
  decoders all the same; they reject such values at the door. (The stand-alone proofs of the
  lower layers, `kiprf::verify_tag` and `cred::verify_possess`, leave this check to
  their caller.)
* `H_1` has no deployment input: a Fiat-Shamir proof is bound to a deployment only through its
  context, which must contain (a digest of) the public parameters, as `ctx_j` and `ctx_0` of the
  construction box do. The stand-alone tag and possession proofs absorb their parameters.
* Proof sizes. The number of responses of an attestation proof and of `π_0` is a constant of the
  base (`POSSESSION_VARIABLES`, `ISSUANCE_VARIABLES`), which makes the compact encoding
  `FSProof::serialize_compact` decodable without a length prefix. The byte sizes of the paper's
  comparison table (§5.3) are those of this fixed format; the derived canonical encoding is 8
  bytes longer per proof and per vector.
* `PCSTag::IDENTITY_IS_DLOG` is a type-level promise about instances built by `PCSTag::setup`.
  Whether a given tag INSTANCE (assembled from parts, or decoded) satisfies `Tag(K, c_0) = g^K`
  is answered by `PCSTag::identity_is_dlog`; `check_compatibility` uses both.
* Restart loops run behind a well-formedness check. `UKeyGen` of the construction box restarts
  while a tag evaluation is `⊥`; under degenerate tag parameters (a `Tag_DY` instance whose
  generator is the identity) EVERY evaluation is `⊥` and such a loop never terminates. Validated
  decoding refuses that instance, and for one decoded without validation
  `PCSTag::is_well_formed` is `false` and `check_compatibility` / `check_dv_compatibility`
  return `Error::DegenerateInput("pp_Tag")`, for every base. The rule: a loop that restarts on
  `⊥` runs only under a tag instance that passed one of these checks. The loops of the
  conformance flows and of `PCS::user_keygen` are guarded this way and bounded on top.
* `Unblind` of every base follows its box and does not verify its result. The construction
  fails closed ONCE, in `PCS::unblind`: it runs `VerifyCred` on the unblinded credential and
  returns `InvalidPreCredential` if that fails, for every publicly verifiable base (module `pcs`,
  "Rules the construction has to keep"). The designated-verifier variant cannot do this: a user
  has no `dvk`.
* The construction follows the protocol box step by step (the step numbers are in the code).
  `R_att` and `R_issue` are built by the public functions `PCS::attestation_relation` and
  `PCS::issuance_relation` over ONE variable for `usk`, with the witness builders next to them,
  so that a harness can run the interactive protocol, its simulator and its extractor on exactly
  the relations the proofs use. The contexts `ctx_j`, `ctx_0` are public functions of public
  data as well; every verifier rebuilds its context and never takes one from the prover.
* Every Fiat-Shamir context starts with a digest of `pp` that covers the deployment label, and
  attestations, issuance proofs and root requests hash under three different labels.
* `VerifyProof` accepts EXACTLY `k = f.threshold` attestations, and `f` itself (not only
  `EncPred(f)`, a hash that does not reveal `k`) is part of `ctx_0`. The fixed-format decoder
  takes the number of attestations from `f` and the numbers of responses from the base; nothing
  is read from the wire.
* `VerifyAtt`, `VerifyProof`, `Unblind` and `VerifyCred` check that `hvk` consists of group
  elements and lies in the range of `KeyGen` (once per call). `Attest` does not (the holder
  checks a key once, when it receives it; `Unblind` has done so), and like the box it does not
  verify its own output: with the weak base
  `Σ-BBS`, `Attest` on a credential that does not belong to `(usk_j, f_j)` returns an attestation
  that `VerifyAtt` rejects, where `Σ-PS` and `Σ-EQ` return an error.
* Clause builders check the caller's variable before they allocate their own
  (`Error::UnallocatedVariable`, relation untouched): a foreign handle with the right index
  would otherwise alias a fresh variable, e.g. `ρ`, without any error.
* Randomized algorithms take an explicit `RngCore + CryptoRng` (rand 0.8, as re-exported by
  `ark_std::rand`). Tests are seeded and reproducible.

## Limitations

* **Secrets in memory.** Secrets owned by this crate are wiped on drop (the witness container
  also wipes a buffer it outgrows instead of leaving that to the allocator), but field elements
  are `Copy` and temporaries may remain on the stack.
* **Plain Fiat-Shamir in the random-oracle model.** Knowledge extraction is by rewinding; the
  interactive protocol, its simulator and its extractor are exposed so that the test harness can
  exercise them directly. The paper takes straight-line extractable proofs as its default
  instantiation and says: "With plain Fiat-Shamir the theorems still hold for sequential
  issuance and constant `k`, with the losses just described" (Remark "Concurrent issuance"). The
  crate does not enforce sequential issuance.
* **Attestations are standing endorsements** (Remark of that title): an attestation binds `id`
  and the attester's key, no session, epoch or predicate, and can be presented again for the
  same `id` under any predicate. Neither remedy of the Remark (a helper nonce in the attestation
  challenge; the helper recording the tag sets it has seen) is implemented.
* arkworks' `DefaultFieldHasher` differs from RFC 9380 `hash_to_field` when hashing to the
  scalar field (zero-padding length). It is used as a random oracle only and does not
  interoperate with RFC 9380 hashers.

## Relation to the paper

The algorithms follow the paper's boxes and remarks, including the key spaces of `Σ-PS` and
`Σ-MAC`, the transparently derived generators of `Σ-BBS`, thresholds `k ≥ 1`, the explicit input
checks of `VerifyProof`, and the root request of Remark "Chaining and the base case". What the
code adds, or fixes where the paper leaves a choice:

* **Sizes.** `|cred|` here is the size of the PCS credential `(cred_Σ, m_aux)`: 96 B for `Σ-PS`,
  112 B for `Σ-BBS` (`cred_Σ = (A, e)` has 80 B, `m_aux = ρ` another 32 B) and 192 B for `Σ-EQ`
  (`(Z, Y, Ỹ)`; its shown form `cred*` has 336 B). `|att|` and `|π|` are 240/1392, 416/2272 and
  480/2512 B over BLS12-381 at `k = 5`, in the fixed format without length prefixes.
* **`Σ-EQ` shows.** A re-randomized `cred'` verifies on the new representative `M' = M^r`
  (SPS-EQ verification is per representative), and `Unblind` returns `ĉred` unverified as in
  the box; the construction's `Unblind` verifies once for every base.
* **The policy `P`** is a field of `PCS` next to `pp` and is not hashed into the contexts: the
  verifier's policy decides, and a proof made under a laxer policy is rejected by `CheckAtts_P`
  of a stricter verifier.
* **Identity point.** `PCSTag::setup` programs `H_2(c_0) = g_1` for every base, following Remark
  "Identity point", so that `id = g_1^usk` whenever the tag is `Tag_DDH`.
* **`Setup` takes no RNG**: every parameter of the classical construction is derived by hashing
  the deployment label. **`UKeyGen` returns a `Result`**: the error case carries implementation
  failures and the exhaustion of its restart bound (`MAX_KEYGEN_ATTEMPTS = 64`, each restart
  having probability about `2/p` under well-formed parameters).
* **Additional checks.** `ValidTag(id, c_0)` is required in `Attest` and `VerifyAtt` as well;
  `Issue` compares its argument `hvk` with the copy inside `hsk`; `hsk` records the digest of
  its `pp` and refuses to issue under another one; received group elements are re-validated by
  every algorithm; received public parameters must EQUAL what `Setup` derives from their label
  (`PCS::from_public_parameters_with_base` compares `pp_Σ` with base parameters the caller
  derived itself, for the IETF parameters of `Σ-BBS`).
