# OpenVTC Integration

How this library could be integrated into [OpenVTC](https://github.com/OpenVTC/openvtc). This is
a proposal: nothing of it exists in OpenVTC today. Statements about OpenVTC refer to its
repository at commit `3329195` (2026-09) and to the crates it links (`vta-sdk` 0.43,
`dtg-credentials` 0.9, `affinidi-data-integrity` 0.7); that code base moves quickly, so re-check
before building on a detail. The community service (VTC) lives in another repository
(`OpenVTC/verifiable-trust-infrastructure`), which was not reviewed for this document: everything
about the helper side is derived from OpenVTC's client code and design documents.

Each section says what was **verified** (read in the code, or run as an experiment) and what is
**proposed**.

## Where the library fits

The library proves "I hold attestations from `k` pairwise-distinct credentialed members, none of
whom is me" without revealing who they are. OpenVTC has one flow with exactly this shape, and it
is not the VRC exchange:

- **Vetted admission** (`docs/design/vetting-process.md`): a community admits an applicant on
  `minStatements` vetting statements from distinct eligible vetters. A statement is an
  endorsement credential (VEC) that names the vetter's member DID in the clear, by decision D7
  of that document. Its roadmap lists "k-of-n proofs over hidden vetters" and "uniqueness
  pseudonyms" as V2 items. That is the place for this library. (Verified.)
- **VRCs** are not consumed by any join, personhood or presentation path today, and since
  pairwise relationship DIDs became the default a VRC no longer names either persona. They are
  not a suitable carrier. (Verified.)

| Library | OpenVTC |
|---------|---------|
| helper, `(hvk, hsk)` | the community service (VTC); one key pair per community |
| deployment label of `Setup` | the community's VTC DID, plus a version string |
| user `(id, usk)` | the applicant's per-community persona; `usk` is a NEW local secret, `id` is bound to the persona DID |
| root credential (`root_request` / `issue_root`) | admission by invitation (VIC) or personhood (PHC): the VTC issues after its existing check |
| attestation `att_j` | replaces the vetting statement that names the vetter |
| predicate `f = (k, label)` | `minStatements` of the join manifest, plus the membership class |
| attribute policy `P` (`AllowList`) | which member classes may vet (today: the `CommunityRole: vetter` endorsement) |
| `Prove` → `Issue` → `Unblind` | join request submit → verdict → credential delivery |
| issued credential | kept by the new member, used only to attest for later applicants |

One consequence must be decided by the OpenVTC maintainers before any code is written. The
vetting design wants ACCOUNTABLE vetters: the VTC counts distinct vetters by member record and
applies velocity caps and cascade review per vetter. With this library the VTC learns that `k`
distinct eligible members vouched, and nothing else: tags of one vetter for two applicants are
unlinkable by design, so per-vetter velocity caps and cascade review are not possible. Distinct
counting and self-exclusion are what the tags provide.

## Packaging

- **Source.** OpenVTC's `deny.toml` denies git dependencies and registries other than crates.io.
  The crate must be published to crates.io, or vendored as a workspace member. (Verified. The
  name `predicate-credential-system` was free on crates.io on 2026-09-19.)
- **Licence.** This crate is MIT, which is on their allow-list for dependencies. Vendoring the
  sources into the Apache-2.0 workspace is a separate decision.
- **Toolchain.** Edition 2024 and `rust-version = "1.95.0"` on both sides. (Verified.)
- **Footprint.** Added as a dependency of `openvtc-core`, the crate brings 13 new packages (the
  arkworks stack), no duplicate versions, and builds without warnings; the `serde` feature adds
  no package, because `serde` and `multibase` are already in their graph. (Verified in a scratch
  copy of OpenVTC, together with a smoke test of a complete join.)
- **Feature gate.** Put the integration behind a non-default cargo feature of `openvtc-core`,
  e.g. `pcs`, as they do for `openpgp-card`. (Proposed.)
- **CI.** Their pipeline runs fmt, clippy with `-D warnings`, rustdoc with `-D warnings`,
  `cargo deny`, an MSRV job, and tests on Linux, macOS and Windows. This crate passes the first
  three locally and has only been tested on macOS. (Verified for macOS; the rest is open.)

## Client side: a `pcs` module in `openvtc-core`

Proposed. The `openvtc` crate is a binary, so testable logic belongs in the core crate.

- **State per community.** `usk`, `id`, the credential, and the issuance state between submit
  and verdict (`IssuanceState`, as secret as `usk`). All of them have JSON forms for protected
  storage in the `serde` feature; they belong into OpenVTC's encrypted `ProtectedConfig` or the
  OS keyring (`SecuredConfig`), next to the other secrets.
- **Key custody.** Generate `usk` locally with `user_keygen` and never hand it to the VTA. New
  OpenVTC profiles are VTA-backed: the VTA generates and stores persona keys, can sign as the
  user and sees the relationship graph, by written design. Tags are deterministic in `usk`, so a
  VTA that held `usk` could link every attestation of its user. The VTA key types (Ed25519,
  X25519, P-256, ML-DSA) have no scalar-field key anyway, and an OpenPGP card cannot run these
  protocols, so `usk` cannot live on one.
- **Binding `id` to the persona.** The library has no notion of a DID. Bind the two at the
  message layer: the persona key signs `(id, community, purpose)` as a Data Integrity proof, and
  every message that carries `id` travels authcrypt from the persona DID, as the join request
  already does.
- **Calls.** Randomized algorithms take `rand::rngs::OsRng` (rand 0.8), the generator OpenVTC
  uses everywhere. (Verified.) Proving and verifying cost pairings: run them through
  `tokio::task::spawn_blocking`, the pattern OpenVTC uses for Argon2id, never on the event loop.
- **Errors.** Map `predicate_credential_system::Error` into one variant of `OpenVTCError`
  (`thiserror`). The error type carries static descriptions, lengths and indices only, never
  key material or witness values.
- **Received parameters.** A client accepts a community's `pp` only through
  `PCS::from_public_parameters`, which recomputes `Setup` from the label and compares.

## Messages

Proposed. Everything in OpenVTC is JSON over DIDComm or TSP, with multibase base58btc for
binary values; the `serde` feature produces exactly that. An attestation is
`{"tag": "z…", "shown": "z…", "phi": "z…", "proof": "z…"}`, an issuance proof is
`{"attestations": […], "encoding": "z…", "t0": "z…", "proof": "z…"}`, a predicate is
`{"threshold": 2, "label": "members"}`, and keys, parameters and pre-credentials are single
strings. At `k = 5` a proof has 1.4 to 2.5 KB in binary and about 1.37 times that in base58btc,
far below OpenVTC's 1 MiB message guard.

| Step | Carrier |
|------|---------|
| community parameters: label, suite, `hvk`, served predicates | the `vetting` object of the join manifest |
| attestation request, applicant → vetter: `id`, community, class | new peer message next to `vetting/request` |
| attestation, vetter → applicant | new peer message; replaces the vetting statement |
| join submit: `id`, predicate, issuance proof | `JoinRequestSubmitBody.extensions`, an open JSON member that is already on the wire |
| pre-credential, VTC → applicant | new message next to `credential-exchange/issue` |
| root request and its answer, after VIC or PHC admission | new message pair |

New DIDComm types must match OpenVTC's inbound type filter, which admits
`https://trusttasks.org/spec/vetting/*`, `https://trusttasks.org/spec/vtc/*`,
`https://firstperson.network/*` and `https://linuxfoundation.org/openvtc/*`, and need an arm in
its dispatch chain; a new Trust Task additionally needs a published spec. (Verified.)

The credential itself never needs a W3C envelope: it is used only to attest, and an attestation
reveals nothing but the class label `phi`. That is fortunate, because `DTGCredential.proof` is
one `DataIntegrityProof` with a closed cryptosuite enum, so a proof object of this library does
not deserialize there. (Verified.) If a community wants the membership to be visible as a VC, it
keeps issuing its VMC as today, next to the PCS credential.

```text
applicant                     vetter_1 … vetter_k                    VTC (helper)
    |  manifest request ------------------------------------------------>|
    |<------------------------------- pp label, suite, hvk, predicates --|
    |  attestation request(id) -->|                                      |
    |                             |  vets the applicant out of band      |
    |<------------ attestation ---|  attest(hvk, usk_j, cred_j, id)      |
    |  prove(hvk, f, id, usk, attestations)                              |
    |  join submit { extensions.pcs: id, f, proof } -------------------->|
    |                                   verify_proof, policy, issue      |
    |<-------------------------------------- verdict + pre-credential ---|
    |  unblind (fails closed), store credential                          |
```

## Helper side: the VTC

Proposed, and subject to the rules of [Operating a helper](./operating-a-helper.md):

- **One `hsk` per community**, bound to that community's `pp`; the crate refuses to issue under
  another `pp`.
- **A closed set of predicates.** The VTC, not the requester, decides which `(threshold, label)`
  pairs exist; take them from the community's join policy.
- **An `AllowList` policy**, never the default `P ≡ 1`, listing the classes whose members may
  vet.
- **Verdict.** Run `verify_proof` before the Rego policy and hand it facts, e.g. that the proof
  is valid, its threshold, and the disclosed class labels. Issue only on `allow`.
- **Root issuance** behind the existing invitation or personhood check, with a root predicate
  chosen by the VTC.
- **Replay.** Attestations are standing endorsements. If one admission per set of attestations
  is wanted, record the tag set seen per `id`.
- **Issuance order.** The proofs are plain Fiat-Shamir; the paper's theorems then hold for
  sequential issuance. OpenVTC's join flow is asynchronous and concurrent, so the VTC has to
  serialize issuance per helper key until straight-line extractable proofs are available.

## Choice of instantiation

`BBS` with `DDH` aligns with the BBS work that exists upstream (`affinidi-bbs`, the `bbs-2023`
cryptosuite): with `BBSPublicParams::ietf` a credential is an IETF BBS signature. The proofs are
not wire compatible with IETF BBS, and upstream keeps issuer-side BBS signing feature-gated
("audit-gated"); see [Encodings and interoperability](./encodings.md). `PS` with `DDH` is the
paper's main instantiation and has the smallest proofs. Both work with everything above; the
suite is one field of the community parameters.

## What is missing

In the library:

- **An application context.** OpenVTC binds vetting material to a request id, an audience and a
  validity window of minutes. `attest` and `prove` take no such input. Adding a caller-supplied
  context to `ctx_j` and `ctx_0` is the first change this integration needs; it is also the
  paper's first remedy for replay.
- **Revocation and expiry.** OpenVTC credentials carry status entries and validity intervals.
  The library has neither.
- **Per-relationship identifiers.** In OpenVTC a vetter may know the applicant under a pairwise
  DID. The paper treats this variant in an appendix; it is not implemented.
- **Concurrent issuance**, as above.
- **Platforms and release.** Tests on Linux and Windows, a crates.io release, a licence
  decision, and a security review.

In OpenVTC: a home for `usk` outside the VTA, the message types above, the VTC-side verifier
and policy facts, and the decision on vetter accountability described at the top.

## Suggested order of work

1. Decide on vetter accountability, and on publishing or vendoring the crate.
2. Add the application context to the library; run its test suite on all three platforms.
3. Add the `pcs` module to `openvtc-core` behind a feature: state, storage, JSON, a local
   end-to-end test with two clients and a mock VTC.
4. Specify the messages and implement them on both sides, starting with root issuance.
5. Wire the verifier into the VTC's policy evaluation and define its operating procedures.
