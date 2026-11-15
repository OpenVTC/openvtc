# D4 — Verifiable Presentation construction + VP requirement discovery (scoping)

Status: **scoping** (not scheduled). Closes the last deferred item from the
multi-community spec (`docs/design/multi-community-support.md` §8, §10 Q1).

> **Out of date.** The stub VP described in §1 is gone. Join step 4 now builds
> its VP with `build_join_vp` (`openvtc-core/src/join.rs`), called from
> `join_flow.rs` and `join_cmd.rs`. D4 needs re-scoping against that; the rest
> of this document is the original scoping and has not been re-checked.

## 1. What D4 is

Join step 4 currently submits a **stub VP**. The spec required the flow around
it (pending state, receipts, persistence, lifecycle) to be built so that
"dropping in real VP construction is a localized change" — that holds:

- **Single stub call site** — `openvtc/src/state_handler/join_flow.rs:644`:
  ```rust
  let vp = serde_json::json!({ "type": "VerifiablePresentation", "holder": applicant_did });
  openvtc_core::join::submit_join_request(atm, &profile, &applicant_did, &vtc_did, &mediator, vp).await
  ```
  `submit_join_request` (openvtc-core/src/join.rs) takes the `vp: Value` and
  packs it into `JoinRequestSubmitBody { vp, .. }`. Replacing the stub is a
  one-function change plus the discovery/selection machinery feeding it.

D4 has two halves: **(A) requirement discovery** (what must the VP contain) and
**(B) VP construction** (build + sign a presentation that satisfies it).

## 2. (A) Requirement discovery — the spec's blocking open question is now ANSWERED

§10 Q1 ("where do a VTC's join requirements come from") was "undecided /
infra-side." Since the spec was written, **vta-sdk 0.12 ships the protocol** for
it (`vta_sdk::protocols::join_requests` + `credential_exchange`). Three channels:

1. **Pre-submit manifest** — `join-requests/manifest/1.0` →
   `JoinRequestManifestResponseBody { community_did, criteria: Vec<ManifestCriterion> }`,
   each `ManifestCriterion { id, description, presentation_definition }` where
   `presentation_definition` is a **DCQL** query. The applicant fetches this
   *before* submitting, builds a VP that satisfies it, and submits.
2. **Post-submit deferred** — `join-requests/status-response/1.0` with
   `status: "deferred"` carries `needs: Vec<String>` + `presentation_definition`
   (DCQL) — "more info required." Today T6 treats `deferred` as a no-op stub
   (`openvtc-core/src/messaging.rs` `handle_join_status_response`); D4 would
   turn that into "build the requested VP and re-present."
3. **Generic credential-exchange** — `credential-exchange/query/1.0`
   (`QueryBody { dcql_query, nonce, purpose }`) → `present/1.0`
   (`PresentBody { vp_token }`), OID4VP-style with purpose binding + nonce.

**Recommendation:** use the **manifest (1)** as the primary path (discover →
build → submit with a real VP), and wire the **deferred (2)** path so a VTC can
ask for more after submit. Both reduce to the same core: *DCQL → vp_token*.

## 3. (B) VP construction — primitives available, one real gap

**Have:**
- **Signing** — `affinidi_data_integrity::DataIntegrityProof::sign` (eddsa-jcs-2022;
  the same primitive the provision-client's VP signer uses, see
  vta-sdk `provision_integration/request.rs::sign`). The persona's signing key
  is already in the TDK secrets resolver after mint/load.
- **Held credentials** — `dtg_credentials::DTGCredential`, stored client-side in
  `openvtc_core::vrc::Vrcs` (per-community `vrcs_received`,
  `account.rs:218`) and the per-community `credentials: BTreeMap<CredentialKind,
  Value>` (`account.rs:230`, e.g. the issued membership VMC). So the wallet of
  presentable credentials exists.
- **Wire shape** — the target is an OID4VP `vp_token` (`PresentBody.vp_token:
  Value`); `JoinRequestSubmitBody.vp` is the same `Value` slot.

**Gap (the real work):**
- **No DCQL / Presentation-Exchange evaluator anywhere in the dep tree** (grep
  across vta-sdk / affinidi-data-integrity / dtg-credentials finds none — only
  the *types* that carry a `presentation_definition`, not a matcher). So nothing
  today: (a) parses a DCQL query, (b) selects which held `DTGCredential`s satisfy
  it, (c) assembles + signs the `vp_token`. This is D4's core deliverable.

## 4. Proposed work breakdown

- **D4.0 — decide the DCQL matcher home** (open decision, see §5). Local crate vs.
  push a `vta-sdk` helper (infra). Affects everything below.
- **D4.1 — discovery client**: send `join-requests/manifest`, handle the
  response; surface `criteria` (DCQL + human `description`) to the user.
  (openvtc-core protocol send/recv + a dispatch handler, mirroring the existing
  join receipt/status handlers.)
- **D4.2 — credential selection (DCQL match)**: given a DCQL
  `presentation_definition` + the persona's held credentials, compute candidate
  credential sets that satisfy it. The matcher from D4.0.
- **D4.3 — VP build + sign**: assemble the selected credentials into a
  holder-bound `vp_token`, sign with the persona key via `DataIntegrityProof`,
  bind the verifier `nonce`/`purpose`. Replaces the stub at `join_flow.rs:644`.
- **D4.4 — UX**: a credential-selection / consent step in the Join flow
  (show `purpose`, the required criteria, which held credentials match, let the
  user approve disclosure). New `JoinPage` state + actions.
- **D4.5 — deferred re-present**: turn T6's `deferred` no-op into "build the VP
  the status-response asks for and re-present" (`messaging.rs` +
  `credential-exchange/present` or a re-submit).
- **D4.6 — tests**: DCQL-match unit tests; a MockVta/mediator e2e once the VTC
  side advertises a manifest (currently the stub VTC does not — likely a VTI
  follow-up to have MockVta/VTC serve a manifest + verify a real VP).

## 5. Open decisions (need a call before building)

1. **DCQL matcher: local vs. infra.** No crate exists. Options: (a) implement a
   focused DCQL evaluator in `openvtc-core` (scope: only the DCQL subset VTCs
   actually use); (b) push a `select_credentials(dcql, &[cred]) -> vp_token`
   helper into `vta-sdk` (keeps client lean, shares with other consumers, matches
   the CLAUDE.md "infra belongs in VTI" stance) — **recommended**. Filed as
   **VTI#437**. The VTC verifies server-side regardless.
2. **Discovery channel for join.** Manifest-first (recommended) vs. submit-then-
   deferred-only. Manifest gives a better UX (know requirements up front) but
   needs the VTC to serve a manifest.
3. **Credential-disclosure UX & consent.** How much selective disclosure / user
   choice in v1 — auto-select the single matching cred vs. a picker; how to show
   `purpose` (purpose binding is "never optional" in `QueryBody`).
4. **Test harness.** Driving a real VP e2e needs a VTC that advertises a manifest
   and verifies the VP over DIDComm — `MockVtc` is REST-only today (`atm: None`)
   and OpenVTC joins over DIDComm. Filed as **VTI#436** (DIDComm join-requests
   MockVtc harness), paralleling the #406/#431 MockVta work.

## 6. Dependencies / sequencing

- vta-sdk 0.12 (already in tree) provides all the protocol types — no new SDK
  dep needed for D4.1/D4.3/D4.5.
- D4.0/D4.2 may add a `vta-sdk` helper (infra) — decision §5.1.
- D4.6 likely needs a VTI MockVTC follow-up — decision §5.4.
- Localized to the join flow + a new dispatch handler + a selection UI; does not
  touch the config model, bootstrap, or lifecycle reducers already shipped.
