# Hidden-vetter admission for OpenVTC using the Predicate Credential System (PCS)

> Branch `zkp-pcs`. The crate that implements this is `openvtc-vetting-pcs`; the library it
> builds on is vendored under `vendor/` (see `vendor/PROVENANCE.md`).

**Status:** research and integration proposal, 2026-09-22. A working prototype exists; see §14.
**Second-pass review (same day):** §13 lists corrections that supersede parts of §3, §4.3 and
§5.1. Read §13 before building anything. The published review page mirrors this document.

**Goal:** Bob, the applicant, proves to a VTC that `k` distinct, currently eligible vetters of
that community vetted him, without the VTC (or anyone else) learning which vetters they were.

**Scope:** this is the "k-of-n proofs over hidden vetters" item of vetted admission V2
(`openvtc/docs/design/vetting-process.md` §14.2). It is an opt-in per-community mode beside the
V0 named-vetter flow, which it does not change. Do not let it touch the 5 Oct V0 critical path.

**Sources read:**
- `etairi/predicate-credential-system` @ `aa57efd`: README, all of `docs/`, `src/pcs/context.rs`,
  `src/kiprf/mod.rs`. The test suite (426 tests, 1 ignored) and benchmarks were run locally.
- `OpenVTC/openvtc` @ `63d1fa1`.
- `verifiable-trust-infrastructure` @ `6f26af19`. `origin/main` is at `1f6025ea`; the two
  commits in between are error-code and auth fixes only.
- `dtgwg-trust-tasks-tf/specs/{vetting,vtc}`.
- `design-docs/persona-to-membership-design.md` §4–§8.

---

## 1. What PCS is, in one paragraph

A **helper** (the issuer) gives users blind credentials. A credentialed user can **attest** for
another user's identifier `id`. The applicant then **proves** in zero knowledge that it holds `k`
attestations from pairwise-distinct credentialed users, none of whom is itself.

Each attestation carries a **tag** `T_j = Tag(usk_j, H0(id))`. That value is:
- deterministic per (vetter, applicant), so the same vetter twice is caught (`DuplicateAttester`);
- unlinkable across applicants, so a vetter's attestations for Alice and for Bob cannot be tied
  together;
- unlinkable to the vetter's identity, even for the helper that issued the vetter's credential.

An attestation also discloses one thing: the class label `φ` of the credential it was made
under, which is how "only vetters count" is enforced (an `AllowList` policy).

| Property | Measured (Σ-PS + Tag_DDH, BLS12-381, Apple Silicon) |
|---|---|
| Attestation | 240 B, ~2.8 ms to make or verify |
| Proof at k = 5 | 1392 B, ~11.6 ms to prove, ~11.5 ms to verify |
| Tests | 426 pass on macOS (1 ignored); Linux and Windows untested |

It is a research artifact: unaudited, not on crates.io, plain Fiat-Shamir (so sequential
issuance only), MIT-licensed, Rust 1.95 / edition 2024 (the same toolchain as OpenVTC). The repo's
own `docs/openvtc-integration.md` is a good starting point. This document corrects and extends
it with the VTC side, which that proposal did not review.

## 2. Where it lands in today's code

The applicant-to-vetter ceremony (ticket → `vetting/request` → `vetting/session` → signed
Vetting Card → human check, match code) **stays exactly as built**. Only the *artifact the vetter
hands back* and *what the VTC verifies* change.

| Today (V0, named) | Hidden mode (PCS) |
|---|---|
| The vetter signs a VEC with `issuer` = its member DID (D7, `vta-sdk/src/vetting/statement.rs`) | The vetter returns a PCS **attestation** plus public statement metadata. No DID of the vetter appears |
| The VTC checks the issuer's member row and `vetter` grant (`vtc-service/src/vetting/mod.rs:371`) | The VTC checks the proof. `φ` ∈ AllowList{`vetter`} under this epoch's `hvk` proves an eligible vetter |
| `StatementFacts.vetter` = the issuer DID, deduplicated in `requirements::evaluate` (`vta-sdk/src/vetting/requirements.rs:215`) | `StatementFacts.vetter` = the tag `T_j` (multibase). The same function deduplicates, unchanged |
| `VettingFacts.statements[].issuer` = DID | `issuer` = the tag. **`join.rego` is untouched** |
| Revocation notice keyed by issuer + id + digest (`vetting/revocation.rs`) | Revocation by tag (§4.4), optionally anonymous |

The key design choice is to **emit the same `VettingFacts` shape** with tags standing in for
issuer DIDs. Counting, `needs` expansion, method floors, independence caps, commitment
consistency and the Rego policy then all keep working, and the admin UI's rule IR needs no
change.

## 3. Role mapping

| PCS | OpenVTC / VTI |
|---|---|
| Helper `(hvk, hsk)` | vtc-service, **one key pair per community per epoch**. `hsk` is a BLS12-381 scalar. The VTA key types cannot hold it, so it goes in the VTC's own secret store |
| Deployment label | `"{communityDid}#vetting-pcs/{epoch}"` |
| Root credential, `f_root = ("vetter")` | Issued when the `vetter` role is granted: `vetters/grant`, `vetters/resend`, `auto_grant::run_sweep`. It sits behind the existing grant check and inside `GRANT_LOCK`, which also satisfies "sequential issuance" |
| AllowList | `{vetter}` only. Admitted members are **not** vetters until granted, as today |
| Applicant `(id, usk)` | Fresh per application, generated locally, **never held by the VTA** (a hosted VTA may belong to the same operator as the VTC; tags are deterministic in `usk`) |
| `attest` | Replaces `sign_statement` at the vetter's attest step (`openvtc/src/state_handler/vetting_actions.rs` ~`:2366`) |
| `prove` / `verify_proof` | Join submit / the VTC's facts builder |
| `issue` / `unblind` for the applicant | **Not used.** Admission still issues the VMC as today. A member who later becomes a vetter gets a root credential then. This drops the concurrent-issuance hazard to the root path, which is already serialised |

**Distinct vetter = distinct member (D14) is kept by one rule:** the VTC issues **at most one
root credential per member record per epoch**, recorded by member id. A vetter holding two
credentials would otherwise produce two different tags and count twice. The root request reveals
the vetter's PCS `id` to the VTC, which is harmless: who holds the vetter role is already known
to the VTC and shown in the directory.

## 4. Closing the gaps between the library and the V0 semantics

### 4.1 Application context: the one library change that blocks everything

`ctx_j` and `ctx_0` (`src/pcs/context.rs`) take no caller input, and every V0 check hangs off
statement-level data. The fix is **caller-supplied context bytes** in `attest` / `verify_att`
(appended to `ctx_j`) and in `prove` / `verify_proof` (appended to `ctx_0`). The library's own
docs name this as the first change an integration needs.

- **Per attestation** (`ctx_j`, public, sent beside the attestation): `community`,
  `requirementsDigest`, `method`, `claimsVerified`, `livenessConfirmed`, `declaredRelationship`,
  `identityCommitment`, `validFrom` (**day granularity**; exact timestamps would let the VTC
  correlate with vetter activity), `validUntil`, `cardDigestMultibase`.
- **Per proof** (`ctx_0`): the VTC's single-use challenge, the audience, and the binding of `id`
  to `joinDid` (§4.2).

With that, every row of the V0 fact set carries over: method floors, `requiredClaims`,
`maxStatementAge`, independence caps, and commitment consistency (all `identityCommitment`
values equal). The VTC reads the metadata **per tag**, so it learns "some vetter did `inPerson`"
but not who.

### 4.2 Binding `id` to the join persona

The library has no DIDs. The applicant's `joinDid` key signs `(id, community, epoch,
requirementsDigest)` as a Data Integrity proof. That digest goes into `ctx_0`, and the submit
already travels authcrypt from `joinDid`.

The vetter **does not need `joinDid`**. It attests `id`. The applicant can therefore run each
vetting session from a pairwise DID, which removes one correlator. Vetters can still link Bob
among themselves through the shared `id`; per-relationship identifiers are an appendix of the
paper and are not implemented.

### 4.3 "Eligible at `validFrom` and now": epochs

PCS has no revocation. Currency comes from **epoch rotation of `(hvk, hsk)`**:
- The VTC accepts the current epoch and the previous one (a grace window, community policy,
  e.g. 30 days).
- Rotation re-issues root credentials to every live vetter automatically, through the resend
  path.
- **Removing a vetter** means not re-issuing, plus an **emergency rotation** when it must take
  effect at once. Honest attestations under the killed epoch are then **re-attested**: the
  vetter's client keeps `(id, metadata)` for each attestation it made, so the applicant asks for
  a refresh and no new session is needed.

The persona-to-membership design wanted clause 3 ("issuer is a current member") evaluated at
application time. Epochs give that, at epoch resolution.

### 4.4 A vetter withdrawing one statement: better than today

The vetter knows `T_j` and can prove knowledge of the key behind it with the library's
stand-alone `kiprf::prove_tag(key = usk_j, tag = T_j, input = H0(id))`. The VTC records `(id,
T_j)` as withdrawn, and the next evaluation stops counting that tag.

The proof does **not** link `T_j` to the vetter's root `id`, so the notice can be sent over an
anonymous channel. `persona-to-membership-design.md` §4.4 recorded exactly this as unsolved:
"a withdrawal that doesn't identify the vetter".

### 4.5 Replay

Attestations are standing endorsements. `ctx_j` pins them to one community, one requirements
version and one validity window. `ctx_0` pins the proof to the VTC's single-use challenge. The
VTC also records the tag set per `id`, which is needed for `requestMore` and supplement anyway,
because the same vetter keeps the same tag across resubmissions.

## 5. Accountability: what is kept, what is given up

The VTC can no longer attribute an admission to a vetter. Without more machinery, that rules
out:
- **per-vetter velocity caps** (10 statements per 30 days, §10.5): **kept**, by the drip
  tokens of §5.1;
- **cascade review** when a vetter turns out bad: **given up**;
- **lineage** and vetter-derived **depth**: **given up**.

Two facts soften the loss:

1. **None of the three is built.** They are designed for V1 (`vetting-process.md` §10.5, §14.2),
   and there is no `vetterRateLimit`, lineage store or `on_statement_revoked` in either repo.
   Hidden mode loses nothing that ships today. It forecloses a planned design, so governance
   still has to accept the trade explicitly, as `persona-to-membership-design.md` §8 item 12
   already asks.
2. **Partial substitutes exist for what is given up:**
   - **Depth:** coarse bands in the label, e.g. `φ ∈ {vetter-d1, vetter-d2}`. This costs
     anonymity-set size.
   - **Cascade review:** needs *accountable* anonymity, i.e. a vetter id verifiably encrypted to
     a k-of-n governance key and opened only by quorum. PCS does not do this, and it is the
     natural next research ask for Berkeley.

### 5.1 Velocity cap: attestation tokens on a constant drip

**Principle:** build everything from PCS, so there is one crate, one curve (BLS12-381 in
arkworks) and one review scope. A token is a Pointcheval–Sanders blind signature on a secret
serial number, made with the blind issuance and re-randomisation that the PCS credential layer
(`cred::PS`: `BlindIssue`, `Unblind`, `ReRand`) already implements for credentials. There is no
RSA and no new dependency.

**The shape is a token bucket.** Every vetter receives the same `r` new tokens on every tick,
whether or not they used any, and tokens expire. Nothing the VTC observes depends on how many
tokens a vetter used.

**Why not "top up what was spent".** Replenishing a vetter to its limit tells the VTC how many
tokens that vetter used, and when. That is per-vetter activity, exactly what hidden mode hides,
and no blinding removes it: the request for `k` new tokens *is* the statement "I handed out `k`".

**Parameters.** Community policy, published in the manifest:

| Parameter | Meaning | Kernel example |
|---|---|---|
| `r` per tick | Drip rate, the same for every vetter | 1 token every 3 days (10 a month) |
| Token-key period | The token key rotates monthly; the VTC accepts the current and the previous key | Monthly |
| `W` | The acceptance window that follows from the key period: 30–60 days | — |
| Holding bound | At most `r × W` live tokens: 20, bursting up to 20 at once, sustained 10 a month | — |

**The flow:**

1. **Drip.**
   - On every tick, the vetter's client draws `r` random serials `s_i`.
   - It sends the VTC hiding commitments `C_i = g_1^{ρ_i} Y_1^{s_i}`, each with a proof of
     knowledge of its opening, over `vtc/vetting/vetters/tokens/0.1`.
   - The VTC checks two things: the sender holds a live `vetter` grant (the same check as root
     issuance), and it has not yet been served for this tick. It then blind-signs under the
     current month's token key, one commitment at a time (sequential issuance, §3).
   - The client unblinds the results into tokens `(s_i, σ_i)`.
   - Fetches are **scheduled and unconditional**, at a random moment within the tick window.
     They carry no information about use.
   - **Missed ticks** (the device was off) are caught up on the next fetch, capped at `r × W`.
     This reveals when the vetter was offline, not when they vetted. A community that minds can
     have the vetter's always-on agent do the fetching.
2. **Hold.**
   - Tokens are never "pushed out" by a rule. They expire when their month's key leaves the
     acceptance window. That enforces the holding bound cryptographically.
   - An idle vetter's bucket fills to `r × W`, and the oldest tokens expire unused. An active
     vetter is replenished by the drip without ever asking.
3. **Reserve and spend at attestation.**
   - The client **reserves a token when it accepts a `vetting/request`** (§5.2), and releases it
     on decline, cancel or timeout.
   - At the attest step, it puts the reserved serial `s_i` in `ctx_j` (§4.1). The attestation
     proof is now bound to that serial, so a token cannot be moved from one attestation to
     another.
   - It hands Bob a **re-randomised** `σ_i'` together with the attestation.
   - It hands out the **newest** token it holds, which gives Bob at least 30 days to submit.
     Older tokens expire unused; that is the FIFO.
4. **Check at submit.**
   - For each attestation, the VTC verifies `σ_i'` on the revealed `(s_i, φ_token)` under a
     token key in the acceptance window.
   - It checks that `s_i` is not in that key's spent set, then records it as spent.
   - An attestation without a valid, unspent token gets the failure code `no-token` and is not
     counted.
   - If Bob's token expires before he submits, his vetter re-attests through the refresh flow of
     §4.3, which costs that vetter one more token.

**Why this hides the vetter.**
- The VTC never saw `s_i` at signing time, only `C_i`, which hides `s_i` perfectly given `ρ_i`.
- `σ_i'` is a fresh re-randomisation.
- Every vetter's fetch pattern is identical.
- A spend reveals only the month of its key, never who fetched the token or when the vetting
  happened.

**What the VTC learns.**
- Which vetters are online enough to fetch.
- Totals per month: tokens issued and tokens spent.
- **Not** any single vetter's use.

**Per-vetter rates.** Vetters may want different limits. The two directions are handled
differently:

- **Lower than the community's drip: purely local, never told to the VTC.**
  - The vetter sets a personal limit in their vetting policy, beside the existing local gate
    (`vetting-process.md` §8.4, §11.2). The client refuses to reserve beyond it.
  - The client **still fetches the full drip**. Fetching less would publish the preference, and
    a preference that changes over time is an activity signal.
  - Unused tokens expire.
- **Higher, e.g. a vetter at an event willing to do 20 a day: "event mode", approved and
  pooled.**
  - **The request.** The vetter requests event mode for a named event and a time window. The
    manifest publishes a small menu of event tiers (e.g. 20 a day, bursting to 40), so vetters
    pick from a menu rather than naming their own number.
  - **Approval by someone other than the vetter.** An admin or moderator approves, via policy
    (`vetter_rate.rego`). Raising your own cap is exactly what a coerced vetter would do, so the
    vetter cannot approve their own request.
  - **A separate event token key per event.** It is valid from the event's start until its end
    plus a short grace (e.g. 14 days), so that applicants met at the event can submit.
  - **Why the separate key: it bounds stockpiling.** Under the monthly key, 3 days at 20 a day
    would leave up to 60 tokens usable for up to 60 days after the event. The event key makes
    them die shortly after the event.
  - **What it costs.** A spend under the event key shows it came from *some* vetter in that
    event's group. The anonymity set for those spends becomes the event group, not the whole
    vetter pool.
  - **Group floor.** Event mode is therefore granted only to a group of at least `m` vetters
    (e.g. `m = 3`) for the same event and window. The VTC refuses a single-vetter event.
  - **The VTC knows who holds event mode**, because it approved it. That reveals capacity, not
    activity: a vetter at the Kernel Maintainer Summit doing sessions at a desk is public
    anyway.

**Rules:**
- **Separate token keys, never `hvk`.** A PS signature on `(s, φ)` under `hvk` *is* a PCS
  credential whose "`usk`" the vetter knows. The AllowList would refuse it, but the whole
  construction must not rest on that one check. Each token key has its own deployment label
  (`…#vetting-token/{month}`, `…#vetting-token/event/{eventId}`) and its own `φ_token`.
- **One spent set per token key.** It is dropped when the key leaves the acceptance window, and
  it stores serials only: no applicant id, no tag.
- **Record a spend only when the submit is accepted for evaluation.** A resubmission after
  `requestMore` re-presents the same `(id, T_j, s_i)`. A spent serial arriving with the same
  `(id, T_j)` is treated as already counted, not as a double spend.
- **Issue sequentially.** PCS is plain Fiat–Shamir, and one-more unforgeability of blind issuance
  is argued for sequential sessions. The external review must cover the token path.

**Residual risk: tokens can be transferred between colluding vetters.** A token is not bound to
the vetter's `usk`, so vetter B can give tokens to vetter A. The cap then holds per colluding
group (together they never exceed the sum of their drips), not strictly per vetter. The strict
version certifies `(usk_j, s_i)` in the token and adds one clause to `R_att` proving that the
token's `usk` equals the credential's `usk`. The PCS sigma layer supports exactly this kind of
shared witness, but the relation change is a library extension (§11, research asks).

**Cost.**
- One blind issuance per token, in the milliseconds range (see `benches/cred.rs`).
- At submit, one PS verification per attestation, about 2.4 ms each.
- About 200 B more on the wire per attestation.
- Drip fetches are tiny: a kernel-sized community of 50 vetters makes one request per vetter
  every 3 days.

### 5.2 When a vetter runs out

"Out" means every live token has been handed out or reserved. Because the drip keeps arriving,
the next token is at most one tick away (3 days in the kernel example).

- **Reserve on accept, not on attest (§5.1 step 3).** A vetter with no free token cannot accept a
  request, so no applicant sits through a video session only to find the vetter can't attest.
- **Decline individually with `atCapacity`.** The decline carries the date of the next free token.
  It is a new code for `vetting/decline/0.1`. Declines go only to the applicant and never to the
  VTC (`vetting-process.md` §9.5).
- **Never toggle the directory listing.** Switching "accepting applicants" off is visible to the
  community, and is the busy-vetter signal hidden mode exists to remove. The listing stays as
  it is, and requests are declined one by one.
- **The applicant's client explains it.** For example: "This vetter can take new applicants
  from 1 Nov. Ask another vetter, or wait." The attestations Bob already holds are unaffected.
- **Attesting without a token is impossible in the client.** If it happened, the VTC would record
  `no-token`, and Bob would get `requestMore`.
- **Planned busy periods use event mode (§5.1).** An emergency top-up for one vetter is an admin
  exception that the vetter opts into and that is logged. It reveals "this vetter ran out", and
  the vetter is told so before agreeing.
- **There is no leak-free top-up.** An anonymous "prove I'm a vetter, give me more" can be
  repeated without limit, which defeats the cap.
- **No reissue after a lost device.** The VTC never saw the serials and cannot cancel lost
  tokens, so reissuing would double that vetter's cap for the window. The drip refills the
  bucket anyway.
- **Oversight works on aggregates only.** The VTC cannot see that one vetter runs dry every
  month; in the named design that would be a warning sign of coercion. A community-wide spend
  rate close to total issuance is still a useful alarm.

## 6. Leaks outside the proof: these decide whether hiding is real

| Leak | Why it matters | Mitigation |
|---|---|---|
| **Mediator metadata** | If the community operator also runs the mediator, it sees the applicant's DID talk to the vetter's DID. That reveals exactly what the proof hides | Vetters take hidden-mode sessions on a **non-member, pairwise DID**; the applicant uses a pairwise session DID; recommend a mediator not run by the VTC operator. The `eligibilityVp` still shows the member role to the applicant only |
| **Anonymity set** | With 3 vetters and k = 2, "hidden" means little | The manifest publishes a bucketed live-vetter count; the client warns below a floor (e.g. `2k`); depth bands shrink the set further |
| **Timing** | Exact `validFrom` values, and a submit minutes after a session | Day granularity in `ctx_j`; the client may delay the submit |
| **Grant-revocation checks** (D28) | The applicant fetching the vetter's status entry | The whole bitstring is fetched, so the index does not leak; the IP address and timing do. Minor |
| **Statement metadata** | Rare method/claim combinations single out a vetter | Communities keep method and claim vocabularies small |
| **Token fetches and top-ups** | A fetch made because a batch ran low says "busy" | Scheduled, unconditional drip; no top-ups except the opted-in exception (§5.1, §5.2) |
| **Directory "accepting" toggles** | Switching off right before a join is a per-vetter signal, which matters most in communities with few joiners | Decline with `atCapacity` instead; hidden mode never changes the listing (§5.2) |
| **VTA-hosted tickets (V1)** | V1 moves ticket issuance into the vetter's VTA. If the community operator hosts that VTA, it sees when each vetter issues a ticket: an activity log beside the VTC | Hidden mode keeps tickets client-local, or requires a VTA not run by the VTC operator |
| **Event tokens** | A spend under an event key shows the vetter was in that event's group | A group floor of `m` vetters per event; event keys expire soon after the event (§5.1) |

## 7. Relation to the earlier design (`persona-to-membership-design.md` §4)

That document recommended (a) **pairwise inequality over committed issuer keys, plus set
membership against the registry**, with bbs-2023 vetting VCs, and (b) **issuer nullifiers** only
"if a threshold gets large".

PCS is a finished construction of **(b)**:
- the tag is the nullifier;
- the vetter's NIZK at attestation time is the correctness proof §4.3 called for;
- membership is proven by possession of a **VTC-issued blind credential**, instead of a ZK
  set-membership proof against a registry accumulator. That accumulator does not exist anywhere
  in the stack.

So the recommendation should flip to (b) via PCS. The issuer-side change that ADR-001's X3 asks
us to name is: **vetters must hold a PCS root credential and run `attest`.**

The bbs-2023 path in VTI is no help here. It exists only on the OID4VP `vp_token` path, is
compiled out by default, and carries no vetting facts (`routes/join_requests/present.rs:108`).

## 8. Wire and spec changes

| Carrier | Change |
|---|---|
| `vtc/join-requests/manifest/0.2` → `vetting.anonymity` | `{mode: "hidden", suite: "ps-ddh-bls12381", epoch, hvk, prevEpoch?, label, vetterCountBucket}`. The schema is already open (`additionalProperties: true`), so it can be prototyped without a version bump. Clients accept `pp` only through `PCS::from_public_parameters` |
| Vetter root credential | Root request/answer pair on the grant and resend paths: `vtc/vetting/vetters/pcs-root/0.1` |
| Vetter → applicant | New peer task `vetting/attestation/0.1` (`{attestation, statement metadata}`), and `…/refresh/0.1` for epoch rotation. It is not a W3C VC: `DTGCredential.proof` has a closed cryptosuite enum and will not parse it |
| Join submit | Prototype in `extensions.pcs` (an open object, capped at 16 KiB; k = 5 is about 2.5 KB in base58). The spec says producers MUST NOT use `extensions` to route around the VP's selective disclosure, so specify a first-class `vettingProof` member in `submit/0.3` before shipping |
| Withdrawal | `vtc/vetting/revoke-statement/0.2` gains a `{id, tag, tagProof}` form |
| Token drip (§5.1) | `vtc/vetting/vetters/tokens/0.1`, vetter → VTC: `{tick, commitments[r], openingProofs[r]}` → `{keyId, blindSignatures[r]}`. The manifest's `vetting.anonymity` gains `tokenKeys` (current and previous month, plus live event keys), `dripRate`, `tickLength` and `eventTiers` |
| Event mode (§5.1) | `vtc/vetting/vetters/event-mode/0.1`, vetter → VTC: `{eventId, tier, window}` → approved or refused, including when the group floor is not met |
| Token spend | `vetting/attestation/0.1` gains `{serial, keyId, token}`; the submit's `vettingProof` carries them per attestation |
| Decline | `vetting/decline/0.1` gains the code `atCapacity`, with `availableFrom` |

All of these fall inside OpenVTC's inbound filter (`trusttasks.org/spec/vetting/*` and
`/spec/vtc/*`, `openvtc-core/src/didcomm.rs:1458`). Each still needs an arm in
`vetting::inbound::handle`.

## 9. Code placement

- **`vta-sdk`, a `vetting-pcs` feature: shared PCS code.** This follows the existing pattern:
  `verify_statement` and `requirements::evaluate` are already shared by client and VTC. The PCS
  proposal put this code in `openvtc-core`, but the VTC must verify too, so shared code is the
  better home. Contents:
  - the scheme type alias;
  - the context builders of §4.1;
  - the `id`↔`joinDid` binding;
  - `verify_hidden_vetting(...) -> Vec<StatementFacts>`.
- **`vtc-service`: the VTC side.** Contents:
  - an epoch key store and rotation job;
  - root issuance in `vetting/vetters.rs`;
  - a facts builder beside `vetting_facts()` in `vetting/mod.rs`, called from
    `join/orchestrate.rs:324`;
  - tag-keyed withdrawals in `vetting/revocation.rs`;
  - monthly and event token keys, drip issuance, a spent set per key, and event-mode approval
    through `vetter_rate.rego` with the group floor (§5.1). The spent sets live in their own
    keyspace and hold serials only.
- **`openvtc-core::vetting`: the applicant and vetter sides.**
  - Applicant: per-application `usk`, `id` and attestations, in `ProtectedConfig.vetting` or the
    `SecuredConfig` / keyring for `usk`.
  - Vetter: the root credential, the per-epoch `usk`, the token bucket (a scheduled drip
    fetch, reservations on accept), the local personal rate limit, and an attestation log for
    refresh.
  - Proving runs under `spawn_blocking`, as Argon2id does.
- **Dependency:** OpenVTC's `deny.toml` forbids git dependencies. The crate must reach crates.io
  (the name was free on 2026-09-19); this is Erkan Tairi's call. Vendoring would put MIT code
  into an Apache-2.0 workspace.

## 10. Sequence

```text
Bob (applicant)          Vetter_j (pairwise DID)              VTC
  manifest ───────────────────────────────────────────────▶ (vetting.anonymity: epoch, hvk, bucket)
  user_keygen → (id, usk)          [vetter: holds root cred for epoch e]
  request/session/card/match code ─▶ human check
                    ◀── attestation(id, ctx_j = metadata) + metadata
  … repeat until k
  prove(id, usk, atts, ctx_0 = challenge ‖ joinDid-binding)
  submit {vp(no VECs), vettingProof} ─────────────────────▶ verify_proof (AllowList{vetter}, epoch e|e-1)
                                                           → VettingFacts{issuer = T_j …}
                                                           → join.rego (unchanged) → VMC
```

## 11. Order of work

1. **Decide (governance and product):**
   - hidden mode as a per-community opt-in;
   - explicit acceptance of §5;
   - the anonymity-set floor;
   - who publishes the crate.
2. **Library (with Berkeley):**
   - caller context on `ctx_j` / `ctx_0` (§4.1);
   - CI on Linux and Windows;
   - a crates.io release;
   - an external review before any production community enables the mode.
3. **`vta-sdk` `vetting-pcs`:** a fixture test with two vetters, one ineligible class label, and a
   duplicate vetter that must be refused. Add token tests that cover:
   - a double spend;
   - a token under an expired key;
   - a token moved to another attestation (it must fail through `ctx_j`);
   - a `requestMore` resubmission (it must not count as a double spend);
   - an event token after its grace period;
   - a monthly token signed under an event key.
4. **Specs:**
   - `manifest.vetting.anonymity`;
   - the `pcs-root`, `attestation` and `refresh` tasks;
   - `submit/0.3 vettingProof`;
   - `revoke-statement/0.2`.
5. **vtc-service:**
   - epoch keys, token keys with drip issuance and the spent sets, and event mode;
   - root issuance on grant;
   - the facts builder;
   - tag withdrawal;
   - `join.rego` tests against the hidden-mode fact fixtures.
6. **openvtc:** the applicant and vetter paths; E2E on MockVtc with the V0 test matrix
   (`vetting-process.md` §14.3) re-run in hidden mode.

**Open research asks for Berkeley:**
- accountable anonymity, i.e. a quorum-openable vetter id, for cascade review;
- binding tokens to the vetter's `usk` (one shared-witness clause in `R_att`), which makes the
  §5.1 cap strictly per vetter;
- a proof that PS blind issuance of `r` tokens per request is secure (one-more unforgeability)
  when they are signed sequentially within one message;
- per-relationship `id`s;
- straight-line extractable proofs, so concurrent issuance is sound.

## 12. Open review items

**Correctness of the design:**
1. **Never mix named and hidden vetting within one criterion.** A vetter could give Bob both a
   VEC and a PCS attestation. The VTC cannot tell they come from the same person, so that vetter
   would count twice. A criterion is either `mode: named` or `mode: hidden`.
2. **PCS self-exclusion gives no protection here.** It compares keys, and the applicant's `usk`
   is fresh for every application. A vetter who applies under a second persona can attest for
   themselves. This is no worse than V0, where the VTC cannot tell that two DIDs are one human.
   The defences are `k ≥ 2` and the token cap. Do not cite self-exclusion as a protection.
3. **Epoch length limits how old a statement can be.** Hidden attestations die at epoch end plus
   grace, and tokens die when their key leaves `W`. The effective age limit is the smallest of
   `maxStatementAge`, epoch + grace, and `W`. Choose epoch ≥ `maxStatementAge`, or state the
   smaller limit in the manifest.
4. **Withdrawal after admission.** The admission record must keep `id` and the counted tags.
   Then a withdrawal by tag (§4.4) after admission still triggers `on_statement_revoked`, which
   re-checks that the admission-time threshold is still met. Cascade review is lost;
   single-statement review is not.

**Spec conformance (`dtgwg-vti-spec`):**
5. **VTI-CMP-070/071.** Actor distinctness MUST NOT be upgraded into evidence independence. PCS
   proves that the vetters are distinct, not that they are independent. `independence_ok` keeps
   coming from declared relationships, and the spec text should say so in those terms.
6. **VTI-MEM-012.** The VTC must record the evidence relied on, "sufficient for the decision to
   be reviewed afterwards". Recording the proof, its public inputs and the tags lets a reviewer
   re-check that policy was satisfied, but not which vetters were chosen. Ask the WG to confirm
   that this meets the requirement before a community enables hidden mode.

**Long-term privacy:**
7. **Anonymity is computational (DDH over BLS12-381), so it is not safe against a quantum
   attacker who collects records today.**
   - With discrete logs, an attacker can recover a vetter's `usk` from their tags and link that
     vetter's attestations.
   - They can *name* the vetter only through the root-request `id` (`= g_1^usk`), which the VTC
     saw at issuance.
   - Mitigation: the VTC keeps no root-request `id`s or `T_0`s after issuance, and keeps proofs
     and tags only as long as MEM-012 needs them. A future attacker then gets linkability, not
     names.
   - Say this in the governance text, next to the stack's post-quantum signature work.

**Governance and people:**
8. **Liability (`vetting-process.md` O4).** Anonymous vetters mean that an attestation later
   found to be fraudulent cannot be traced to anyone. The LF or community governance must accept
   this, and the attestation text should say so.
9. **Moderators.** A hidden-mode referral shows metadata per tag, and no names. The moderator
   runbook needs a hidden-mode section.
10. **The benefit to vetters.** Anonymity protects a vetter from coercion and retaliation, because
    nobody can name who admitted whom. This belongs in the governance case, not only the costs
    in §5.

**Planning:**
11. **Prototype first.** Build a throwaway branch with a mock VTC, two vetters, one applicant and
    the application context stubbed. It shows whether the facts mapping, `requestMore` and the
    token spend rules hold before four specs are written. The PCS author already ran a similar
    smoke test inside OpenVTC.
12. **Ownership of library changes.** The application context, the token binding and the
    crates.io release all live in Erkan Tairi's repo. Agree whether we send PRs upstream or
    Berkeley implements them; everything else waits on it.
13. **Reconcile the documents.**
    - `vetting-process.md` §14.2 points V2 at the `OpenVTC/probablistic-sampling-for-connection-vcs`
      PoC. It has not been reviewed; check it for anything worth keeping.
    - `persona-to-membership-design.md` §4.3 still recommends option (a).
    - Both need a pointer to this document.
14. **Custody of VTC keys.** A leaked `hsk` or token key lets an attacker forge vetters or tokens
    without limit. Keep them in the same custody as the VTC's other signing keys (`vti-secrets` /
    TEE), and write an emergency-rotation runbook.
15. **Rate parameters are community policy.** Needed: the kernel instance's `r`, tick length, event
    tiers and the group floor `m`, alongside the O11 numbers (`minStatements` and the others).

## 13. Second-pass review: corrections that supersede earlier sections

**C1 — Put epochs in the class label, not the helper key (supersedes §3 "deployment label",
§4.3, and the per-month token keys of §5.1).** A proof is verified under ONE `hvk`
(`verify_proof(&hvk, …)`), and every `ctx_j` includes that `hvk`. Attestations made under
`hvk_{e-1}` and `hvk_e` therefore cannot be combined in one proof, and "accept the current and
the previous epoch" only holds per proof. Worse, a label of the form `…/{epoch}` changes `pp`,
hence `c_0`, hence Bob's `id`, so attestations from two epochs are not even about the same
identifier. The fix:
- The deployment label is `"{communityDid}#vetting-pcs"` with no epoch, and `pp` is fixed for
  the life of the community.
- `hvk` is long-lived and rotates only on compromise (emergency rotation stays as in §4.3).
- The vetter root predicate carries the epoch in its label: `f_root = root("vetter/2026-09")`.
  Rotation issues every live vetter a root credential under the new label; the AllowList holds
  the live labels (current and previous, `pp.allow_list([&f_cur, &f_prev])`).
- Removal = not re-issuing the new label, plus dropping the old label early when it must take
  effect at once; honest attestations under the dropped label are refreshed as in §4.3.
- What this reveals: an attestation discloses `φ`, so the VTC sees which epoch label the vetter's
  credential carried. Every live vetter is re-issued at rotation, so this only says when the
  attestation was made, at epoch granularity, which `validFrom` already shows.
- Tokens the same way: ONE token key `(tvk, tsk)` ≠ `hvk`, with the month in `φ_token`
  (`token/2026-09`) and event mode as `token/event/{eventId}`. The spent set is per label.

**C2 — The vetter's `usk` and `id` are stable across re-issuance.** With C1, `id = g_1^usk` is
fixed, and every re-issued root credential is on the same `usk`. This matters: a refreshed
attestation must produce the SAME tag `T_j`, or Bob could present the old and the refreshed
attestation from one vetter as two. The VTC binds `member_id → id` at first root issuance and
refuses a root request for that member with any other `id`, which is also how "one root
credential per member record" (§3) is enforced.

**C3 — Serialise every blind signing per key.** §3 said the concurrency hazard "drops to the
root path"; token issuance is blind signing too. Concurrent sessions under one key are the
hazard, across vetters as well as within one. One lock per signing key (`hsk`, `tsk`); the
volumes involved make this free.

**C4 — Verify-only predicates may have any threshold.** `verify_proof` accepts EXACTLY
`k = f.threshold` attestations and `f` is in `ctx_0`. The VTC never calls `issue` under an
applicant predicate, so the threshold-1 warning of `operating-a-helper.md` does not apply here:
serve `("hidden-vetting", n)` for `1 ≤ n ≤ maxStatements` and count tags. (If a community ever
wants PCS credentials for admitted members, that changes, and only then.)

**C5 — The client verifies what it receives.** Bob's client runs `verify_att` and the token check
(signature under `tvk`, live label) on every attestation before storing it, so `no-token` and
`unverified` are discovered at the session, not at submit. A vetter's client never reuses a
serial; if the VTC ever sees one serial with two `(id, T_j)` pairs it records the collision as
an anomaly (it cannot name the vetter) and the second spend fails.

**C6 — Withdrawals go from a fresh sender.** §4.4's "anonymous channel" means a fresh `did:key`
(or anoncrypt), never the vetter's member DID or its pairwise session DID: over the mediator the
sender is otherwise visible to the VTC.

**Effect on §8.** `vetting.anonymity` becomes `{mode, suite, label, hvk, tvk, liveVetterLabels[],
liveTokenLabels[], eventTiers, dripRate, tickLength, vetterCountBucket}`. `pcs-root/0.1` and
`tokens/0.1` name the label they want, and the VTC decides whether it is live.

**C7 — The VTA is the PCS engine (supersedes §3 "never held by the VTA" and §9's placement of
`usk`).** Every PCS operation on the member side runs inside the VTA, as Trust Tasks:
`vta/pcs/root-request`, `vta/pcs/attest`, `vta/pcs/prove`, `vta/pcs/verify-attestation`,
`vta/pcs/tokens/fetch`, `vta/pcs/withdraw`. `usk` (vetter and applicant) is a new VTA key kind
(a BLS12-381 scalar) in the VTA's key store, alongside the persona keys. openvtc is the UI and
the message carrier only, and never sees `usk`.
- **Why.** This is the stack's direction (VTA-authoritative state; persona keys already live
  there). D19 wants the attest gate inside the VTA, and `attest` is the most consequential
  signature a member makes: step-up via the mobile authorizer belongs on it. The token drip needs
  an always-on agent (§5.1 "missed ticks"), which the VTA is and openvtc is not. And openvtc
  need not carry arkworks at all.
- **What it costs, stated plainly.** The VTA can compute every tag of its user, so vetter
  anonymity holds against the VTC, other members, applicants and the mediator, and NOT against
  the vetter's own VTA. That is the same trust the member already places in the VTA for their
  persona keys and relationship graph.
- **Deployment rule.** Hidden mode requires that the vetter's VTA is not operated by the VTC
  operator (or a party colluding with it), the same rule §6 already sets for the mediator. The
  manifest states it; the client warns when it can tell they coincide.
- **Terminology.** PCS calls the issuer, our VTC, the *helper*. Do not call the VTA a helper
  anywhere; call it the PCS engine.
- **Effect on §9.** `openvtc-core::vetting` keeps only the application state and the UI;
  `vta-service` gains the PCS engine module and the key kind; `vta-sdk` keeps the shared
  contexts and facts builder. The fallback, `usk` local to openvtc, remains possible for a
  member who runs no trusted VTA, at the cost of no step-up gate.

## 14. Build status (2026-09-22)

Local only: nothing is pushed, published or merged.

- **Library change: application contexts (§4.1).** In `~/devel/predicate-credential-system`,
  branch `feat/application-context`, commit `0b5a058`. It adds the new inherent entry points
  `attest_in_context`, `check_attestation_in_context`, `prove_in_context`,
  `check_proof_in_context` and `issue_in_context`, plus `*_context_with_app` builders.
  - With no context, the contexts are byte-identical to the paper's. The trait of the ten
    algorithms is unchanged.
  - `ctx_0` also binds each attestation's context.
  - Tests: 432 pass (426 plus 6 new, for PS, BBS and EQ). fmt, clippy and rustdoc are clean
    with `-D warnings`.
- **Prototype.** In `~/devel/pcs-vetting-prototype`, commit `cb4e21e`. It covers:
  - the VTC as helper, with label epochs, member→id binding, the token drip with per-label spent
    sets, event mode with its group floor, and tag withdrawal;
  - vetter and applicant engines standing in for the VTA.
  - Tests: 14 end-to-end tests, counted by `vta-sdk 0.48`'s own `requirements::evaluate`,
    unchanged.
  - Mutation-checked: disabling each of five VTC defences (the double-spend check, the member→id
    binding, the token signature check, single-use challenges and the event group floor) fails
    the test that covers it.
- **Findings from building:**
  - Tokens need no library change. The proof of opening is one G1 equation, built with the
    public `sigma` API. `UserSecretKey::expose_scalar` makes the tag proof for withdrawal
    possible as is.
  - An attestation carries its class `φ`, so the helper's AllowList is the whole
    eligibility-at-submit check. A dropped period fails the *whole* proof (`PolicyRejected`). The
    applicant's engine must therefore filter out stale attestations before proving, which is what
    the prototype does.
  - **Open semantics.** The VTC keeps statements per applicant `id` and re-counts on every
    submit. A later submit re-presents a statement whose token label has since closed. It then
    overwrites the earlier "counted" record with `no-token`. For admission this is harmless,
    because the decision is taken at the first satisfied submit. It needs a rule before
    re-evaluation after admission (§12 item 4) is built.
- **Not covered:**
  - transport and Trust Task messages;
  - DIDs (the `id ↔ joinDid` binding is a digest stand-in for the Data Integrity proof);
  - VTA custody;
  - persistence;
  - concurrency (the locks are there, but the prototype is single-threaded);
  - a JCS encoding of the metadata.

## 15. Testing it (branch `zkp-pcs`)

The flow runs end to end today, in tests. Nothing is wired to a TUI screen yet, so this is how
to exercise it.

**The onboarding flow, client side** — manifest with published parameters, two vetting
sessions, the proof, the submission, the community's decision:

```sh
cd ~/devel/openvtc-worktrees/zkp-pcs
cargo test -p openvtc-core --test hidden_vetting_onboarding -- --nocapture
```

Two tests. The first drives `vetting::hidden` directly; the second drives `Application`, the
type the join flow holds, and asserts the proof lands in `join_extensions()` beside the
requirements digest, inside the VTC's 16 KiB cap.

**The adversarial cases** — double-spent token, tokens and metadata moved between
attestations, a forged withdrawal, a twin key pair for one member, replayed opening proofs,
epoch rotation, event mode:

```sh
cargo test -p openvtc-vetting-pcs --release
```

**Criticality** — a community that marks a namespace this build does not implement stops the
application instead of quietly applying the named way:

```sh
cargo test -p openvtc-core --lib vetting::hidden
cargo test -p openvtc-core --lib vetting::tests::a_critical_namespace
```

**The VTC half** (VTI branch `zkp-pcs`), including the cross-repo fixture — the VTC's own
verifier reading a submission this client produced:

```sh
cd ~/devel/vti-worktrees/zkp-pcs
cargo test -p vti-vetting-pcs --release
cargo test -p vtc-service --features vetting-pcs --lib vetting::
```

### What a real run still needs

Two of the four are now built — see §17. What is left:

- **The vetter's screen.** `vetting::hidden::attest` is the whole vetter half, but no TUI action
  calls it: the attest action still signs a named statement. The applicant's PCS identifier also
  has to reach the vetter through the session for the vetter to attest it.
- **The transport.** Enrolment, the drip and the challenge are service functions with durable
  state; nothing carries them over the wire yet. Each is one Trust Task
  (`vtc/vetting/vetters/pcs-root/0.1`, `.../pcs-tokens/0.1`, `vtc/vetting/pcs-challenge/0.1`)
  over the shapes in `issuer.rs`, which is deliberately where they already live.
- **A trust-tasks-rs release** carrying manifest 0.2's `ext`, after which the client reads the
  typed member instead of parsing the raw criterion.


## 16. Admission credentials: what a hidden admission issues (2026-09-23)

Checked against `vtc-service`'s own issuance paths, because a proof that gets Bob past the
criterion is only half an admission — the other half is the membership credential he walks away
with, and the question is whether hiding the vetters costs him any of it.

It does not, and the reason is structural: the hidden path rejoins the named one at
`vetting::vetting_facts`. `join::orchestrate` calls it, gets the same `VettingFacts` shape with a
tag where each vetter's DID would be, and everything downstream — `requirements::evaluate`,
`join.rego`, `EffectPlan::Admit`, `ceremony::execute::issue_member_credentials` — is untouched.
So a live hidden admission already mints the VMC against a revocation slot, the role VEC at the
granted role, and solicits the member's reciprocal VMC, exactly as a named one does. Nothing in
the hidden branch had to be taught about credentials.

The reference example (`openvtc-core/examples/zkp_reference_flow.rs`) now mints the same three
in-process, and asserts each proof verifies, that the reciprocal's subject is the community, and
that its `digestMultibase` matches a digest of the grant **as it arrived** — the wire-form rule
`DTGCredential::new_member_vmc` exists to enforce. It also asserts no vetter DID appears in any
of the three.

Deliberately **not** issued on this path, and each for its own reason:

| credential | why not |
| --- | --- |
| Vetting statement VEC (`IdentityVettingEndorsement`) | it names its issuer. This is the whole point: the endorsement is still built — it is where the attested facts come from — but never signed and never sent. `presentable_statements()` returns 0. |
| VRC pair | not part of admission on any path; VRCs are the peer relationship layer, and D8 does not require one for V0 membership. Worth stating plainly: a community that required a VRC pair **with its vetters** could not run hidden vetting at all, because a VRC names both ends. |
| VIC | invitation-gated admission only. |
| Personhood (VPC / `personhood: true`) | a separate evaluation; `admit` mints the VMC with `personhood = false`. |
| VWC | withdraws a *named* statement. Hidden withdrawal is the token spend-set and class-label rotation (§4.4). |

The status-list credential itself is referenced by the VMC's `credentialStatus` and served by a
running `vtc-service`; the in-process example has no HTTP host, so it points at an example URL
and says so.


## 17. The challenge and the minting half (2026-09-23)

Two of the three gaps §15 listed are closed. Both were the same shape of gap: a rule that
existed on the client but had no half in the community that enforced it.

### 17.1 The challenge is the community's

`vtc-service/src/vetting/pcs_challenge.rs`, modelled on `credentials::present_challenge` because
it is the same problem: `issue` mints 16 random bytes for an applicant DID and stores them with a
15-minute TTL; `consume` removes the row **before** checking expiry, then compares. `pcs::decide`
consumes it as step 0, before it reads the spent-token rows, so a replay costs nothing.

What this buys, precisely: a proof verifies as often as it is submitted, so without a freshness
anchor the second submission of the same bytes counts. Now the second one finds no challenge.
A proof bound to a challenge the applicant minted for itself never had a row at all. The
reference run demonstrates both — `step08_decision.replayRefused` and
`unissuedChallengeRefused` — and `vetting::pcs`'s own test drives the *service* path with the
cross-repo fixture: no challenge → refused, recorded challenge → counted, replayed → refused.

The cost is deliberate: a supplement after `requestMore` needs a *new* challenge and a new
proof, because a challenge that survives its first use is not a freshness anchor.

Rows share the `join_requests` keyspace under a prefix of their own and are swept by the same
retention pass, so an applicant who asks and walks away leaves nothing behind.

### 17.2 The community mints

`vti-vetting-pcs/src/issuer.rs` holds the keys and signs; `vtc-service/src/vetting/pcs_issue.rs`
holds the rules and the records. The split is the point: **an in-memory set is not a rule, it is
a rule until the process exits**, and every question about whether to sign is a question about
the community's own records.

- **The keys are derived, not stored.** HKDF-SHA256 from the same master secret the credential
  signer uses, with `vtc-vetting-pcs-secret/v1`, then ChaCha20 seeded from
  `SHA-256(info ‖ len(community) ‖ community ‖ secret)` — the community is in the seed, so two
  communities under one master secret cannot share a helper key. Nothing new to provision or
  back up. The consequence is stated where it lives: **the master secret is the vetter class**,
  so `pcs_issue::issuer` refuses to mint if the derived `hvk` is not the published one.
  `pcs_issue::publish` is where a deployment's published parameters come from, so an operator
  never types a key in.
- **Enrolment** is once per member per class label, with the PCS identifier bound at the first
  one — a member who came back with a second identifier would hold two class credentials and
  count twice in one proof (§13 C2). Across a rotation the same member re-enrols under the new
  label with the *same* identifier, which the test pins.
- **The grant check is the community's own**, not a list of the minting half's: `vetter_eligible`
  — membership row, not removed, joined before the grant, live role endorsement — the same
  function the named path calls.
- **The drip is capped by the issuer.** This closed a real hole: `TokenIssuer::issue` checked the
  label, the tick and every opening proof, and never checked *how many* requests were in the
  batch. A vetter could ask for a thousand tokens in one tick and be served. The quota is now a
  parameter of `Issuer::issue_tokens`, enforced before anything is signed, and published as
  `dripPerTick` so a vetter knows what to ask for. Event labels carry their own, higher rate
  (`DEFAULT_EVENT_DRIP_PER_TICK = 20`), which is the reason event labels exist (§5.1).
- **Once per tick is a row**, keyed `(member, label, tick)`, length-framed. The issuer's own
  in-memory `served` set stays as a second guard within a process.

Both exchanges have wire shapes in `issuer.rs` (`RootRequestWire` / `RootCredentialWire`,
`TokenBatchRequestWire` / `TokenBatchWire`) and the vetter half is split to match
(`VetterEngine::enrolment_request` / `accept_enrolment`, `drip_request` / `accept_drip`), so
adding the Trust Tasks is plumbing rather than design.

### 17.3 Why issuance randomness is an argument

`Issuer::issue_root` and `issue_tokens` take an RNG rather than reaching for `OsRng`. A service
passes `OsRng`; the fixture test passes a seeded one, and that is what keeps the cross-repo wire
fixture reproducible. A signing routine that samples its own randomness cannot be pinned by a
test, and the drift protection between the two repos is exactly a pinned fixture.
## 18. Quantum posture, and what is kept (2026-09-23)

Σ-PS, the Fiat–Shamir proofs and the DDH tag all rest on discrete log in a bilinear group, so a
cryptographically relevant quantum computer breaks all three. That much is unsurprising. What is
worth writing down is the asymmetry, because it decides what to protect.

**Two harms, with different clocks.**

- *Forgery* — credentials and tokens become mintable and proofs become unsound. The exposure
  begins when a CRQC exists, and migrating fixes it: re-enrol under a new suite, drop the old
  class label from the AllowList, done.
- *Retroactive deanonymisation* — a tag is `T = usk·H₀(id)`. One discrete log recovers `usk`;
  the community's own enrolment table maps that key to a member DID; every archived tag that
  vetter produced then links up. The exposure begins **today**, because the material is already
  recorded. Migrating does not reach it.

**What survives a quantum adversary.** The Σ-protocol proofs are statistically zero-knowledge —
a transcript is simulatable, so it leaks nothing to any adversary, quantum or not. Blind
issuance hides the identifier behind a perfectly-hiding commitment, so enrolment transcripts do
not retro-leak either. The unlinkability of a *showing* rests on group assumptions and should be
assumed exposed until someone checks the PS variant we vendored. The part that certainly leaks
is the tag, which means the protection worth building is retention, not more proof machinery.

### 18.1 What the code now keeps

Two changes, both about keeping less:

- **Tags are masked before they are stored.** `vetting::pcs::mask` is
  `HKDF(key, salt = applicant DID, info = tag)` under a key derived from the community's master
  secret (`vtc-vetting-pcs-tagmask/v1`). Every path that used to keep the group element — the
  `VettingFacts.statements[].issuer` rows and the spent-token ledger's `(id, tag)` pair — keeps
  the mask instead. Equality is all either needed: distinctness within a submission, and "same
  applicant, same vetter" for a resubmission, both survive it.
- **A decided proof is not kept.** `vetting::redact_hidden_submission` replaces the
  `hiddenVetting` member of the stored join request with `{ redacted, suite, bytes, sha256 }`.
  The facts row is what every reader downstream actually uses; the submission was being kept for
  nobody. It runs whether or not this build implements the suite, which is why the member name
  is spelled in `vetting/mod.rs` and pinned against the crate's constant by a test.

**What the mask is not.** A community that keeps both the masking key and the applicant DID can
recompute it, so this raises the cost of a future deanonymisation rather than removing it. The
stronger variant — storing a per-submission ordinal (`hidden-vetter-1`) instead of a pseudonym —
loses nothing functional and is available if a community wants it; it is not the default only
because a stable pseudonym is worth something for audit. The other half of the join is the
**enrolment table**, which exists to enforce one credential per member per label; its retention
window is a privacy decision, not bookkeeping. Spent serials can stay — they are random scalars
and link to nobody.

### 18.2 If the suite has to change

The wire was built for it, which is the one piece of good luck here. The criterion publishes
`suite`, both halves check it, and `extCritical` makes a client that cannot honour a suite refuse
rather than guess. So a post-quantum suite is *additive*: dual-publish during an overlap, vetters
enrol in both, applicants prove in whichever they implement, retire the old label. The facts
shape, `requirements::evaluate`, `join.rego`, the spent-serial ledger, the enrolment and drip
rules and the Trust Tasks are all suite-independent.

The likely shape of such a suite is Merkle commitments plus nullifiers plus a hash-based proof —
`C = H(usk ‖ label)` in a tree whose root is the class label, `T = H(usk ‖ id)` as the tag, the
same token trick, one proof over the lot. It removes the pairing and the blind signature
entirely. The open question is size: we are at a 952-byte proof inside a 4 KB submission against
a **16 KiB `extensions` cap**, and a hash-based proof of this statement plausibly does not fit —
so the cap, which is a number we published, is the first thing a prototype puts pressure on.

A cheaper lever, available now and needing no new cryptography: **per-period vetter keys**. Today
a vetter keeps one key for life and re-binds the same identifier at every rotation, because two
class labels overlap and a member with two identifiers could count twice in one proof. A
community that gives up the overlap can give its vetters a fresh key each period, which bounds
any future deanonymisation to one period instead of a career — at the cost of proofs that can no
longer span a rotation.

## 19. The vetter's half, and the four tasks (2026-09-23)

### 19.1 The tasks exist now

`vetting/attestation/0.1`, `vtc/vetting/vetters/pcs-root/0.1`,
`vtc/vetting/vetters/pcs-tokens/0.1` and `vtc/vetting/pcs-challenge/0.1` are written, validated
and generated for all four languages on branch `hidden-vetting-tasks` of
`dtgwg-trust-tasks-tf`. The schemas carry the shapes this branch already speaks, so nothing on
either side had to be reshaped to fit them.

One decision worth keeping: `vetting/attestation` declares `identifierScope: any`. Nothing in it
needs a reusable identifier — the community never sees the document, and the applicant only needs
the identifier the session was held under — so a pair running the whole vetting exchange under
pairwise identifiers loses nothing. It also states, as a conformance requirement, that a consumer
MUST NOT record the delivering `issuer` beside the attestation: doing so rebuilds, in the
applicant's own store, exactly the link the exchange removes.

**The bindings are not consumable yet.** `trust-tasks-rs` generates them as 0.22.0, and published
crates in both workspaces (`affinidi-messaging-sdk`, `affinidi-tdk`) pin `^0.21`, so a
`[patch.crates-io]` cannot apply: two incompatible `trust-tasks-rs` nodes do not unify. Until the
release lands, `wire::hidden_attestation` builds the payload directly under the published type
URI. Swapping to the generated types is a mechanical follow-up, not a redesign.

### 19.2 The vetter attests through the desk

`VettingBook::attest_hidden` is the whole vetter half, and it deliberately reuses
`statement_draft` to build what it will *not* sign: one checklist, one set of refusals, one place
where "the card has no such claim" or "a documentary method with nothing to rely on" is decided.
Only the last step differs.

- The applicant's PCS identifier reaches the vetter in the **request's `ext`**
  (`hidden::request_ext`), which is the framework's own extension point. A community that does
  not run hidden vetting sees a `vetting/request` it already understands.
- The engine lives on the book as `HiddenVetterState`, one per community and persona, carrying
  the published parameters beside the snapshot — because a parsed `VettingRequirements` has
  dropped `ext` by then, and the parameters are in `ext`.
- The desk closes the request into `Attested` exactly as the named path does, and adds nothing to
  `issued`: there is no statement to withdraw, and hidden withdrawal is the token spend-set and
  label rotation (§4.4).
- The TUI's attest action branches on whether this persona holds an engine for the community. The
  operator-facing words differ where the situation differs: sending succeeds with "the community
  will count it without learning it was you", and a failed send says the token it spent is gone.

The reference example now drives this path rather than calling the engine directly, so the run
that produces the vector set is the run the screen makes.

### 19.3 The wire, closed

All three exchanges now run end to end.

**The community serves them.** `vetting::pcs_tasks` binds the three published URIs into the same
dispatcher every other task goes through, with each refusal carrying its declared code.
`tests/hidden_vetting_tasks.rs` drives them as an agent would — signed documents posted to
`/v1/trust-tasks` — and checks what a client actually needs: the pre-credential *unblinds*, the
served tokens *verify* under the published key, the challenge is 16 bytes of lowercase hex as the
schema says. Then the refusals that make each one a rule: a stranger enrolling, a second
enrolment under one label, a second draw for one tick, a batch over the published rate.

**The client asks for them.** Enrolment and the drip are split into request and accept on both
sides. The enrolment blinding is held in memory for one round trip and deliberately not
persisted — it is useless without the answer and dangerous to keep past it — so an answer that
arrives after a restart is dropped and the client asks again.

**The schedule reads the clock, never the wallet.** `hidden::due` decides what a vetter owes a
community from the labels and the time, and is not given a balance to consult: a client that drew
when it ran low would publish, in the timing of its own requests, how much vetting it had done. A
vetter back after a week asks for the current tick and not the seven it missed — the same answer
an idle vetter gets, which is the property worth having. Four tests hold it.

**The screens say what is happening.** The applicant's requirements line ends "their names never
reach this community"; its checklist counts held attestations rather than reporting zero while it
holds three (its own estimate — two attestations from one vetter carry one tag, and the tag is
inside the proof); and it binds the community's challenge rather than one it minted, saying so
while it waits. The admin panel renders a tag as a tag instead of passing it to a DID renderer,
with a note that the count came from a proof.

### 19.4 Event mode, over the wire

`vtc/vetting/vetters/event-mode/0.1` is authored and served, and §5.1's design survives the
transit intact — which was the point of writing it as a task rather than a setting.

**The task carries the request and nothing else.** A vetter asks; the answer says `pending` or
`approved`, and `pending` is an answer rather than a refusal. There is deliberately no task for
the *approval*: a task the vetter could send is a task a vetter could be made to send, so
approving an event is an act by an admin through the criterion that publishes it — `POST
/v1/schemas/accepts`, which is admin-authenticated and already carries these parameters verbatim.
The specification says so in its Authorization section, which is where a future implementer will
look for permission to add the convenience.

That is a narrowing of §5.1, which said an admin **or moderator** approves via `vetter_rate.rego`.
The policy hook is not built; what is built is the admin route. The rule §5.1 was protecting — the
vetter cannot be the approver — is not in the route either, because a route is the wrong place for
it: an approver's DID in a configuration file is a claim, and the check belongs where the tokens
are. `pcs_event::gate` refuses an event whose `approvedBy` holds a request row of its own, so a
self-approval opens nothing however it was written and whoever wrote it.

**Four conditions, checked where tokens are served.** `vetting::pcs_event::gate` stands between
an event being configured and its label being drawn under: an approver has named themselves and
is not one of the group; the group is at least the floor; the day is inside the window and its
grace; and this member asked. They are checked at the drip rather than at approval because
approval is a configuration edit, and a configuration edit is what a coerced approver would be
asked for. A refusal carries `pcs-tokens:eventRefused` rather than `notAVetter` — the vetter
holds the grant, and sending them to chase one would be the wrong answer to the right complaint.

**A count, never a roster.** The response says how many vetters have asked and how many the
community needs. Who they are is the anonymity set the event's smaller label is bought with, so
the number is the most a member is told — enough to tell "nobody has approved it" from "not
enough people have asked", which are the two reasons a request waits and have different answers.

**The client draws under both labels.** `hidden::due` now keys its tick per label, because a
vetter at a conference owes two draws a day: the event's, and the ordinary monthly one. Dropping
the monthly draw for the three days of a summit would say, in the timing of the requests alone,
that those three days were a summit. The schedule reads only the events the community has
approved us for — a published label says an event exists, never that we are in it — and stops
asking once the label closes.

**The screen offers a menu, not a number.** `e` on the desk lists each (event, tier) the
community publishes, with the event's own days as the window, and says the price before it is
asked for: an attestation made there says *someone vetting at this event* rather than *someone in
this community*. The window is the event's rather than the vetter's, because a vetter naming
their own days would say which days of a conference they expect to be at the desk.

The menu reaches the client the same way the rest of these parameters do — out of band, §8 —
where `HiddenParams.events` takes the community's `events` verbatim. `approvedBy` is not part of
the offer type, so it is dropped on the way in rather than shown to a vetter who has no use for
it.

### 19.5 Still open

- **The `trust-tasks-rs` release.** Both halves hand-write the payload types and validate them
  against the published schemas; the release deletes both copies. That is a queue, not a design
  question: the specifications are in `trustoverip/dtgwg-trust-tasks-tf` PR #618.

## 20. The protocol on its own

`openvtc-vetting-pcs/examples/hidden_vetting.rs` runs the whole thing with no ceremony around it:

```sh
cargo run --release -p openvtc-vetting-pcs --example hidden_vetting
```

Ten members enrol, three of them vet one applicant, he proves it once, the community counts it —
and the example then prints what the community holds afterwards (ten enrolled identifiers, three
tags, overlap zero) and submits the same proof a second time to show the challenge is what stops
it. Every step says what it gives up, so the privacy argument can be read in one file rather than
assembled from five.

It is deliberately separable from everything else in this document. The ticket, the session, the
Vetting Card, the Trust Tasks, the membership credential — none of it changes what happens in the
example, which is why the example is the thing to hand someone who asks how this works.
