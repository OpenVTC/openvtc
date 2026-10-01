# SPEC — VTA-Authoritative State and Reinstall Recovery

> Status: **DRAFT v6** — for review. Decisions D1–D22; D17–D22 agreed in review.
> External asks E1–E4; **E2 is the substantial one** and is specified in §6.
> Scope: the `openvtc` CLI and `openvtc-core` config model, plus three asks on
> `verifiable-trust-infrastructure` — **E2 is blocking**, E1 and E3 are not.
> Sealed bootstrap turns out to be **already implemented** in `pnm-cli` (§4).
>
> **Changed in v2:** the admin credential is reframed as an authorisation grant
> rather than an identity (§3); recovery becomes a branch in the existing setup
> flow rather than a separate command (§5); "start fresh" no longer means
> "destroy" (D11); and a latent coupling that currently prevents the whole model
> from working is called out (§7, D12).
>
> **Changed in v6:** E1 is reframed as **DTTE** — reprovision becomes a
> consent-requiring Trust Task rather than new authentication machinery, which
> collapses it to a policy registration (and improves D20, since the approver's
> decision is itself signed). New D23: nominate a recovery approver *before* you
> need one. E2 gains three layers — atomic records, batch transport,
> and out-of-band blobs — plus JSON merge-patch, so latency comes down without
> giving up per-record versioning (E2c–E2g).
>
> **Changed in v5:** the external asks. **E2 is now a store design, not a field**
> — agent memory is the wrong home for application metadata, because clearing an
> agent's memory must not delete your account. **E3 is sharper**: protect the
> established connection rather than the newcomer, and the redelivery carve-out
> turns out to be unnecessary. **E1 is deferred** (convenience, not capability)
> and **E4 becomes a pluggable audit sink** rather than a tamper-evidence
> mandate.
>
> **Changed in v4:** recovery safety (§10) — revoking the authorisation you just
> replaced (D17), verifying the rebuilt model instead of trusting it (D18),
> forward-compatible records (D19), and making recovery auditable *and provable*
> (D20). D2a is **withdrawn**: contacts and the agent-name cache sync after all
> (D22), which was a correction, not a refinement.
>
> **Changed in v3:** concurrency (§9). Two instances against one context is not
> a future risk — the messaging layer breaks on it **today**, by mutual
> eviction. E2 is promoted from a minor ask to **blocking**, because
> `MemoryItem` carries no version at all and there is nothing to build a
> precondition on. New decisions D13–D16 and a new external ask E3.

---

## 1. Objective

Make the VTA the keeper of keys, identities, and credentials, and reduce
OpenVTC's local state to a cache it can rebuild.

> My laptop died. I install OpenVTC on a new machine, point it at my VTA and my
> Trust Context, and it tells me the context already has content and offers to
> recover it. I did not have to have kept a backup file.

### Non-goals

- Automatic *merge* of concurrent edits. §9 detects and surfaces conflicts;
  it never resolves them for you (D14, R2).
- Changing the VTA's trust posture — D1 argues this moves no boundary.
- **D21 — recovering a lost VTA.** Out of scope. This spec protects against a
  lost *OpenVTC instance*, not a lost agent. The encrypted export
  (Settings → Export Config) remains the answer to a VTA that is gone, and the
  docs must keep saying so rather than letting "recovery" imply it covers both.

---

## 2. Where authority sits today

From `openvtc-core/src/config/{loading,keys,secured_config,protected_config}.rs`
against `vta-sdk` 0.25.1.

| State | Authoritative today | Target |
|---|---|---|
| Persona **private keys** | **VTA** — `KeySourceMaterial::VtaManaged` → `get_key_secret`, every startup | unchanged |
| Persona DIDs + documents | **VTA** — `list_dids_webvh`, `get_did_webvh_log`; local copy is a perf cache | unchanged |
| VICs (invitations) | **VTA** — credential vault | unchanged |
| Account model — persona list, labels, mediator refs | OpenVTC only | **→ VTA** |
| Community memberships — status, sub-context, VMC, request ids | OpenVTC only | **→ VTA** |
| Relationships (relationship DIDs, `did:peer`) | OpenVTC only | **→ VTA** |
| VRCs issued / received | OpenVTC only | **→ VTA credential vault** |
| Contacts (DID + your alias) | OpenVTC only | **→ VTA** (D22) |
| Agent-name cache | OpenVTC only | **→ VTA** as a *stale* hint (D22) |
| Tasks, activity log, UI preferences | OpenVTC only | stays local (D9) |
| Admin credential bundle | OpenVTC keyring only | re-issuable (§3, §4) |

**Half the target is already the reality.** The rows marked *→ VTA* are a
migration, not a new architecture.

---

## 3. D1 — What the admin credential actually is

**The admin credential is an authorisation grant, not an identity.**

It is a `did:key` whose subject holds an ACL entry against a context. The VTA
owns that ACL. The credential can be rotated (`spec/acl/swap-key/0.1` —
self-service rotation onto a new subject DID, proven by a `link_proof` VP-JWT)
and re-issued (§4). Losing it is losing an authorisation, not an identity — the
same shape as losing an SSH key that is listed in `authorized_keys`.

Your *identity* is the persona `did:webvh`s, and those live at the VTA along
with their private keys.

This is the load-bearing reframing. Everything else follows:

- **Recovery is re-authorisation**, not key recovery (§4).
- **The VTA may read the account model** (D2) — it already holds keys that can
  sign as you, so withholding your membership list protects nothing it could not
  obtain by acting as you.
- **Nothing durable may be derived from the admin credential** — because it is
  designed to change. This is currently violated; see §7.

### D2 — The VTA may read this state

Store the account model as documents the VTA can read. Encrypting to a key only
the client holds is the one alternative that changes the trust position, and it
defeats the objective: recovery would then need a secret the user kept.

What this means, to be said plainly in the docs rather than buried:

- The VTA can see your community memberships and relationship graph.
- A VTA operator, or a VTA database leak, exposes that graph.

**D2a is withdrawn** (v4). It excluded contacts and the agent-name cache on the
grounds that they had "no recovery value". That was wrong about contacts — a
`Contact` is `{did, alias}`, and the alias is user-authored data that exists
nowhere else and cannot be re-derived — and it contradicted D2 itself, which
already uploads the *relationship graph*. A relationship is strictly more
revealing than a contact. Excluding one while including the other was an
inconsistency, not a privacy position. See D22.

---

## 4. Re-authorisation — already built

**Correction to v1**, which claimed sealed bootstrap was unimplemented. It is
implemented, in `pnm-cli`. The `sealed-bootstrap.md` status header is stale.

The working flow today:

| Step | Who | Command |
|---|---|---|
| 1 | New install | `pnm bootstrap request --out req.json` — generates an ephemeral X25519 keypair, secret stays local at mode 0600; the file carries only a public key, a fresh nonce, and a label |
| 2 | Operator | `pnm context reprovision --id <context> --recipient req.json` — mints an admin key for the **existing** context and seals the credential to that public key |
| 3 | New install | `pnm bootstrap open --bundle <file> --expect-digest <hex>` — single-use; no silent TOFU |

`vta_sdk::sealed_transfer` carries it: HPKE/RFC 9180, DHKEM-X25519 +
HKDF-SHA256 + ChaCha20-Poly1305, ASCII armor with chunk headers bound as AEAD
AAD. `SealedPayloadV1::AdminCredential` already exists.

Crucially, `reprovision` targets an **existing context and leaves its content
alone**. The new admin credential is a new ACL entry against the same context.
That is exactly "just reconnect and away you go".

### D3 — OpenVTC performs the recipient side natively

Rather than making users drive `pnm` for step 1 and 3, OpenVTC does them itself:
generate the ephemeral key, display/export the request, accept the armored
bundle, verify the digest, open it, store the credential. Step 2 stays with
whoever administers the VTA — see D4.

### E1 (external, VTI) — reprovision as a DTTE-consentable task

v5 proposed a bespoke "passkey- or device-authenticated reprovision". Review
pointed out the right shape: this is just **DTTE** — Delegated Trust-Task
Execution — which already exists.

The machinery is built. Approvals are *"one rule list keyed on **Trust Task type
URI**"* in the reserved `approvals` policy row; `requires: consent` routes
through the PDP to the consent ceremony —
`task-consent/request/0.1` (outbound push, VTA-signed),
`task-consent/decision/0.1` (**DI-signed by the approver**),
`task-consent/granted/0.1` (notice). And provisioning is already a dispatched
Trust Task: `TASK_PROVISION_INTEGRATION_0_2`.

So E1 collapses from *new authentication machinery* to **register the
provisioning task URI as consent-requiring, with a recovery approver set**.
Everything else is existing behaviour.

Three properties make it a better fit than what v5 proposed:

- **Approver-set membership alone authorizes a decision — an ACL entry is not
  required** (VTI #907). A recovery approver does not need to be an admin of the
  context, which is exactly right: the phone approving your laptop's recovery
  should not itself hold admin rights.
- **Consent binds to the payload digest, not a session.** The approver approves
  *this* reprovision — this context, this recipient public key — rather than
  elevating anything. Delegated step-up was deliberately deleted in favour of
  this, and for recovery it is the difference between "approve one act" and
  "grant a capability".
- **The approver only ever sees a challenge-salted `wire_digest`**, never the
  internal `payload_digest` that keys storage.

**E1a — it improves D20 as a side effect.** `task-consent/decision/0.1` is signed
by the approver, so an approved recovery produces a *second* independently
verifiable artifact alongside the sealed bundle's producer assertion: proof that
a human approved, and which one. Better evidence than an audit row.

**E1b — caveats.** Approvals are inert unless `policy.enforcement = true`, which
defaults to false, so this is opt-in per deployment. The `pnm approvals` surface
is **Trust-Task transport only** — the SDK's REST arm is unimplemented and a REST
client gets a 404. Fine for OpenVTC, which speaks DIDComm, but it means a
REST-only VTA cannot configure this today.

### D23 — Nominate a recovery approver *before* you need one

The whole scheme is worthless if it is set up after the laptop is gone. An
approver set established at recovery time is not a recovery mechanism; it is a
formality.

OpenVTC therefore treats it as a first-class setup concern: after a successful
setup, prompt to nominate a recovery approver — another device, a colleague, a
phone — and surface the current approver set in Settings alongside D17's
revocation view. The two belong together: *who can let a new device in* and
*which devices are currently in* are the same question asked in two directions.

**D23a — say what it does and does not cover.** A nominated approver can
authorise a new install against your context. They cannot read your data, and
they do not hold your keys. Users will assume one or both unless told.

**D4 — until then, an operator step is correct, not a workaround.** Anything
that lets an unauthenticated caller re-issue an admin credential for a context
means anyone who knows your context id can become you. The out-of-band step is
the security boundary. Docs must say so rather than implying recovery is
unconditional.

---

## 5. D5 — Recovery is a branch in setup, not a command

There is no `openvtc recover` command, because there does not need to be. Setup
already asks for the VTA DID and a context id, and already authenticates. The
moment it holds a `VtaClient`, it can see whether that context has content.

**Flow:**

1. Operator supplies VTA DID + context id (unchanged).
2. Authorise — existing provisioning, or §4's sealed bootstrap.
3. **Probe the context** — `list_dids_webvh`, the appstate listing, `cred_vault_query`.
4. If it is empty → continue as today. Nothing changes for a genuine first run.
5. If it has content → present what was found and offer three choices (D11).

**D6 — the probe is read-only and cheap**, three list calls against a context we
have just authenticated to. It runs on every setup, not behind a flag, because a
user who needs it is by definition not expecting it.

**D7 — the summary is concrete.** "This Trust Context already contains 3
personas, 2 community memberships and 14 credentials, last updated 3 days ago" —
not "existing content found". The user is deciding whether this is *their*
account; they need enough to tell.

---

## 6. D8 — Rebuild, storage, and offline

### Rebuild

| Step | Call | Rebuilds |
|---|---|---|
| 1 | `list_contexts()` | `top_context_id` |
| 2 | `get_context(id)` | context DID, sub-contexts |
| 3 | `list_dids_webvh(context)` | persona DIDs |
| 4 | `get_did_webvh(did)` | documents; mediator via existing `did::mediator_from_document` |
| 5 | `list_keys(.., context)` | `key_info` as `VtaManaged { key_id }` |
| 6 | `appstate.list(context, "openvtc")` | the account model — needs E2 |
| 7 | `cred_vault_query({})` | VICs, VMCs, VRCs |

Only step 6 needs new work; the rest exist.

### Storage — agent memory, one key per record

Three candidate stores; one fits:

- **Secrets vault** (`vault_upsert_typed`) — a password manager
  (`secret_kind: password|passkey|oauth-tokens`, required site-oriented
  `targets`). **Rejected**: our records are not site credentials, and it would
  pollute a user-facing vault UI.
- **Credential vault** (`cred_vault_*`) — **adopted for VICs/VMCs/VRCs**, where
  VICs already live.
- **Agent memory** (`vta/memory/{put,list,delete}/0.1`) — per-context key/value
  for AI-agent recall. **Rejected for application state**: clearing an agent's
  memory must not delete your account, `list` has no prefix or pagination, and
  there is no version to build a precondition on. See E2.
- **A new application-state store** (`spec/vta/appstate/*` — E2) — versioned,
  namespaced, prefix-listable. **Adopted for the account model**, and blocking.

**D8a — one key per record, never one account-model blob.** Batching (E2c) and
attached blobs (E2e) do not change this: the record remains the unit that carries
a version and a conflict. Keys:

```
namespace = "openvtc"

v1/account
v1/persona/{persona_id}
v1/membership/{vtc_hash}/{persona_id}
v1/relationship/{r_did_hash}
v1/contact/{did_hash}
v1/agent-name/{did_hash}
```

1. **Payload size** — a blob grows without bound, and this project has already
   lost a join to a bridge file-size limit silently dropping an oversized
   submit (PR #137).
2. **Blast radius** — last-write-wins on a blob loses unrelated records.
3. **Partial rebuild** — an unparseable record is skipped and reported through
   the `LoadIntegrity` machinery already merged.

**D8b** — every record carries `schema_version` and `updated_at`.

### E2 (external, VTI) — an application-state store · **blocking**

v4 asked for `expectedVersion` on `vta/memory/put`. Review pushed back on the
premise: is agent memory the right home at all? It is not.

**Why not `vta/memory`.** Its stated purpose is *"a per-context key/value store
for AI-agent memory"* — free-form recall for an agent. Three concrete problems
with overloading it:

1. **"Forget everything" would delete your account.** Clearing an agent's memory
   is a reasonable, expected user action. It must not take your community
   memberships with it. That alone settles the question.
2. **`list` returns the entire context.** No prefix, no pagination. An agent
   with a large memory makes every application read expensive, and the two grow
   independently.
3. **No versioning, and nothing to add it to.** `MemoryItem` is `{key, value}`.

So: **a third store, with three jobs cleanly separated** —
secrets in the vault, verifiable credentials in the credential vault,
application metadata here.

#### Proposed: `spec/vta/appstate/{get,put,list,delete}/1.0`

Addressed by `(contextId, namespace, key)`. The **namespace** scopes an
application — `openvtc`, `cnm`, a future agent runtime — so several tools share
a context without colliding, and it gives a natural seam for per-namespace ACLs
later.

| Property | Behaviour | Why |
|---|---|---|
| `version` | Server-assigned, monotonic per record. Returned by `get`, `list` and `put`. | The thing v4 asked for, and the thing that does not exist today. |
| `expectedVersion` on `put` | Optional precondition. On mismatch, a typed conflict that **carries the current version and value**. | Returning the loser's view with the rejection saves a round trip and removes the re-read race. |
| `expectedVersion: 0` | "Create only — fail if it exists." | Makes lease acquisition (D15) safe. Without it two instances can both believe they won. |
| `list` with `prefix` + pagination | Scoped enumeration. | `v1/membership/` without dragging every record. |
| `list` with `sinceVersion` | Incremental: only records changed since a watermark. | This is what makes write-behind reconcile cheap instead of a full pull each connect. |
| **Tombstones on delete** | A delete leaves a versioned tombstone, reaped after a retention window. | Without it, incremental sync **cannot converge** — a peer pulling `sinceVersion` never learns a record was deleted, and silently keeps it forever. |
| Documented size limit | A stated per-record cap, and an explicit error on exceeding it. | This project has already lost a join to a size limit that dropped a write silently. |
| Not for secrets | Stated in the protocol docs. | Three stores, three jobs; the boundary has to be written down or it will erode. |

#### Three layers, kept distinct

Batching and blobs do not weaken D8a — they sit either side of it. The record
stays the unit of *correctness*; batching is a unit of *transport*; blobs are a
different class of data entirely.

| Layer | Unit | Versioned | In `list` |
|---|---|---|---|
| **Record** | one small JSON document, one key | Yes — individually | Yes |
| **Batch** | N records in one round trip | Per record, unchanged | n/a |
| **Blob** | one large opaque payload attached to a key | With its record | **No** — reference only |

**E2c — batch get and put.** `get_many(keys[])` and `put_many(writes[])`, each
write carrying its own `expectedVersion`, and the response carrying a per-record
result. This is the latency answer: a rebuild or a write-behind flush becomes one
round trip instead of N, without giving up per-record versioning.

`put_many` takes an explicit **mode**, because the two callers want opposite
things:

- `independent` (**default**) — each write is applied or rejected on its own
  merits. One conflicted record does not block the other nine. This is what a
  write-behind flush of unrelated edits wants, and it preserves exactly the
  blast-radius property D8a was written for.
- `atomic` — all preconditions must hold or nothing is written. Needed when
  records carry a joint invariant: minting a persona *and* the membership that
  references it should not half-land, which is the same two-writes-one-truth
  problem that produced `LoadIntegrity` locally.

Defaulting to `independent` is deliberate. An atomic default would mean a single
stale record silently blocking an entire flush, and the user would see "sync is
stuck" with no indication which record is at fault.

**E2d — `list` returns values, optionally.** `includeValues` on `list` so a
prefix scan is one call rather than a scan plus N gets. Off for a browse, on for
a rebuild. This is the single biggest latency win on the recovery path.

**E2e — blobs travel out of band.** A record may carry an attached blob,
addressed by the same key and versioned with its record, but **never returned by
`list`** — only a `blobRef` with its size and digest. Fetching is explicit.

The transport pattern already exists in this codebase: `backup_export_via_descriptor`
returns a descriptor with a `transport_url` and token, and the bytes move through
`download_blob` / `upload_blob` outside the trust-task envelope, with a
wire-level digest check independent of any inner MAC. Reusing it keeps large
payloads away from the message-size limit that has already silently dropped a
write in this project.

**Caveat worth stating up front:** that descriptor path is documented as
REST-only — *"the descriptor pattern doesn't have a DIDComm path"*. OpenVTC runs
over DIDComm by default, so blobs need either a DIDComm descriptor story or an
explicit statement that they are REST-only. Not a blocker for the account model,
which has no blobs; it matters the moment something large is stored.

**E2f — JSON-aware, schema-agnostic.** Values are JSON by contract, and the
store may act on that structure without understanding *what* the structure
means:

- **Merge-patch on put** (RFC 7386). Sending a patch rather than a whole record
  cuts payload, and — more valuably — cuts *conflicts*: two instances editing
  different fields of one record no longer collide at all.
- **Field projection on list.** Return only named paths, so a browse does not
  drag every field of every record.

**E2a — the store understands JSON, not your schema.** Refined from v5's "the
value stays opaque". `schemaVersion` and the D19 flatten-through are still the
application's business, and the store never migrates, validates, or interprets a
record's meaning. It only manipulates generic JSON structure on request.

**E2b — `vta/memory` is left exactly as it is.** This is additive. Agent memory
keeps its semantics, including being safe to clear.

**E2g — change notification is a later addition, not part of this.** Polling on
reconnect is adequate for the write-behind model, and `device/set-wake` already
provides the hook (`WakeHandle`) if push becomes worthwhile. Noted so the store's
shape does not preclude it.

**Until this lands, the account model does not move.** Along with D12, it is one
of two blockers on the whole spec.

### D8c — Cache and write-behind

Local config becomes a full read cache plus a persisted pending-write queue.
Reads never block on the network. Writes apply locally first (preserving today's
coalesced save), then enqueue. Reconcile on connect: push, then pull and
compare. Conflicts are never auto-merged — they surface through the same
acknowledge-and-continue path as `LoadIntegrity`. Pending state is visible;
silent divergence is what makes people distrust sync.

**D8d** — this is not a general-purpose sync engine. It handles the
single-active-device case correctly and reports the multi-device case honestly.

### D9 — What stays local

Tasks, activity log, UI preferences, working-community selection. Genuinely
per-installation state with nothing to recover. Contacts and the agent-name
cache were here in v1–v3 and moved out under D22.

---

## 7. D12 — Break the credential ⇄ local-encryption coupling

**This currently blocks everything above, and it is a code change in this repo.**

`ProtectedConfig::get_seed_from_credential` derives the local config's
encryption key as:

```
HKDF-SHA256(admin_credential_private_key, "openvtc-protected-config-seed-v1")
```

So the admin credential is simultaneously:

- an **authorisation grant**, designed to rotate and be re-issued (D1), and
- a **data-at-rest encryption key**, which must never change.

Those are irreconcilable. Two concrete consequences:

- Rotating the admin key via `acl/swap-key` — which vta-sdk supports and
  performs — makes the existing `public.private` blob **undecryptable**.
- A recovered install necessarily holds a *different* admin key, so it can never
  decrypt a pre-existing local config. Recovery and local state are mutually
  exclusive.

Not a live bug today: OpenVTC uses `AdminRotated` only at provision time, before
any `ProtectedConfig` exists, and never rotates at runtime. It is a latent
blocker that must clear before the rest of this spec is buildable.

**Fix:** give `ProtectedConfig` its own randomly-generated 32-byte key, stored in
`SecuredConfig` beside the credential bundle — the same keyring entry, already
protected by the same passphrase or token. The admin credential then becomes
purely an authorisation grant, freely rotatable and re-issuable.

**Migration:** on load, try the stored key; fall back to the credential-derived
seed; on fallback success, generate a fresh key and re-encrypt on next save.
Exactly the shape of the legacy-seed migration already in `load_step2`.

---

## 8. D10, D11 — The setup branch, and what "fresh" means

**D10 — recover is the default.** The highlighted choice, because a user who
reaches this screen with content in their context is overwhelmingly a returning
user, not someone who typed the wrong context id.

**D11 — "start fresh" means a different context, not a destroyed one.**

The three choices:

| Choice | Effect | Guard |
|---|---|---|
| **Recover** (default) | Rebuild from this context (§6). Local state untouched at the VTA. | Confirmation showing the D7 summary. |
| **Use a different context** | Create/choose another context id and set up normally. The existing context is left completely alone. | None needed — non-destructive. |
| **Delete and start over** | Destroy the context's DIDs, keys and credentials, then set up fresh. | `preview_delete_context` first, showing exactly what dies; then typed confirmation. Never the default, never one keypress. |

The middle option is the important one. "Start fresh" in most tools means
"destroy what is there", and here that would mean irreversibly destroying
persona DIDs and their keys because someone re-ran setup. Making it mean *use a
different context* removes the destructive path from the common flow entirely
and leaves deletion as a deliberate, separate act.

**D11a** — deletion is never implicit in setup, even with a typed confirmation,
if the context contains personas that are members of a community. Leave the
community first, so the VTC learns about it.

---

## 9. Concurrency — two instances, one context

### 9.1 What guards this today

| Case | Guard | Status |
|---|---|---|
| Same machine, same `OPENVTC_CONFIG_PATH`, same profile | `process_lock.rs` — PID lock file, atomic `create_new` | Covered |
| Same machine, **different** `OPENVTC_CONFIG_PATH`, same profile name | none — the lock path is derived from the config dir, so two config dirs get two lock files | Gap |
| Same machine, different profile names sharing one persona DID | none | Gap |
| Two machines, same context | none | Gap |
| Messaging | mediator ceiling of **one websocket per DID** | **Actively harmful** |
| Shared application state | no store exists yet — see E2 | Gap |

### 9.2 The messaging layer is already broken

This is not a future risk. From the SDK's own docs: *"The mediator's real ceiling
is **one websocket per DID**."* It does not refuse a second connection — it
**evicts the first**. Two OpenVTC instances presenting the same persona DID
therefore each connect, each evicts the other, and both reconnect-loop
indefinitely.

That is the listener-flapping class already debugged in this project (openvtc
#231, and the upstream `force_refresh` fix in affinidi-tdk-rs). Eviction is the
worst available behaviour: it does not prevent the conflict, it makes both
parties permanently unstable, and it presents as a network fault rather than as
"you have this open twice".

**Anyone who opens OpenVTC twice against one persona hits this now**, with no
part of this spec implemented.

### 9.3 D13 — Detect and say so, before anything else

The cheapest useful step, and it needs no VTA change: `device_register` at
startup, `device_heartbeat` on the timer, `device_list` to see siblings. All
three are in vta-sdk 0.25.1, and `DeviceBinding` already carries `last_seen_at`.

A `DeviceBinding` is *"the device-facing half of an `AclEntry`"* and the caller
always acts on its own binding — so each install naturally has its own identity
at the VTA, without inventing anything.

Surface it plainly: *"This context is also open on 'glenn-laptop', last seen 30
seconds ago."* It blocks nothing. The point is that the user is not surprised,
and that a support conversation starts from the real cause.

### 9.4 D14 — Optimistic concurrency is the correctness mechanism

**Not a lock.** Every write to agent memory carries `expectedVersion` (E2); a
rejected write is a conflict, surfaced through the same acknowledge-and-continue
path as `LoadIntegrity`, naming both sides. Never auto-merged, never silently
retried with a fresh version — that would be a clobber with extra steps.

This is the layer that *prevents corruption*. Everything else in this section
only reduces how often it is exercised.

### 9.5 D15 — An advisory writer lease, if exclusion is wanted

A single appstate record, `v1/writer-lease`, holding
`{device_id, display_name, expires_at}`, refreshed by the heartbeat already
running under D13. An instance that sees a live lease held by someone else opens
**read-only** and offers "take over".

Three properties, all deliberate:

- **Advisory, not enforced.** The VTA does not police it. A lease that could
  lock you out of your own account when a laptop dies is a worse failure than
  divergence.
- **It expires.** Takeover after expiry needs no human and no support ticket.
- **It is acquired with `expectedVersion`.** Without E2, two instances can both
  believe they won it — a lease with no precondition is theatre.

**D15a — the lease reduces conflict; the precondition prevents corruption.**
Never rely on the lease alone. D14 stands whether or not D15 is built.

### 9.6 D16 — Persona listener ownership

The messaging problem (§9.2) needs an answer regardless of the state layer,
because it bites first.

**Whoever holds the writer lease runs the persona listeners.** Instances without
it do not open persona sockets at all — they read, and they show why messaging
is idle. That converts a mutual-eviction loop into one working instance and one
that says what is going on.

Without D15, the fallback is D13 alone: still connect, but detect the sibling
and warn loudly that both are open and the connection will be unstable. Better
than today, which is silence.

### E3 (external, VTI/mediator) — protect the incumbent

The mediator's one-socket-per-DID ceiling is enforced by **evicting the
established connection in favour of the new one**. That is backwards. The
incumbent is authenticated, live, and possibly mid-exchange; the newcomer has
proved only that it can also authenticate. Preferring the newcomer means any
second process can silently take over a live session — and when both retry, they
take turns doing it forever.

**Requested:** an established, authenticated connection for a DID is **kept**. A
second connection attempt is **refused**, with a reason the client can render
("this DID already has a live connection"), so the newcomer can say so instead
of looping.

v4 hedged this with "displacement as an explicit opt-in", because displacing a
socket is how stored-mail redelivery gets triggered (openvtc #218). Checked, and
the hedge is unnecessary for OpenVTC: it already collects stored mail explicitly
through the standard message-pickup protocol
(`affinidi_messaging_sdk::protocols::message_pickup`, via `Messaging::pickup_stored`).
Redelivery does not need eviction, because there is a pull for it.

**E3a — confirm before removing it.** Other clients may still rely on
displacement for redelivery. The check is "does anything depend on connect-time
displacement", not "assume nothing does" — but if OpenVTC is representative, the
opt-in carve-out is dead weight and the rule can simply be: the incumbent wins.

## 10. Recovery safety and data integrity

Five decisions agreed in review. Four of them exist because moving authority to
the VTA changes what can go wrong, and one because it changes who you have to
trust.

### D17 — Recovery must offer to revoke what it replaced

Recovering onto a new machine mints a **new** admin ACL entry. The old one is
still valid. If the laptop was stolen rather than dead, the thief keeps a
working credential and the account they can reach with it.

After a successful recovery, show the other bindings — `device_list` gives
`display_name` and `last_seen_at` — and ask which to revoke. `delete_acl(did)`
(`acl/revoke/0.1`) removes the entry; `device_disable` / `device_wipe` handle
the device half.

**D17a — offer, do not assume.** Revoking every other binding by default would
break the legitimate two-machine user on their first recovery. The prompt
defaults to revoking nothing and names each binding with when it was last seen,
so "the one I lost on Tuesday" is identifiable.

**D17b — the offer is repeatable.** A user who skips it under pressure must be
able to find it later, in Settings, not only in the minute after recovery.

### D18 — Verify the rebuilt account model, do not trust it

Today the local config is the source of truth, so a hostile VTA cannot invent a
membership. Once the VTA is authoritative it can — and a fabricated membership
is a fabricated claim about who you belong to.

The material to prevent this is already in the record: `CommunityRecord` carries
its VMC under `CredentialKind::Membership`. So on rebuild, **each membership is
verified against its own credential** rather than accepted because the VTA said
so. A record whose VMC is missing, expired, or issued by someone other than the
VTC it claims is not silently dropped and not silently trusted — it is reported
through the `LoadIntegrity` path (already merged) and the user decides.

**D18a — verify on rebuild, not on every load.** The local cache is ours; the
check belongs at the trust boundary the data crosses, which is the rebuild.

**D18b — this is why the credential vault and the appstate store are separate.**
Credentials are signed and independently verifiable; the account model is
metadata *about* them. Keeping metadata in a store the VTA can rewrite is only
safe because the signed artifact backing each record lives elsewhere and is
checked.

### D19 — Records must survive a round trip through an older build

`Account`, `PersonaRecord`, `CommunityRecord` and `ProtectedConfig` carry no
`deny_unknown_fields` and no catch-all, so unknown fields are **silently dropped
on deserialize**. Harmless with a single writer, and the reason it has never
bitten: a newer build only ever reads its own older data.

With two instances on one store at different versions it becomes data loss by
round trip — the older build reads a record, drops the fields it does not know,
and writes it back without them.

**Fix:** a `#[serde(flatten)] extra: serde_json::Map<String, Value>` on every
record that goes to agent memory, so unknown fields are carried through
untouched rather than discarded. The pattern is already used in vta-sdk's own
protocol types for exactly this reason.

**D19a — `schema_version` is a second line, not the first.** Refusing to write a
record whose `schema_version` exceeds what this build understands stops the
worst case, but it also stops the user working. Preserving the fields is what
lets an older build stay useful.

### D20 — Recovery is audited *and* provable

Two different properties, and only one of them is available from the audit log.

**Audited** — the VTA records the reprovision and the ACL grant, readable via
`list_audit_logs`. Surface it: a user should be able to see *"a new device was
authorised on 12 Aug from …"* without leaving OpenVTC. This is the detection
mechanism for a recovery nobody authorised, and it pairs with D17.

**Provable** — the audit log is VTA-asserted. `AuditLogEntry` is
`{id, timestamp, action, actor, resource, outcome, channel, contextId, detail}`
with **no signature and no hash chain**, so it corroborates, it does not prove.
The proof already exists elsewhere: the sealed bundle opened during recovery
carries a `ProducerAssertion` — `AssertionProof::DidSigned(DidSignedAssertion)`,
or an attestation quote for a TEE VTA — which is signed and independently
verifiable.

**D20a — keep the assertion as a recovery receipt.** OpenVTC stores the producer
assertion of every bundle it opens, with the resulting subject DID and the
timestamp. That answers *"prove this device was authorised, and by whom"*
without trusting the VTA's own account of it.

**E4 (external, VTI) — a pluggable audit sink.** Tamper-evidence is deliberately
*not* being solved now. The more useful move is an extension point: an audit
trait the VTA writes through, with the current database sink as one
implementation, so an operator who needs stronger guarantees can add a sink —
an append-only log, a transparency log, a blockchain anchor — without the VTA
committing to any one of them.

That keeps the crypto decision out of the protocol and turns "make the audit
tamper-evident" from a design argument into a deployment choice. D20a already
supplies the property where it matters most: the recovery receipt is signed and
verifiable regardless of what the audit sink does.

### D22 — Restored caches are stale by construction

Contacts and the agent-name cache sync (D2a withdrawn). The alias in a contact
is irreplaceable user data; the name cache is what makes the first launch after
a recovery readable instead of fifty cold round-trips.

But a cache carries "I checked this" semantics, and after a restore that becomes
"something told me it checked this". For agent names that distinction is the
whole phishing surface the project's rule exists to close: *never display an
unverified name*. A hostile VTA could inject `bigbank.com/@support → attacker`
and, because the cache is the display path, it would render as verified.

**Every restored cache entry is marked stale on import.** A remote `checked_at`
is never imported as fresh. The existing TTL and background re-verify machinery
in `agent_name` then does exactly what it already does: re-verify through
`verified_agent_name` before anything is shown. The restored cache is a list of
*DIDs worth resolving*, not a list of answers.

**D22a — the rule generalises.** It applies to anything whose local copy means
"I verified this", including the cached persona `did_document`. Restore for
speed; re-verify before trust.

---

## 11. Migration and work split

No breaking config reset. Steps are independently useful; none is a one-way door.

**Two hard blockers gate everything that touches shared state:** D12 (decouple
the local encryption key) and E2 (a precondition on `memory/put`). Neither is
large; both must land first.

1. **D12** — decouple the ProtectedConfig key. Self-contained, and nothing else
   works until it lands.
2. **D13** — register as a device, heartbeat, and report siblings. Needs no VTA
   change, and is worth shipping on its own: it turns today's silent
   reconnect-loop into a stated cause.
3. **Ship the probe + branch** (§5, D10/D11) — useful before recovery is
   complete, because "this context already has content" is information a user
   always wants.
4. **Ship rebuild** (§6) behind the recover branch. Read-only against the VTA,
   so it does not depend on E2.
5. **E2 lands** → ship the writer. Every mutation to personas, memberships or
   relationships enqueues an appstate write with `expectedVersion`; existing
   profiles back-fill on first connect. **D19 must already be in** — a record
   format that cannot survive an older build is not safe to share.
6. **Ship the recipient side of sealed bootstrap** (D3), the revoke prompt
   (D17) and the audit view (D20) together — recovery should not ship without
   the means to see and undo it.
7. **Optionally D15/D16** — the advisory lease and listener ownership, once
   there is real multi-device usage to justify them.
8. **Only then** consider demoting the local file from source-of-truth to cache.

### Work split

**openvtc**: D12 decoupling · forward-compatible records (D19, do it *before*
anything writes to agent memory) · device registration + heartbeat + sibling
reporting (D13) · setup probe and three-way branch (D5–D7, D10, D11) · rebuild
with per-membership VMC verification (§6, D18) · account model, contacts and
name cache → the appstate store with `expectedVersion` (D14, D22) · VRCs/VMCs →
credential vault · sealed-bootstrap recipient side, retaining the producer
assertion (D3, D20a) · revoke-what-you-replaced prompt (D17) · audit view (D20)
· write-behind queue and conflict surfacing (D8c) · optionally the writer lease
and listener ownership (D15, D16).

**verifiable-trust-infrastructure**:

| Ask | What | Status |
|---|---|---|
| **E2** | A new application-state store — `spec/vta/appstate/*`: versions and `expectedVersion`, prefix + `sinceVersion` listing, tombstones, batch get/put with per-record results, optional values in `list`, out-of-band blobs, and JSON merge-patch. Agent memory is the wrong home. | **Blocking** |
| **E3** | Mediator: keep the established authenticated connection and refuse the newcomer, rather than evicting the incumbent | High — fixes a live bug |
| E1 | Register the provisioning task URI as consent-requiring, so recovery runs through the existing DTTE ceremony with a recovery approver set | Small — the machinery exists |
| E4 | A pluggable audit sink (trait + backends), *not* tamper-evidence in the protocol | When convenient |
| — | Fix the stale *"Design — not yet implemented"* header on `sealed-bootstrap.md` | Trivial |

## 12. Risks

- **R1 — reprovision is account takeover if unguarded.** D4 keeps a human or a
  second factor in the loop. E1 must not weaken this to "knows the context id".
- **R2 — multi-device divergence.** Draft 2 called this "mitigated by
  per-record keys", which was too generous. Per-record keys bound *which*
  records collide; they do nothing about whether a collision is noticed,
  because `MemoryItem` carries nothing that could reveal one. Until E2 lands
  there is no detection at all, which is why the account model must not move
  to a shared store before it. After E2, D14 makes a collision a surfaced
  conflict rather than a silent clobber — and D15/D16 reduce how often it
  happens, without ever being the thing that prevents corruption.
- **R3 — the VTA sees your whole social graph.** Wider in v4: memberships,
  relationships *and* contacts, including the aliases you chose for people.
  Accepted under D2 — the VTA already holds keys that can sign as you — but this
  is a bigger disclosure than v3 described, and it belongs in the user-facing
  docs rather than buried in a decision record.
- **R4 — a VTA outage becomes a sync outage.** Bounded by D8c.
- **R5 — a mis-typed context id shows someone else's summary.** The D7 summary
  must not leak content the caller is not authorised for; the probe is
  ACL-gated, so an unauthorised context returns nothing rather than a teaser.
- **R6 — `internal: true` keys are unrecoverable by design.** vta-sdk documents
  them as excluded from backup and unrecoverable from the mnemonic. OpenVTC sets
  `internal: None` explicitly today, with a comment saying why. If that changes,
  revisit this whole spec.
- **R8 — an advisory lease that is trusted like a real one.** If D15 ships and
  anyone treats it as exclusion rather than advice, a crashed holder locks a
  user out of their own account until expiry. The lease must never be the only
  thing standing between two writers and a corrupt record — that is D14's job
  (D15a).
- **R9 — another client may depend on connect-time displacement.** OpenVTC does
  not: it collects stored mail explicitly through message-pickup. E3a makes
  confirming that across other clients a precondition of the change, rather than
  assuming it.
- **R10 — revocation is destructive and easy to get wrong.** D17 offers to
  remove an ACL entry. Revoking the binding you are *currently using* would lock
  you out immediately; revoking a colleague's shared-context access would be
  worse. The prompt must name what each binding is and never preselect.
- **R11 — D18 could reject legitimate memberships.** A VMC that has expired, or
  a VTC that has rotated its issuing key, would fail verification on a record
  that is genuinely fine. That is why a failed check reports through
  `LoadIntegrity` and asks, rather than dropping the membership.
- **R7 — D12's migration must not lock anyone out.** The fallback path has to
  survive a profile that is mid-migration when it crashes; the existing
  legacy-seed migration is the template.
