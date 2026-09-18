# Consuming vtc-client for VTC interactions (scoping)

Status: **scoping** (not scheduled). Covers the two intertwined backlog items —
"Consume `vtc-client` for VTC interactions and delete the hand-built path" and
"Verify VTC trust-task reply proofs" (see [`follow-ups.md`](./follow-ups.md)).

## 1. What this is, and why it is NOT a drop-in

The backlog framed this as an unblocked consumer change: VTI #1399 shipped
`vtc-client`'s `submit_join_as` (any DID method) and `connect_didcomm` /
`connect_tsp` behind off-by-default features, so the hope was to delete the
hand-built join transport in `openvtc-core/src/join.rs` (submit / status-poll /
self-remove), our half of `tsp.rs`, and the DIDComm-vs-TSP thread-id
reconciliation, keeping `message_dispatch.rs` for inbound.

**It is not a drop-in.** Verified against `vta-sdk 0.42.1` /`vtc-client 0.6.7`
source, two independent walls:

1. **vtc-client's session verbs open their own per-DID socket.**
   `VtcClient::connect_didcomm`/`connect_tsp` → `vta_sdk::client::VtaClient::
   connect_didcomm` → `DIDCommSession::connect(...)`, a fresh mediated session.
   The SDK says it plainly: "each client gets its own profile and its own
   mediator websocket (the mediator's ceiling is one socket per DID)". OpenVTC
   already holds exactly one listener per persona (`didcomm::build_listener_configs`,
   one per identity; and #337 now installs a persona's listener at runtime). A
   second socket for the same persona DID **displaces** OpenVTC's listener, so
   the join reply and all later inbound land on vtc-client's ephemeral session,
   invisible to `message_dispatch`. This is the `stored-mail-never-collected` /
   `listener-socket-leak` failure class.
2. **The REST verbs avoid the socket but regress transport support.**
   `submit_join_as` over HTTPS opens no socket, but the join flow addresses a VTC
   *by DID* over DIDComm/TSP and never discovers a REST base URL
   (`join_flow.rs` resolves the mediator / `peer_tsp_mediator`, and warns when a
   community "advertises no messaging transport"). Many VTCs are DIDComm/TSP-only.
   REST-only submit drops them; REST *alongside* the hand-built path is more code,
   not less.

**Root cause:** an architectural mismatch, not an upstream gap. `vtc-client` is
built for a caller that owns its VTC sessions through `vta-sdk`; OpenVTC owns its
transports through `affinidi-messaging-delivery` (one per identity + durable
outbox, #194). The two are different messaging stacks, and running both for the
same DIDs is the conflict above.

## 2. Consequence: the real deliverable is a messaging-layer migration

To consume vtc-client's session verbs without breaking inbound, OpenVTC's
**entire** persona messaging layer would move onto `vta-sdk` sessions — one
`SessionHub` for the account, one `VtaClient` per persona on it
(`connect_didcomm_on`), so a persona has exactly one socket that BOTH the VTC
verbs and inbound dispatch share. That is a large initiative, not a backlog
cleanup, and it subsumes the "verify reply proofs" item for free (an SDK session
verifies reply proofs — `require_signed_replies: true` by default).

## 3. What is coupled (the migration surface)

- **Outbound VTC verbs** (`openvtc-core/src/join.rs`): `submit_join_request`
  (+ the #339 oversize guard), `poll_join_status`, `send_community_profile_show`
  (#335), and `MEMBER_SELF_REMOVE` — each currently `build_trust_task_document`
  + `pack_and_send` / `tsp::send_trust_task`.
- **The transport** (`openvtc-core/src/didcomm.rs`, `tsp.rs`): `build_listener_configs`
  (one listener per identity), `pack_and_send`, `peer_tsp_mediator`, the
  per-persona/-relationship listeners on `affinidi-messaging-delivery`.
- **Session tracking** (`state_handler/session_manager.rs`, `mod.rs`): the
  session manager, `register_joined_session`, `install_persona_listener` (#337),
  the reconcile tick, the connection indicator.
- **Inbound dispatch** (`state_handler/message_dispatch.rs`): reads OpenVTC's ATM
  listeners today; would read the shared SDK session instead. This is where the
  reply-proof verification lands.
- **The durable outbox** — `affinidi-messaging-delivery`'s guarantee (D1). Any
  replacement must not lose the "sent-but-unacked survives a restart" property.

## 4. Options

- **(A) Do nothing — keep the hand-built path.** Lowest risk. The hand-built
  transport works and is guarded (#339). Cost: the stale-REST comment in
  `join.rs` stays wrong (see §6), and the thread-id reconciliation stays a
  consumer concern.
- **(B) REST for VTCs that advertise it, hand-built otherwise.** Adds a REST
  discovery + `submit_join_as` path *alongside* the existing one. More code,
  narrow benefit (skip a mediator hop for REST-capable VTCs); does not delete
  anything. Not recommended.
- **(C) Full migration to `vta-sdk` sessions (`SessionHub`).** The only path that
  actually deletes the hand-built transport and unlocks library-verified replies
  — but it replaces OpenVTC's messaging foundation. Its own initiative.

**Recommendation:** **(A) for now**, and if the reply-proof integrity of inbound
VTC replies is wanted sooner, do that as a *separate, conflict-free* piece (verify
the inbound reply's DI proof on OpenVTC's own inbound path with the
`affinidi-data-integrity` verifier the VRC path already uses — no transport
change). Pursue (C) only as a scheduled initiative.

## 5. If (C) is scheduled — work breakdown

- **C.0 — decide durable-outbox story.** Does the `SessionHub` model preserve
  `affinidi-messaging-delivery`'s durable outbox (D1), or is a replacement needed?
  Blocking; everything else assumes an answer.
- **C.1 — stand up a `SessionHub` per account**, one `VtaClient` per persona via
  `connect_didcomm_on` / `connect_tsp` (mirror `build_listener_configs`' per-identity
  set, plus per-relationship R-DIDs).
- **C.2 — route inbound off the shared session** into the existing
  `process_inbound_message`, with reply-proof verification on (closes the
  "verify reply proofs" item).
- **C.3 — move the outbound verbs** (join submit/status/self-remove, profile-show,
  relationship/VRC sends) onto the `VtaClient`; delete `join.rs`'s hand-built
  senders, our half of `tsp.rs`, and the thread-id reconciliation. Re-home the
  #339 oversize guard (the SDK submit path needs its own guard, or keep a
  pre-flight check).
- **C.4 — session lifecycle**: reconcile `session_manager`, `register_joined_session`,
  runtime persona install (#337), token-refresh reconnects (see
  `listener-flapping` history) against the hub's lifecycle + `shutdown` contract.
- **C.5 — tests + live validation**: the MockVta transport harness is WIP/blocked
  (`tasks/` + memory), so this needs it unblocked, or a live VTA. Every ignored
  join/relationship/mediator e2e becomes runnable.

## 6. Corrections to carry (true regardless of option)

- `openvtc-core/src/join.rs`'s header says REST is unusable for a `did:webvh`
  persona because "the VTC's REST holder-binding verification accepts `did:key`
  applicants only." That describes the retired per-verb `holder_signature.rs`
  binding; the current document endpoint resolves the proof's `verificationMethod`
  through a DID resolver and has accepted `did:webvh` since the vm-resolver work.
  Fix that comment whenever this area is next touched.

## 7. Dependencies / sequencing

- No new dep: `vtc-client 0.6.7` (features `didcomm`/`tsp`) and `vta-sdk 0.42.1`
  (`SessionHub`, `connect_didcomm_on`) are already resolvable in the tree.
- (C) is gated on C.0 (durable outbox) and on a working transport test harness
  (MockVta, currently blocked) or a live VTA.
- (C) touches the config-adjacent messaging foundation but not the config model,
  bootstrap, or lifecycle reducers already shipped.
