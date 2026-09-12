# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

- **Release builds no longer take their VTA or mediator from the environment.**
  `OPENVTC_VTA_URL`, `OPENVTC_VTA_DID` and `OPENVTC_MEDIATOR_DID` are honoured
  only by a build compiled with the new `dev-overrides` feature
  (`cargo run -p openvtc --features dev-overrides`). Any other build ignores
  them and says so, on stderr before the TUI starts and in the Activity Log.
  This covers the setup wizard's `OPENVTC_VTA_URL` shortcut too.

  In a `dev-overrides` build the values are validated (DIDs must parse, the URL
  must be http(s)). They apply to the running process only, and a red
  `DEV OVERRIDE` badge stays in the bottom bar while they do. Saves and exports
  keep writing the stored VTA URL, VTA DID and persona mediator. Before this
  change, a variable set for one launch was written into the profile by the
  next save and outlived the environment. CI now also runs
  `cargo test -p openvtc --features dev-overrides`.

### Fixed

- **The wipe-profile screen names the context it tells you to delete.** It sent
  the operator to `pnm contexts delete` with no id — on the one screen that is
  about to take the config file and the keyring entry holding that id with it.
  It now prints `pnm contexts delete <this account's context>` on its own row,
  with the id positional, as `pnm-cli`'s `ContextCommands` defines it. A nested
  context keeps its whole `<parent>/<id>` path; an unloaded account still falls
  back to a placeholder rather than naming the wrong context in a destructive
  command.

### Added

- **`openvtc health` prints the DID this install authenticates to the VTA as.**
  A new *VTA access* section names the agent, the context, the transport that
  would be opened (the same mediator-vs-REST rule `build_runtime_vta_client`
  branches on), its mediator or REST endpoint, and — in full, untruncated — the
  `did:key` this install presents.

  That last one is the point. The VTA keys its ACL entry on it, so it is the
  DID an operator has to name in `pnm acl get` / `pnm acl update`, and it was
  reachable from nowhere but the TUI's VTA panel, truncated to fit — while the
  identity pane's own refusal hint said "`openvtc health` prints the DID". The
  section prints both commands ready to run, and says why `--capabilities
  persona-holder` grants rather than narrows.

  It is read from the loaded config, so it answers on the run where the network
  leg is the broken thing. `--json` carries it as `vta_access`, null for a BIP32
  profile so a script need not branch on the backend first.

### Fixed

- **The identity pane's grant hint is now a command you can run.** It named a
  `--did` flag that `pnm acl update` does not have (the DID is positional), and
  it left the DID itself as `<this install's DID>` — a placeholder pointing at
  `openvtc health`, which did not print it either. The hint now carries the real
  DID from the config the pane is already rendering from.

### Added

- **Facts that are sensitive by what they are stay masked, and say so.** The
  identity pane resolves each fact's claim type against the persona claim-type
  registry (`specs/persona/_shared/0.1/claim-types.json`) and paints anything
  carrying a mask style reduced — `••••••••••••4242` for a card, `••••••••••56`
  for a mobile number, `a•••@example.com` for an email address, `••••••••` for a
  date of birth. A type the registry does not list, and anything under `x:`,
  resolves to the conservative default: masked entirely; a new token in a
  registered family (`payment.giftCard`) inherits the family rather than the
  floor. `s` shows the selected fact and only that one; moving the selection,
  changing tab or re-reading puts it back.

  A masked row says *masked — s to show*, because `••••••••` and *(no value)*
  are the same shape and one of them is a wrong answer about what the holder
  holds.

  **This is not a security control and the pane does not claim it is.** The
  value has already been fetched, decrypted by the agent and parked in this
  process; masking it defends against someone reading the terminal over a
  shoulder and against a screenshot, and against nothing else. The half of the
  registry that is not cosmetic is `sensitivity: high` — *withheld from a
  listing that did not ask for sensitive values* — and that is a read-path
  control which does not exist: `persona/attribute/list` takes `includeValues`
  and nothing finer. The mask is what makes that missing control visible.

  The table is a **vendored copy**: the agent serves no claim-type registry, so
  `openvtc-core/src/persona/claim_types.rs` ships one and names the file to
  re-sync it against.

### Changed

- **The join flow and communities panel speak the persona vocabulary too.** The
  pane was brought over in #280; this is the copy outside it —
  *"Who should this community know you as?"*, *"Already known to:"*, and the
  reuse warning in the sentence the table asks every surface to share:
  *"the same person to anyone who sees both."*

  `profile` elsewhere in the TUI is left alone on purpose: setup, backup and
  `--profile` mean the **config profile**, a different thing that predates the
  persona family and has its own meaning to operators.


### Changed

- **The identity pane speaks the words a person would use.** Following
  `design-docs/persona-vocabulary.md`, which fixes one vocabulary across the
  console, `pnm`, the mobile agent and this TUI: an *attribute* is a **fact**,
  a *profile* is a **face** — the set of facts you show together — and a persona
  **wears** a face in a community. The tabs read *Personas · Your facts · Faces ·
  Communities · What has left*.

  The spec's words are exact and are not being replaced in code, on the wire or
  in the audit log; they are kept off the screen. `persona/attribute/put` stays
  `persona/attribute/put` — the form says *Add a fact*.

  A test renders every tab, both empty and populated, plus each editor, and
  fails if any word from the table's avoid-list reaches the screen. Each of them
  is a word this pane's own code uses, so they are one careless `format!` away
  at all times, and the drift is invisible in review.


### Added

- **Setup now asks for the grant the identity pane needs.** The `pnm` command on
  the setup screen ends `--admin-holder`, which grants the `persona-holder`
  capability alongside OpenVTC's context-scoped admin entry.

  Without it the pane's Attributes, Profiles and Disclosures tabs are refused on
  every install — correctly. Those sit above every trust context, and OpenVTC's
  credential is scoped to one, so reaching them used to require making OpenVTC
  an administrator of *every* context on the agent. The capability grants
  authority over your own identity without granting that
  (verifiable-trust-infrastructure#1286).

  On an install that already exists, the pane's refusal now carries the command
  to fix it rather than only the agent's explanation of why it said no.


- **One pane for your own identity — "My Identity" on the main menu.** Everything
  a holder can do with their persona now lives in one place, with five tabs in
  the order the concepts build on each other: **Personas** (the persona DIDs),
  **Attributes** (the pool of facts behind them), **Profiles** (named subsets of
  that pool), **Communities** (which persona each community sees and what it
  presents there) and **Disclosures** (the read-only record of what has actually
  left).

  Before this, minting a persona DID was a menu item that fired an action, the
  list of personas was a section of the VTA Service panel, and the three layers
  above them — the attribute pool, the profiles over it, and the bindings that
  decide what a community is shown — were reachable only from `pnm persona`.

  Four decisions worth knowing:

  - **Values are opt-in and cost a round-trip.** The attribute list is read
    without values; `v` re-reads *with* them. It is not a display flag over data
    already in memory, because a listing that holds values has read the holder's
    identity whether or not the panel painted it.
  - **"We could not ask" is never drawn as "you hold nothing."** Every
    agent-served tab renders the failure and its reason instead of an empty
    list. An unreachable agent and an empty pool are one pixel apart, and only
    one of them is a confident wrong answer about the holder's own data.
  - **Destructive questions are asked once, correctly.** Deleting an attribute a
    profile uses, or a profile a persona presents, needs a cascade or an unbind —
    and the pane knows which from data it already holds, so the first prompt
    names the real consequence rather than being refused and re-asked.
  - **The editor authors what it can honestly author.** Self-asserted attributes
    and live profile references. A credential-backed attribute is shown but not
    editable (retyping its value would turn an attested claim into a typed one),
    and a profile's pinned, overridden and inline entries are read, carried
    through a save untouched, and left to `pnm` to change.

- **A persona's linkage is on screen.** A membership row says when the same persona is
  shown to other communities — the fact that lets two of them compare notes and
  find one person behind both, and the one thing a holder cannot work out by
  looking at a single row.

### Changed

- **The VTA Service panel is about the agent again.** Its Context Identities
  list, and the `n` / `g` / `d` verbs that acted on it, moved to the identity
  pane; a persona DID is the holder's identity, not a property of the agent that
  hosts its keys. With one list left on the panel, `Tab` no longer switches
  focus — it asks for the invitation-credential listing, which is all it ever
  did besides move the cursor.

### Fixed

- **Saving a profile on Linux corrupted the whole login keyring.** Not just the
  OpenVTC entry — every secret in the collection became unreadable, and the
  next unlock prompt from any application was really a *create a new keyring*
  prompt, which orphaned the original one.

  OpenVTC stored its `SecuredConfig` envelope pretty-printed, so the secret
  handed to the credential store contained real newlines. gnome-keyring writes
  an item's secret into its `.keyring` file verbatim but reads it back through
  `GKeyFile` unescaping, so those newlines came back as extra lines of the
  file, and the daemon rejected the file entirely:
  `keyring was in an invalid or unrecognized format`.

  Nothing about that is visible on macOS or Windows, whose stores treat a
  secret as opaque bytes — which is why a formatting choice with no reader
  survived this long.

  The envelope is now written as compact single-line JSON, and the encoder
  refuses to hand the store a secret containing a line break, a control
  character, a backslash, or any non-ASCII byte at all: its payloads are
  BASE64URL, so anything else is our bug, and it now fails the save instead of
  corrupting a keyring. Existing entries are read back unchanged.

  An already-corrupted keyring is orphaned, not destroyed;
  `docs/secured-configuration-management.md` has the recovery steps.

- **Setup could not link this client to a VTA at all.** The last step of the
  wizard — "Provision integration DID + admin credential" — failed on every
  fresh install with `unsupportedType`, against a VTA that was otherwise
  healthy and had already authenticated the setup key.

  The cause was upstream and had nothing to do with the VTA being asked. The
  `provision/integration` trust task moved to 0.3 and 0.2 was removed rather
  than deprecated (the two disagree about the bundle digest and both close
  their response schema, so no single response satisfies both). The VTA moved;
  so did the SDK's REST runner. Its TSP runner did not, and its DIDComm runners
  did not — each held its own version literal, and each had been correct on the
  day it was written, because the two transports genuinely used to address
  different versions of this operation.

  Setup prefers TSP, so setup got the half that was left behind. Worse, the
  refusal arrives *after* authentication succeeds, which the SDK classifies as
  terminal — so it never fell back to the REST leg that would have worked, and
  the checklist showed a clean run of ticks with a failure on the last line.

  Fixed upstream in vta-sdk 0.32.1, which routes every transport through one
  version constant and guards the client/server pair with a test. This release
  floors the dependency there.

- **A community could refuse something and this client would say nothing.**
  Every inbound DIDComm problem-report went through the *join* handler, which
  correlates the thread id against a pending join request. A report threaded on
  anything else — a `members/vmc` delivery, say — matched nothing, and was
  dropped with a warn naming the correlation miss rather than the failure.

  Paired with a send that reported success on a bare local `Ok`, that is how a
  completely broken reciprocal-VMC exchange stayed invisible for its entire
  life: the community rejected every delivery, said so, and the UI reported
  each one as sent.

  The join handler still declines to *interpret* a report it cannot correlate —
  it genuinely does not know what failed — but it now hands the code and comment
  back instead of swallowing them, and the dispatcher writes them to the
  community log. "We don't know which request" is not a reason to say nothing.

  Two related honesty fixes: issuing a membership credential now says "sent —
  waiting for the community to acknowledge it" rather than claiming it was
  received, matching the personhood verbs beside it; and the community's
  acknowledgement receipt, previously an `info!` in a log file, is written to
  the community log, since it is the only positive evidence the member ever gets
  that their half of the pair landed.

- **A reciprocal membership credential never closed the join request it
  answered.** `vtc/members/vmc/0.1` carries an optional `requestId` — the
  retired `join-requests/accept` semantics — and this client always sent
  `None`, so a community's join request sat `Approved` indefinitely after the
  member was admitted and had sent their half back.

  Not an oversight in the wire body: the id was *destroyed* before anything
  could read it. `activate` replaces `Pending { request_id }` with `Active`, so
  by the time the caller looked there was nothing to find.
  `handle_credential_issue` now returns a `CredentialIssueOutcome` (modelled on
  the `StatusOutcome` beside it) reporting the join it closed, captured before
  activation, and admission sends the reciprocal VMC naming it.

  **Behaviour change:** receiving the community's membership credential now
  auto-issues ours back. That is what admission means — membership is a pair,
  and the community is holding the request open waiting for our half — and this
  client already auto-answers `members/request-vmc` the same way. Best-effort:
  a failure is logged and leaves the join open, recoverable by issuing manually
  or by the community asking.

- **A relationship credential carried no identifier of its own.** `new_vrc`
  leaves `id` unset, so every VRC this client issued went out without one. A
  credential with no identifier cannot be stored under one — a peer keying
  relationship credentials by `id` cannot make a re-issue idempotent, tell a
  renewal from a duplicate, or reference the VRC from a witness credential's
  `digest`.

  Nothing rejects a VRC for it today, which is the point: that is exactly what
  the reciprocal membership credential looked like right up until a community
  started keying on it and every delivery began failing silently. VRC issuance
  now goes through `openvtc_core::vrc::new_identified_vrc`, which sets a fresh
  `urn:uuid:` id — before signing, since a Data Integrity proof covers it and
  one added afterwards would leave a document whose proof no longer verifies.

- **A renamed machine kept announcing its old name.** `displayName` is written
  once, at registration, and `device/register` is intentionally refused from the
  second launch on — so nothing could ever change it. Rename the machine, or run
  the install under a different profile, and its binding went on identifying it
  by a name that no longer picked it out of the list the name exists for.

  The heartbeat now carries the current name (vta-sdk 0.32 /
  `device_heartbeat_named`), which the VTA applies only when it differs and only
  to the binding the caller authenticated as. A drift spotted in the listing is
  corrected immediately rather than on the next beat: the correction only travels
  on a heartbeat, so an install opened and closed inside five minutes would
  otherwise never send one and the stale name would outlive every launch.

- **The activity log reported the mediator's scheduled reconnect as a fault,
  every twelve minutes.** The messaging stack reconnects on purpose: the
  mediator's access token is refreshed at 80% of its ~900 s life and the SDK's
  websocket transport re-establishes the socket as part of that refresh — one
  drop per token per listener, back inside a second or two. That arrived as
  `Listener '…' disconnected (no transport error reported)` followed by a
  reconnect, which made the log's most alarming line the one it printed most
  often. A real disconnect looked exactly like the routine one, so the line
  stopped carrying information.

  A drop is now held for 15 seconds before it is reported. If the listener
  returns first, the pair becomes one calm line — `Listener '…' reconnected
  after 2.1s` — which states what was observed and not a cause the transport
  never surfaces. If it does not return, the line still appears and now says the
  listener is *still* disconnected, which is the thing worth acting on. Nothing
  is quietened that shouldn't be: the rapid-cycling warning still fires on the
  drop itself, before any grace can absorb it, so duelling sockets shout as
  loudly as before.

- **Every launch after the first warned that the account was open somewhere
  else — naming this machine.** `device/register` is deliberately not
  idempotent: a `DeviceBinding` hangs off the caller's ACL entry, there is
  exactly one per DID, and the VTA refuses a second claim with
  `device/register:alreadyRegistered`. OpenVTC read that refusal as a failure,
  so from the second launch on it held no device id — and the sibling filter
  excluded "us" by id alone. With nothing to exclude, this install reported its
  *own* binding as another live instance, on every start, with no second process
  anywhere. The one situation the warning exists for (two installs evicting each
  other from the mediator's one socket per DID) was the one it stopped being
  able to tell you about, because the same sentence appeared when nothing was
  wrong.

  A row now carries the DID that owns it (`consumerDid`), which is exact rather
  than a guess: one binding per ACL entry means a row naming the DID we
  authenticate as *is* us, on every launch. The already-registered refusal is
  understood as the ordinary case it is (typed 409 over REST, either spelling of
  the reject code over DIDComm/TSP), and the listing recovers our own device id
  so a later launch names us the way a first one does. An install that can
  identify itself by neither id nor DID still reports everything live — a missed
  warning is the costlier direction.

- **Every reciprocal membership credential we sent a community was rejected, and
  nothing here said so.** A community stores a member's VMC keyed by the
  credential's own top-level `id`, and refuses one that has none. Ours never had
  one: `dtg-credentials` had no field for it at all, so a VMC built with
  `new_vmc()` could not carry the W3C VC Data Model's credential identifier —
  the property was not merely unset, there was nowhere to put it. Every
  submission therefore failed the community's last check, *after* the issuer,
  subject and Data Integrity proof checks had all passed. The member → community
  half of the membership pair has never once landed, whether sent by hand or
  auto-issued in answer to a `members/request-vmc`.

  It was silent from both ends. The send reports success as soon as the frame is
  accepted locally — "Membership credential issued and sent to the community." —
  which says nothing about whether the community took it. The community's
  rejection comes back as a problem-report threaded on the delivery, and this
  client routes every inbound problem-report through the join handler, which
  correlates against pending *join request* ids; a VMC's thread matches none, so
  the report was discarded with a warn that names the correlation miss rather
  than the failure. Two independent silences over one broken exchange.

  `dtg-credentials` 0.3 adds the field (`with_id()`), and the member VMC now
  gets a fresh `urn:uuid:` identifier before it is signed — before, necessarily,
  since the proof covers it and an id spliced in afterwards would leave a
  document whose proof no longer verifies. Regression tests assert the id is
  present, fresh per issuance, and inside what the proof covers.

  The two silences are not fixed here and are worth their own change: a send
  `Ok` still reads as acceptance, and a problem-report on any thread other than a
  join is still dropped.

- **Stopping a listener left its mediator socket open, so the next listener for
  the same DID fought it forever.** `Messaging::remove_listener` dropped the
  identity's wire and nothing more. That closes nothing:
  `affinidi-messaging-sdk` has no `Drop` for `ATM` — the websocket task holds its
  own state and keeps reconnecting on its timer — and the identity's outbox drain
  still held the transport that owns the ATM. So the socket stayed up, holding the
  mediator's one-socket-per-DID slot, invisible to `has_listener`. Anything that
  re-added that DID (a community going inactive and then being re-joined, a
  mediator change, the supervisor's own rebuild — which leaked another socket per
  attempt) opened a second one, and the mediator evicted each in favour of the
  other indefinitely. It read as a network fault: `Listener '…' disconnected (no
  transport error reported)` every 30-60 s, `cycling rapidly` warnings, and a
  restart as the only cure.

  Removal now aborts that listener's drain and closes its websocket **before it
  returns**, then finishes the ATM's teardown detached so the state-handler loop
  never parks on it; `shutdown` awaits the same teardown, because a caller that
  rebuilds the runtime would otherwise race its own orphans. Installing over an
  existing id — which no caller should do — tears the displaced wire down and
  warns rather than dropping it silently. Covered by a mediator-backed regression
  test that remove/re-adds one DID and fails if the new listener is evicted.

- **The admin credential was doing two irreconcilable jobs.** `ProtectedConfig`'s
  encryption key was `HKDF(admin_credential_private_key, …)`, which made one
  value both an **authorisation grant** designed to rotate (`acl/swap-key`) and
  be re-issued to a recovering install, *and* a **data-at-rest key** that must
  never change. Rotating the credential would have made the on-disk config
  undecryptable, and a recovered install necessarily holds a different
  credential — so recovery and existing local state were mutually exclusive.
  The profile now carries its own random 32-byte key in `SecuredConfig`, beside
  the credential bundle and under the same passphrase or token.

  Migration is transparent and crash-safe. Load tries three keys, newest first:
  the stored key, the pre-D12 derivation, and the pre-0.1.4 BIP32 seed. Anything
  but the first flags a re-key, completed on the next save. Keeping the older
  keys readable is what makes an *interrupted* re-key survivable — `Config::save`
  writes the secured blob before the public one, so a crash between them leaves
  the new key stored and the old blob on disk, and the user must still get in.

- **Config records silently dropped fields written by newer builds.** Neither
  `Account`, `PersonaRecord`, `CommunityRecord` nor `ProtectedConfig` carried
  `deny_unknown_fields` or a catch-all, so serde discarded anything it did not
  recognise. Harmless while one writer owns the config — which is why it never
  bit — but a round trip through an older build strips a newer one's work, and
  that becomes real the moment a record is shared between two installs. Each now
  carries a `#[serde(flatten)] extra` that preserves unknown fields verbatim.
  `CommunityRecord`'s had to go on its deserialization shadow, which parses
  first; putting it on the record itself compiles and drops everything.

- **One half-written persona took down the entire profile.** A profile is saved
  in two non-atomic writes — the config file (carrying the account, and with it
  the persona records) and the `SecuredConfig` blob in the OS credential store
  (carrying `key_info`). A crash between them left a persona recorded with no
  key material, and key rehydration returned `Err` on the first verification
  method it could not find. That error propagated out of the persona loop and
  failed the whole load: every *other* persona, every community, every
  relationship, gone — reported as a verification method id, which tells the
  user nothing. Now a fault is isolated to the persona that has it. Everything
  loadable loads, what could not is collected into a `LoadIntegrity` report, and
  the startup screen shows it and requires an explicit acknowledgement before
  continuing. The report distinguishes an interrupted write (real loss — say so)
  from an unreachable VTA (transient — say that instead), names what still works,
  and states plainly that nothing has been deleted: a degraded persona keeps its
  record and is skipped, never dropped, so an already-damaged profile is not
  quietly made worse. A membership whose persona did not load is reported and
  cannot be selected as the working context, which would otherwise be a silent
  dead end.

- **`Config::save` wrote the config file before the secrets, manufacturing the
  above.** Both orders lose the persona that was mid-creation — that is
  unavoidable without a transaction across two stores — but only file-first
  leaves damage behind: an account referencing keys that were never written.
  Secrets-first leaves the interrupted persona simply absent, with leftover keys
  reported as orphaned key records, and the load is clean.

- **OpenVTC silently chose where to keep your keys, and on Linux chose badly.**
  `linux-keyutils-keyring-store` documents itself as RAM-only — *"completely
  in-memory and will not persist across reboots. Consider the keyring a secure
  cache"* — and OpenVTC registered it unconditionally on Linux as the sole home
  of a profile's BIP32 seed / VTA credential bundle. A reboot, a logout, or three
  days of the persistent keyring's default expiry destroyed the account, and it
  surfaced as `Config Error: Couldn't find openvtc secured configuration.
  Reason: No matching credential found` — which reads like a corrupt install
  rather than the expected data loss it was.

  Two changes, and the second matters more than the first.

  **Durable, and the same as every other tool.** Store registration now
  delegates to `vta_sdk::keyring_init::install_default_store` — the same call
  `pnm-cli` makes — so `openvtc`, `pnm` and anything else on the SDK put secrets
  in the same place on the same OS: Apple Keychain, Windows Credential Manager,
  or DBus Secret Service. OpenVTC was the only tool in the workspace using the
  kernel keyring. Every store it will now select is durable.

  **Fail closed.** If the credential store cannot be opened, OpenVTC exits with
  an explanation instead of quietly writing the keys somewhere weaker. A tool
  that silently downgrades its own storage teaches users the secure backend is
  optional, and the moment it matters they discover their secrets were somewhere
  they never agreed to. Headless machines choose durable file storage
  deliberately with `OPENVTC_SECURE_STORE=file` — a new encrypted-file store
  under `~/.config/openvtc/secrets/` at mode `0600` that refuses to hold an
  unencrypted profile, so key material is never written to disk in the clear.
  `keyutils` remains selectable but is deprecated, warns loudly on every launch,
  and exists only so a profile written by an older build can be started once and
  exported.

- **Every startup failure printed the same advice, including the ones with no
  network in them.** The loading screen's single hint — *"Check your network and
  that your VTA/mediator are reachable"* — was shown for a missing credential, a
  locked keychain, a wrong passphrase and a corrupt blob alike, pointing the user
  away from the machine the problem was on. This is what the stack development
  guide's **R6.4** forbids. `OpenVTCError` gained a typed `SecureStore { fault,
  .. }` variant (missing / unavailable / ambiguous / corrupt / rejected) so the
  cases stay distinguishable, and a new `diagnostics` module turns each into its
  own report: what failed, what it means, the state of the profile's config file
  and credential store, commands to confirm it, and remedies in order — with
  restore-a-backup always ahead of the destructive reset, and no reset offered at
  all for a locked store or a wrong passphrase, where the keys are intact. The
  report is scrollable, is written to
  `~/.config/openvtc/last-startup-failure.txt` for bug reports, and the rotating
  "your keys never leave your device" tip no longer appears under a fatal error.

### Added

- **`openvtc health` now reports local storage first.** Which credential store
  is in use, where it keeps things, whether *this* profile's credential is
  actually there, and how long it will survive — plus the command to check it
  yourself. It runs when no account can be loaded at all, which used to abort
  with "nothing to check" and is exactly the run where the answer is wanted.
  `--json` gains a `local` object alongside the existing keys.

- **An explicit `[Ctrl+V]` "paste an invitation" action on the join entry
  page.** Bracketed paste worked the whole time, but nothing on screen said so —
  which is why the issue behind it was filed as "I cannot find anywhere to
  import a VIC". The key is named in every invitation state, and the terminal's
  own paste still works and remains the path that survives SSH, where reading
  the OS clipboard cannot. (vti-setup#29)

### Removed

- **Thirteen setup-wizard pages that had become unreachable.** R-A-5 moved
  persona minting out of setup and into the State-B join flow, which drives it
  from `JoinProgress` rather than through wizard pages. The pages it left behind
  — mediator choice, display name, webvh address and webvh-server selection, DID
  key display and PGP export, and did-git-sign install — had no inbound
  navigation from any reachable page, and had sat that way long enough to start
  reading as live code. Tracing from `StartAsk` confirmed the whole subgraph was
  orphaned: `MediatorAsk` and `WebvhServerSelect` had no callers at all, and
  everything else hung off one of those two.

  Gone with them: `Action::SetDIDKeys` (never sent by anything),
  `VtaCreateKeys`, `ExportDIDKeys`, `DidGitSignInstall`, `WebvhServerCreateDid`,
  `SetCustomMediator`, `SetUsername`, `CreateWebVHDID`, `ResetWebVHDID`,
  `ResolveWebVHDID`; sixteen `SetupEvent` variants; `SetupState.did_git_sign`,
  `.did_keys_export`, `.webvh_server` and `vta.use_webvh_server` /
  `.webvh_servers`; and the webvh-server probe provisioning ran to fill a list
  nothing read. `SetupState` keeps the fields the deleted pages *wrote* —
  `did_keys`, `webvh_address`, `custom_mediator`, `username` — because the join
  flow and the standalone persona mint now fill the same struct themselves
  before calling `Config::mint_persona_into`. Roughly 3,800 lines. (vti-setup#31)

  Note for anyone who wanted the git-signing setup: installing did-git-sign was
  only ever offered by one of these pages, so it has been unreachable since
  R-A-5 regardless. The main page still *detects* an existing did-git-sign
  config; re-offering the install needs a new entry point.

### Changed

- **The runtime loop's action handling is now callable by a test.** It was a
  ~1,600-line function with a 900-line `match` at its centre and no seam a test
  could reach, which is why every fix in this release was verified by reading
  the code, by a live log, or by a unit test on some piece extracted from it.
  The actions move to `runtime_actions::handle_action`, taking an `ActionCtx` of
  everything they act on; the loop keeps only the three arms that are about the
  loop itself. No behaviour changes — what changes is that a test can now press
  a key and assert what happened, including that an action *dispatched at all*,
  which is the property three surfaces were found to be silently violating.

- **Requesting a credential from a peer, and creating a persona, no longer
  freeze the application.** These were the last two network actions still
  awaited on the state-handler thread. Creating a persona is half a dozen VTA
  round-trips, so it was the longest freeze left in the app — and the one an
  operator is most likely to hit, since it is how an account gets its first
  identity. Both now run off the loop, and the persona overlay still shows each
  step as it happens: long jobs can report progress without blocking anything.
  A persona is only shown as created once it has actually been written to the
  config, rather than when the VTA finished minting it.

- **Leaving a community, or issuing it your membership credential, no longer
  freezes the application.** Both send to the community and were awaited on the
  state-handler thread — and an unreachable community is a *likely* reason to
  leave one, which is exactly when the send retries longest. Both now run off
  the loop. A successful leave still marks the membership Left and tears down
  its messaging session; the record moves on the send rather than on a receipt,
  because the community's acknowledgement is advisory and a member who has
  announced a departure should not still be shown as a member if it never
  answers.

- **Opening the capabilities view, refreshing it, or committing a toggle no
  longer freezes the application.** Each of those sends a governance document to
  the community and waits for the *send* — which retries against an unreachable
  peer — on the one thread that also services the inbound channel the reply will
  arrive on. Nothing could be received while a send was retrying, including the
  reply being waited for. The sends now run off the loop, and a reply armed for
  a community you have since navigated away from is dropped rather than matched
  against the wrong view.

- **Importing or archiving an invitation credential no longer freezes the
  application.** Every vault verb — import, archive, unarchive, restore,
  soft-delete, purge — ran its round-trip on the state-handler thread, and each
  was followed by a re-read of the listing, so a single keypress could park
  every other part of the app for two round-trips. The work now runs off the
  loop. Validation of a pasted credential deliberately stays on it: rejecting a
  bad paste is local and instant, and it is what keeps you on the input field
  with the reason rather than dropping you into a failed state.

- **Managing agent names no longer freezes the application.** The overlay's five
  verbs are Trust Tasks with a 60-second timeout each, and a mutation is *two* of
  them — the change, then the authoritative re-read of the registry. They ran on
  the state-handler thread, which is the only thread that services anything: for
  up to two minutes no inbound DIDComm was processed, no listener lifecycle
  applied, and no key read, including `q`. The overlay locks its own input while
  it works, so the freeze looked local to the overlay; it was not. The work now
  runs off the loop, and a result that arrives after the overlay has been closed
  or switched to another persona is dropped rather than written over it — though
  a name it verified is still cached, because that is a fact about the DID
  regardless of what is on screen.

- **Neither event loop can silently drop an action again.** OpenVTC runs two
  action loops — the runtime one, and a smaller one for an account with no
  community — and each matched a hand-written list of actions ending in a silent
  catch-all. That is how three surfaces came to be missing from the second one,
  each presenting as a key that did nothing. Both matches are now exhaustive with
  no catch-all, so adding an `Action` variant fails to compile until someone
  decides what *each* loop does with it. Verified by adding a probe variant: two
  `E0004` errors, one per loop. Actions that are genuinely unavailable before you
  join a community stay inert, but say so on screen rather than doing nothing.

### Fixed

- **Removing a persona, and changing settings, work before you join a
  community.** Two more casualties of the same gap: `y` on the remove-identity
  confirm was dropped, leaving the prompt on screen with nothing behind it —
  which reads as a hang — and the entire settings surface was inert, so a
  State-A account could not change its own protection, logging or mediator.
  Settings need no messaging and no VTA session at all; they were simply never
  wired into that loop.
- **Agent names can be managed on an account's first persona.** With no
  communities yet, OpenVTC runs a second, smaller event loop (State A), and that
  loop had no arm for the agent-name verbs — so `g` on a freshly minted persona
  was dropped into a catch-all and nothing happened, on the very screen that had
  just reported "Created persona DID …". State A is where an account's *first*
  persona is created, so it is also the first place anyone wants to name one.
  Restarting made it work, because an account that already has a persona starts
  in the full runtime loop instead — which is why this went unnoticed.

  The catch-all that swallowed them now says so on screen, rather than leaving a
  key that does nothing and no way to tell an unimplemented action from a broken
  one. What remains behind it genuinely needs a community — the inbox,
  relationships, credential exchange and the community verbs — and now says
  that instead of nothing.

- **The main page appears as soon as you press Enter on the loading screen.**
  Startup brought every DIDComm listener up — a mediator authentication
  handshake and a websocket connect each, one after another — on the
  state-handler thread, which is the only thread that services UI actions. The
  loading screen had already been told to offer "Press Enter to continue", so
  the keypress sat unread in the action channel until the last socket was up,
  and the main page then arrived in one late jump. It reads as a freeze, and it
  got worse with every extra identity on the account. The connects now happen
  off that thread, which is what the code around them already claimed ("Phase 2
  … runs ASYNCHRONOUSLY: we do NOT block the UI waiting for the listener").
- **A listener's messaging profile now says which identity is speaking, not
  just which community.** The label named the community only, so two personas
  in one community produced byte-identical labels, a persona in several
  communities took whichever membership happened to be found first, and a
  persona with no community at all was labelled the literal string `"Persona"`.
  All three showed up in live logs. Because this label names the messaging
  profile, it is what the transport puts in every `websocket_run{profile=…}`
  span and what a mediator-side log has to be correlated against — so one
  listener reconnecting and several reconnecting independently looked the same.
  Each label now carries the persona's own DID alongside the community,
  truncated the way the relationship labels already truncate theirs.

- **The VTA Service panel stops feeling frozen.** Tab into the Invitation
  Credentials list ran a credential-vault query *before* the focus change, and
  the state handler services actions one at a time — so a two-line in-memory
  focus move waited on a network round-trip with a 30-second timeout, and
  nothing on screen explained the pause. The listing now runs off the loop:
  focus moves immediately, the panel says a query is in flight, and "No
  invitation credentials" is only claimed once the vault has actually answered.
  A refresh asked for while one is running is deferred rather than dropped, so a
  just-archived credential is never left rendered as active.
- **`g` opens the agent-name manager whichever list is focused.** It was bound
  only to the Context Identities list, so pressing it after a Tab produced
  nothing at all — no action, no message — which is indistinguishable from a
  dead keyboard and had people restarting the app. Two more silent no-ops
  behind the same report are fixed with it: a persona selection left pointing
  past the end of a rebuilt list disabled every key scoped to that list (and
  restarting "fixed" it only because the selection resets to the first row), and
  both lists drew a "◀ focus" marker from their own focus alone — so a panel the
  keyboard could not reach still claimed focus and advertised keys that were
  being discarded. It now points at the key that gets you there.
- **A claimed agent name is no longer reported as no name at all.** When the
  claim succeeded but the read-back that follows it failed, the overlay rendered
  "No agent names yet." directly above "Applied, but could not reload the list"
  — the prominent half saying the opposite of what had happened, for a name the
  DID document already carried. A registry that could not be read is now shown
  as unknown rather than empty.
- **Listener log lines identify the listener, not just its name.** A name is not
  an identity: aliases and verified agent names are many-to-one, and a
  relationship R-DID resolves through to its peer's name — so two different
  listeners could produce byte-identical activity-log lines. Once names resolved
  a few minutes after launch, a log that had been readable as distinct listeners
  collapsed into one repeated name, and "one listener reconnecting in a loop"
  became indistinguishable from "several reconnecting on their own schedules".
  Every line that names a listener now carries the listener id it resolved from
  — abbreviated beside the name, in full behind `Enter` — because the id is what
  correlates with the mediator's own logs.
- **A disconnect with no transport error says so.** It rendered as a bare
  "disconnected", identical to a drop whose cause was simply not captured, so a
  socket that closed cleanly and one that was lost for unknown reasons read the
  same.

- **A pasted invitation now fills in the community it is for, and Enter says
  something either way.** On the join entry page a pasted VIC was routed to the
  invitation slot and nothing else: the DID input stayed empty, so Enter — which
  swallowed the keypress on an empty field, with no message — did nothing at
  all. The credential in hand names its community (a VIC's issuer *is* the VTC),
  so the operator was being asked to go and find a DID they already had, and got
  a screen that looked frozen when they didn't.

  A paste now records the issuer and prefills the input with it, and the loaded
  invitation says which community it came from. Prefilled, not auto-submitted:
  an invitation arrives from someone else, so the community stays visible and
  editable before Enter commits to joining it. Anything typed by hand wins over
  the credential, and a redraw never overwrites an edit. Enter on an empty field
  now reports why nothing happened. (vti-setup#29)
- **The invitation prompt is legible, and sits where it is needed.** It was dark
  grey italic — the dimmest text on the page — below the input and below the
  brighter examples block, and read as decoration; the reporter could not find
  anywhere to import a VIC at all. The invitation status and any error now sit
  directly above the input in full-contrast colours, and all of it wraps to the
  terminal width rather than clipping its tail. (vti-setup#29)
- **The setup wizard no longer advertises a step it will never run.** R-A-5
  ended setup at profile security — a persona is minted later by the join flow —
  but the breadcrumb still listed a fourth "Digital Identity" step (or "Display
  Name" on the webvh-server path) that could never become active, so the wizard
  appeared to skip a step on the way to Setup Complete. Setup is now shown as
  the four steps it actually has. (vti-setup#31)

- **Take `affinidi-messaging-delivery` 0.1.14, which stops the layer acking a
  message no consumer received.** An ack is a delete at the mediator, and the
  dispatcher acked unconditionally — including when its subscriber broadcast had
  just reported that nobody was listening. Those messages were destroyed: no
  subscriber is installed for a moment at startup and again on the way down, and
  what arrives in that window is whatever the peer happened to send.

  This is the layer-side half of the same defect as the unbounded event channel
  below. That change stopped *this* client discarding messages the mediator had
  already deleted; this one stops them being deleted before this client is
  listening at all. Lockfile only — the requirement was already `0.1.12`, so
  nothing but resolution moves. Verified against a live test mediator: all four
  `didcomm_transport_e2e` cases pass, including the stored-mail pickup path.
- **A join whose reply was lost can be reconciled again.** `join_status_poll`
  exists to ask a community what became of a join it never answered, but it was
  gated on `request_id_confirmed` — and the id it needed is the community's,
  learned from the first correlated reply. A join that never got one held only
  its own placeholder, which the VTC answers `not found` for, so the mechanism
  worked whenever it wasn't needed and failed whenever it was. The other
  recovery, collecting stored mail, is empty once that mail has been acked and
  deleted, so both failed together and the record sat `Pending` for good.

  A poll now omits the id when we don't hold the community's, which asks "what
  is my open request?" — resolved from the authenticated applicant
  (VTI#985). The reply carries the id, and `handle_join_status_response`
  already adopts it, so an unconfirmed record repairs itself on the first answer
  and quotes the real id from then on. `request_id_confirmed` still decides what
  we send; it no longer decides whether we may ask.

  Requires `vta-sdk` 0.24.

- **Inbound messages are no longer dropped when the event channel fills.** The
  DIDComm event channel was a 256-slot bounded channel whose overflow behaviour
  was log-and-drop, on the reasoning that a pathological mediator should not grow
  memory without bound. That missed what a dropped event costs: by the time an
  event reaches this channel the delivery layer has already acked the message,
  and an ack is a delete at the mediator. A dropped event was therefore not a
  deferred message but a **permanently destroyed** one — carrying membership
  credentials and join verdicts — with one `warn!` line as the only record.

  Backpressure was never actually on offer. Blocking on a full channel would
  stall the consumer, the delivery layer's subscriber broadcast would overflow
  instead, and its `subscribe()` stream swallows that as `Lagged` **silently** —
  strictly worse than the warned drop. The only real choice was where the loss
  happens, so the channel is now unbounded and the answer is nowhere.

  `pickup_stored` keeps its ack-after-handoff ordering: a message that cannot be
  taken stays stored at the mediator and is offered again.

### Added

- **A persona minted without TSP now says so, at mint time.** OpenVTC always
  requests the `#tsp` service — `create_did_via_server` sets
  `add_tsp_service: true` on every one of the three paths that mint a persona —
  but the VTA drops it unless it has `[services] tsp` enabled with a mediator
  configured. That refusal was silent, and the resulting persona looks entirely
  healthy: it resolves, it has a mediator, it messages DIDComm peers fine. It is
  only unable to reach a TSP-only community, which surfaces much later as a join
  that goes out and is never answered.

  Since the service is written at mint time and the document is never revisited,
  such a persona never recovers on its own — so the warning names the
  consequence, says the DID cannot gain the service later, and names the VTA
  setting that fixes it. Emitted as a `warn!` at the single mint point (so the
  log always has it) and surfaced on all three user-facing surfaces: the setup
  wizard's message list, the join flow's status line, and the persona manager's
  progress channel. A healthy mint stays silent.

- **`openvtc health` reports progress as it works.** The command is almost
  entirely network waits — a `did:webvh` resolution is an HTTPS fetch and each
  probe is bounded at 10s — so a chain with a few mediators could sit silent for
  most of a run that took 14 seconds. Each step now announces itself *before* the
  wait and reports the time it actually took, which makes the slow step visible
  while it is slow rather than inferable afterwards (it isn't: the finished
  report has no timings). Progress goes to stderr and the report to stdout, so
  `openvtc health --json > report.json` still pipes cleanly while showing the
  operator what is being waited on.

### Changed

- **`openvtc health` no longer probes `#files` and `#whois`.** Both are served by
  the DID host the report just fetched `did.jsonl` from, so resolving the DID had
  already proven that host answers — and `#files` points at the directory rather
  than the document, so the probe reported a 404 for a path that never serves a
  bare GET. Four such lines per party buried the transport probes that carry
  information. Implemented as a skip-list of the two document-adjacent service
  types rather than an allow-list of known transports, so a transport type this
  build has never heard of is still probed.

- **A probe's verdict now agrees with its status code.** "reachable (HTTP 404)"
  read as a contradiction — the word claimed health, the number denied it, and
  nothing told the reader which to believe. Statuses are graded: 2xx/3xx is `ok`,
  4xx is `responding` (the normal answer from an endpoint that takes POSTs and
  websockets rather than GETs), and 5xx is `server error`. Only the last is
  raised as a finding, which is a case the flat "reachable" actively hid: the
  host is up and the service behind it is failing.

- **A DIDComm-only persona against a TSP-only community now says what to do.**
  The advertised sets alone (`we offer [didcomm], they offer [tsp]`) do not tell
  an operator which side to change. A persona minted before the client requested
  `#tsp` cannot reach a TSP-only community and will never gain the service on its
  own — the document is written at mint time and not revisited — so the finding
  now says that, and that re-minting is the fix. Scoped to that one direction:
  re-minting our persona does not fix a DIDComm-only community.

### Fixed

- **The Communities footer no longer advertises `c` twice.** It listed every
  binding unconditionally, so `c: capabilities` and `c: cancel` appeared side by
  side and read as a collision. It never was one — `c` is capabilities on an
  Active row and cancel on a Pending one, and the states are mutually exclusive.
  The footer now shows what the selected row actually accepts, which also removes
  four silent no-ops it was advertising: `l`/`m` on a Pending or Inactive row and
  `x`/`d` on an Active one. The two panel-level keys (`j`, `v`) stay listed
  always, including when nothing is selected.

## [0.3.1] - 2026-08-15

A first-run join could go out and never be answerable. This fixes the state
machine that caused it, and adds the command that would have found it in one
step instead of five service logs.

### Fixed

- **A first-run join is answerable again.** Creating a persona and then joining
  — the ordinary first-run order — left the client in the State-A degraded loop
  instead of handing off to the runtime. That loop has no inbound arm, so the
  community's reply was received by the SDK, acknowledged (and therefore deleted
  at the mediator), and dropped before any handler saw it. The join stayed
  `Pending` forever with a clean log on both sides, and no restart could recover
  it: the mail was gone from the mediator, and `join-requests/status` polling is
  gated on a request id that only arrives in a reply that was never processed.

  The hand-off was gated on the join having minted the account's *first*
  identity. It never was: the degraded loop mints personas too
  (`CreatePersonaSubmit`), and `Config::active_identity()` reports `Some` for any
  persona at all, so the guard was false exactly when a persona had been created
  first. It is now gated on the join alone.

- **A live listener can no longer outlive its consumer.** The degraded loop
  re-checks `list_listeners()` each iteration and hands off whenever it holds
  one, whatever opened it. A socket this loop owns is a mailbox nobody reads, so
  the backstop is unconditional rather than specific to the join path — the
  failure mode it prevents is silent, permanent message loss that looks like a
  community which never answered.

### Added

- **`openvtc health [--vtc <did>] [--json]`** — resolve the messaging chain and
  print the map. For every DID involved (each persona, the VTA, every mediator,
  each VTC) it resolves the document, prints the `service` array verbatim —
  including entries of types this build does not recognise, since a party
  publishing one is indistinguishable from a party publishing nothing when read
  through the capability matcher alone — and probes any transport URLs. It then
  runs the same TSP > DIDComm > REST negotiation a real send performs, so the
  reported transport is the one that would actually be used, and names every
  party behind each mediator so a split-mediator topology is visible rather than
  assumed away.

  Read-only, and deliberately usable while things are broken: it takes no
  process lock (so it runs against a profile a stuck TUI is holding), and account
  details are best-effort (`--vtc` alone works with no account, and a config that
  will not decrypt is reported as a finding rather than an abort). Exits non-zero
  if any DID fails to resolve or any pair shares no transport.

### Changed

- **`trust-tasks-rs` 0.4 → 0.6, `trust-tasks-capability-client` 0.3 → 0.5,
  floor `vta-sdk` at 0.23.3.** This is a follow, not a lead: vta-sdk 0.23.3
  declares `trust-tasks-rs ^0.6` where 0.23.0 declared `^0.4`, so holding 0.4
  stopped matching the stack and started splitting the type — a dependency
  refresh alone put 0.4.1 and 0.6.5 in the same binary, which is precisely what
  the pin exists to prevent. `cargo tree -d` showing two `trust-tasks-rs` rows
  is the check that it has drifted again.

- Dependency refresh: `affinidi-messaging-sdk` 0.19.5 → 0.19.7, `vta-sdk` 0.23.0
  → 0.23.3, `vta-service` 0.15.0 → 0.15.3, `vti-common` 0.11.39 → 0.11.40, plus
  transitive updates.

## [0.3.0] - 2026-08-15

The first tagged release since 0.2.0 (21 May). 0.2.1 was version-bumped and
written up but never tagged or published, so everything under it ships here too.

The theme is the join ceremony's asynchronous half: a community's reply now
reaches the applicant whether or not it happened to be connected when the reply
was sent, and a join left unresolved is reconciled by asking rather than by
waiting.

### Added

- **Ask a community about a join it has not answered** — every way a `Pending`
  join could previously resolve was the community volunteering something: a
  verdict, a credential, a problem-report. If any of those was lost — a socket
  down at the wrong moment, a mediator that dropped it, a decision a human took
  days later when nothing was listening — the record sat `Pending` and this
  client never asked. `join-requests/status/0.1` is the protocol's answer to
  exactly that, and OpenVTC had implemented only the receiving half
  (`handle_join_status_response` existed with nothing to trigger it).

  A minute-by-minute tick now reconciles each pollable `Pending` join, starting
  with an immediate poll at launch — a join still `Pending` when the app starts
  is precisely the one whose answer may have been lost. Per record it then backs
  off 1 → 2 → 4 → 8 minutes, capped at 15, with at most four polls per tick
  across the account (R1.4), so a parked join is noticed promptly without this
  client becoming a load source. Pacing is deliberately in memory: it is about
  this process's politeness, and a stale on-disk backoff would suppress the poll
  a fresh launch most wants to make. The poll takes the transport the submit took
  — a TSP-only community would never see a DIDComm poll.

- **Adopt the community's own request id when it first replies** — a join is
  recorded against the id of the request document *we* sent, because that is the
  only handle available until the VTC answers; the VTC mints its own and returns
  it in the first correlated reply. The submit-receipt path already swapped the
  id in, but a `refer` / `request_more` verdict carries `requestId` too and read
  straight past it — correlation there is by `thid`, so nothing needed it.

  A referred join is the one that then sits `Pending` for as long as a human
  takes, so it is the one that most needs to be askable-about later, and without
  the id there is no handle to ask with. `CommunityRecord::request_id_confirmed`
  now records *whose* id a record holds, and is the gate on polling: quoting our
  own placeholder would be asking about a request the community has never heard
  of. Records written before this default to unconfirmed, which is the safe
  reading — we cannot tell whose id they hold.

  Note what this does **not** cover: a join that received *no* reply at all has
  no confirmed id and cannot be polled. That case is not a gap here — it is
  recovered by collecting the stored mail the reply is sitting in.

### Fixed

- **Collect the messages the mediator is holding, instead of waiting to be
  pushed** — every inbound message OpenVTC has ever received arrived by live
  delivery. A mediator live-streams a message only to a recipient connected at
  the instant it lands; everything else is stored, and a stored inbox is
  redelivered **only** when a new websocket *displaces* an existing one for the
  same DID (`websocket_streaming.rs`, `if replacing`). Enabling live delivery
  drains nothing. So a listener that connects for the first time — the applicant
  persona during a join, a community's session after a restart, any identity
  whose socket was down when a reply arrived — was never told what was already
  waiting for it, and nothing in this client ever asked.

  That is the join that sits `Pending` while the community's outbox reports
  `Sent`, and it is why relaunching the app appeared to fix it: the new process's
  socket displaced the old one, and *that* is what made the mediator redelivery
  fire. The recovery was a side effect of how the previous process happened to
  exit.

  `Messaging::pickup_stored` now collects a listener's stored mail over
  message-pickup 3.0 and hands each message to the state handler on the same
  channel a live frame uses, and `pickup_on_connect` runs it on every connect —
  first connect and reconnect alike, since a reconnect is exactly when something
  may have landed with nobody attached. Messages are acknowledged **after**
  handoff, never before, the same discipline the delivery layer's own dispatcher
  follows; a frame that could not be unsealed, mapped, or queued is deliberately
  *not* acked, so nothing is deleted unread. Bounded at 200 messages per connect
  (R1.4), with the remainder logged rather than silently dropped.

  Classification is shared with the live dispatcher rather than copied
  (`classify_inbound`), so the two paths cannot drift into admitting different
  message types — and the authcrypt sender binding is applied to a collected
  message too, because these carry membership decisions and credentials and must
  not be the one path where a spoofed `from` is believed.

  Delivery is at-least-once by design (a message may also arrive live); the
  runtime loop's `SeenMessages` is what makes that harmless.

- **Start messaging before the first join, not after it** — a State-A account
  (no persona yet) ran its join with no messaging runtime at all, so the
  applicant had no socket for the entire ceremony. A community auto-admitting an
  invited join answers in under a second, so its reply was stored rather than
  streamed — and since the hot-start's listener was a *first* connect, the
  mediator never redelivered it either. The first join a new operator makes was
  the one join with no live recipient.

  The runtime now comes up **before** the State-A branch and empty
  (`start_empty_service`; `Messaging::start` runs its dispatcher before the first
  transport exists, so this is a supported state, not a stub), and the degraded
  loop hands it to `join_flow`. A State-A join therefore connects its applicant
  before submitting, exactly as the runtime-loop join already does.
  `install_listeners` then adds whatever is missing, skipping any the join
  already brought up — one websocket per DID.

  The durable join record also now states whether the applicant was connected at
  submit. A join sent from an unconnected persona is still valid, but it is the
  one that takes the collect-on-connect path, and an operator reading the log
  later could not otherwise tell that from a community that never answered.

- **Connect the applicant persona before submitting the join, not after** — a
  join over an accepted invitation is auto-admitted in well under a second, and
  the community pushes the membership credential (VMC) and role credential (VEC)
  straight back. The persona's mediator socket, though, only came up once the
  join flow had returned to the main page, so the reply arrived while its
  recipient had no live stream. A mediator live-streams a message only if the
  recipient is connected at the instant it lands: both credentials were stored
  and never pushed, and nothing polled the mailbox afterwards.

  It read as a failed join with clean logs at every hop — the community's outbox
  said *sent*, the mediator held two messages, and the membership sat `Pending`
  with no error anywhere. Observed with a ~29 s gap between the credentials
  landing and the persona's websocket registering, which is simply how long the
  operator spent on the confirmation screen.

  `run_join_sequence` now installs the persona listener as soon as the applicant
  identity exists and waits — bounded at 10 s — immediately before
  `submit_join_request`, so the socket is live for the whole window in which a
  reply can arrive and the connect is spent on the invitation resolution and VP
  build rather than on the operator's time. The wait is finite and never fatal
  (R1.2): a slow or failed connect says which it was (R6.4) and the submit goes
  out regardless — the community still admits, and the reply is collected when
  the listener does come up. `register_joined_session` already tolerated a
  listener that exists, so it now binds to it rather than installing a second.

  Cancel-safety is preserved on the pattern `minted_persona` established: the
  listener id is returned only when *this* call installed it, and is held outside
  the interruptible future so a Ctrl-C — or a failed submit — tears it down
  instead of leaving a socket open for a persona that was just rolled back. A
  reused persona already serving another community is never claimed, so its
  session survives a cancelled join.

  Independent of this, the mediator-side half of the same gap is fixed upstream
  in `affinidi-messaging-mediator` 0.18.16: enabling live delivery now redelivers
  what is already queued. Deployments want both — this change stops the reply
  from being stranded, that one stops an already-stranded reply from staying
  stranded.

### Changed

- **Refresh every dependency to its latest release** — `cargo update` across
  the whole graph, plus the manifest bumps needed to cross a major boundary:
  `vta-sdk` 0.20 → 0.21.7, `affinidi-messaging-sdk` 0.18 → 0.19.2,
  `trust-tasks-rs` 0.2 → 0.3.0, `trust-tasks-capability-client` 0.1 → 0.2.0,
  and the `vta-service` dev-dependency 0.13 → 0.14.16.

  One source change was needed. `affinidi-messaging-core` 0.1.6 marks
  `Protocol` `#[non_exhaustive]` and adds a `DIDCommV1` variant (Aries RFC
  0019), so the inbound dispatcher's `match` in `didcomm.rs` no longer
  compiles as written. It gained a wildcard arm that logs and drops: OpenVTC
  speaks DIDComm v2.1 and TSP, neither listener it installs ever negotiates
  v1, and nothing downstream of that match could read a v1 payload. The arm
  is also what keeps the *next* variant from being a compile break.

  Everything else rode the bump untouched — the join ceremony, the reciprocal
  VMC exchange, and the TSP leg all dispatch on `vta_sdk::protocols`
  constants rather than string literals. Verified with the full suite
  including the `#[ignore]`d e2e tests, which are the ones that actually
  exercise these crates: the in-process mediator transport round-trip, the
  join/self-remove lifecycle, and the MockVta bootstrap against
  `vta-service` 0.14.

  Two pins survive re-evaluation and stay: `rand` 0.8 and `x25519-dalek` 2.x
  are both still forced by `pgp` 0.20.0, which remains the latest release and
  declares `rand ^0.8.6` / `x25519-dalek ^2.0.1`.

  Known duplicate, upstream to fix: `did-git-sign` 0.4.1 still depends on
  `vta-sdk` 0.19.28, so the binary links two vta-sdk majors. That belongs to
  `verifiable-git-infrastructure`, not here.

- **Drop two resolved advisory ignores from `deny.toml`** — RUSTSEC-2026-0215
  (`smallstr` unmaintained) and RUSTSEC-2024-0370 (`proc-macro-error`
  unmaintained). Both crates left the dependency graph with this refresh,
  exactly as each ignore's comment predicted, and `cargo deny` now reports
  them as unmatched. The remaining ignores still match and stay.

- **Follow the VTC Trust Tasks onto the `spec/vtc` registry authority** —
  `vta-sdk` 0.20.0 → 0.20.1 (and `trust-tasks-rs` 0.2.26 → 0.2.38). The VTC's
  Trust Tasks have moved off the non-conformant
  `trusttasks.org/openvtc/vtc/…` authority to the canonical registry at
  `trusttasks.org/spec/vtc/…`
  (OpenVTC/verifiable-trust-infrastructure#806, dtgwg-trust-tasks-tf#144).

  No source change was needed: the join ceremony and the reciprocal-VMC
  exchange dispatch on `vta_sdk::protocols` constants rather than string
  literals, so the new URIs arrive with the bump —
  `MEMBER_REQUEST_VMC_TYPE` and `MEMBER_VMC_TYPE` now read
  `spec/vtc/members/{request-vmc,vmc}/0.1`, and the join-request and
  self-remove receipts likewise. That indirection is why this is a lockfile
  change and not an audit of every dispatch site.

  The inbound router already accepted both authorities — `OPENVTC_CATCH_ALL_PATTERN`
  gained its `spec/vtc/` arm ahead of the migration precisely so migrated
  traffic would not be dropped before dispatch. It stays dual-arm for now:
  the `openvtc/vtc/` arm can be retired once no supported VTC emits it, and
  eight VTC tasks are still on the old authority awaiting a canonical fold.

## [0.2.1] - 2026-05-24

### Security

- **Derive unlock key via Argon2id in non-openpgp import path** — the non-`openpgp-card` build was passing the raw passphrase to `SecuredConfig::save()` as the AES-256 key, bypassing the Argon2id KDF and making the saved config unrecoverable since `UnlockCode::from_string()` always applies Argon2id at load time
- **Reject path-traversal characters in profile name** — `--profile` and `OPENVTC_CONFIG_PROFILE` were spliced verbatim into lock-file paths, config paths, and OS keyring account names; now restricted to `[A-Za-z0-9._-]` with no `..` component
- **Redact armored private key block in `DIDKeysExportState` `Debug`** — the derived `Debug` impl could dump the full PGP-armored private key through any `{:?}` of `State` (panic backtrace, tracing, debug print)
- **Warn that `--unlock-code` is visible in the process list** — the flag exposes the passphrase via `ps`/`/proc/<pid>/cmdline` and shell history; help text now documents this and a runtime warning nudges users toward the interactive prompt
- **Restore terminal on panic via panic hook** — panics inside the render loop, key handlers, or spawned tasks no longer leave the TTY in raw mode on the alternate screen
- **Drop exported private-key armor from `State` after use** — the armored PGP private key block was cloned through the state broadcast channel on every tick for the remainder of the setup wizard
- **Avoid OOB panic on stale token-list index** — unplugging or re-enumerating tokens no longer panics the TUI when a retained selection index exceeds the new bounds
- **Clear private-key clipboard when leaving export page** — the ASCII-armored PGP private key block placed on the OS clipboard by `[C]` is now cleared on continue (unless the user has copied something else in the meantime)
- **Clear `ConfigImport` passphrase `Input` buffers after dispatch** — both passphrase inputs are now reset once wrapped in `SecretString` and dispatched, matching the other secret-input pages

## [0.2.0] - 2026-05-05

### Added

- **Full TUI main menu panels** in `openvtc` — 8 panels: Inbox, Relationships, Credentials, Settings, VTA Service, Logs, Help/Status, Quit
- **Inbox panel** with real-time task processing: auto-handles trust-pongs, relationship finalization, and rejections; queues interactive tasks; detail views for all task types (inbound/outbound requests, VRCs, pings, informational)
- **Relationships panel** with list/detail/new-request views, inline alias editing ('e' key), R-DID privacy toggle, trust-ping with RTT latency
- **Credentials panel** with Received/Issued tabs, raw VRC JSON in detail view, clipboard copy ('c' key), VRC request and removal
- **Settings panel** with inline editing, config export/import, passphrase protection management, hardware token detection and factory reset
- **VTA Service panel** showing VTA URL, DID, credential DID, key count, and backend type
- **Logs panel** with scrollable timestamped activity log, selected entry copy ('c'), copy all ('a')
- **Activity log panel** at bottom of screen showing real-time timestamped events (`[HH:MM:SS] message`)
- **Status/Help panel** with DID clipboard copy hotkeys ([1] persona, [2] mediator), visual feedback on copy
- **R-DID generation** for both BIP32 and VTA backends — VTA path authenticates and creates keys via API; both sender and receiver can use R-DIDs
- **Dynamic R-DID listeners** — automatically added when creating R-DIDs (sender or receiver), enabling message delivery to relationship-specific DIDs
- **VRC issuance** from inbox with DataIntegrityProof signing; **VRC rejection** with message back to requester
- **Friendly name in relationship requests** — sender's name included in request body, auto-set as contact alias on accept, R-DID recommendation shown when sender uses one
- **DIDComm service integration** (`affinidi-messaging-didcomm-service` 0.2) — replaces manual messaging with Router-based dispatch, automatic reconnection, message pickup, and multi-DID listener support
- **Periodic keepalive ping** (60s) with live RTT latency in connection status header
- **Inbox task count badge** on menu item ("Inbox (3)" in red when tasks pending)
- **Bracketed paste** for all 21 text input fields — paste is instant regardless of string length
- **Up/Down arrow navigation** in all multi-field forms alongside Tab
- **Config versioning** with stepwise migration framework
- **Panel trait** for content panels — unified render interface
- **Outbound message retry** via `DIDCommService::send_message_with_retry`
- **Auto-reconnect mediator** on DID change in settings
- 15 unit tests covering core functions
- **Contact management** actions (add/remove)

### Security

- Trust-pings only responded to from mediator DID or established relationships — prevents presence leakage
- Passphrases removed from cloned State — length-only fields in UI, consumed via `mem::take`
- Token admin PIN wrapped in `Arc<SecretString>` for shared allocation
- Inbound message body size validation (1MB limit), task ID deduplication, sender verification
- Collection bounds (10K tasks, 5K relationships), untrusted display text sanitization
- Unlock rate limiting (5 attempts, exponential backoff), path redaction, file path validation
- Key material explicit drop with documented zeroization limitation
- Structured audit log entries for security-relevant operations

### Fixed

- **R-DID message routing** — acceptance, finalize, VRC, and ping messages now use relationship DID instead of persona DID when R-DID exists
- **Config persistence** — all mutating actions save to disk
- **Setup → main transition** — `sync_from_config()` now called after setup wizard completes
- **VRC "From:" blank** — extract remote DID from relationship for VRC tasks
- **Alias on accept** — sender's name set as contact alias, existing alias-less contacts updated
- **Backspace to empty** in relationship form fields
- **Tab after backspace fix** — dedicated `FocusField` action for field switching
- **DIDComm listener secrets** — pass DID secrets to listeners for mediator authentication
- All `.unwrap()`/`.expect()` replaced with proper error propagation
- Clipboard graceful degradation, `sanitize_display` ANSI stripping order

### Changed

- **Workspace consolidation** — renamed the active CLI package and binary `openvtc-cli2` → `openvtc`, and renamed the supporting library `openvtc-lib` → `openvtc-core`. The unsuffixed name now belongs to the user-facing binary, matching the convention used by uv, ruff, deno, and cargo. The library is `publish = false`, so no external consumers are affected.
- **`vta-sdk` 0.5** consumed from crates.io — dropped the temporary `../verifiable-trust-infrastructure/vta-sdk` path pin so the workspace no longer requires a sibling checkout to build.
- **Replaced manual messaging layer** with `affinidi-messaging-didcomm-service` — deleted messaging/mod.rs (~280 lines) and outbound_queue.rs (~90 lines), added didcomm.rs (~260 lines) with Router, listeners, and send_message_with_retry
- Grouped ~65-variant Action enum into 5 domain sub-enums
- `tokio::sync::watch` replaces mpsc for State updates
- Panel trait with per-panel structs implementing unified render interface
- Dynamic DID display width (`shorten_did(did, max_width)` — 60 chars default, full if fits)
- `Cow<str>` for zero-alloc DID truncation
- Explicit `Arc::clone()`, `#[must_use]` on pure functions, doc comments on State types
- `VecDeque<String>` for O(1) bounded activity log
- `RelationshipRequestBody.name` protocol field for friendly names

### Removed

- **Legacy `openvtc-cli` crate** — the original prompt-driven CLI was phased out in favour of the TUI. All ongoing work lives in `openvtc`.
- **Dead `VtaAuthenticate` setup page** — online provisioning emits `VtaAuthCompleted` directly from `VtaProvisioning`, so the legacy authenticate screen was unreachable.

### Post-release deep-review pass

After cutting the v0.2.0 branch a multi-axis review (code quality, security, tests, docs) flagged a set of findings that landed on the same release branch before merge. They're listed separately so the diff between v0.1.x and v0.2.0 stays readable.

#### Security

- **Per-entry random Argon2 salt with transparent v1→v2 migration.** `derive_passphrase_key` previously used a deterministic salt = SHA-256(info), so two operators with the same passphrase produced the same KEK and exported backups were byte-comparable. The new `passphrase_encrypt_v2` / `passphrase_decrypt` API in `openvtc-core::config::secured_config` writes a magic-prefixed `[OPV2 | salt(16) | nonce(12) | ct+tag]` blob with a fresh random salt; the decrypt path auto-detects v1/v2 so existing exports keep opening. Argon2id parameters bumped to OWASP "high-value KEK" floor (m=128 MiB, t=4, p=1).
- **`did-git-sign` signing policy.** The proxy now refuses to sign unless the parent process name starts with `git` or `ssh-keygen`, and writes every signing attempt — accepted or denied — to `~/.config/did-git-sign/audit.log` (mode 0600) with parent PID/name, namespace, buffer path and SHA-256. Blocks the "malicious build script obtains a signature with namespace=git over attacker-chosen content" pivot.
- **DIDComm replay window + seen-message LRU** in `process_inbound_message`: drop messages with `created_time` outside ±48h / +5m skew, drop messages whose `expires_time` already passed, dedupe on a 1024-entry process-lifetime ID LRU.
- **DID validation** uses a real W3C DID Core 1.0 syntax parser instead of a `did:` prefix check; rejects bidi-override / zero-width chars in DID fields.
- **Inbox display-name sanitisation** strips bidi-override / isolate / zero-width / BOM unicode (Cf class) plus ANSI escapes / control chars, and clamps inbound contact aliases to 64 chars before persistence.
- **Bounded DIDComm event channel** (256-entry capacity) so a noisy mediator can't grow memory without limit; overflow logs and drops, mediator pickup redelivers when we drain.
- **`did.jsonl` write path** is now the resolved profile dir, not the current working directory.
- **Dependabot:** transitive openssl/rustls-webpki/rand bumped via `cargo update` to clear nine open advisories. `pgp` was already at the patched 0.19.
- **Tagged-variant downgrade defence on `SecuredConfigFormat`.** Switched the on-disk variant tag from `#[serde(untagged)]` to `#[serde(tag = "format")]` so every blob carries an explicit `"format"` discriminator. Without it, an attacker with write access to the OS keychain could substitute a `PasswordEncrypted` blob with `{"text": "<plaintext>"}` and serde would silently match it as `PlainText`, bypassing AES-256-GCM. New `assert_format_matches_intent` cross-validation gate adds a second defence layer — a tagged-but-weaker blob is rejected before any decrypt or re-save. Old (untagged) blobs migrate transparently on first load. Folded from @ojasshelke's PR #34; the PR's HKDF v2 fixed-salt variant is superseded by our random-per-entry-salt v2 (`OPV2` magic prefix) above.

#### Community contributions

Three community PRs against `main` were assessed and folded into the release. Each PR's substantive value is preserved with `Co-authored-by:` trailers; the corresponding PRs are closed with a comment pointing here.

- **#57 — profile-name validation hardening (@sameerchore).** `validate_profile_name` now trims leading/trailing whitespace before validating, and the empty/whitespace check runs before the character check (so `"   "` gets a clear "cannot be empty or contain only whitespace" error instead of the confusing "Invalid profile name '   '"). Three new integration tests pin the behaviour.
- **#51 — cross-platform config paths (@krsatyamthakur-droid, closes #47).** `profile_dir` and `get_lock_file` now use `dirs::config_dir()` on Windows (typically `%APPDATA%\openvtc`); Unix/macOS continues to use `~/.config/openvtc/` so existing installs don't move. `get_config_path` and `get_lock_file` return `PathBuf` instead of `String` end-to-end.
- **#34 — `SecuredConfig` serde-format hardening (@ojasshelke).** Tagged-variant downgrade defence + intent-gate cross-validation, described under Security above. The PR's HKDF v2 fixed-salt scheme was superseded by our random-salt OPV2 v2 and intentionally not folded.

#### Architecture & code quality

- **State-handler split.** `state_handler/mod.rs` was 2,255 lines with a 500-line `tokio::select!` arm; it's now 813 lines (-64%). Each per-domain match (Inbox, Relationship, Credential, Settings, Contact) was extracted to a `dispatch(action, ctx).await` entry point in the corresponding sub-module.
- **Layering:** moved `colors.rs` and the `dialoguer` passphrase prompt out of `openvtc-core` so the daemon (`openvtc-service`) and automation (`robotic-maintainers`) crates no longer pull in `ratatui` + `dialoguer` transitively.
- **Lifted four DID-truncation helpers** into a single `openvtc-core::display` module (`truncate_did`, `truncate_did_centered`).
- **Tightened `openvtc-core` public surface** — dropped a dead `pub use` re-export and scoped two helpers to `pub(crate)`.
- **Fixed silent failures** in the state handler: surfaced previously-swallowed `save_config` / `remove_listener` / inbox-task errors via `log_error`. Replaced four `.expect("valid route")` panics in DIDComm router init with `?`. Replaced `panic!("Cannot create log file …")` with stderr + continue.
- **Fixed DIDComm-only VTA fallback** in `relationships.rs` (used `build_runtime_vta_client` instead of REST-only `challenge_response`).

#### Tests & CI

- **In-process mediator harness** (`openvtc-core/tests/common/mod.rs`): wraps the upstream `affinidi-messaging-test-mediator` 0.2 fixture via `TestMediator::with_users(["alice", "bob"])`, which boots a real `affinidi-messaging-mediator` on an ephemeral loopback port (memory-backed store, generated `did:peer` identity advertising `dm`/`#auth`/`#ws`, Ed25519 JWT signing keypair) and returns Alice + Bob as ALLOW_ALL accounts whose DIDComm service URI is the mediator's DID — the routing/2.0 shape required for forwards to short-circuit to local delivery instead of being enqueued for external forwarding. The previous in-tree harness predated the test-mediator crate; the migration drops ~400 lines of fixture code and four dev-deps (`affinidi-messaging-mediator`, `-mediator-common`, `-sdk`, `sha256`).
- **End-to-end integration tests** (`relationship_e2e.rs`): drive a real Alice→Mediator→Bob DIDComm round-trip, a production `RelationshipRequestBody` round-trip, and a two-leg VRC request/reject round-trip — all in ~350ms once the mediator is up. Plus a smoke test (`mediator_smoke.rs`) that asserts the well-known endpoint serves a DID Document. Marked `#[ignore]` (each spawns the mediator, ~1s); CI's coverage job runs them with `--include-ignored`.
- **38 new unit tests** across `setup_flow/navigation` (25 table-driven), BIP32 derivation (7 known-answer vectors), AES-GCM tampering (6) — locking the wizard flow, derivation contract, and AEAD failure modes before the v0.3.0 work begins.
- **CI** adds a `cargo-deny` job (advisories + licenses + bans + sources, with documented `RUSTSEC-2023-0071` rsa Marvin-Attack and `RUSTSEC-2024-0370` proc-macro-error ignores) and a `cargo-llvm-cov` coverage job (uploads `lcov.info` artifact, runs ignored tests). MSRV check bumped 1.91 → 1.94 to match `Cargo.toml`.

#### Dependency refresh

Picks up the May 2026 Affinidi-stack releases. All bumps cleared on crates.io; build, full test suite, and integration tests pass.

- **`affinidi-tdk` 0.6 → 0.7** — accessor-method API on `TDKSharedState`/`TDKEnvironment`/`TDKProfile`. Field accesses (`.secrets_resolver`, `.environment`, `.profiles`, `.default_mediator`, `.ssl_certificate_paths`) are now method calls. `TDKSharedState::default().await` (removed in tdk 0.6) replaced with `TDKSharedState::new(TDKConfig::headless()?).await?` in `openvtc-service`.
- **`affinidi-messaging-didcomm-service` 0.2 → 0.3** — version bump driven by the upstream `MediatorACLSet` error-type relocation; downstream impact is `?`-transparent thanks to `From<ACLError> for ATMError`.
- **`affinidi-messaging-test-mediator` 0.1 → 0.2** (dev-deps only) — `TestMediator::with_users(["alice", "bob"])` replaces our hand-rolled `MemoryStore` + ALLOW_ALL registration dance. Drops `affinidi-messaging-mediator`, `-mediator-common`, `-sdk` and `sha256` from dev-deps.
- Working with the upstream maintainers, this branch's review of the May 2026 test-mediator changes also surfaced two follow-ups landing post-publication: an IPv6 routing-classification fix and `mediator-common` feature-gating to keep the SDK light. Neither is on the path used by openvtc tests (loopback over `127.0.0.1`).

#### Docs

- README, CONTRIBUTING, SECURITY, CLAUDE.md aligned to the post-rename workspace shape (`openvtc` binary + `openvtc-core` lib).
- CHANGELOG `[0.2.0]` entry above describes the release as it actually shipped.

## [0.1.5] - 2026-04-14

### Security

- Upgraded `pgp` 0.18 &rarr; 0.19, resolving 3 Dependabot alerts: parser crash on crafted RSA secret key packets (CVE-2026-21895), crash from deeply nested messages, and integrity protection not always checked on encrypted data

### Added

- Hardware token touch prompt overlay in `openvtc-cli2` — a centered popup now appears when a YubiKey (or other OpenPGP card) requires physical touch confirmation, and auto-dismisses when the touch completes
- Progress feedback during VTA credential validation in `openvtc-cli2` setup wizard
- Unit tests for `MessageType` and `KeyPurpose` in `openvtc-lib`
- GitHub Discussions guidance in `CONTRIBUTING.md`

### Changed

- Upgraded `secrecy` 0.8 &rarr; 0.10 (`SecretVec<u8>` replaced with `SecretBox<Vec<u8>>`, `SecretString::new()` API updated)
- Upgraded `openpgp-card` 0.5 &rarr; 0.6 and `openpgp-card-rpgp` 0.6 &rarr; 0.7
- Migrated pgp 0.19 API changes: `EncryptionKey`/`DecryptionKey` traits, `SubpacketData::IssuerKeyId`, `Timestamp` types

### Removed

- Stale `openvtc-cli2/did.jsonl` test artifact

## [0.1.4] - 2026-04-12

### Breaking Changes

- **Removed legacy SHA-256+HKDF encryption** — existing configs must be recreated with `openvtc setup`
- **`UnlockCode::from_string()` now returns `Result`** and enforces minimum 8-character passphrase
- **`derive_passphrase_key()` now returns `Result`** — callers must handle the error

### Security

- Replaced `rand::thread_rng()` with `OsRng` in all cryptographic key generation paths (BIP39 entropy, PGP export, DID key generation)
- Hardened Argon2id parameters: 64 MiB memory / 3 iterations (up from default 19 MiB / 2 iterations) per OWASP recommendations
- Added `#![deny(unsafe_code)]` to `openvtc-lib` — no unsafe code in production paths
- Added DID format validation for `OPENVTC_MEDIATOR_DID` and `OPENVTC_ORG_DID` environment variable overrides
- Replaced all production `unwrap()` calls with proper error handling in setup wizard, clipboard operations, and service initialization
- Replaced ~15 silent `let _ =` error discards with `debug!`/`warn!` logging in state handler, service, and robotic-maintainers

### Added

- Argon2id as sole KDF (removed legacy fallback)
- Profile name validation (alphanumeric, hyphens, underscores only)
- Rate limiting to `openvtc-service` (50 msg/sec with throttle logging)
- Graceful shutdown signal handling (SIGINT/SIGTERM) in `openvtc-service`
- Criterion benchmarks for `derive_passphrase_key` and `unlock_code_encrypt`/`unlock_code_decrypt`
- Integration tests for profile validation, relationships, VRCs, tasks, and logs (38 new tests)
- `CODE_OF_CONDUCT.md` (Contributor Covenant v2.1)
- Windows to CI test matrix
- MSRV verification (Rust 1.91.0) in CI pipeline
- API documentation for public modules (relationships, VRCs, tasks, logs, config)

### Fixed

- All Clippy warnings (migrated deprecated Protocols API, collapsible-if, items-after-test-module)
- Corrected valid-until prompt handling for VRC issuance in `openvtc-cli` (PR #23)

### New: `did-git-sign` crate

A standalone CLI tool for signing git commits using DID Ed25519 keys managed by a VTA. Acts as a git SSH signing proxy — no private key material ever touches disk.

- Git SSH signing proxy via `gpg.ssh.program` integration
- VTA authentication with token caching in OS keyring
- Credential private key stored in OS keyring (macOS Keychain / Linux Secret Service)
- Ed25519 signing key fetched from VTA at sign-time and zeroized after use
- SSH signature output in PROTOCOL.sshsig format
- `init` command — configures git and sets up allowed_signers for verification
- `status` command — displays current signing configuration and keyring state
- `verify` command — end-to-end test of keyring, VTA auth, key fetch, and signing
- Config validation: rejects non-HTTPS VTA URLs, empty credentials, non-Ed25519 keys
- Retry logic for VTA authentication (up to 2 attempts on transient failures)

### Dependency Updates

- `didwebvh-rs` 0.1 &rarr; 0.4
- `affinidi-tdk` 0.5 &rarr; 0.6 (`affinidi-messaging-didcomm` 0.12 &rarr; 0.13)
- `affinidi-data-integrity` 0.4 &rarr; 0.5
- `dtg-credentials` switched from local path to crates.io (`0.1`)
- `vta-sdk` updated to 0.3 (`health.version` is now `Option<String>`, `VtaClient::set_token` no longer requires `&mut self`, `CreateDidWebvhRequest` has new optional fields)
- All transitive dependencies updated to latest compatible versions via `cargo update`

### didwebvh-rs 0.4 Migration

- Replaced manual `DIDWebVHState::default()` + `create_log_entry()` pattern with the new `create_did(CreateDIDConfig)` API in both `openvtc-lib` and `openvtc-cli`
- `create_initial_webvh_did()` is now async (required by `create_did`)
- Added `LogEntryMethods` trait import for `get_did_document()` access

### Breaking API Changes (from dependency updates)

- `DataIntegrityProof::sign_jcs_data()` is now async — added `.await` in `openvtc-cli`, `robotic-maintainers`, and `dtg-credentials`
- `DTGCredential::sign()` is now async
- `CreateDidWebvhRequest.server_id` changed from `String` to `Option<String>`
- `CreateDidWebvhRequest` now requires `url: Option<String>` field and new optional fields (`did_document`, `did_log`, `signing_key_id`, `ka_key_id`, `set_primary`)
- `CreateDidWebvhResultBody.mnemonic` changed to `Option<String>`
- `Message::pack_encrypted()` removed — replaced with `ATM::pack_encrypted(&msg, to, from, sign_by)`
- `Message.type_` field renamed to `Message.typ`
- `didcomm::error::Error` replaced by `didcomm::DIDCommError`
- `PackEncryptedOptions` removed — encryption options are now implicit in the pack function choice
- `UnpackMetadata` moved from `didcomm` to `messaging::messages::compat`
- `VtaClient::set_token()` no longer requires `&mut self`
- `HealthResponse.version` changed from `String` to `Option<String>`

### Security Improvements

- Custom `Debug` implementations for `PersonaDIDKeys` and `KeyInfo` that redact secret material
- Replaced debug logging of full `SecuredConfig` struct with safe summary
- Fixed `unwrap()` in SSH signature encoding path with `expect()` and context
- VTA URL validation — rejects plain HTTP (except localhost for development)
- Ed25519 key type validation when fetching signing keys from VTA
- Empty access token rejection after VTA authentication

### Code Quality

- Extracted 11 hardcoded protocol URLs to `protocol_urls` constants module in `openvtc-lib`
- Added `mediator_did()` and `org_did()` helper functions with environment variable overrides (`OPENVTC_MEDIATOR_DID`, `OPENVTC_ORG_DID`)
- Updated `MessageType` `From`/`TryFrom` impls and VRC message builders to use protocol URL constants
- Removed unused `console` and `crossterm` dependencies from `openvtc-lib`

### Tests

- **openvtc-lib**: Added 14 new tests (2 &rarr; 16 total)
  - Encrypt/decrypt roundtrip, wrong key rejection, empty data, large data, different key ciphertext divergence, corrupted data detection, zeroize verification
  - Protected config save/load roundtrip, wrong seed rejection, serialization, contacts find/remove, credential seed determinism and divergence
- **did-git-sign**: Added 6 new tests (5 &rarr; 11 total)
  - Config validation (empty URL, HTTP rejection, HTTPS acceptance, localhost exception, empty key ID rejection, seed material zeroization)

### Documentation

- Added `did-git-sign/README.md` with setup instructions, architecture diagram, security model, and config format reference
- Added workspace crates table and DID Git Signing section to root `README.md`

## [0.1.3] - 2026-04-03

### Security

- Fixed deterministic encryption vulnerability in `unlock_code_encrypt`/`unlock_code_decrypt` (`openvtc-lib`). The previous implementation used a seeded PRNG to derive both the AES-256-GCM key and nonce from the unlock code, producing identical ciphertext for the same password and plaintext. The fix uses HKDF-SHA256 for key derivation with a random nonce (via `OsRng`), ensuring each encryption produces unique output. Existing configs encrypted with the old format are transparently decrypted via a legacy fallback and re-encrypted with the secure format on the next save.

## [0.1.2] - 2026-04-03

### Added

- CLI interface for `openvtc-service` with `--config`/`-c` flag to specify an alternate configuration file path (default: `conf/config.json`).
- `--help` and `--version` flags for `openvtc-service`.
- Comprehensive operator documentation for `openvtc-service`: configuration schema, logging (`RUST_LOG`), runtime behavior, and protocol context.

### Removed

- Unused `chrono` and `rand` dependencies from `openvtc-service`.

## [0.1.1] - 2026-04-03

### Fixed

- Aligned documented minimum Rust version with workspace `rust-version` (1.91.0) in root README, `openvtc-lib`, and `openvtc-service` READMEs.
- Removed duplicate introductory paragraph and repeated bullet in Decentralised Identity section.
- Fixed typo "Remove" to "Remote" in Private Configuration section.
- Changed incorrect `html` code fence to `text` for a URL example under Host Your DID Document.
- Updated README badges to link to current repository (`OpenVTC/openvtc`).
