# Hidden vetting: a live run

How to stand up a community that hides its vetters, and take an applicant through it with the
real client over the real wire. Everything here runs against two processes — a `vtc-service` and
an `openvtc` — and nothing is mocked.

For the design, read [`vetting-hidden-vetters-pcs.md`](vetting-hidden-vetters-pcs.md). For what
the protocol does with nothing around it, run the example instead:

```sh
cargo run --release -p openvtc-vetting-pcs --example hidden_vetting
```

## 0. What is different about this build

Two things, and both are deliberate.

**The community must be built with the feature.** `vetting-pcs` is off by default in
`vtc-service`, because it pulls in a vendored, unaudited research library. A community built
without it cannot verify a hidden proof, and — by design — will not advertise the mode either.

```sh
cargo run -p vtc-service --features vetting-pcs -- serve
```

**The client needs no flag.** `openvtc` always carries the hidden path; whether it is used is the
community's decision, read from the community's own manifest.

## 1. Stand up a community

Follow the VTI repository's `docs/03-vtc/getting-started.md` as normal — a VTA provisions the
VTC's DID and keys, and the VTC writes its config. Nothing on that path is specific to hidden
vetting.

What matters for what follows: **the credential signer must be initialised**, because the
hidden-vetting keys are derived from its master secret rather than stored separately. A community
that can issue a membership credential can run hidden vetting; one that cannot, cannot.

## 2. Register a criterion that asks for vetting

Hidden vetting qualifies a community's vetting requirements — it does not replace them. So the
criterion needs requirements first, and they are the ordinary ones:

```sh
curl -sS -X POST http://localhost:8200/v1/schemas/accepts \
  -H "authorization: Bearer $VTC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{
    "id": "kernel-developer",
    "query": { "credentials": [ { "id": "membership", "format": "dc+sd-jwt",
                "meta": { "vct_values": ["https://openvtc.org/credentials/MembershipCredential"] },
                "claims": [ { "path": ["givenName"] } ] } ] },
    "vetting": {
      "version": "0.1",
      "statementType": "https://firstperson.network/endorsements/identity-vetting/0.1",
      "minStatements": 3,
      "minByMethod": { "inPerson": 1 },
      "acceptedMethods": ["inPerson", "video"],
      "requiredClaims": ["name.legal"],
      "eligibleVetters": { "role": "vetter" }
    }
  }'
```

Three vetters, one of them in person. That is what the community will require whether the vetters
are named or hidden — which is the whole point of the design.

## 3. Turn on hidden vetting

One call. It derives the community's PCS keys from the credential signer, publishes them on the
criterion, and hands back exactly what applicants and vetters will read:

```sh
curl -sS -X POST http://localhost:8200/v1/vetting/hidden \
  -H "authorization: Bearer $VTC_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{ "criterionId": "kernel-developer" }'
```

Defaults are this month's labels and a drip of three tokens a tick. The response carries:

- `stored` — what the community keeps, including the members a client is never told.
- `published` — what now appears in the join manifest under `vetting.ext`.
- `requirementsDigest` — **it moves**, because the digest covers the published parameters. Any
  applicant mid-application will be told its requirements changed. That is correct: they have.

Check it landed where a client looks:

```sh
curl -sS http://localhost:8200/v1/join-requests/manifest \
  -H "authorization: Bearer $VTC_ADMIN_TOKEN" \
  | jq '.criteria[0].vetting.ext'
```

The keys are derived, never chosen. Calling this again with the same body produces the same keys;
calling it with different labels rotates them, which is a real change.

## 4. Name some vetters

Three members, through the ordinary grant path (`POST /v1/vetting/vetters`, or
`vtc/vetting/vetters/grant/0.1` over DIDComm). Nothing here knows about hidden vetting — a vetter
grant is a vetter grant, and that is what the hidden path checks too.

## 5. Each vetter's client enrols and draws tokens

In `openvtc`, as each vetter: go to the vetting desk and press **`m`**.

That asks every community that has named you a vetter what it requires. When the answer says the
community hides its vetters, the client mints this vetter's key pair, and the schedule takes over.
Press `m` again to advance it — each press is one round trip:

1. the manifest arrives, and the client says the community hides its vetters;
2. enrolment: a blind class credential for `vetter/<month>`;
3. the first tick of the drip — three attestation tokens.

The drip is **unconditional and on a schedule**. A vetter draws whether or not it has vetted
anyone, because a fetch that happened only when someone was busy would announce that they were
busy.

To vet at a conference instead, press **`e`**: the community's published event tiers, with the
event's own days as the window, and the price of the faster rate stated before it is asked for.
Approving an event is an admin re-posting the criterion with `approvedBy` set — a vetter cannot
approve its own.

## 6. The applicant applies

In another `openvtc`: start an application to the community as usual. On `m`, the client reads
the manifest, sees the parameters, and mints a key for this application and no other. The
requirements line ends **"their names never reach this community"** — that is the mode saying so
on screen.

Then the ordinary ceremony: a ticket, a session, a Vetting Card. Nothing about it changes. Only
the last step differs — the vetter attests under its blind credential and spends a token, and what
the applicant receives carries a tag where an issuer would be.

## 7. Submit

The applicant asks the community for a challenge and submits one proof over all three
attestations. The community counts it with the rule it already had, and admits — minting the same
membership credential pair and role credential a named admission mints.

Afterwards, check what the community can tell:

```sh
curl -sS http://localhost:8200/v1/join-requests/<id>/vetting \
  -H "authorization: Bearer $VTC_ADMIN_TOKEN" | jq
```

Three distinct vetters, their methods, their claims — and three tags where three DIDs would be.
The admin console renders them as tags rather than passing them to a DID renderer, with a note
that the count came from a proof.

## What is still manual

- **Approving an event** is a criterion re-post rather than a console action.
- **Rotating the class label** is the same call as §3 with different `livePeriods`; nothing
  schedules it.
- **The payload types are hand-written** and validated against the published schemas
  (`vtc-service/src/vetting/schemas/`). They are deleted when the `trust-tasks-rs` 0.22 line
  reaches the VTI graph — see §19.5 of the design note for why that is a five-crate queue and
  none of it ours.
