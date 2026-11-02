# Community data rooms

A community can own **data rooms**: shared, end-to-end sealed sets of records and
files. Administrators create them and offer members admission; a member accepts.
Press **`o`** on an active community in the Communities panel to open its rooms.

## One record, every surface

You can reach a community's rooms from its **member portal** (through your wallet),
from **`pnm`**, and from **OpenVTC**. None of them keeps its own note of which rooms
you accepted. Each reads the same two records:

| Record | Kept by | Says |
|---|---|---|
| `vtc/rooms/memberships/list` (0.2) | the community | every room it offered you: `offered`, `admitted`, `suspended` or `removed`, and where the room itself stands |
| `rooms/keys/list` | your VTA | which rooms' keys it holds, for which persona |

and shows the same standing from them:

| Community | Tier | VTA holds the keys | Shown as |
|---|---|---|---|
| offered | any | — | **offered** — ⏎ accepts |
| admitted | open | — | **joined** |
| admitted | sealed | yes | **joined** |
| admitted | sealed | no, while the community keeps the Welcome | **accepted — finish joining** — ⏎ finishes |
| admitted | sealed | no, after that | **needs re-admission** — an administrator removes and re-admits you |
| suspended | any | either | **suspended** — the room is closed; restored if it reopens |
| removed | any | either | **removed** |

So a room you accepted in the portal shows here as joined, with nothing to do.

## Archived and removed rooms

An administrator can archive a room or remove it. Beside your standing the panel shows
what the room's state means for you:

| Room | Shown as | What it means |
|---|---|---|
| archived read-only | **· read-only** | you can still read it; nothing can be written and nobody new is admitted |
| archived, no access | **suspended · closed for now** | your access is withdrawn; it is restored if the community reopens the room |
| removal scheduled | **suspended · being removed** | its content is deleted on the date shown |
| removed | **removed · room removed** | nothing of it is left to open |

Accepting is offered only in an active room: an archived one, or one being removed,
admits nobody. Nothing you already read is affected by any of these.

## Renewed access

The community renews an admission by having the room issue you fresh credentials, kept
for you in `vtc/rooms/offers/list/0.4`'s `renewals`. This is also how a member suspended
while a room was closed gets back in when it reopens. On every read, once a VTA is
connected, OpenVTC has your VTA store any renewal it does not hold yet, in place of the
credential it renews (as `pnm rooms offers renew` does), and says so. A renewal already
stored is left alone.

## Accepting, and finishing elsewhere

Accepting a sealed room is four steps: collect the offer's credentials from the
community, have your VTA store them and give a KeyPackage, accept with it, and have
your VTA join from the Welcome the community answers with. Each step answers a repeat
with its first answer:

- your VTA returns the KeyPackage it already holds for the same room, persona and
  invitation (`rooms/keys/key-package/0.2`), instead of making another;
- the community answers an acceptance carrying it with the Welcome it kept;
- your VTA answers a Welcome it already processed with `alreadyJoined`, which OpenVTC
  reads as joined.

So if an acceptance was interrupted — the portal tab closed, the laptop slept —
pressing ⏎ on the room here finishes it, and the panel says it is finishing an
acceptance begun elsewhere. Against a VTA that predates `key-package/0.2` OpenVTC
still accepts, but an acceptance interrupted there can't be finished from another
surface.

## Requirements

- **A VTA.** It holds the rooms' keys and your credentials for them; without one the
  panel shows the community's record but can't accept or tell whether a sealed room
  is joined.
- A community serving `vtc/rooms/memberships/list/0.2` (VTI #2380 and later). One that
  doesn't says so, and the panel shows its refusal.
