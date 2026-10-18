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
| `vtc/rooms/memberships/list` | the community | every room it offered you: `offered`, `admitted` or `removed` |
| `rooms/keys/list` | your VTA | which rooms' keys it holds, for which persona |

and shows the same standing from them:

| Community | Tier | VTA holds the keys | Shown as |
|---|---|---|---|
| offered | any | — | **offered** — ⏎ accepts |
| admitted | open | — | **joined** |
| admitted | sealed | yes | **joined** |
| admitted | sealed | no, while the community keeps the Welcome | **accepted — finish joining** — ⏎ finishes |
| admitted | sealed | no, after that | **needs re-admission** — an administrator removes and re-admits you |
| removed | any | either | **removed** |

So a room you accepted in the portal shows here as joined, with nothing to do.

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
- A community serving `vtc/rooms/memberships/list/0.1`. One that doesn't says so, and
  the panel shows its refusal.
