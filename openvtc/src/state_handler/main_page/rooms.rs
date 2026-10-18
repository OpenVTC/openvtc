//! The Rooms panel's state: a community's data rooms, from the member's side.
//!
//! Display state only, rebuilt from the community's record
//! (`vtc/rooms/memberships/list`) and the member's VTA (`rooms/keys/list`) on every open
//! and refresh. **Nothing here is persisted**: the member reaches these rooms from other
//! surfaces too — the member portal, `pnm` — and a record kept here would be the one place
//! they disagree ([`openvtc_core::community_rooms`]).

use std::time::Instant;

use openvtc_core::community_rooms::{Offer, RoomMembership, Standing};
use openvtc_core::config::account::PersonaId;

pub use super::repos::{Severity, Status};

/// What the community and the member's VTA say, once both have answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomsPhase {
    Loading,
    Loaded,
    /// The first read failed, and why.
    Failed(String),
}

/// What an outstanding request to the community is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A page of the record (`vtc/rooms/memberships/list`).
    Memberships,
    /// The open offers, to accept `room` from.
    Offers { room: String },
    /// The acceptance of `room`, carrying the KeyPackage when sealed.
    Accept { room: String },
}

/// A request to the community awaiting its answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub thid: String,
    pub sent_at: Instant,
    pub purpose: Purpose,
}

/// One room, as every surface shows it.
#[derive(Clone, Debug)]
pub struct RoomRow {
    pub room: RoomMembership,
    pub standing: Standing,
}

/// Where an acceptance is, across the community and the VTA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptStep {
    /// Reading the offer's credentials from the community.
    Collecting,
    /// The VTA is storing the credentials and giving the KeyPackage.
    Preparing,
    /// The acceptance is with the community.
    Accepting,
    /// The VTA is joining from the Welcome.
    Joining,
}

/// The next step a reply or a VTA answer calls for. Taken by the loop
/// ([`crate::state_handler::rooms_actions::advance`]), which alone can send; a step that
/// finds its lane busy waits here for the next tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Read the record and the custody again.
    Refresh,
    /// The record's next page.
    MembershipsPage { cursor: String },
    /// The offers' next page, still looking for `room`.
    OffersPage { room: String, cursor: String },
    /// Have the VTA store the offer's credentials and give the KeyPackage.
    Prepare,
    /// Send the acceptance.
    SendAccept {
        room: String,
        key_package: Option<String>,
    },
    /// Have the VTA join from the Welcome.
    Join {
        room: String,
        welcome: String,
        ratchet_tree: Option<String>,
    },
}

/// An acceptance in progress. One at a time.
#[derive(Clone, Debug)]
pub struct AcceptFlow {
    pub room: String,
    pub step: AcceptStep,
    /// The offer, once collected: its invitation is what the Welcome is joined under.
    pub offer: Option<Box<Offer>>,
}

/// The open panel.
#[derive(Clone, Debug)]
pub struct RoomsView {
    pub vtc_did: String,
    pub persona: PersonaId,
    /// The persona DID the community knows the member by.
    pub me: String,
    pub community: String,
    pub phase: RoomsPhase,
    /// The community's record, as it last answered. Pages accumulate in `incoming`.
    pub rooms: Vec<RoomMembership>,
    incoming: Vec<RoomMembership>,
    /// The rooms whose groups the VTA holds for `me`; `None` before it answered or
    /// when there is no VTA to ask.
    pub held: Option<Vec<String>>,
    /// Why the VTA could not be asked, when it could not.
    pub held_error: Option<String>,
    pub selected: usize,
    pub pending: Option<Pending>,
    pub accept: Option<AcceptFlow>,
    pub next: Option<Next>,
    pub status: Option<Status>,
}

impl RoomsView {
    #[must_use]
    pub fn new(vtc_did: String, persona: PersonaId, me: String, community: String) -> Self {
        Self {
            vtc_did,
            persona,
            me,
            community,
            phase: RoomsPhase::Loading,
            rooms: Vec::new(),
            incoming: Vec::new(),
            held: None,
            held_error: None,
            selected: 0,
            pending: None,
            accept: None,
            next: None,
            status: None,
        }
    }

    /// The rooms, each with its standing.
    #[must_use]
    pub fn rows(&self) -> Vec<RoomRow> {
        self.rooms
            .iter()
            .map(|room| {
                let held = self
                    .held
                    .as_ref()
                    .map(|h| h.iter().any(|r| r == room.room_id.as_str()));
                RoomRow {
                    room: room.clone(),
                    standing: Standing::of(room, held),
                }
            })
            .collect()
    }

    #[must_use]
    pub fn selected_row(&self) -> Option<RoomRow> {
        self.rows().into_iter().nth(self.selected)
    }

    /// Take one page of the record; `last` says whether it was the last.
    pub fn take_page(&mut self, items: Vec<RoomMembership>, last: bool) {
        self.incoming.extend(items);
        if last {
            self.rooms = std::mem::take(&mut self.incoming);
            self.selected = self.selected.min(self.rooms.len().saturating_sub(1));
            self.phase = RoomsPhase::Loaded;
        }
    }

    /// Start reading the record again from its first page.
    pub fn restart_pages(&mut self) {
        self.incoming.clear();
    }

    pub fn note(&mut self, severity: Severity, text: impl Into<String>) {
        self.status = Some(Status {
            text: text.into(),
            severity,
        });
    }

    pub fn clear_progress(&mut self) {
        if self
            .status
            .as_ref()
            .is_some_and(|s| s.severity == Severity::Progress)
        {
            self.status = None;
        }
    }
}

/// The panel, when open.
#[derive(Clone, Debug, Default)]
pub struct RoomsState {
    pub view: Option<RoomsView>,
}
