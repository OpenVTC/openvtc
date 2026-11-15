//! Fixtures shared by the vetting tests: a hidden-vetter book, mode readings,
//! a pending ticket, and first-vtc's manifest.

use chrono::{DateTime, Utc};
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::book::HiddenVetterState;
use openvtc_core::vetting::mode::VetterMode;
use serde_json::Value;

use crate::state_handler::main_page::content::{PendingTicket, VettingMembership};

/// An application made as a persona this account no longer holds is never
/// offered as the one to search a community's directory as: it cannot sign
/// the request, and offering it made every search fail.
pub(super) fn hidden_vetter_book(tokens: usize, enrolled: bool) -> (VettingBook, PersonaId) {
    use openvtc_core::vetting::hidden::HiddenParams;
    let persona = PersonaId::new();
    let params = HiddenParams {
        suite: openvtc_core::vetting::hidden::SUITE.into(),
        helper_key: "zHelper".into(),
        token_key: "zToken".into(),
        vetter_labels: vec!["vetter/2026-10".into()],
        token_labels: vec!["token/2026-10".into()],
        drip_per_tick: 10,
        events: Vec::new(),
        tick_length: None,
    };
    let mut held = HiddenVetterState::new("did:web:first-vtc.example", persona, params);
    // What the VTA reports holding.
    let tokens = u64::try_from(tokens).unwrap();
    held.take_engine(openvtc_core::vetting::pcs_vta::VetterView {
        id: "z3Vetter".into(),
        enrolled_labels: if enrolled {
            vec!["vetter/2026-10".into()]
        } else {
            Vec::new()
        },
        tokens_free: tokens,
        tokens_held: tokens,
        ..Default::default()
    });
    let mut book = VettingBook::default();
    book.hidden_vetter.push(held);
    read_as(
        &mut book,
        "did:web:first-vtc.example",
        VetterMode::PcsZkp,
        Utc::now(),
    );
    (book, persona)
}

/// Record that `community`'s manifest, read at `at`, said `mode`.
pub(super) fn read_as(
    book: &mut VettingBook,
    community: &str,
    mode: VetterMode,
    at: DateTime<Utc>,
) {
    use openvtc_core::vetting::book::KnownCommunity;
    use openvtc_core::vetting::mode::ModeRead;
    let read = Some(ModeRead { mode, read_at: at });
    match book
        .communities
        .iter_mut()
        .find(|c| c.community == community)
    {
        Some(known) => known.vetter_mode = read,
        None => book.communities.push(KnownCommunity {
            community: community.into(),
            branding: Default::default(),
            requested: Vec::new(),
            fetched_at: at,
            protocol: None,
            routes: Vec::new(),
            post_quantum_key: None,
            vetter_mode: read,
            directory: None,
        }),
    }
}

/// A manifest payload whose one criterion names its vetters (`false`) or publishes
/// hidden-vetting parameters (`true`).
pub(super) fn manifest_payload(pcs: bool) -> Value {
    let mut vetting = serde_json::json!({});
    if pcs {
        vetting["ext"] = serde_json::json!({
            openvtc_core::vetting::hidden::HIDDEN_VETTING_NS: {
                "suite": openvtc_core::vetting::hidden::SUITE,
                "helperKey": "zHelper",
                "tokenKey": "zToken",
                "vetterLabels": ["vetter/2026-10"],
                "tokenLabels": ["token/2026-10"],
            }
        });
    }
    serde_json::json!({ "criteria": [ { "id": "c1", "vetting": vetting } ] })
}

pub(super) fn pending_for(persona: PersonaId, asked_at: DateTime<Utc>) -> PendingTicket {
    PendingTicket {
        membership: VettingMembership {
            community: "did:web:first-vtc.example".into(),
            name: "first-vtc".into(),
            persona,
            accent: None,
        },
        uses: 1,
        asked_at,
    }
}

/// first-vtc's live manifest: `vetted-member` runs PCS ZKP alongside named vetters.
pub(super) fn first_vtc_book() -> (VettingBook, String) {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../openvtc-core/tests/fixtures/first-vtc-manifest-0.3.json"
    ))
    .unwrap();
    let payload = document["payload"].clone();
    let community = payload["communityDid"].as_str().unwrap().to_string();
    let protocol = openvtc_core::vetting::protocol::JoinProtocol::V0_4;
    let (parsed, meta) =
        openvtc_core::vetting::protocol::read_manifest(protocol, &payload).unwrap();
    let mut book = VettingBook::default();
    let now = Utc::now();
    book.learn_manifest_in(&community, &parsed, Some(protocol), &meta, now);
    book.learn_mode(&community, &payload, None, now);
    (book, community)
}
