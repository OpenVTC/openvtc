//! Fixtures shared by the identity-pane tests: an attribute, a state holding a
//! pane, and an open face.

use openvtc_core::persona::pool::PoolAttribute;

use crate::state_handler::main_page::content::IdentityState;
use crate::state_handler::state::State;

pub(super) fn attribute(id: &str) -> PoolAttribute {
    PoolAttribute {
        attribute_id: id.to_string(),
        claim_type: "email.work".to_string(),
        value_type: "string".to_string(),
        version: 4,
        ..PoolAttribute::default()
    }
}

pub(super) fn state_with(personas: IdentityState) -> State {
    let mut state = State::default();
    state.main_page.content_panel.identity = personas;
    state
}

pub(super) fn personas(state: &State) -> &IdentityState {
    &state.main_page.content_panel.identity
}

/// A face detail with three claims, two of which carry a mask style.
pub(super) fn open_face() -> openvtc_core::persona::profile::ProfileDetail {
    use openvtc_core::persona::profile::{ProfileDetail, ProfileSummary, ResolvedClaim};
    ProfileDetail {
        summary: ProfileSummary {
            profile_id: "01P".into(),
            name: "OSS Developer".into(),
            ..ProfileSummary::default()
        },
        resolved: vec![
            ResolvedClaim {
                claim_type: "name.legal".into(),
                value: Some(serde_json::json!("Glenn Gore")),
                ..ResolvedClaim::default()
            },
            ResolvedClaim {
                claim_type: "email.work".into(),
                value: Some(serde_json::json!("glenn@example.com")),
                ..ResolvedClaim::default()
            },
        ],
        ..ProfileDetail::default()
    }
}
