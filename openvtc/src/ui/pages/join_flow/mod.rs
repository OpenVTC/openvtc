//! The State-B "join a community" flow UI (R-A-5 Stage 4).
//!
//! A small multi-page [`Component`] mirroring [`SetupFlow`](super::setup_flow):
//! `VtcEnterDid` collects the community DID, `IdentityChoice` picks the persona
//! to present, `InvitationChoice` asks whether an invitation rides with it (on
//! the reuse path — a freshly minted persona can hold none), then `JoinProgress`
//! shows the automated mint + join sequence. The page selection is driven by
//! [`JoinState.page`](crate::state_handler::join::JoinState::page); the VTC DID
//! `Input` lives on this component (mirroring how `vta_enter_did` holds its
//! input), and persists across re-renders via `move_with_state`.

use crate::{
    state_handler::{
        actions::Action,
        join::{JoinPage, JoinState},
        state::State,
    },
    ui::{
        component::{Component, ComponentRender},
        pages::join_flow::{
            context_choice::ContextChoice, identity_choice::IdentityChoice,
            invitation_choice::InvitationChoice, join_progress::JoinProgress,
            vtc_enter_did::VtcEnterDid,
        },
    },
};
use crossterm::event::{KeyEvent, KeyEventKind};
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;
use tui_input::Input;

pub mod context_choice;
pub mod identity_choice;
pub mod invitation_choice;
pub mod join_progress;
pub mod vtc_enter_did;

/// Handles the join flow sequence.
#[derive(Clone)]
pub struct JoinFlow {
    /// Action sender.
    pub action_tx: UnboundedSender<Action>,

    /// The community (VTC) DID input (page 1). Held on the component so it
    /// survives re-renders without round-tripping through the watch channel.
    pub vtc_did: Input,

    /// The issuer DID last prefilled into [`vtc_did`](Self::vtc_did) from a
    /// pasted invitation. `move_with_state` runs on every state broadcast, so
    /// without this the prefill would fight the operator — retyping over it on
    /// each redraw. Comparing against it means a *new* invitation prefills once
    /// and anything typed afterwards is left alone.
    pub prefilled_issuer: Option<String>,

    // Page handlers (zero-sized — they read from `props.state`).
    pub vtc_enter_did: VtcEnterDid,
    pub invitation_choice: InvitationChoice,
    pub identity_choice: IdentityChoice,
    pub context_choice: ContextChoice,
    pub join_progress: JoinProgress,

    /// State-mapped join props.
    pub props: Props,
}

#[derive(Clone)]
pub struct Props {
    pub state: JoinState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            state: state.join.clone(),
        }
    }
}

impl JoinFlow {
    /// Fill the community-DID input from a pasted invitation's issuer.
    ///
    /// A VIC's issuer *is* the community that will receive the join, so once one
    /// is loaded the DID is already in hand — asking the operator to go and find
    /// the same DID a second time is the "pressing Enter does nothing" report in
    /// issue #29. Prefilling (rather than submitting) keeps the community on
    /// screen and editable: an invitation is handed to you by someone else, so
    /// the DID it points at is worth a look before Enter commits to joining it.
    ///
    /// Only fills an empty field or one still holding a previous prefill —
    /// anything typed or pasted by hand wins over the credential.
    fn prefill_from_invitation(&mut self) {
        let Some(issuer) = self.props.state.invitation_issuer.as_deref() else {
            // Invitation cleared (Ctrl+L): forget the prefill so re-pasting the
            // same VIC fills the field again.
            self.prefilled_issuer = None;
            return;
        };
        if self.prefilled_issuer.as_deref() == Some(issuer) {
            return;
        }
        let current = self.vtc_did.value().trim();
        if current.is_empty() || Some(current) == self.prefilled_issuer.as_deref() {
            self.vtc_did = Input::new(issuer.to_string());
        }
        self.prefilled_issuer = Some(issuer.to_string());
    }
}

impl Component for JoinFlow {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        JoinFlow {
            action_tx,
            vtc_did: Input::default(),
            prefilled_issuer: None,
            vtc_enter_did: VtcEnterDid,
            invitation_choice: InvitationChoice,
            identity_choice: IdentityChoice,
            context_choice: ContextChoice,
            join_progress: JoinProgress,
            props: Props::from(state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        let mut next = JoinFlow {
            props: Props::from(state),
            ..self
        };
        next.prefill_from_invitation();
        next
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match self.props.state.page {
            JoinPage::EnterDid => VtcEnterDid::handle_key_event(self, key),
            JoinPage::InvitationChoice => InvitationChoice::handle_key_event(self, key),
            JoinPage::IdentityChoice => IdentityChoice::handle_key_event(self, key),
            JoinPage::ContextChoice => ContextChoice::handle_key_event(self, key),
            JoinPage::Progress => JoinProgress::handle_key_event(self, key),
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        if self.props.state.processing {
            return;
        }
        let trimmed = text.trim();
        match self.props.state.page {
            JoinPage::EnterDid => {
                // A pasted JSON object is treated as an invitation credential
                // (VIC): hand it to the state handler to validate + stash (#3).
                // Anything else is the VTC DID being pasted into the input.
                if trimmed.starts_with('{') {
                    // Re-arm the prefill: a paste is a deliberate act, so
                    // pasting the same VIC again after clearing the input fills
                    // it back in rather than being a no-op.
                    self.prefilled_issuer = None;
                    let _ = self
                        .action_tx
                        .send(Action::JoinPasteVic(trimmed.to_string()));
                } else {
                    self.vtc_did = Input::new(trimmed.to_string());
                }
            }
            // The invitation step has no text input, so anything pasted there is
            // an invitation being offered. This is the portable half of the paste
            // row — bracketed paste works over SSH, where reading the OS
            // clipboard does not.
            JoinPage::InvitationChoice => {
                let _ = self
                    .action_tx
                    .send(Action::JoinPasteVic(trimmed.to_string()));
            }
            // A pasted name lands in the new sub-context's name.
            JoinPage::ContextChoice if self.props.state.new_context_selected() => {
                let mut slug = self.props.state.context_slug.clone();
                slug.push_str(trimmed);
                let _ = self.action_tx.send(Action::JoinContextSlug(slug));
            }
            JoinPage::IdentityChoice | JoinPage::ContextChoice | JoinPage::Progress => {}
        }
    }
}

impl ComponentRender<()> for JoinFlow {
    fn render(&self, frame: &mut Frame, _props: ()) {
        match self.props.state.page {
            JoinPage::EnterDid => {
                self.vtc_enter_did
                    .render(&self.props.state, &self.vtc_did, frame)
            }
            JoinPage::InvitationChoice => self.invitation_choice.render(&self.props.state, frame),
            JoinPage::IdentityChoice => self.identity_choice.render(&self.props.state, frame),
            JoinPage::ContextChoice => self.context_choice.render(&self.props.state, frame),
            JoinPage::Progress => self.join_progress.render(&self.props.state, frame),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Prefilling the community-DID input from a pasted invitation (issue #29).
    //! `move_with_state` runs on every state broadcast, so the interesting cases
    //! are all about *not* overwriting the operator on a redraw.
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    const ISSUER: &str = "did:webvh:QmRoot:community.example.com";

    fn flow() -> JoinFlow {
        let (tx, _rx) = unbounded_channel();
        JoinFlow::new(&State::default(), tx)
    }

    /// Set an issuer on the state and push it through the same path the runtime
    /// uses, so the tests exercise `move_with_state` rather than the helper.
    fn broadcast(flow: JoinFlow, issuer: Option<&str>) -> JoinFlow {
        let mut state = State::default();
        state.join.invitation_issuer = issuer.map(str::to_string);
        flow.move_with_state(&state)
    }

    #[test]
    fn a_pasted_invitation_fills_the_empty_did_input() {
        let flow = broadcast(flow(), Some(ISSUER));
        assert_eq!(flow.vtc_did.value(), ISSUER);
    }

    /// The whole point of the guard: a redraw must not keep re-stamping the
    /// input after the operator has edited what was prefilled.
    #[test]
    fn a_later_redraw_leaves_an_edited_prefill_alone() {
        let mut flow = broadcast(flow(), Some(ISSUER));
        flow.vtc_did = Input::new("did:webvh:somewhere.else".to_string());
        let flow = broadcast(flow, Some(ISSUER));
        assert_eq!(flow.vtc_did.value(), "did:webvh:somewhere.else");
    }

    /// A DID typed *before* the paste is the operator's own answer; the
    /// credential fills a blank, it does not overrule one.
    #[test]
    fn a_typed_did_survives_a_paste() {
        let mut flow = flow();
        flow.vtc_did = Input::new("did:webvh:typed.by.hand".to_string());
        let flow = broadcast(flow, Some(ISSUER));
        assert_eq!(flow.vtc_did.value(), "did:webvh:typed.by.hand");
    }

    /// Clearing the invitation (Ctrl+L) drops the issuer, which re-arms the
    /// prefill so a subsequent paste is not a no-op.
    #[test]
    fn clearing_the_invitation_re_arms_the_prefill() {
        let flow = broadcast(flow(), Some(ISSUER));
        let mut flow = broadcast(flow, None);
        assert_eq!(flow.prefilled_issuer, None);
        flow.vtc_did = Input::default();
        let flow = broadcast(flow, Some(ISSUER));
        assert_eq!(flow.vtc_did.value(), ISSUER);
    }

    /// Pasting a VIC is a deliberate act, so it re-arms the prefill: paste,
    /// clear the field by hand, paste the same VIC again — it fills back in.
    #[test]
    fn re_pasting_after_clearing_the_field_fills_it_again() {
        let mut flow = broadcast(flow(), Some(ISSUER));
        flow.vtc_did = Input::default();
        // The paste itself only re-arms; the fill lands on the state broadcast
        // the handler sends back.
        flow.handle_paste_event(r#"{"id":"urn:uuid:one"}"#);
        let flow = broadcast(flow, Some(ISSUER));
        assert_eq!(flow.vtc_did.value(), ISSUER);
    }

    /// Non-JSON pasted on the entry page is still the VTC DID going into the
    /// input, untouched by any of the above.
    #[test]
    fn a_pasted_did_still_goes_into_the_input() {
        let mut flow = flow();
        flow.handle_paste_event("  did:webvh:pasted.example.com  ");
        assert_eq!(flow.vtc_did.value(), "did:webvh:pasted.example.com");
    }
}
