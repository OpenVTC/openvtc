//! Communities panel key handling, including the sub-views it routes to
//! (capabilities, repos, rooms, elections, personhood evidence, context
//! deletion and device access).

use crate::state_handler::actions::Action;
use crate::state_handler::main_page::MainPanel;
use crate::state_handler::main_page::content::CommunitySend;
use crate::ui::pages::main::MainPage;
use crate::ui::pages::main::components::{
    self as components,
    elections_panel::elections_key,
    repos_panel::keys::{repos_copy_path, repos_view_key},
    rooms_panel::rooms_key,
};
use crate::ui::pages::main::grant_form_text;
use crossterm::event::{KeyCode, KeyEvent};

impl MainPage {
    /// Communities overview keys (R-A-5 Stage 4): `n` starts the join flow
    /// (incl. from the empty state), ↑/↓ move the selection, `d`/Del removes the
    /// selected community. Returns true if consumed.
    pub(in crate::ui::pages::main) fn handle_communities_key(&mut self, key: KeyEvent) -> bool {
        // Capabilities view open: it owns the keys until closed (Esc).
        if let Some(view) = self.props.main_page.content_panel.capabilities.view.clone() {
            return self.handle_capabilities_key(key, &view);
        }
        // Repos view open: the same.
        if let Some(view) = self.props.main_page.content_panel.repos.view.clone() {
            if key.code == KeyCode::Char('p')
                && let Some(path) = repos_copy_path(&view)
            {
                let said = match crate::clipboard::copy_to_clipboard(&path) {
                    Ok(method) => format!("✓ Path copied via {}", method.label()),
                    Err(e) => format!("✗ Copy failed: {e}"),
                };
                let _ = self.action_tx.send(Action::Repos(
                    crate::state_handler::actions::ReposAction::Workspace(
                        crate::state_handler::actions::WorkspaceAction::Copied(said),
                    ),
                ));
                return true;
            }
            let action = repos_view_key(key, &view);
            let handled = action.is_some();
            if let Some(action) = action {
                let _ = self.action_tx.send(Action::Repos(action));
            }
            return handled;
        }
        // Rooms view open: the same.
        if let Some(view) = self.props.main_page.content_panel.rooms.view.as_ref() {
            let action = rooms_key(key, view);
            let handled = action.is_some();
            if let Some(action) = action {
                let _ = self.action_tx.send(Action::Rooms(action));
            }
            return handled;
        }
        // Elections view open: the same.
        if let Some(view) = self.props.main_page.content_panel.elections.view.as_ref() {
            let action = elections_key(key, view);
            let handled = action.is_some();
            if let Some(action) = action {
                let _ = self.action_tx.send(Action::Elections(action));
            }
            return handled;
        }
        // The personhood witness-credential picker owns the keys while open.
        if let Some(view) = self
            .props
            .main_page
            .content_panel
            .communities
            .personhood_evidence
            .clone()
        {
            let action = personhood_evidence_key(key, &view);
            let handled = action.is_some();
            if let Some(action) = action {
                let _ = self.action_tx.send(action);
            }
            return handled;
        }
        // Deleting a context, or device access, owns the keys while open.
        if let Some(view) = self
            .props
            .main_page
            .content_panel
            .communities
            .context_delete
            .clone()
        {
            return self.handle_context_delete_key(key, &view);
        }
        if let Some(view) = self
            .props
            .main_page
            .content_panel
            .communities
            .device_access
            .clone()
        {
            return self.handle_device_access_key(key, &view);
        }
        let comms = &self.props.main_page.content_panel.communities;
        // `count` is the memberships — every index-taking action below indexes
        // them, so a cursor on a "Joining" row (`selected >= count`) leaves
        // those keys inert. `rows` is what the cursor moves over.
        let count = comms.items.len();
        let rows = count + comms.joining.len();
        let selected = comms.selected_index;
        let joining = components::communities_panel::joining_selected(comms)
            .map(|j| j.application_id.clone());

        // A removal confirmation is pending: only confirm (y/Enter) or cancel
        // (n/Esc) apply; every other key is swallowed so nothing slips through.
        if let Some(idx) = comms.confirm_delete {
            match key.code {
                KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                    let _ = self.action_tx.send(Action::DeleteCommunity(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelDelete);
                }
            }
            return true;
        }
        // A leave confirmation is pending (R-L-1): same y/n gate.
        if let Some(idx) = comms.confirm_leave {
            match key.code {
                KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                    let _ = self.action_tx.send(Action::LeaveCommunity(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelLeave);
                }
            }
            return true;
        }
        // A cancel-pending-join confirmation is pending: same y/n gate.
        if let Some(idx) = comms.confirm_withdraw {
            match key.code {
                KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                    let _ = self.action_tx.send(Action::WithdrawJoin(idx));
                }
                _ => {
                    let _ = self.action_tx.send(Action::CommunityCancelWithdraw);
                }
            }
            return true;
        }

        // A message to the community is pending: same `y` gate (#579).
        if let Some(send) = comms.confirm_send {
            let _ = self.action_tx.send(Action::CommunityCancelSend);
            if crate::ui::pages::main::confirm::is_yes(&key) {
                let _ = self.action_tx.send(match send {
                    CommunitySend::IssueVmc(idx) => Action::IssueMemberVmc(idx),
                    CommunitySend::Renew(idx) => Action::RenewMembership(idx),
                });
            }
            return true;
        }

        // Status of the highlighted row gates which management keys apply.
        let sel_active = comms.items.get(selected).is_some_and(|c| c.is_active);
        let sel_inactive = comms.items.get(selected).is_some_and(|c| c.is_inactive);
        let sel_pending = comms.items.get(selected).is_some_and(|c| c.is_pending);
        let sel_renewable = comms
            .items
            .get(selected)
            .is_some_and(|c| c.is_active || c.approved_awaiting_credential);
        let sel_own_context = comms.items.get(selected).is_some_and(|c| c.has_own_context);

        match key.code {
            // `n` joins, as `n` starts something new on every other list;
            // `j`/`k` move, as they do in rooms, elections and the menu (#580).
            KeyCode::Char('n') => {
                let _ = self.action_tx.send(Action::StartJoin);
                true
            }
            KeyCode::Up | KeyCode::Char('k') if rows > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect(selected.saturating_sub(1)));
                true
            }
            KeyCode::Down | KeyCode::Char('j') if rows > 0 => {
                let _ = self
                    .action_tx
                    .send(Action::CommunitySelect((selected + 1).min(rows - 1)));
                true
            }
            KeyCode::Enter if selected < count => {
                // Make the highlighted community the working context (R-C-6).
                let _ = self.action_tx.send(Action::SetActiveCommunity(selected));
                true
            }
            KeyCode::Enter if joining.is_some() => {
                // A join in progress: its journey on the Vetting page, where
                // every step of the application is taken.
                if let Some(id) = joining {
                    let _ = self.action_tx.send(Action::Vetting(
                        crate::state_handler::actions::VettingAction::OpenApplication(id),
                    ));
                }
                true
            }
            KeyCode::Char('f') if selected < count => {
                // Toggle the favourite star (R-C-4); the row re-sorts to the top.
                let _ = self.action_tx.send(Action::ToggleFavourite(selected));
                true
            }
            KeyCode::Char('a') if selected < count => {
                // Acknowledge a terminal outcome, clearing its badge (R-S-2).
                let _ = self.action_tx.send(Action::AcknowledgeCommunity(selected));
                true
            }
            KeyCode::Char('l') if sel_active => {
                // Leave an Active community (R-L-1) — arm the y/n confirmation.
                let _ = self.action_tx.send(Action::CommunityConfirmLeave(selected));
                true
            }
            KeyCode::Char('m') if sel_active => {
                // Issue this membership's reciprocal VMC back to the community and
                // send it to the VTC (members/vmc/1.0). Active-only.
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmSend(CommunitySend::IssueVmc(
                        selected,
                    )));
                true
            }
            KeyCode::Char('R') if sel_renewable => {
                // Ask the community to renew this membership — re-issue its
                // membership and role credentials (vtc/members/renew/0.1). This
                // is how a member replaces credentials set aside as pre-v1, and
                // the manual rescue for an approved join whose credential never
                // arrived: the community re-issues, and the renewal activates
                // the membership as delivery would have.
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmSend(CommunitySend::Renew(selected)));
                true
            }
            KeyCode::Char('c') if sel_active => {
                // Open the community's capabilities view (governance/capability/*).
                let _ = self.action_tx.send(Action::CapabilitiesOpen(selected));
                true
            }
            KeyCode::Char('r') if sel_active => {
                // Open the community's Repos view (git-ns/*).
                let _ = self.action_tx.send(Action::Repos(
                    crate::state_handler::actions::ReposAction::Open(selected),
                ));
                true
            }
            KeyCode::Char('o') if sel_active => {
                // Open the community's data rooms (vtc/rooms/memberships/*).
                let _ = self.action_tx.send(Action::Rooms(
                    crate::state_handler::actions::RoomsAction::Open(selected),
                ));
                true
            }
            KeyCode::Char('e') if sel_active => {
                // Open the community's elections (vtc/elections/*).
                let _ = self.action_tx.send(Action::Elections(
                    crate::state_handler::actions::ElectionsAction::Open(selected),
                ));
                true
            }
            // Cancel is pending-only: a Pending join can be withdrawn (arming on
            // any other state would only fail downstream, so it's gated).
            KeyCode::Char('c') if sel_pending => {
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmWithdraw(selected));
                true
            }
            KeyCode::Char('p') if sel_active => {
                // Ask this community for a personhood challenge. Active-only:
                // a community that has not admitted us has no personhood state
                // to assert against.
                let _ = self
                    .action_tx
                    .send(Action::RequestPersonhoodChallenge(selected));
                true
            }
            // Assert is offered only while a live challenge is in hand.
            // Gating on the challenge rather than on the row means the key does
            // nothing surprising when there is nothing to answer — and the
            // panel only advertises it in the same condition.
            KeyCode::Char('P')
                if comms
                    .personhood_challenge
                    .as_ref()
                    .is_some_and(|c| c.is_live(chrono::Utc::now())) =>
            {
                // Asks first: the witness credentials to present are chosen in a picker
                // that opens with none chosen.
                let _ = self
                    .action_tx
                    .send(Action::AssertPersonhood { witnessed: None });
                true
            }
            KeyCode::Char('x') if sel_inactive => {
                // Archive an inactive community (R-C-8).
                let _ = self.action_tx.send(Action::ArchiveCommunity(selected));
                true
            }
            KeyCode::Char('v') => {
                // Toggle whether archived communities are listed (R-C-8).
                let _ = self.action_tx.send(Action::ToggleShowArchived);
                true
            }
            // Delete is inactive-only (R-C-8): an Active community must be left
            // first. Arming on Active would only fail downstream, so it's gated.
            KeyCode::Char('d') | KeyCode::Delete if sel_inactive => {
                let _ = self
                    .action_tx
                    .send(Action::CommunityConfirmDelete(selected));
                true
            }
            // Delete a finished membership's own context. Never offered for the
            // top context or a live membership; what else uses the context is
            // checked in the loop before the VTA is asked anything.
            KeyCode::Char('D') if sel_inactive && sel_own_context => {
                let _ = self.action_tx.send(Action::CommunityContext(
                    crate::state_handler::actions::CommunityContextAction::DeleteStart(selected),
                ));
                true
            }
            // Device access, scoped to this community's own context.
            KeyCode::Char('g') if sel_own_context => {
                let _ = self.action_tx.send(Action::CommunityContext(
                    crate::state_handler::actions::CommunityContextAction::DevicesOpen(selected),
                ));
                true
            }
            KeyCode::Esc => {
                let _ = self
                    .action_tx
                    .send(Action::MainPanelSwitch(MainPanel::MainMenu));
                true
            }
            _ => false,
        }
    }

    /// Context-deletion keys, while one is open. While the VTA is previewing,
    /// only Esc (close). With the preview shown: typing builds the
    /// confirmation, Backspace erases, Enter deletes, Esc closes. While the
    /// delete runs, nothing — it cannot be called back. Paste is deliberately
    /// not accepted into the confirmation: typing it is the point.
    fn handle_context_delete_key(
        &mut self,
        key: KeyEvent,
        view: &crate::state_handler::main_page::content::ContextDeleteView,
    ) -> bool {
        use crate::state_handler::actions::CommunityContextAction as C;
        use crate::state_handler::main_page::content::ContextDeletePhase as Phase;
        let action = match (&view.phase, key.code) {
            (Phase::Deleting, _) => None,
            (_, KeyCode::Esc) => Some(C::DeleteCancel),
            (Phase::Ready(_), KeyCode::Enter) => Some(C::DeleteConfirm),
            (Phase::Ready(_), KeyCode::Backspace) => {
                let mut typed = view.typed.clone();
                typed.pop();
                Some(C::DeleteInput(typed))
            }
            (Phase::Ready(_), KeyCode::Char(c)) => {
                Some(C::DeleteInput(format!("{}{c}", view.typed)))
            }
            _ => None,
        };
        let handled = action.is_some();
        if let Some(action) = action {
            let _ = self.action_tx.send(Action::CommunityContext(action));
        }
        handled
    }

    /// Device-access keys, while the view is open. With the grant form open:
    /// typing fills the focused field, Tab/↑/↓ move between fields, ←/→ choose
    /// the expiry, Enter grants, Esc closes the form. With a revocation armed:
    /// y/Enter revokes, anything else disarms. Otherwise ↑/↓ select, `n` adds a
    /// device (live memberships only), `x`/Delete arms a revocation, `r`
    /// re-reads, Esc closes. While a request runs, only Esc (close).
    fn handle_device_access_key(
        &mut self,
        key: KeyEvent,
        view: &crate::state_handler::main_page::content::DeviceAccessView,
    ) -> bool {
        use crate::state_handler::actions::CommunityContextAction as C;
        use crate::state_handler::main_page::content::GrantForm;
        let grants = self
            .props
            .main_page
            .content_panel
            .communities
            .device_grants
            .get(&view.context_id)
            .map_or(0, |l| l.grants().len());
        let action = if view.busy {
            matches!(key.code, KeyCode::Esc).then_some(C::DevicesClose)
        } else if let Some(form) = &view.form {
            let fields = GrantForm::FIELDS;
            match key.code {
                KeyCode::Esc => Some(C::GrantCancel),
                KeyCode::Enter => Some(C::GrantSubmit),
                KeyCode::Tab | KeyCode::Down => Some(C::GrantField((form.field + 1) % fields)),
                KeyCode::BackTab | KeyCode::Up => {
                    Some(C::GrantField((form.field + fields - 1) % fields))
                }
                KeyCode::Left if form.field == 2 => {
                    Some(C::GrantExpiry(form.expiry.saturating_sub(1)))
                }
                KeyCode::Right if form.field == 2 => Some(C::GrantExpiry(form.expiry + 1)),
                KeyCode::Backspace if form.field < 2 => {
                    let mut value = grant_form_text(form).to_string();
                    value.pop();
                    Some(C::GrantInput {
                        field: form.field,
                        value,
                    })
                }
                KeyCode::Char(c) if form.field < 2 => Some(C::GrantInput {
                    field: form.field,
                    value: format!("{}{c}", grant_form_text(form)),
                }),
                _ => None,
            }
        } else if view.confirm_revoke {
            Some(match key.code {
                KeyCode::Char('y') if crate::ui::pages::main::confirm::is_yes(&key) => {
                    C::RevokeConfirm
                }
                _ => C::RevokeCancel,
            })
        } else {
            match key.code {
                KeyCode::Esc => Some(C::DevicesClose),
                KeyCode::Up if grants > 0 => {
                    Some(C::DevicesSelect(view.selected.saturating_sub(1)))
                }
                KeyCode::Down if grants > 0 => Some(C::DevicesSelect(view.selected + 1)),
                KeyCode::Char('n') if view.can_grant => Some(C::GrantStart),
                KeyCode::Char('x') | KeyCode::Delete if grants > 0 => Some(C::RevokeArm),
                KeyCode::Char('r') => Some(C::DevicesRefresh),
                _ => None,
            }
        };
        let handled = action.is_some();
        if let Some(action) = action {
            let _ = self.action_tx.send(Action::CommunityContext(action));
        }
        handled
    }
}

/// A key in the personhood witness-credential picker.
///
/// "Include all" is two keys: `A` asks, and only `y` to that question includes them; any other
/// key backs out with the choices as they were. Enter asserts with exactly what is chosen —
/// nothing, unless something was.
fn personhood_evidence_key(
    key: KeyEvent,
    view: &crate::state_handler::main_page::content::PersonhoodEvidenceView,
) -> Option<Action> {
    use crate::state_handler::actions::PersonhoodEvidenceAction as E;
    if view.confirm_all {
        return Some(Action::PersonhoodEvidence(match key.code {
            KeyCode::Char('y') => E::ConfirmIncludeAll,
            _ => E::CancelIncludeAll,
        }));
    }
    let action = match key.code {
        KeyCode::Up => E::Up,
        KeyCode::Down => E::Down,
        KeyCode::Char(' ') => E::Toggle,
        KeyCode::Char('A') => E::ArmIncludeAll,
        KeyCode::Esc => E::Close,
        KeyCode::Enter => {
            return Some(Action::AssertPersonhood {
                witnessed: Some(view.selected()),
            });
        }
        _ => return None,
    };
    Some(Action::PersonhoodEvidence(action))
}

#[cfg(test)]
mod personhood_evidence_key_tests {
    use super::*;
    use crate::state_handler::actions::PersonhoodEvidenceAction as E;
    use crate::state_handler::main_page::content::{PersonhoodEvidenceView, WitnessChoice};
    use crossterm::event::KeyModifiers;

    fn view(chosen: Vec<bool>, confirm_all: bool) -> PersonhoodEvidenceView {
        PersonhoodEvidenceView {
            choices: (0..chosen.len())
                .map(|i| WitnessChoice {
                    session_id: format!("urn:uuid:{i}"),
                    witness: "w".into(),
                    counterparty: "c".into(),
                    witnessed_at: "t".into(),
                    digest: "z".into(),
                })
                .collect(),
            chosen,
            confirm_all,
            ..PersonhoodEvidenceView::default()
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Enter asserts with exactly what is chosen — nothing when nothing is.
    #[test]
    fn enter_presents_only_the_chosen() {
        match personhood_evidence_key(key(KeyCode::Enter), &view(vec![false, false], false)) {
            Some(Action::AssertPersonhood { witnessed: Some(w) }) => assert!(w.is_empty()),
            _ => panic!("expected an assertion with nothing chosen"),
        }
        match personhood_evidence_key(key(KeyCode::Enter), &view(vec![false, true], false)) {
            Some(Action::AssertPersonhood { witnessed: Some(w) }) => {
                assert_eq!(w, vec!["urn:uuid:1".to_string()])
            }
            _ => panic!("expected an assertion with the one chosen"),
        }
    }

    /// `A` only asks; `y` to the question includes all, any other key backs out.
    #[test]
    fn include_all_is_a_separate_confirmation() {
        assert!(matches!(
            personhood_evidence_key(key(KeyCode::Char('A')), &view(vec![false], false)),
            Some(Action::PersonhoodEvidence(E::ArmIncludeAll))
        ));
        assert!(
            personhood_evidence_key(key(KeyCode::Char('y')), &view(vec![false], false)).is_none(),
            "`y` means nothing until include-all was asked for"
        );
        assert!(matches!(
            personhood_evidence_key(key(KeyCode::Char('y')), &view(vec![false], true)),
            Some(Action::PersonhoodEvidence(E::ConfirmIncludeAll))
        ));
        for other in [KeyCode::Enter, KeyCode::Char('n'), KeyCode::Esc] {
            assert!(matches!(
                personhood_evidence_key(key(other), &view(vec![false], true)),
                Some(Action::PersonhoodEvidence(E::CancelIncludeAll))
            ));
        }
    }
}
