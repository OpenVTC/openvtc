//! Centralized navigation for the setup wizard flow.
//!
//! All flow-level navigation decisions live here. Individual page files emit
//! a `SetupEvent` and call `handle_nav_result(navigate(..), flow)` instead of
//! directly setting `active_page` or sending `Action`s.

use secrecy::SecretString;

use super::SetupFlow;
use crate::state_handler::{
    actions::Action,
    setup_sequence::{SetupPage, SetupState},
};

/// Every page-exit event that requires a flow decision.
pub enum SetupEvent {
    // StartAsk
    CreateNew,
    ImportConfig,

    // VtaProvisioning
    VtaAuthCompleted,
    /// The operator saw that the chosen Trust Context already holds an account
    /// and chose to continue into it regardless (D5/D11).
    ContextOccupiedAccepted,
    /// The operator confirmed the recovery plan shown on
    /// [`SetupPage::RecoverConfirm`]. From here setup continues exactly as a
    /// fresh one, except the account it will write was rebuilt rather than
    /// created.
    RecoverConfirmed,

    // Token pages (cfg-gated)
    #[cfg(feature = "openpgp-card")]
    TokenSkipped,
    #[cfg(feature = "openpgp-card")]
    TokenNoSelection,
    #[cfg(feature = "openpgp-card")]
    TokenWritingComplete,
    #[cfg(feature = "openpgp-card")]
    TokenTouchComplete,
    #[cfg(feature = "openpgp-card")]
    TokenNameDone,
    #[cfg(feature = "openpgp-card")]
    TokenNameSkipped,

    // UnlockCode
    WantUnlockCode,
    SkipUnlockCode,
    /// The unlock code, checked for length and confirmation. The key is
    /// derived by the handler, off the render task.
    UnlockCodeSet {
        passphrase: SecretString,
    },
    ReturnToSetCode,
    AcceptNoCodeRisk,

    // FinalPage
    SetupDone,
}

/// What should happen after a navigation decision.
pub enum NavResult {
    /// Navigate to a specific page.
    GoTo(SetupPage),
    /// Send an action to the backend.
    SendAction(Action),
    /// Send SetupCompleted (needs flow.clone()).
    CompleteSetup,
    /// Do nothing.
    // No navigation branch currently returns this no-op, but the dispatcher
    // handles it; kept so `navigate` can express "stay put" without a new arm.
    #[allow(dead_code)]
    None,
}

/// Central navigation function — all conditional flow logic lives here.
pub fn navigate(event: SetupEvent, state: &SetupState) -> NavResult {
    match event {
        // === StartAsk ===
        SetupEvent::CreateNew => NavResult::GoTo(SetupPage::VtaEnterDid),
        SetupEvent::ImportConfig => NavResult::GoTo(SetupPage::ConfigImport),

        // === VtaProvisioning ===
        // R-A-5: setup is State A (account bootstrap) only. Once the admin
        // credential is issued, go straight to protection then create the
        // account — minting a persona / did:webvh belongs to the State-B join
        // flow, which drives it itself rather than through wizard pages.
        // D5: the probe runs during provisioning, so by the time the operator
        // confirms we already know whether this context holds an account.
        // Detour through the warning only when it does — a genuine first run
        // never sees the page, and an unreachable listing (`Unknown`) does not
        // gate setup, because failing to inform a decision must not prevent
        // making it.
        SetupEvent::VtaAuthCompleted => {
            if state
                .vta
                .context_probe
                .as_ref()
                .is_some_and(openvtc_core::context_probe::ProbeOutcome::needs_confirmation)
            {
                NavResult::GoTo(SetupPage::ContextOccupied)
            } else {
                NavResult::GoTo(protection_entry())
            }
        }

        // Acknowledged: carry on exactly where an empty context would have.
        SetupEvent::ContextOccupiedAccepted => NavResult::GoTo(protection_entry()),

        // Same destination, different account. Protection is still the
        // operator's choice — a recovered profile is protected on this machine
        // by whatever they pick here, not by whatever the old one used.
        SetupEvent::RecoverConfirmed => NavResult::GoTo(protection_entry()),

        // === Token pages ===
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenSkipped => NavResult::GoTo(SetupPage::UnlockCodeAsk),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenNoSelection => NavResult::GoTo(SetupPage::UnlockCodeAsk),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenWritingComplete => NavResult::GoTo(SetupPage::TokenSetTouch),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenTouchComplete => NavResult::GoTo(SetupPage::TokenSetCardholderName),
        #[cfg(feature = "openpgp-card")]
        SetupEvent::TokenNameDone | SetupEvent::TokenNameSkipped => {
            NavResult::GoTo(after_tokens(state))
        }

        // === UnlockCode ===
        // R-A-5: after protection is decided, create the account (State A) and
        // land on FinalPage. SetUnlockCode derives the key and then runs
        // `Config::create_account` itself.
        SetupEvent::WantUnlockCode => NavResult::GoTo(SetupPage::UnlockCodeSet),
        SetupEvent::SkipUnlockCode => NavResult::GoTo(SetupPage::UnlockCodeWarn),
        SetupEvent::UnlockCodeSet { passphrase } => {
            NavResult::SendAction(Action::SetUnlockCode(passphrase))
        }
        SetupEvent::ReturnToSetCode => NavResult::GoTo(SetupPage::UnlockCodeSet),
        SetupEvent::AcceptNoCodeRisk => NavResult::CompleteSetup,

        // === FinalPage ===
        SetupEvent::SetupDone => NavResult::SendAction(Action::ActivateMainMenu),
    }
}

/// The page Esc goes back to (#588), or `None` where there is no way back.
///
/// Back stops at the VTA: once its admin credential is issued, the one-time
/// grant is spent, so the protection pages do not lead back into provisioning.
/// Within a run going back keeps what was entered and the setup DID, so a
/// grant already made for it still applies.
#[must_use]
pub fn previous_page(page: SetupPage) -> Option<SetupPage> {
    match page {
        SetupPage::StartAsk | SetupPage::FinalPage => None,
        SetupPage::ConfigImport | SetupPage::VtaEnterDid => Some(SetupPage::StartAsk),
        SetupPage::VtaAclInstructions => Some(SetupPage::VtaEnterDid),
        SetupPage::VtaProvisioning | SetupPage::ContextOccupied => {
            Some(SetupPage::VtaAclInstructions)
        }
        SetupPage::RecoverConfirm => Some(SetupPage::ContextOccupied),
        #[cfg(feature = "openpgp-card")]
        SetupPage::TokenStart | SetupPage::TokenSetTouch | SetupPage::TokenSetCardholderName => {
            None
        }
        #[cfg(feature = "openpgp-card")]
        SetupPage::TokenSelect => Some(SetupPage::TokenStart),
        #[cfg(feature = "openpgp-card")]
        SetupPage::TokenFactoryReset => Some(SetupPage::TokenSelect),
        #[cfg(feature = "openpgp-card")]
        SetupPage::UnlockCodeAsk => Some(SetupPage::TokenStart),
        #[cfg(not(feature = "openpgp-card"))]
        SetupPage::UnlockCodeAsk => None,
        SetupPage::UnlockCodeSet | SetupPage::UnlockCodeWarn => Some(SetupPage::UnlockCodeAsk),
    }
}

/// Entry point into the config-protection sub-flow (token setup on openpgp-card
/// builds, otherwise the unlock-code prompt). Reached straight after VTA
/// provisioning.
fn protection_entry() -> SetupPage {
    #[cfg(feature = "openpgp-card")]
    {
        SetupPage::TokenStart
    }
    #[cfg(not(feature = "openpgp-card"))]
    {
        SetupPage::UnlockCodeAsk
    }
}

/// After token setup is done, go to unlock code.
#[cfg(feature = "openpgp-card")]
fn after_tokens(state: &SetupState) -> SetupPage {
    let _ = state; // tokens always lead to UnlockCodeAsk
    SetupPage::UnlockCodeAsk
}

/// Executes a `NavResult` against the setup flow.
pub fn handle_nav_result(result: NavResult, flow: &mut SetupFlow) {
    match result {
        NavResult::GoTo(page) => {
            flow.props.state.active_page = page;
        }
        NavResult::SendAction(action) => {
            let _ = flow.action_tx.send(action);
        }
        NavResult::CompleteSetup => {
            let _ = flow
                .action_tx
                .send(Action::SetupCompleted(Box::new(flow.clone())));
        }
        NavResult::None => {}
    }
}

#[cfg(test)]
mod tests {
    //! Table-driven tests for the central navigation function. The pure
    //! `(SetupEvent, &SetupState) -> NavResult` shape makes this exhaustive
    //! coverage cheap, and locks in the flow before the larger state-handler
    //! split refactor that's coming next.

    use super::*;

    fn empty_state() -> SetupState {
        SetupState::default()
    }

    fn matches_goto(result: &NavResult, expected: SetupPage) -> bool {
        matches!(result, NavResult::GoTo(p) if std::mem::discriminant(p) == std::mem::discriminant(&expected))
    }

    fn is_send_action(result: &NavResult) -> bool {
        matches!(result, NavResult::SendAction(_))
    }

    fn is_complete(result: &NavResult) -> bool {
        matches!(result, NavResult::CompleteSetup)
    }

    /// D5 — the whole point of the probe. A context that already holds an
    /// account must not be written into without the operator seeing it first.
    #[test]
    fn an_occupied_context_detours_through_the_warning() {
        use openvtc_core::context_probe::{ContextContents, ProbeOutcome};
        let mut state = empty_state();
        state.vta.context_probe = Some(ProbeOutcome::Occupied(Box::new(ContextContents {
            persona_dids: vec!["did:webvh:Qm:example.com:alice".to_string()],
            sub_context_count: 1,
        })));

        let r = navigate(SetupEvent::VtaAuthCompleted, &state);
        assert!(
            matches_goto(&r, SetupPage::ContextOccupied),
            "an occupied context must stop and ask"
        );
    }

    /// A genuine first run must be completely unchanged — no extra page, no
    /// extra keystroke.
    #[test]
    fn an_empty_context_is_unaffected() {
        use openvtc_core::context_probe::ProbeOutcome;
        let mut state = empty_state();
        state.vta.context_probe = Some(ProbeOutcome::Empty);

        let r = navigate(SetupEvent::VtaAuthCompleted, &state);
        assert!(matches_goto(&r, protection_entry()));
    }

    /// "We could not tell" must not gate setup: failing to inform the decision
    /// cannot be allowed to prevent making it.
    #[test]
    fn an_inconclusive_probe_does_not_gate_setup() {
        use openvtc_core::context_probe::ProbeOutcome;
        let mut state = empty_state();
        state.vta.context_probe = Some(ProbeOutcome::Unknown("refused".to_string()));

        let r = navigate(SetupEvent::VtaAuthCompleted, &state);
        assert!(matches_goto(&r, protection_entry()));
    }

    /// A VTA old enough that the probe never ran at all behaves as before.
    #[test]
    fn no_probe_at_all_behaves_as_before() {
        let r = navigate(SetupEvent::VtaAuthCompleted, &empty_state());
        assert!(matches_goto(&r, protection_entry()));
    }

    /// Acknowledging rejoins the normal flow at exactly the point an empty
    /// context would have.
    #[test]
    fn accepting_an_occupied_context_rejoins_the_normal_flow() {
        let r = navigate(SetupEvent::ContextOccupiedAccepted, &empty_state());
        assert!(matches_goto(&r, protection_entry()));
    }

    #[test]
    fn create_new_routes_to_vta_enter_did() {
        let r = navigate(SetupEvent::CreateNew, &empty_state());
        assert!(matches_goto(&r, SetupPage::VtaEnterDid));
    }

    #[test]
    fn import_config_routes_to_config_import() {
        let r = navigate(SetupEvent::ImportConfig, &empty_state());
        assert!(matches_goto(&r, SetupPage::ConfigImport));
    }

    #[test]
    fn vta_auth_completed_routes_to_protection() {
        // R-A-5: provisioning now leads straight into the protection sub-flow
        // (then State-A account creation) — no persona-minting pages.
        let r = navigate(SetupEvent::VtaAuthCompleted, &empty_state());
        assert!(matches_goto(&r, protection_entry()));
    }

    #[test]
    fn want_unlock_code_routes_to_unlock_code_set() {
        let r = navigate(SetupEvent::WantUnlockCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeSet));
    }

    #[test]
    fn skip_unlock_code_routes_to_warn() {
        let r = navigate(SetupEvent::SkipUnlockCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeWarn));
    }

    #[test]
    fn return_to_set_code_routes_back_to_unlock_set() {
        let r = navigate(SetupEvent::ReturnToSetCode, &empty_state());
        assert!(matches_goto(&r, SetupPage::UnlockCodeSet));
    }

    #[test]
    fn accept_no_code_risk_completes_account_setup() {
        // R-A-5: no passcode → create the State-A account directly.
        let r = navigate(SetupEvent::AcceptNoCodeRisk, &empty_state());
        assert!(is_complete(&r));
    }

    #[test]
    fn unlock_code_set_hands_the_code_to_the_handler() {
        let r = navigate(
            SetupEvent::UnlockCodeSet {
                passphrase: SecretString::from("correct horse"),
            },
            &empty_state(),
        );
        assert!(matches!(r, NavResult::SendAction(Action::SetUnlockCode(_))));
    }

    #[test]
    fn setup_done_emits_activate_main_menu() {
        let r = navigate(SetupEvent::SetupDone, &empty_state());
        assert!(is_send_action(&r));
    }
}
