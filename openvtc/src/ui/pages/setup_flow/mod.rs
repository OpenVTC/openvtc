use crate::colors::{
    COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
#[cfg(feature = "openpgp-card")]
use crate::ui::pages::setup_flow::pgp_token::{
    token_factory_reset::TokenFactoryReset, token_select::TokenSelect,
    token_set_cardholder_name::TokenSetCardholderName, token_set_touch::TokenSetTouch,
    token_start::TokenStart,
};
use crate::{
    state_handler::{
        actions::Action,
        setup_sequence::{SetupPage, SetupState},
        state::State,
    },
    ui::{
        component::{Component, ComponentRender},
        pages::setup_flow::{
            config_import::ConfigImport, context_occupied::ContextOccupied, final_page::FinalPage,
            recover_confirm::RecoverConfirm, start_ask::StartAskPanel,
            unlock_code_ask::UnlockCodeAsk, unlock_code_set::UnlockCodeSet,
            unlock_code_warn::UnlockCodeWarn, vta_acl_instructions::VtaAclInstructions,
            vta_enter_did::VtaEnterDid, vta_provisioning::VtaProvisioning,
        },
    },
};
use crossterm::event::{KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph},
};
use tokio::sync::mpsc::UnboundedSender;

pub mod choice_page;
pub mod config_import;
pub mod context_occupied;
pub mod final_page;
pub mod navigation;
pub mod recover_confirm;
pub mod start_ask;
pub mod unlock_code_ask;
pub mod unlock_code_set;
pub mod unlock_code_warn;
pub mod vta_acl_instructions;
pub mod vta_enter_did;
pub mod vta_provisioning;

#[cfg(feature = "openpgp-card")]
pub mod pgp_token;

/// Handles the Setup Flow sequence
#[derive(Clone)]
pub struct SetupFlow {
    /// Action sender
    pub action_tx: UnboundedSender<Action>,

    // Local state
    pub start_ask: StartAskPanel,
    pub config_import: ConfigImport,

    pub vta_enter_did: VtaEnterDid,
    pub vta_acl_instructions: VtaAclInstructions,
    pub vta_provisioning: VtaProvisioning,
    pub context_occupied: ContextOccupied,
    pub recover_confirm: RecoverConfirm,

    #[cfg(feature = "openpgp-card")]
    pub token_start: TokenStart,
    #[cfg(feature = "openpgp-card")]
    pub token_select: TokenSelect,
    #[cfg(feature = "openpgp-card")]
    pub token_factory_reset: TokenFactoryReset,
    #[cfg(feature = "openpgp-card")]
    pub token_set_touch: TokenSetTouch,
    #[cfg(feature = "openpgp-card")]
    pub token_set_cardholder_name: TokenSetCardholderName,

    pub unlock_code_ask: UnlockCodeAsk,
    pub unlock_code_warn: UnlockCodeWarn,
    pub unlock_code_set: UnlockCodeSet,

    pub final_page: FinalPage,

    /// State Mapped MainPage Props
    pub props: Props,
}

#[derive(Clone)]
pub struct Props {
    pub state: SetupState,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            state: state.setup.clone(),
        }
    }
}

impl Component for SetupFlow {
    fn new(state: &std::sync::Arc<State>, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        SetupFlow {
            action_tx: action_tx.clone(),

            start_ask: StartAskPanel::default(),
            config_import: ConfigImport::default(),
            vta_enter_did: VtaEnterDid::default(),
            vta_acl_instructions: VtaAclInstructions::default(),
            vta_provisioning: VtaProvisioning,
            context_occupied: ContextOccupied,
            recover_confirm: RecoverConfirm,

            #[cfg(feature = "openpgp-card")]
            token_start: TokenStart::default(),
            #[cfg(feature = "openpgp-card")]
            token_select: TokenSelect::default(),
            #[cfg(feature = "openpgp-card")]
            token_factory_reset: TokenFactoryReset::default(),
            #[cfg(feature = "openpgp-card")]
            token_set_touch: TokenSetTouch::default(),
            #[cfg(feature = "openpgp-card")]
            token_set_cardholder_name: TokenSetCardholderName::default(),

            unlock_code_ask: UnlockCodeAsk::default(),
            unlock_code_warn: UnlockCodeWarn::default(),
            unlock_code_set: UnlockCodeSet::default(),
            final_page: FinalPage::default(),

            // set the props
            props: Props::from(&**state),
        }
        .move_with_state(state)
    }

    fn move_with_state(self, state: &std::sync::Arc<State>) -> Self
    where
        Self: Sized,
    {
        // Copied only while the wizard is on screen (#556): its props are a
        // working copy the pages edit, and an update that arrives while
        // another page is up has nothing here to refresh.
        if !matches!(
            state.active_page,
            crate::state_handler::state::ActivePage::Setup
        ) {
            return self;
        }
        SetupFlow {
            props: Props::from(&**state),
            // propagate the update to the child components
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }

        // Esc goes back a page on every wizard page that has one (#588). Step
        // 2 decides its own way back, because it carries the reason for step
        // 1's banner; every other page's Esc is this one.
        let page = self.props.state.active_page;
        if key.code == crossterm::event::KeyCode::Esc
            && !matches!(page, SetupPage::VtaProvisioning)
            && let Some(previous) = navigation::previous_page(page)
        {
            self.props.state.active_page = previous;
            return;
        }

        match self.props.state.active_page {
            SetupPage::StartAsk => StartAskPanel::handle_key_event(self, key),
            SetupPage::ConfigImport => ConfigImport::handle_key_event(self, key),
            SetupPage::VtaEnterDid => VtaEnterDid::handle_key_event(self, key),
            SetupPage::VtaAclInstructions => VtaAclInstructions::handle_key_event(self, key),
            SetupPage::VtaProvisioning => VtaProvisioning::handle_key_event(self, key),
            SetupPage::ContextOccupied => ContextOccupied::handle_key_event(self, key),
            SetupPage::RecoverConfirm => RecoverConfirm::handle_key_event(self, key),

            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenStart => TokenStart::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSelect => TokenSelect::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenFactoryReset => TokenFactoryReset::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetTouch => TokenSetTouch::handle_key_event(self, key),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetCardholderName => {
                TokenSetCardholderName::handle_key_event(self, key)
            }

            SetupPage::UnlockCodeAsk => UnlockCodeAsk::handle_key_event(self, key),
            SetupPage::UnlockCodeWarn => UnlockCodeWarn::handle_key_event(self, key),
            SetupPage::UnlockCodeSet => UnlockCodeSet::handle_key_event(self, key),
            SetupPage::FinalPage => FinalPage::handle_key_event(self, key),
        }
    }

    fn handle_paste_event(&mut self, text: &str) {
        // Handle paste as a single operation instead of per-character key events.
        // This makes pasting large strings (DIDs) instant. The paste is
        // inserted at the cursor, as on the main page (#578).
        let trimmed = text.trim();
        let insert = |target: &mut tui_input::Input| {
            for c in trimmed.chars().filter(|c| !c.is_control()) {
                target.handle(tui_input::InputRequest::InsertChar(c));
            }
        };
        match self.props.state.active_page {
            SetupPage::ConfigImport => {
                let target = match self.config_import.active_input {
                    0 => &mut self.config_import.filename,
                    1 => &mut self.config_import.config_unlock_passphrase,
                    _ => &mut self.config_import.new_unlock_passphrase,
                };
                insert(target);
            }
            SetupPage::UnlockCodeSet => {
                let target = if self.unlock_code_set.active_input == 0 {
                    &mut self.unlock_code_set.passphrase
                } else {
                    &mut self.unlock_code_set.confirm
                };
                insert(target);
            }
            SetupPage::VtaEnterDid => insert(&mut self.vta_enter_did.vta_did),
            SetupPage::VtaAclInstructions => insert(&mut self.vta_acl_instructions.context_id),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetCardholderName => {
                insert(&mut self.token_set_cardholder_name.name);
            }
            _ => {}
        }
    }
}

// ****************************************************************************
// Render the page
// ****************************************************************************
impl ComponentRender<()> for SetupFlow {
    fn render(&self, frame: &mut Frame, _props: ()) {
        match self.props.state.active_page {
            SetupPage::StartAsk => self.start_ask.render(&self.props.state, frame),
            SetupPage::ConfigImport => self.config_import.render(&self.props.state, frame),
            SetupPage::VtaEnterDid => self.vta_enter_did.render(&self.props.state, frame),
            SetupPage::VtaAclInstructions => {
                self.vta_acl_instructions.render(&self.props.state, frame)
            }
            SetupPage::VtaProvisioning => self.vta_provisioning.render(&self.props.state, frame),
            SetupPage::ContextOccupied => self.context_occupied.render(&self.props.state, frame),
            SetupPage::RecoverConfirm => self.recover_confirm.render(&self.props.state, frame),

            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenStart => self.token_start.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSelect => self.token_select.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenFactoryReset => {
                self.token_factory_reset.render(&self.props.state, frame)
            }
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetTouch => self.token_set_touch.render(&self.props.state, frame),
            #[cfg(feature = "openpgp-card")]
            SetupPage::TokenSetCardholderName => self
                .token_set_cardholder_name
                .render(&self.props.state, frame),

            SetupPage::UnlockCodeAsk => self.unlock_code_ask.render(&self.props.state, frame),
            SetupPage::UnlockCodeWarn => self.unlock_code_warn.render(&self.props.state, frame),
            SetupPage::UnlockCodeSet => self.unlock_code_set.render(&self.props.state, frame),
            SetupPage::FinalPage => self.final_page.render(&self.props.state, frame),
        }
    }
}

/// Renders the top headline for the setup pages
pub fn render_setup_header(frame: &mut Frame, rect: Rect, state: &SetupState) {
    let mut line1 = Line::default();

    // Get Started → Key Management → Profile Security → Setup Complete.
    //
    // R-A-5 ended setup at protection (`UnlockCode*` → `FinalPage`) — a persona
    // is minted later by the State-B join flow, which draws its own progress —
    // but the breadcrumb went on advertising a fourth "Digital Identity" step
    // that could never become active, so the wizard read as skipping a step.
    // The pages behind that step, and the alternate webvh-server labelling that
    // went with them, are gone; this is the flow that remains.
    let total_step: usize = 4;

    // Determine which step we're on
    let active = state.active_page;

    let is_step1 = matches!(active, SetupPage::StartAsk);

    let is_step2_key_mgmt = matches!(
        active,
        SetupPage::VtaEnterDid | SetupPage::VtaAclInstructions | SetupPage::VtaProvisioning
    );

    let is_config_import = matches!(active, SetupPage::ConfigImport);

    let is_profile_security = matches!(
        active,
        SetupPage::UnlockCodeAsk | SetupPage::UnlockCodeSet | SetupPage::UnlockCodeWarn
    );
    #[cfg(feature = "openpgp-card")]
    let is_profile_security = is_profile_security
        || matches!(
            active,
            SetupPage::TokenStart
                | SetupPage::TokenSelect
                | SetupPage::TokenFactoryReset
                | SetupPage::TokenSetTouch
                | SetupPage::TokenSetCardholderName
        );

    let is_final = matches!(active, SetupPage::FinalPage);

    let steps = [
        "Get Started",
        "Key Management",
        "Profile Security",
        "Setup Complete",
    ];

    // Determine current step index (0-based)
    let current = if is_step1 {
        0
    } else if is_step2_key_mgmt || is_config_import {
        1
    } else if is_profile_security {
        2
    } else if is_final {
        3
    } else {
        0
    };
    let step = current + 1;

    // Special case: config import has only 2 steps
    let total_step = if is_config_import { 2 } else { total_step };

    // Build the breadcrumb line
    if is_config_import {
        // Config import: just "Get Started → Restore Backup"
        line1.push_span(Span::styled(
            "✓ Get Started",
            Style::new().fg(COLOR_SUCCESS),
        ));
        line1.push_span(Span::styled(" → ", Style::new().fg(COLOR_TEXT_DEFAULT)));
        line1.push_span(Span::styled(
            "● Restore Backup",
            Style::new().fg(COLOR_ORANGE).bold(),
        ));
    } else {
        for (i, label) in steps.iter().enumerate() {
            if i > 0 {
                line1.push_span(Span::styled(" → ", Style::new().fg(COLOR_TEXT_DEFAULT)));
            }
            if i < current {
                line1.push_span(Span::styled(
                    format!("✓ {label}"),
                    Style::new().fg(COLOR_SUCCESS),
                ));
            } else if i == current {
                line1.push_span(Span::styled(
                    format!("● {label}"),
                    Style::new().fg(COLOR_ORANGE).bold(),
                ));
            } else {
                line1.push_span(Span::styled(
                    format!("○ {label}"),
                    Style::new().fg(COLOR_DARK_GRAY),
                ));
            }
        }
    }

    let line2 = Line::from(Span::styled(
        format!("Section {}/{}", step, total_step),
        Style::new().fg(COLOR_BORDER),
    ));

    frame.render_widget(
        Paragraph::new(vec![line2, line1])
            .alignment(Alignment::Left)
            .block(Block::new().padding(Padding::new(2, 0, 0, 0))),
        rect,
    );
}
