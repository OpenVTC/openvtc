use crossterm::event::KeyEvent;
use ratatui::{Frame, style::Style, text::Line};

use crate::{
    colors::{COLOR_BORDER, COLOR_DARK_GRAY},
    state_handler::setup_sequence::SetupState,
    ui::pages::setup_flow::{
        SetupFlow,
        choice_page::{self, ChoiceOption, ChoiceSpec},
        navigation::SetupEvent,
    },
};

// ****************************************************************************
// UnlockCodeAsk
// ****************************************************************************
#[derive(Copy, Clone, Debug, Default)]
pub enum UnlockCodeAsk {
    #[default]
    UseCode,
    NoCode,
}

impl UnlockCodeAsk {
    fn index(&self) -> usize {
        match self {
            UnlockCodeAsk::UseCode => 0,
            UnlockCodeAsk::NoCode => 1,
        }
    }

    fn from_index(i: usize) -> Self {
        if i == 0 {
            UnlockCodeAsk::UseCode
        } else {
            UnlockCodeAsk::NoCode
        }
    }

    fn spec() -> ChoiceSpec {
        ChoiceSpec {
            title: [" Set up unlock code ", " Set up unlock code "],
            intro: vec![
                Line::styled(
                    "An unlock code encrypts your cryptographic keys, configuration, and private data stored by OpenVTC.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::styled(
                    "This prevents unauthorised access even if someone gains access to your device.",
                    Style::new().fg(COLOR_DARK_GRAY),
                ),
                Line::default(),
                Line::styled(
                    "Would you like to set an unlock code?",
                    Style::new().fg(COLOR_BORDER).bold(),
                ),
                Line::default(),
            ],
            options: [
                ChoiceOption {
                    label: "Yes, require unlock code (recommended)",
                    description: vec![Line::styled(
                        "    Encrypts your keys, configuration, and private data for protection against unauthorised access.",
                        Style::new().fg(COLOR_DARK_GRAY),
                    )],
                    event: SetupEvent::WantUnlockCode,
                },
                ChoiceOption {
                    label: "No, do not require unlock code",
                    description: vec![Line::styled(
                        "    Anyone with access to this device will be able to open OpenVTC and use your keys and access your private data.",
                        Style::new().fg(COLOR_DARK_GRAY).bold(),
                    )],
                    event: SetupEvent::SkipUnlockCode,
                },
            ],
        }
    }

    pub fn handle_key_event(state: &mut SetupFlow, key: KeyEvent) {
        let selected = state.unlock_code_ask.index();
        choice_page::handle_key_event(
            state,
            key,
            selected,
            |s, i| s.unlock_code_ask = UnlockCodeAsk::from_index(i),
            Self::spec(),
        );
    }

    pub fn render(&self, state: &SetupState, frame: &mut Frame) {
        choice_page::render(&Self::spec(), self.index(), state, frame);
    }
}
