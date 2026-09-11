use std::fmt::Display;

use strum_macros::EnumIter;

/// Holds all state related info for the main page
#[derive(Clone, Debug)]
pub struct MenuPanelState {
    /// Selected?
    pub selected: bool,

    /// What is the selected menu item?
    pub selected_menu: MainMenu,
}

impl Default for MenuPanelState {
    fn default() -> Self {
        MenuPanelState {
            selected: true,
            selected_menu: MainMenu::default(),
        }
    }
}

#[derive(Default, Debug, Clone, EnumIter, PartialEq, Eq)]
pub enum MainMenu {
    /// Communities overview — the account hub and post-bootstrap landing (R-C).
    #[default]
    Communities,
    Inbox,
    Relationships,
    Credentials,
    /// Peer identity vetting: applications to be vetted, and the vetter desk
    /// (`docs/design/vetting-process.md`).
    Vetting,
    /// The holder's own identity — personas, the attribute pool behind them, the
    /// profiles over that pool, and what each persona presents in each community.
    ///
    /// Sits beside the other "my …" panels rather than under the VTA service,
    /// which is where its parts used to live: minting a persona DID was a menu
    /// action, the list of them was a section of the VTA panel, and everything
    /// above them was reachable only from `pnm`. Identity is not a property of
    /// the agent that hosts its keys.
    Identity,
    Settings,
    Vta,
    Logs,
    Help,
    Quit,
}

impl Display for MainMenu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MainMenu::Communities => write!(f, "Communities"),
            MainMenu::Inbox => write!(f, "Inbox"),
            MainMenu::Relationships => write!(f, "My Relationships"),
            MainMenu::Credentials => write!(f, "My Credentials"),
            MainMenu::Vetting => write!(f, "Vetting"),
            MainMenu::Identity => write!(f, "My Identity"),
            MainMenu::Settings => write!(f, "Settings"),
            MainMenu::Vta => write!(f, "VTA Service"),
            MainMenu::Logs => write!(f, "Logs"),
            MainMenu::Help => write!(f, "Help / Status"),
            MainMenu::Quit => write!(f, "Quit"),
        }
    }
}

impl MainMenu {
    /// Returns the previous MainMenu item
    pub fn prev(&self) -> MainMenu {
        match self {
            MainMenu::Communities => MainMenu::Quit,
            MainMenu::Inbox => MainMenu::Communities,
            MainMenu::Relationships => MainMenu::Inbox,
            MainMenu::Credentials => MainMenu::Relationships,
            MainMenu::Vetting => MainMenu::Credentials,
            MainMenu::Identity => MainMenu::Vetting,
            MainMenu::Settings => MainMenu::Identity,
            MainMenu::Vta => MainMenu::Settings,
            MainMenu::Logs => MainMenu::Vta,
            MainMenu::Help => MainMenu::Logs,
            MainMenu::Quit => MainMenu::Help,
        }
    }

    /// Returns the next MainMenu item
    pub fn next(&self) -> MainMenu {
        match self {
            MainMenu::Communities => MainMenu::Inbox,
            MainMenu::Inbox => MainMenu::Relationships,
            MainMenu::Relationships => MainMenu::Credentials,
            MainMenu::Credentials => MainMenu::Vetting,
            MainMenu::Vetting => MainMenu::Identity,
            MainMenu::Identity => MainMenu::Settings,
            MainMenu::Settings => MainMenu::Vta,
            MainMenu::Vta => MainMenu::Logs,
            MainMenu::Logs => MainMenu::Help,
            MainMenu::Help => MainMenu::Quit,
            MainMenu::Quit => MainMenu::Communities,
        }
    }
}
