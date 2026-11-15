use crate::colors::{
    COLOR_BORDER, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::menu::{MainMenu, MenuPanelState};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Stylize,
    symbols::merge::MergeStrategy,
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph},
};
use strum::IntoEnumIterator;

/// Columns the menu needs: its longest item, a marker and the border.
pub const MENU_WIDTH: u16 = 23;

// ****************************************************************************
// Render the Main Menu panel
// ****************************************************************************
impl MenuPanelState {
    /// Render the main menu based on current state
    pub fn render(
        &self,
        frame: &mut Frame,
        rect: Rect,
        badges: &crate::state_handler::main_page::MenuBadges,
    ) {
        // The surrounding block for the menu

        let menu_block = if self.selected {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .border_type(BorderType::Double)
                .fg(COLOR_SUCCESS)
                .title("Menu")
        } else {
            Block::bordered()
                .merge_borders(MergeStrategy::Fuzzy)
                .fg(COLOR_BORDER)
                .title("Menu")
        };

        let mut lines = Vec::new();
        for item in MainMenu::iter() {
            let is_selected = item == self.selected_menu;
            let base_color = if is_selected {
                COLOR_SUCCESS
            } else {
                COLOR_TEXT_DEFAULT
            };

            let badge = match item {
                MainMenu::Inbox => badges.inbox,
                MainMenu::Communities => badges.communities,
                MainMenu::Vetting => badges.vetting,
                _ => 0,
            };
            if badge > 0 {
                lines.push(Line::from(vec![
                    Span::styled(format!("* {item} "), base_color),
                    Span::styled(format!("({badge})"), COLOR_WARNING_ACCESSIBLE_RED),
                ]));
            } else {
                lines
                    .push(Line::from(["* ".to_string(), item.to_string()].concat()).fg(base_color));
            }
        }

        // Scroll so the selection is always on screen when the menu is
        // taller than its panel (#576).
        let inner = menu_block.inner(rect).height as usize;
        let selected = MainMenu::iter()
            .position(|m| m == self.selected_menu)
            .unwrap_or(0);
        let offset = selected.saturating_sub(inner.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(lines)
                .dark_gray()
                .alignment(Alignment::Left)
                .scroll((offset as u16, 0))
                .block(menu_block),
            rect,
        );
    }
}
