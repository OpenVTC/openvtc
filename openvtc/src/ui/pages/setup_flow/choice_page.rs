//! Data-driven two-option prompt shared by the setup-wizard "ask" pages.
//!
//! Several setup pages are the exact same component: a bordered block with a
//! title, an intro blurb, and two mutually exclusive options rendered as a
//! checkbox list (`[✓]` / `[ ]`). The selected option additionally shows one or
//! more grey description lines. `TAB` / `↑` / `↓` toggle the selection, `ENTER`
//! confirms it (emitting a [`SetupEvent`]), and `F10` quits.
//!
//! Each concrete page is now just *data*: a [`ChoiceSpec`] supplying its title,
//! intro and the two options. The rendering and key handling live here once.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    colors::{COLOR_BORDER, COLOR_SUCCESS, COLOR_TEXT_DEFAULT},
    state_handler::{actions::Action, setup_sequence::SetupState},
    ui::pages::setup_flow::{
        SetupFlow,
        navigation::{SetupEvent, handle_nav_result, navigate},
        render_setup_header,
    },
};

/// One of the two selectable options on a choice page.
pub struct ChoiceOption {
    /// The label shown next to the `[✓]` / `[ ]` checkbox.
    pub label: &'static str,
    /// Detail lines shown underneath the label only while this option is
    /// selected. Each carries its own styling so per-page differences (e.g. a
    /// bold warning line) are preserved verbatim.
    pub description: Vec<Line<'static>>,
    /// The event emitted when this option is confirmed with `ENTER`.
    pub event: SetupEvent,
}

/// Full description of a binary choice page.
pub struct ChoiceSpec {
    /// Block title. Indexed by the selected option, so a page can show a
    /// selection-dependent title (most pages just repeat the same string).
    pub title: [&'static str; 2],
    /// Intro lines rendered above the options (already fully styled, including
    /// any trailing blank lines).
    pub intro: Vec<Line<'static>>,
    /// The two options, in display order.
    pub options: [ChoiceOption; 2],
}

/// Shared `ENTER` / `TAB` / `F10` handling for a binary choice page.
///
/// `selected` is the current selection index (0 or 1); `set_selected` flips the
/// stored selection on the owning [`SetupFlow`]. `spec` supplies the events.
pub fn handle_key_event(
    state: &mut SetupFlow,
    key: KeyEvent,
    selected: usize,
    set_selected: impl FnOnce(&mut SetupFlow, usize),
    spec: ChoiceSpec,
) {
    match key.code {
        KeyCode::F(10) => {
            let _ = state.action_tx.send(Action::Exit);
        }
        KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
            set_selected(state, 1 - selected);
        }
        KeyCode::Enter => {
            let [opt0, opt1] = spec.options;
            let event = if selected == 0 {
                opt0.event
            } else {
                opt1.event
            };
            handle_nav_result(navigate(event, &state.props.state), state);
        }
        _ => {}
    }
}

/// Renders a binary choice page. `selected` is the current selection index.
pub fn render(spec: &ChoiceSpec, selected: usize, state: &SetupState, frame: &mut Frame<'_>) {
    let [top, middle, bottom] =
        Layout::vertical([Length(3), Min(0), Length(3)]).areas(frame.area());

    render_setup_header(frame, top, state);

    let block = Block::bordered()
        .fg(COLOR_BORDER)
        .padding(Padding::proportional(1))
        .title(spec.title[selected]);

    let mut lines = spec.intro.clone();

    for (i, option) in spec.options.iter().enumerate() {
        let chosen = i == selected;
        let (marker, style) = if chosen {
            ("[✓] ", Style::new().fg(COLOR_SUCCESS).bold())
        } else {
            ("[ ] ", Style::new().fg(COLOR_TEXT_DEFAULT))
        };
        lines.push(Line::styled(format!("{marker}{}", option.label), style));
        if chosen {
            lines.extend(option.description.iter().cloned());
        }
    }

    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled("[TAB]", Style::new().fg(COLOR_BORDER).bold()),
        Span::styled(" to select  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
        Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
        Span::styled(" to confirm", Style::new().fg(COLOR_TEXT_DEFAULT)),
    ]));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        middle,
    );

    let mut hints = vec![
        Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
        Span::styled(" to quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
    ];
    if super::navigation::previous_page(state.active_page).is_some() {
        hints.extend([
            Span::styled("  |  ", Style::new().fg(COLOR_TEXT_DEFAULT)),
            Span::styled("[ESC]", Style::new().fg(COLOR_BORDER).bold()),
            Span::styled(" to go back", Style::new().fg(COLOR_TEXT_DEFAULT)),
        ]);
    }
    let bottom_line = Line::from(hints);
    frame.render_widget(
        Paragraph::new(bottom_line).block(Block::new().padding(Padding::new(2, 0, 1, 0))),
        bottom,
    );
}
