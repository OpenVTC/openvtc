//! The key map's contract (#580): on every view, the keys its footer — and so
//! the `?` overlay — lists are exactly the keys its handler takes.
//!
//! Each case builds a page on one view, draws it once (which is what
//! advertises the view's keys), then presses every key in [`universe`] on a
//! fresh copy and asks the view's handler whether it took it. A key taken but
//! not listed is a hidden key; a key listed but not taken is a lie in the
//! footer. Either fails the case, naming the key.

use super::key_handler_tests::{
    community_summary, community_summary_with, page_for, press, rel_summary, task_summary, vic,
    vrc_summary,
};
use super::*;
use crate::state_handler::main_page::content::{
    ActiveTaskView, CredentialTab, CredentialsMode, RelationshipsMode, SettingsMode, VicLifecycle,
};
use crossterm::event::KeyModifiers;
use std::sync::Arc;

/// Every key worth pressing: letters both cases, digits, the punctuation the
/// panels use, and the navigation and editing keys. Not PgUp/PgDn/Home/End,
/// which scroll every view before it is asked.
fn universe() -> Vec<KeyEvent> {
    let mut keys: Vec<KeyEvent> = ('a'..='z')
        .chain('A'..='Z')
        .chain('0'..='9')
        .chain([' ', '/', '?', '+', '-'])
        .map(|c| press(KeyCode::Char(c)))
        .collect();
    keys.extend(
        [
            KeyCode::Enter,
            KeyCode::Esc,
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Backspace,
            KeyCode::Delete,
        ]
        .map(press),
    );
    keys.extend(
        ['a', 'e', 'k', 't', 'u', 'v', 'w']
            .map(|c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)),
    );
    keys
}

/// The keys the view advertised when drawn.
fn advertised(page: &MainPage) -> Vec<keymap::Binding> {
    use ratatui::{Terminal, backend::TestBackend};
    let mut terminal = Terminal::new(TestBackend::new(140, 60)).expect("test terminal");
    terminal
        .draw(|frame| page.render(frame, ()))
        .expect("render");
    page.panel_keys.borrow().clone()
}

/// Assert the view's footer lists exactly the keys its handler takes.
#[track_caller]
fn keys_match(what: &str, menu: MainMenu, arm: impl Fn(&mut State) + Copy) {
    let (page, _rx) = page_for(menu.clone(), arm);
    let listed = advertised(&page);
    assert!(!listed.is_empty(), "{what}: the view advertises no keys");
    for b in &listed {
        assert!(
            b.is_typing() || !b.codes().is_empty(),
            "{what}: unknown key label {:?}",
            b.key
        );
    }
    let mut problems = Vec::new();
    for key in universe() {
        let (mut page, _rx) = page_for(menu.clone(), arm);
        let _ = advertised(&page);
        let taken = page.handle_content_key_event(key);
        let shown = listed.iter().any(|b| b.matches(&key));
        if taken != shown {
            problems.push(format!(
                "{} {}",
                keymap::describe(&key),
                if taken {
                    "is taken but not listed"
                } else {
                    "is listed but not taken"
                }
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{what}: footer and handler disagree:\n  {}\n listed: {:?}",
        problems.join("\n  "),
        listed.iter().map(|b| b.key).collect::<Vec<_>>()
    );
}

fn three<T: Clone>(make: impl Fn(&str) -> T) -> Arc<[T]> {
    Arc::from(vec![make("a"), make("b"), make("c")])
}

#[test]
fn inbox_keys_are_exactly_its_footer() {
    keys_match("inbox, empty", MainMenu::Inbox, |_| {});
    keys_match("inbox list", MainMenu::Inbox, |s| {
        s.main_page.content_panel.inbox.tasks = three(task_summary);
        s.main_page.content_panel.inbox.selected_index = 1;
    });
    keys_match("inbox: relationship request", MainMenu::Inbox, |s| {
        s.main_page.content_panel.inbox.active_task =
            Some(ActiveTaskView::RelationshipRequestInbound {
                task_id: "t1".into(),
                from_did: "did:example:them".into(),
                from_agent_name: None,
                their_did: "did:example:them".into(),
                reason: None,
                name: None,
            });
    });
}

#[test]
fn relationships_keys_are_exactly_its_footer() {
    let rels = |s: &mut State| {
        s.main_page.content_panel.relationships.relationships = three(rel_summary);
        s.main_page.content_panel.relationships.selected_index = 1;
    };
    keys_match("relationships list", MainMenu::Relationships, rels);
    keys_match("relationship detail", MainMenu::Relationships, move |s| {
        rels(s);
        s.main_page.content_panel.relationships.mode = RelationshipsMode::Detail {
            index: 1,
            selected_vrc: None,
        };
    });
    keys_match("relationship alias", MainMenu::Relationships, move |s| {
        rels(s);
        s.main_page.content_panel.relationships.mode = RelationshipsMode::EditAlias {
            index: 1,
            alias_input: "Al".into(),
        };
    });
    for field in 0..4 {
        keys_match(
            &format!("new relationship, field {field}"),
            MainMenu::Relationships,
            move |s| {
                s.main_page.content_panel.relationships.mode = RelationshipsMode::NewRequest {
                    did_input: String::new(),
                    alias_input: String::new(),
                    reason_input: String::new(),
                    generate_r_did: true,
                    active_field: field,
                    community_default: None,
                };
            },
        );
    }
}

#[test]
fn credentials_keys_are_exactly_its_footer() {
    let creds = |s: &mut State| {
        s.main_page.content_panel.credentials.selected_tab = CredentialTab::Received;
        s.main_page.content_panel.credentials.received = three(vrc_summary);
        s.main_page.content_panel.credentials.selected_index = 1;
    };
    keys_match("credentials list", MainMenu::Credentials, creds);
    keys_match("credential detail", MainMenu::Credentials, move |s| {
        creds(s);
        s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 1 };
    });
    keys_match(
        "credential detail, membership",
        MainMenu::Credentials,
        move |s| {
            creds(s);
            s.main_page.content_panel.credentials.selected_tab = CredentialTab::Membership;
            s.main_page.content_panel.credentials.membership = three(vrc_summary);
            s.main_page.content_panel.credentials.mode = CredentialsMode::Detail { index: 1 };
        },
    );
}

#[test]
fn vta_keys_are_exactly_its_footer() {
    for lifecycle in [
        VicLifecycle::Active,
        VicLifecycle::Archived,
        VicLifecycle::Deleted,
    ] {
        keys_match(
            &format!("VTA, {lifecycle:?} VIC"),
            MainMenu::Vta,
            move |s| {
                let vta = &mut s.main_page.content_panel.vta;
                vta.vics = vec![vic("v1", lifecycle), vic("v2", lifecycle)].into();
                vta.vic_selected_index = 0;
            },
        );
    }
    keys_match("VTA, no VICs", MainMenu::Vta, |_| {});
}

#[test]
fn communities_keys_are_exactly_its_footer() {
    keys_match("communities, active", MainMenu::Communities, |s| {
        s.main_page.content_panel.communities.items = Arc::from(vec![
            community_summary("A"),
            community_summary("B"),
            community_summary("C"),
        ]);
        s.main_page.content_panel.communities.selected_index = 1;
    });
    keys_match("communities, inactive", MainMenu::Communities, |s| {
        s.main_page.content_panel.communities.items = Arc::from(vec![
            community_summary_with("A", false, true, false),
            community_summary_with("B", false, true, false),
        ]);
    });
    keys_match("communities, pending", MainMenu::Communities, |s| {
        s.main_page.content_panel.communities.items =
            Arc::from(vec![community_summary_with("A", false, false, true)]);
    });
    keys_match("communities, none", MainMenu::Communities, |_| {});
}

#[test]
fn settings_logs_help_and_tsp_keys_are_exactly_their_footers() {
    keys_match("settings", MainMenu::Settings, |s| {
        s.main_page.content_panel.settings.selected_index = 1;
    });
    keys_match("settings, protection", MainMenu::Settings, |s| {
        s.main_page.content_panel.settings.mode = SettingsMode::ChangeProtection {
            selected_option: 0,
            passphrase_len: 0,
            confirm_len: 0,
            active_field: 0,
        };
    });
    keys_match("help / status", MainMenu::Help, |_| {});
    keys_match("TSP relationships", MainMenu::TspRelationships, |_| {});
}

/// `?` opens the overlay; it lists the focused view's keys and the global
/// ones, from the tables the footers are drawn from; any key closes it.
#[test]
fn question_mark_lists_the_focused_views_keys() {
    let (mut page, _rx) = page_for(MainMenu::Inbox, |s| {
        s.main_page.content_panel.inbox.tasks = three(task_summary);
    });
    let footer = advertised(&page);
    page.handle_key_event(press(KeyCode::Char('?')));
    assert!(page.help_open);
    let (_, listed) = page.help_bindings();
    assert_eq!(listed, footer);
    let drawn = {
        use ratatui::{Terminal, backend::TestBackend};
        let mut terminal = Terminal::new(TestBackend::new(140, 60)).expect("test terminal");
        terminal
            .draw(|frame| page.render(frame, ()))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>()
    };
    for b in footer.iter().chain(keymap::global().iter()) {
        assert!(
            drawn.contains(&b.does),
            "{} missing from the overlay",
            b.does
        );
    }
    page.handle_key_event(press(KeyCode::Char('x')));
    assert!(!page.help_open, "any key closes the overlay");
}

/// A key a view does not take says so in the footer row instead of vanishing.
#[test]
fn an_unused_key_gives_feedback() {
    let (mut page, mut rx) = page_for(MainMenu::Inbox, |_| {});
    let _ = advertised(&page);
    page.handle_key_event(press(KeyCode::Char('z')));
    assert!(rx.try_recv().is_err(), "nothing is sent");
    let feedback = page.key_feedback.clone().expect("feedback");
    assert!(feedback.contains("z does nothing here"), "{feedback}");
}

/// While a text field has the focus, ←/→ and Tab do not leave the panel.
#[test]
fn a_focused_text_field_keeps_the_arrows() {
    let (mut page, mut rx) = page_for(MainMenu::Relationships, |s| {
        s.main_page.content_panel.relationships.mode = RelationshipsMode::EditAlias {
            index: 0,
            alias_input: "Al".into(),
        };
        s.main_page.content_panel.relationships.relationships = three(rel_summary);
    });
    let _ = advertised(&page);
    page.handle_key_event(press(KeyCode::Left));
    while let Ok(action) = rx.try_recv() {
        assert!(
            !matches!(action, Action::MainPanelSwitch(_)),
            "← must not switch panels from a text field"
        );
    }
}

#[test]
fn identity_tab_keys_are_exactly_their_footers() {
    use super::key_handler_tests::persona;
    use crate::state_handler::main_page::content::PersonaTab;
    for tab in PersonaTab::all() {
        keys_match(
            &format!("identity, {tab:?}, empty"),
            MainMenu::Identity,
            move |s| {
                s.main_page.content_panel.identity.tab = tab;
            },
        );
    }
    keys_match(
        "identity, personas, an orphan selected",
        MainMenu::Identity,
        |s| {
            let id = &mut s.main_page.content_panel.identity;
            id.personas = vec![
                persona("did:example:a", "A", 1),
                persona("did:example:b", "B", 0),
            ]
            .into();
            id.persona_selected = 1;
        },
    );
    keys_match(
        "identity, personas, a bound one selected",
        MainMenu::Identity,
        |s| {
            let id = &mut s.main_page.content_panel.identity;
            id.personas = vec![
                persona("did:example:a", "A", 1),
                persona("did:example:b", "B", 0),
            ]
            .into();
            id.persona_selected = 0;
        },
    );
}

#[test]
fn community_sub_views_keys_are_exactly_their_footers() {
    use crate::state_handler::main_page::content::{CapabilitiesPhase, CapabilitiesView};
    for failed in [false, true] {
        keys_match(
            &format!("capabilities, failed: {failed}"),
            MainMenu::Communities,
            move |s| {
                let mut view = CapabilitiesView::new(
                    "did:example:vtc".into(),
                    openvtc_core::config::account::PersonaId(uuid::Uuid::nil()),
                    "Acme".into(),
                );
                view.phase = if failed {
                    CapabilitiesPhase::Failed("x".into())
                } else {
                    CapabilitiesPhase::Loading
                };
                s.main_page.content_panel.capabilities.view = Some(view);
            },
        );
    }
}

// ----- One text-input behaviour (#578) ----------------------------------

fn alias_form(s: &mut State) {
    s.main_page.content_panel.relationships.relationships = three(rel_summary);
    s.main_page.content_panel.relationships.mode = RelationshipsMode::EditAlias {
        index: 0,
        alias_input: "Al".into(),
    };
}

fn alias_sent(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Action>) -> Option<String> {
    let mut last = None;
    while let Ok(action) = rx.try_recv() {
        if let Action::Relationship(
            crate::state_handler::actions::RelationshipAction::EditAliasUpdate(v),
        ) = action
        {
            last = Some(v);
        }
    }
    last
}

/// ← moves the cursor inside the field, and typing inserts there.
#[test]
fn arrows_move_the_cursor_and_typing_inserts_at_it() {
    let (mut page, mut rx) = page_for(MainMenu::Relationships, alias_form);
    let _ = advertised(&page);
    page.handle_key_event(press(KeyCode::Left));
    assert_eq!(alias_sent(&mut rx), None, "a move sends nothing");
    page.handle_key_event(press(KeyCode::Char('x')));
    assert_eq!(alias_sent(&mut rx).as_deref(), Some("Axl"));
}

/// A paste lands at the cursor, as typing does.
#[test]
fn a_paste_is_inserted_at_the_cursor() {
    let (mut page, mut rx) = page_for(MainMenu::Relationships, alias_form);
    let _ = advertised(&page);
    page.handle_key_event(press(KeyCode::Home));
    page.handle_paste_event("Big");
    assert_eq!(alias_sent(&mut rx).as_deref(), Some("BigAl"));
}

/// A Ctrl chord edits or does nothing; it never types its letter.
#[test]
fn ctrl_chords_never_type_their_letter() {
    let (mut page, mut rx) = page_for(MainMenu::Relationships, alias_form);
    let _ = advertised(&page);
    page.handle_key_event(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
    assert_eq!(
        alias_sent(&mut rx).as_deref(),
        Some(""),
        "Ctrl+U clears the line"
    );
    let (mut page, mut rx) = page_for(MainMenu::Relationships, alias_form);
    let _ = advertised(&page);
    page.handle_key_event(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL));
    assert_eq!(alias_sent(&mut rx), None, "Ctrl+T is not a letter");
}

/// The cursor is drawn where it is.
#[test]
fn the_cursor_is_drawn_in_the_field() {
    let (mut page, _rx) = page_for(MainMenu::Relationships, alias_form);
    let _ = advertised(&page);
    page.handle_key_event(press(KeyCode::Left));
    use ratatui::{Terminal, backend::TestBackend};
    let mut terminal = Terminal::new(TestBackend::new(140, 60)).expect("test terminal");
    terminal
        .draw(|frame| page.render(frame, ()))
        .expect("render");
    let drawn: String = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect();
    assert!(drawn.contains("A▏l"), "{drawn}");
}

// ----- 80x24 (#576) ------------------------------------------------------

fn screen(page: &MainPage, width: u16, height: u16) -> Vec<String> {
    use ratatui::{Terminal, backend::TestBackend};
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| page.render(frame, ()))
        .expect("render");
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(width as usize)
        .map(|row| row.iter().map(ratatui::buffer::Cell::symbol).collect())
        .collect()
}

/// At the default terminal size every menu item is drawn whole — Quit
/// included — and the footer row keeps the quit and help hints.
#[test]
fn at_80x24_the_menu_and_the_quit_hint_are_whole() {
    let (page, _rx) = page_for(MainMenu::Communities, |s| {
        s.main_page.content_panel.selected = false;
        s.main_page.menu_panel.selected = true;
    });
    let rows = screen(&page, 80, 24);
    let all = rows.join("\n");
    for item in [
        "Communities",
        "My Relationships",
        "TSP Relationships",
        "My Credentials",
        "Help / Status",
        "Quit",
    ] {
        assert!(all.contains(item), "{item} is cut at 80x24:\n{all}");
    }
    let footer = rows.last().expect("a footer row");
    assert!(footer.contains("F10: quit"), "{footer}");
    assert!(footer.contains("?: keys"), "{footer}");
    assert!(
        !footer.trim_end().ends_with('·'),
        "the footer keeps whole hints: {footer}"
    );
}

/// With the Quit item selected on a short terminal, the menu scrolls so the
/// selection is on screen.
#[test]
fn a_short_terminal_scrolls_the_menu_to_the_selection() {
    let (page, _rx) = page_for(MainMenu::Quit, |s| {
        s.main_page.content_panel.selected = false;
        s.main_page.menu_panel.selected = true;
    });
    let all = screen(&page, 80, 16).join("\n");
    assert!(all.contains("Quit"), "{all}");
}
