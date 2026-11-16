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

// ----- Connectivity (#585) -------------------------------------------------

fn failed(class: openvtc_core::errors::ErrorClass) -> impl Fn(&mut State) + Copy {
    move |s: &mut State| {
        s.connection.status = crate::state_handler::state::MediatorStatus::Failed(
            crate::state_handler::state::ConnectionFailure::new("tls handshake eof", class),
        );
    }
}

/// The header names the class of failure — unreachable, refused and
/// incompatible read differently — and where the retry is.
#[test]
fn the_header_tells_unreachable_from_rejected_from_incompatible() {
    use openvtc_core::errors::ErrorClass as C;
    let mut seen = Vec::new();
    for class in [C::Unreachable, C::AuthRejected, C::Contract] {
        let (page, _rx) = page_for(MainMenu::Inbox, failed(class));
        let rows = screen(&page, 140, 40);
        let header = rows[0].clone();
        assert!(header.contains("see Help"), "{header}");
        seen.push(header);
    }
    assert!(seen[0].contains("mediator unreachable"), "{}", seen[0]);
    assert!(seen[1].contains("mediator refused us"), "{}", seen[1]);
    assert!(seen[2].contains("mediator incompatible"), "{}", seen[2]);
}

/// Help / Status shows the whole reason and the remedy, and `r` there
/// reconnects.
#[test]
fn help_status_shows_the_cause_and_r_retries() {
    use openvtc_core::errors::ErrorClass as C;
    let (mut page, mut rx) = page_for(MainMenu::Help, failed(C::AuthRejected));
    let all = screen(&page, 140, 60).join("\n");
    assert!(all.contains("tls handshake eof"), "{all}");
    assert!(all.contains("refused our credentials"), "{all}");
    page.handle_key_event(press(KeyCode::Char('r')));
    assert!(matches!(
        rx.try_recv(),
        Ok(Action::Settings(
            crate::state_handler::actions::SettingsAction::ReconnectMediator
        ))
    ));
}

/// Enter on the Settings mediator row reconnects.
#[test]
fn the_mediator_row_reconnects() {
    let (mut page, mut rx) = page_for(MainMenu::Settings, |s| {
        s.main_page.content_panel.settings.selected_index = 1;
    });
    page.handle_key_event(press(KeyCode::Enter));
    assert!(matches!(
        rx.try_recv(),
        Ok(Action::Settings(
            crate::state_handler::actions::SettingsAction::ReconnectMediator
        ))
    ));
}

// ----- Vetting, repos, rooms, elections and the overlays -----------------

/// [`keys_match`] for a view whose handler is `taken` rather than the
/// content panel's.
#[track_caller]
fn keys_match_with(
    what: &str,
    menu: MainMenu,
    arm: impl Fn(&mut State) + Clone,
    taken: fn(&mut MainPage, KeyEvent) -> bool,
) {
    let (page, _rx) = page_for(menu.clone(), arm.clone());
    let listed = advertised(&page);
    assert!(!listed.is_empty(), "{what}: the view advertises no keys");
    let mut problems = Vec::new();
    for key in universe() {
        let (mut page, _rx) = page_for(menu.clone(), arm.clone());
        let _ = advertised(&page);
        let took = taken(&mut page, key);
        let shown = listed.iter().any(|b| b.matches(&key));
        if took != shown {
            problems.push(format!(
                "{} {}",
                keymap::describe(&key),
                if took {
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

/// A view that takes every key — a confirmation, or a result any key
/// dismisses — and says so: every plain key in [`universe`] is taken. A Ctrl
/// chord reaches a view only where it lists it, so chords are left out.
#[track_caller]
fn takes_every_key(
    what: &str,
    menu: MainMenu,
    arm: impl Fn(&mut State) + Clone,
    taken: fn(&mut MainPage, KeyEvent) -> bool,
) {
    let (page, _rx) = page_for(menu.clone(), arm.clone());
    let listed = advertised(&page);
    assert!(!listed.is_empty(), "{what}: the view advertises no keys");
    for key in universe()
        .into_iter()
        .filter(|key| !key.modifiers.contains(KeyModifiers::CONTROL))
    {
        let (mut page, _rx) = page_for(menu.clone(), arm.clone());
        let _ = advertised(&page);
        assert!(
            taken(&mut page, key),
            "{what}: {} is not taken",
            keymap::describe(&key)
        );
    }
}

fn content(page: &mut MainPage, key: KeyEvent) -> bool {
    page.handle_content_key_event(key)
}

fn overlay(page: &mut MainPage, key: KeyEvent) -> bool {
    page.handle_overlay_key(key).expect("an overlay is open")
}

fn vetting_mode(
    mode: impl Fn() -> crate::state_handler::main_page::content::VettingMode + Copy,
) -> impl Fn(&mut State) + Copy {
    move |s: &mut State| s.main_page.content_panel.vetting.mode = mode()
}

fn desk_row() -> crate::state_handler::main_page::content::DeskRow {
    use crate::state_handler::main_page::content::{DeskRow, DeskStage};
    DeskRow {
        request_id: "r1".into(),
        applicant: "did:example:applicant".into(),
        applicant_name: None,
        community: "did:example:community".into(),
        pcs_zkp: false,
        pcs_tokens: None,
        pcs_events: false,
        state: "accepted".into(),
        stage: DeskStage::Accepted,
        method: None,
        match_code: None,
        claims: Vec::new(),
        required_claims: Vec::new(),
        message: None,
    }
}

#[test]
fn vetting_lists_and_desk_keys_are_exactly_their_footers() {
    use crate::state_handler::main_page::content::{DeskView, VettingTab};
    keys_match(
        "vetting applications, no persona",
        MainMenu::Vetting,
        |_| {},
    );
    keys_match(
        "vetting applications, one",
        MainMenu::Vetting,
        super::key_handler_tests::vetting_rows,
    );
    for view in DeskView::ALL {
        keys_match(
            &format!("vetting desk, {view:?}, a row in every list"),
            MainMenu::Vetting,
            move |s| {
                super::key_handler_tests::vetting_rows(s);
                s.main_page.content_panel.vetting.tab = VettingTab::Desk;
                s.main_page.content_panel.vetting.desk_view = view;
            },
        );
    }
    for view in DeskView::ALL {
        for rows in [0, 2] {
            keys_match(
                &format!("vetting desk, {view:?}, {rows} rows"),
                MainMenu::Vetting,
                move |s| {
                    let v = &mut s.main_page.content_panel.vetting;
                    v.tab = VettingTab::Desk;
                    v.desk_view = view;
                    if rows > 0 {
                        v.desk = vec![desk_row(), desk_row()].into();
                    }
                },
            );
        }
    }
}

#[test]
fn vetting_form_keys_are_exactly_their_footers() {
    use crate::state_handler::main_page::content::{
        AttestForm, DirectoryView, FaceChoice, VettingMode, VettingPersona,
    };
    let face = |name: &str| FaceChoice {
        profile_id: name.into(),
        name: name.into(),
        entries: 1,
        worn: false,
        claim_types: Vec::new(),
    };
    keys_match(
        "new application, community",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::NewApplication {
            community: String::new(),
            persona_index: 0,
            context_options: Vec::new(),
            context_index: 0,
            field: 0,
        }),
    );
    for personas in [1, 2] {
        keys_match(
            &format!("new application, persona of {personas}"),
            MainMenu::Vetting,
            move |s| {
                s.main_page.content_panel.vetting.personas = (0..personas)
                    .map(|i| VettingPersona {
                        persona: openvtc_core::config::account::PersonaId::new(),
                        did: format!("did:key:z{i}"),
                        label: format!("p{i}"),
                    })
                    .collect::<Vec<_>>()
                    .into();
                s.main_page.content_panel.vetting.mode = VettingMode::NewApplication {
                    community: String::new(),
                    persona_index: 0,
                    context_options: Vec::new(),
                    context_index: 0,
                    field: 1,
                };
            },
        );
    }
    keys_match(
        "holder grant",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::HolderGrant {
            credential_did: None,
        }),
    );
    keys_match(
        "choose a face, none made",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::ChooseFace {
            application_id: "a1".into(),
            faces: Vec::new(),
            index: 0,
            required: Vec::new(),
        }),
    );
    keys_match("choose a face, two made", MainMenu::Vetting, move |s| {
        s.main_page.content_panel.vetting.mode = VettingMode::ChooseFace {
            application_id: "a1".into(),
            faces: vec![face("work"), face("home")],
            index: 0,
            required: Vec::new(),
        };
    });
    keys_match(
        "ask a vetter",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::RequestVetter {
            application_id: "a1".into(),
            entry: String::new(),
            vetter: String::new(),
            ticket: None,
            note: None,
        }),
    );
    keys_match(
        "vetter directory",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::Directory(Box::default())),
    );
    keys_match(
        "vetter directory, results",
        MainMenu::Vetting,
        vetting_mode(|| {
            let mut view = DirectoryView {
                searched: true,
                ..DirectoryView::default()
            };
            view.field = crate::state_handler::main_page::content::DIRECTORY_FIELDS;
            VettingMode::Directory(Box::new(view))
        }),
    );
    {
        use crate::state_handler::main_page::content::{
            EventForm, PROFILE_FIELDS, VetterProfileForm,
        };
        use openvtc_core::vetting::book::VetterPolicy;
        use openvtc_core::vetting::registry::{EventDraft, ProfileDraft};
        let form = |field: usize, event: bool| {
            let mut draft = ProfileDraft::new(&VetterPolicy::default());
            draft.events.push(EventDraft::default());
            VetterProfileForm {
                membership_index: 0,
                draft,
                field,
                event: event.then(EventForm::default),
                error: None,
                state_line: None,
            }
        };
        for field in 0..=PROFILE_FIELDS + 1 {
            keys_match(
                &format!("profile, field {field}"),
                MainMenu::Vetting,
                move |s| {
                    s.main_page.content_panel.vetting.mode =
                        VettingMode::Profile(Box::new(form(field, false)));
                },
            );
        }
        keys_match("profile, an event", MainMenu::Vetting, move |s| {
            s.main_page.content_panel.vetting.mode = VettingMode::Profile(Box::new(form(0, true)));
        });
    }
    keys_match(
        "resend",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::Resend { index: 0 }),
    );
    keys_match(
        "event mode",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::EventMode { index: 0 }),
    );
    keys_match(
        "hidden vetting",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::HiddenVetting { index: 0 }),
    );
    keys_match(
        "send a card",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::SendCard {
            application_id: "a1".into(),
            session_id: "s1".into(),
            preview: None,
        }),
    );
    for field in [0, 1] {
        keys_match(
            &format!("new ticket, field {field}"),
            MainMenu::Vetting,
            move |s| {
                s.main_page.content_panel.vetting.mode = VettingMode::NewTicket {
                    membership_index: 0,
                    uses_index: 0,
                    field,
                };
            },
        );
    }
    keys_match(
        "open a session",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::OpenSession {
            request_id: "r1".into(),
            method_index: 0,
        }),
    );
    for field in 0..AttestForm::FIELDS {
        keys_match(
            &format!("attest, field {field}"),
            MainMenu::Vetting,
            move |s| {
                s.main_page.content_panel.vetting.desk = vec![desk_row()].into();
                s.main_page.content_panel.vetting.mode = VettingMode::Attest {
                    request_id: "r1".into(),
                    form: AttestForm {
                        field,
                        ..AttestForm::default()
                    },
                };
            },
        );
    }
    for field in [0, 1] {
        keys_match(
            &format!("decline, field {field}"),
            MainMenu::Vetting,
            move |s| {
                s.main_page.content_panel.vetting.mode = VettingMode::ConfirmDecline {
                    request_id: "r1".into(),
                    reason_index: 0,
                    message: String::new(),
                    field,
                };
            },
        );
    }
    keys_match(
        "withdraw",
        MainMenu::Vetting,
        vetting_mode(|| VettingMode::Withdraw {
            statement_id: "st1".into(),
            reason_index: 0,
        }),
    );
    for (what, mode) in [
        (
            "abandon",
            (|| VettingMode::ConfirmAbandon {
                application_id: "a1".into(),
            }) as fn() -> VettingMode,
        ),
        ("delete a ticket", || VettingMode::ConfirmDeleteTicket {
            ticket_id: "t1".into(),
        }),
    ] {
        takes_every_key(what, MainMenu::Vetting, vetting_mode(mode), content);
    }
}

fn room(state: &str) -> openvtc_core::community_rooms::RoomMembership {
    serde_json::from_value(serde_json::json!({
        "roomId": format!("did:webvh:example.com:rooms:{state}"),
        "host": "did:example:community",
        "label": "Board pack",
        "visibility": "private",
        "actions": ["read"],
        "validUntil": "2027-10-01T00:00:00Z",
        "state": state,
        "offeredAt": "2026-10-14T10:00:00Z",
        "roomState": "active",
    }))
    .unwrap()
}

fn rooms(
    phase: crate::state_handler::main_page::rooms::RoomsPhase,
    states: &'static [&'static str],
) -> impl Fn(&mut State) + Clone {
    move |s: &mut State| {
        let mut view = crate::state_handler::main_page::rooms::RoomsView::new(
            "did:key:zVtc".into(),
            Default::default(),
            "did:key:zAlice".into(),
            "Acme".into(),
        );
        view.phase = phase.clone();
        view.rooms = states.iter().map(|st| room(st)).collect();
        view.held = Some(Vec::new());
        s.main_page.content_panel.rooms.view = Some(view);
    }
}

#[test]
fn rooms_keys_are_exactly_their_footers() {
    use crate::state_handler::main_page::rooms::RoomsPhase;
    let cases: [(&str, RoomsPhase, &'static [&'static str]); 4] = [
        ("rooms, loading", RoomsPhase::Loading, &[]),
        ("rooms, failed", RoomsPhase::Failed("x".into()), &[]),
        ("rooms, none offered", RoomsPhase::Loaded, &[]),
        (
            "rooms, offered",
            RoomsPhase::Loaded,
            &["offered", "admitted"],
        ),
    ];
    for (what, phase, states) in cases {
        let arm = rooms(phase, states);
        let (page, _rx) = page_for(MainMenu::Communities, arm.clone());
        let listed = advertised(&page);
        let mut problems = Vec::new();
        for key in universe() {
            let (mut page, _rx) = page_for(MainMenu::Communities, arm.clone());
            let _ = advertised(&page);
            let took = page.handle_content_key_event(key);
            if took != listed.iter().any(|b| b.matches(&key)) {
                problems.push(keymap::describe(&key));
            }
        }
        assert!(problems.is_empty(), "{what}: disagree on {problems:?}");
    }
}

#[test]
fn elections_keys_are_exactly_their_footers() {
    use super::key_handler_tests::with_elections;
    use crate::state_handler::main_page::elections::Screen;
    for screen in [Screen::List, Screen::Detail, Screen::Ballot, Screen::Result] {
        let arm = move |s: &mut State| with_elections(screen)(s);
        keys_match(
            &format!("elections, {screen:?}"),
            MainMenu::Communities,
            arm,
        );
    }
    takes_every_key(
        "elections, confirm the cast",
        MainMenu::Communities,
        |s| with_elections(Screen::Confirm)(s),
        content,
    );
    takes_every_key(
        "elections, disclose the membership",
        MainMenu::Communities,
        |s| with_elections(Screen::Disclose)(s),
        content,
    );
}

#[test]
fn repos_keys_are_exactly_their_footers() {
    use super::key_handler_tests::repos_view;
    use crate::state_handler::main_page::repos::ReposPhase;
    keys_match("repos, loading", MainMenu::Communities, |s| {
        s.main_page.content_panel.repos.view = Some(repos_view());
    });
    keys_match("repos, failed", MainMenu::Communities, |s| {
        let mut view = repos_view();
        view.phase = ReposPhase::Failed("x".into());
        s.main_page.content_panel.repos.view = Some(view);
    });
    keys_match("repos, none", MainMenu::Communities, |s| {
        let mut view = repos_view();
        view.phase = ReposPhase::Loaded;
        s.main_page.content_panel.repos.view = Some(view);
    });
    // One repository, not checked out here: clone and use-existing apply,
    // signing a checkout does not.
    let with_repo = |screen: crate::state_handler::main_page::repos::ReposScreen| {
        move |s: &mut State| {
            let mut view = repos_view();
            view.data = Some(Arc::new(
                serde_json::from_value(serde_json::json!({
                    "accounts": [],
                    "namespaces": [{"id": "ns_1", "forge": "github.com", "owner": "acme",
                                    "kind": "organization", "mode": "bridge", "state": "bound"}],
                    "repos": [{"resource": "github.com/acme/gadgets", "visibility": "public",
                               "state": "active", "owners": ["did:webvh:me"],
                               "bootstrap": {"workflow": true, "keyring": true, "variables": true, "requiredCheck": true},
                               "sync": {"state": "inSync", "drift": []}}],
                    "rights": []
                }))
                .unwrap(),
            ));
            view.phase = ReposPhase::Loaded;
            view.screen = screen.clone();
            s.main_page.content_panel.repos.view = Some(view);
        }
    };
    use crate::state_handler::main_page::repos::ReposScreen;
    keys_match_with(
        "repos, one repository",
        MainMenu::Communities,
        with_repo(ReposScreen::List),
        content,
    );
    keys_match_with(
        "repos, the repository",
        MainMenu::Communities,
        with_repo(ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        }),
        content,
    );
}

#[test]
fn overlay_keys_are_exactly_their_footers() {
    use crate::state_handler::main_page::content::{
        AddVicPhase, AddVicState, AgentNameManagerPhase, AgentNameManagerState, AgentNameRow,
        CommunitySwitcherState, CreatePersonaPhase, CreatePersonaState, PersonaPathChoice,
    };
    let create = |phase: CreatePersonaPhase, path_choice: PersonaPathChoice| {
        move |s: &mut State| {
            s.main_page.create_persona = Some(CreatePersonaState {
                phase: phase.clone(),
                path_choice,
                ..CreatePersonaState::default()
            });
        }
    };
    keys_match_with(
        "create persona, label",
        MainMenu::Identity,
        create(CreatePersonaPhase::Label, PersonaPathChoice::Auto),
        overlay,
    );
    for choice in [PersonaPathChoice::Auto, PersonaPathChoice::Custom] {
        keys_match_with(
            &format!("create persona, path {choice:?}"),
            MainMenu::Identity,
            create(CreatePersonaPhase::Path, choice),
            overlay,
        );
    }
    for phase in [CreatePersonaPhase::Done, CreatePersonaPhase::Failed] {
        takes_every_key(
            &format!("create persona, {phase:?}"),
            MainMenu::Identity,
            create(phase, PersonaPathChoice::Auto),
            overlay,
        );
    }

    for names in [0, 2] {
        keys_match_with(
            &format!("agent names, {names} held"),
            MainMenu::Identity,
            move |s| {
                s.main_page.agent_names = Some(AgentNameManagerState {
                    phase: AgentNameManagerPhase::Ready,
                    names: (0..names)
                        .map(|i| AgentNameRow {
                            name: format!("n{i}"),
                            enabled: true,
                        })
                        .collect(),
                    ..AgentNameManagerState::default()
                });
            },
            overlay,
        );
    }

    keys_match_with(
        "add a VIC",
        MainMenu::Vta,
        |s| s.main_page.add_vic = Some(AddVicState::default()),
        overlay,
    );
    for phase in [AddVicPhase::Done, AddVicPhase::Failed] {
        takes_every_key(
            &format!("add a VIC, {phase:?}"),
            MainMenu::Vta,
            move |s| {
                s.main_page.add_vic = Some(AddVicState {
                    phase: phase.clone(),
                    ..AddVicState::default()
                });
            },
            overlay,
        );
    }

    keys_match_with(
        "community switcher",
        MainMenu::Communities,
        |s| {
            s.main_page.switcher = Some(CommunitySwitcherState {
                items: vec![
                    super::key_handler_tests::switcher_item("a", true),
                    super::key_handler_tests::switcher_item("b", false),
                ],
                selected: 0,
            });
        },
        overlay,
    );
}
