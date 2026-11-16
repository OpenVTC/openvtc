//! Vetting page key handling, beside the page's rendering in
//! `vetting_panel.rs`.

use crate::state_handler::actions::Action;
use crate::state_handler::main_page::MainPanel;
use crate::state_handler::main_page::status::Status;
use crate::ui::pages::main::MainPage;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

impl MainPage {
    /// Vetting page keys.
    ///
    /// In a list: `Tab` switches tab, `↑/↓` select, and each tab has its own
    /// verbs (shown in its footer). In a form: `↑/↓`/`Tab` move between fields,
    /// a text field takes typing, `←/→` cycle a choice, `Space` ticks, `Enter`
    /// commits and `Esc` leaves.
    pub(in crate::ui::pages::main) fn handle_vetting_key(&mut self, key: KeyEvent) -> bool {
        use crate::state_handler::actions::VettingAction as V;
        use crate::state_handler::main_page::content::{DeskView, VettingMode, VettingTab};

        let vetting = &self.props.main_page.content_panel.vetting;
        if !matches!(vetting.mode, VettingMode::List) {
            let text = vetting.mode.focused_text().map(str::to_string);
            // Tab/↑/↓, ←/→ and Space are taken only where they do something
            // on this form (and its footer lists them only there).
            let moves = vetting.form_moves();
            let cycles = vetting.form_cycles();
            let ticks = vetting.form_ticks();
            let confirming = matches!(vetting.mode, VettingMode::ConfirmDecline { .. });
            // Abandon, delete-ticket and withdraw are committed by `y` alone
            // (#579): Enter opened this view, and a key held a moment too long
            // must not also commit it. A plain prompt (abandon, delete) takes
            // any other key as "keep it".
            let plain_prompt = matches!(
                vetting.mode,
                VettingMode::ConfirmAbandon { .. } | VettingMode::ConfirmDeleteTicket { .. }
            );
            let y_commits =
                confirming || plain_prompt || matches!(vetting.mode, VettingMode::Withdraw { .. });
            if plain_prompt {
                let action = if crate::ui::pages::main::confirm::is_yes(&key) {
                    V::Submit
                } else {
                    V::Back
                };
                let _ = self.action_tx.send(Action::Vetting(action));
                return true;
            }
            // The holder-grant view's whole job is to send you to another
            // terminal and back, and it ends with "then press f again". That
            // key was not bound here, so the one thing the screen asks for did
            // nothing — and with no field to type in and no rows to move
            // between, Tab and the arrows did nothing visible either. The view
            // read as frozen, and the only way back to a working `f` was to
            // restart.
            // `f` chooses the face wherever a missing or wrong one is what the
            // page is reporting: the grant page, and the card it reads from.
            // A card for an application that is gone has nothing to act on.
            let card_gone = matches!(
                &vetting.mode,
                VettingMode::SendCard { application_id, .. }
                    if !vetting.applications.iter().any(|a| &a.id == application_id)
            );
            let chooses_face = !card_gone
                && matches!(
                    vetting.mode,
                    VettingMode::HolderGrant { .. } | VettingMode::SendCard { .. }
                );
            let on_result = matches!(&vetting.mode, VettingMode::Directory(view) if view.result_index().is_some());
            let on_event = matches!(
                &vetting.mode,
                VettingMode::Profile(form) if form.event.is_none() && form.event_index().is_some()
            );
            let hidden_row = match vetting.mode {
                VettingMode::HiddenVetting { index } => vetting.hidden.get(index),
                _ => None,
            };
            let on_hidden = hidden_row.is_some();
            let rechecks = hidden_row.is_some_and(|row| !row.key.is_empty());
            // Nothing to do on a hidden-vetting view with no community, or on
            // a card whose preview found a problem — except choose the face.
            let no_enter = card_gone
                || matches!(vetting.mode, VettingMode::HiddenVetting { .. }) && !on_hidden
                || matches!(
                    &vetting.mode,
                    VettingMode::SendCard { preview: Some(p), .. } if p.problem.is_some()
                );
            let shown_ticket = match vetting.mode {
                VettingMode::ShowTicket { index } => vetting.tickets.get(index),
                _ => None,
            };
            if let Some(ticket) = shown_ticket
                && let Some(status) = copy_ticket(ticket, key.code)
            {
                let _ = self.action_tx.send(Action::Vetting(V::Status(status)));
                return true;
            }
            // Ctrl+V on the one field whose whole content is something pasted.
            // Ahead of the text handler, which would otherwise type a literal
            // `v` into the ticket link. Bracketed paste still works and is the
            // path that survives SSH; this is the one that is on the screen.
            if matches!(vetting.mode, VettingMode::RequestVetter { .. })
                && key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('v' | 'V'))
            {
                let action = match crate::clipboard::read_clipboard() {
                    Ok(pasted) => V::PasteTicket(pasted),
                    // Reading the OS clipboard cannot work over SSH, where a
                    // bracketed paste still can — so the refusal says that
                    // rather than only that it failed.
                    Err(why) => V::Status(Status::error(format!(
                        "Could not read the clipboard ({why}). Paste directly into this screen \
                         instead — that works over SSH, where reading the clipboard cannot."
                    ))),
                };
                let _ = self.action_tx.send(Action::Vetting(action));
                return true;
            }
            let action = match key.code {
                KeyCode::Esc => Some(V::Back),
                // On the decline note, Enter finishes typing and moves on; `y`
                // then declines. On the other y-committed views Enter does
                // nothing.
                KeyCode::Enter if confirming && text.is_some() => Some(V::NextField),
                KeyCode::Enter if y_commits || no_enter => None,
                KeyCode::Enter => Some(V::Submit),
                KeyCode::Tab | KeyCode::Down if moves => Some(V::NextField),
                KeyCode::BackTab | KeyCode::Up if moves => Some(V::PrevField),
                KeyCode::Left if cycles => Some(V::Cycle(false)),
                KeyCode::Right if cycles => Some(V::Cycle(true)),
                code => match text {
                    // Typing is the field's (`text_input`).
                    Some(_) => None,
                    None if chooses_face && code == KeyCode::Char('f') => Some(V::ChooseFace),
                    None if code == KeyCode::Char('y') && y_commits => Some(V::Submit),
                    None if code == KeyCode::Char('n') && confirming => Some(V::Back),
                    None if on_result && code == KeyCode::Char('n') => Some(V::DirectoryPage(true)),
                    None if on_result && code == KeyCode::Char('p') => {
                        Some(V::DirectoryPage(false))
                    }
                    None if on_result && code == KeyCode::Char('a') => Some(V::AskListedVetter),
                    None if on_event && matches!(code, KeyCode::Char('x') | KeyCode::Delete) => {
                        Some(V::RemoveEvent)
                    }
                    None if on_hidden && code == KeyCode::Char('d') => Some(V::DrawNow),
                    None if rechecks && code == KeyCode::Char('r') => Some(V::CheckHiddenKey),
                    None if ticks && code == KeyCode::Char(' ') => Some(V::Toggle),
                    None => None,
                },
            };
            return match action {
                Some(action) => {
                    let _ = self.action_tx.send(Action::Vetting(action));
                    true
                }
                None => false,
            };
        }

        // A journey is open: its keys are the current step's, and the way out.
        // A key for a step not reached yet does nothing — the strip says why —
        // so the steps cannot be taken out of order by accident.
        if let Some(journey) = &vetting.journey {
            use crate::state_handler::main_page::content::JourneySteps;
            use openvtc_core::vetting::journey::{ApplicantStep, StepState, VetterStep};
            let reached = |state: StepState| state != StepState::Todo;
            let action = match &journey.steps {
                JourneySteps::Applicant(steps) => {
                    let at = |step: ApplicantStep| {
                        steps.iter().any(|s| s.step == step && reached(s.state))
                    };
                    match key.code {
                        KeyCode::Esc => Some(V::CloseJourney),
                        KeyCode::Char('m') => Some(V::RefreshRequirements),
                        KeyCode::Char('x') | KeyCode::Delete => Some(V::ArmAbandon),
                        // The face can be changed until a card has gone.
                        KeyCode::Char('f') if at(ApplicantStep::Face) => Some(V::ChooseFace),
                        KeyCode::Char('r') if at(ApplicantStep::Vetters) => Some(V::RequestVetter),
                        KeyCode::Char('v') if at(ApplicantStep::Vetters) => Some(V::FindVetters),
                        KeyCode::Enter | KeyCode::Char('c') if at(ApplicantStep::Sessions) => {
                            Some(V::ReviewCard)
                        }
                        KeyCode::Char('j')
                            if steps.iter().any(|s| {
                                s.step == ApplicantStep::Join && s.state == StepState::Current
                            }) =>
                        {
                            if let Some(application) = vetting.applications.get(vetting.selected) {
                                let _ = self
                                    .action_tx
                                    .send(Action::StartJoinFor(application.community.clone()));
                            }
                            return true;
                        }
                        _ => None,
                    }
                }
                JourneySteps::Vetter(steps, ending) => {
                    let current = openvtc_core::vetting::journey::current(steps);
                    match key.code {
                        KeyCode::Esc => Some(V::CloseJourney),
                        _ if ending.is_some() => None,
                        KeyCode::Char('x') => Some(V::ArmDecline),
                        KeyCode::Char('o')
                            if matches!(current, Some(VetterStep::Session | VetterStep::Code)) =>
                        {
                            Some(V::OpenSession)
                        }
                        KeyCode::Enter | KeyCode::Char('a')
                            if matches!(current, Some(VetterStep::Check | VetterStep::Sign)) =>
                        {
                            Some(V::StartAttest)
                        }
                        _ => None,
                    }
                }
            };
            if let Some(action) = action {
                let _ = self.action_tx.send(Action::Vetting(action));
            }
            // Every key is the journey's while it is open, including the ones
            // it ignores: falling through would act on the list behind it.
            return true;
        }

        // The desk's views take ←/→, which everywhere else on the main page is
        // how focus returns to the menu (they fall through to the page-level
        // handler). Consuming them without offering another way out would make
        // the desk a room whose door is bound to something else, so Esc is that
        // way out — and it is bound for the whole page, not just the desk, so
        // it means one thing here.
        if key.code == KeyCode::Esc {
            let _ = self
                .action_tx
                .send(Action::MainPanelSwitch(MainPanel::MainMenu));
            return true;
        }

        // The list takes exactly the keys its footer lists.
        if !crate::ui::pages::main::components::vetting_panel::list_keys(vetting)
            .iter()
            .any(|b| b.matches(&key))
        {
            return false;
        }
        let selected = vetting.selected;
        let len = vetting.tab_len();
        let view = vetting.desk_view;
        // The desk's three views share one key space: the arms match on the tab
        // and guard on the view. A key bound on the desk generally (`p`, `g`)
        // has no guard, which is the point of the header — the profile and the
        // vetter credential belong to the whole desk, not to whichever list is
        // open.
        let action = match (vetting.tab, key.code) {
            (_, KeyCode::Tab) => V::SwitchTab,
            (VettingTab::Desk, KeyCode::Left) => V::SwitchDeskView(false),
            (VettingTab::Desk, KeyCode::Right) => V::SwitchDeskView(true),
            (_, KeyCode::Up) => V::Select(selected.saturating_sub(1)),
            (_, KeyCode::Down) => V::Select((selected + 1).min(len.saturating_sub(1))),
            (VettingTab::Applications, KeyCode::Char('n')) => V::StartApplication,
            (VettingTab::Applications, KeyCode::Char('f')) => V::ChooseFace,
            (VettingTab::Applications, KeyCode::Char('r')) => V::RequestVetter,
            (VettingTab::Applications, KeyCode::Char('m')) => V::RefreshRequirements,
            (VettingTab::Applications, KeyCode::Char('p')) => V::SwitchVettingPath,
            (VettingTab::Applications, KeyCode::Char('v')) => V::FindVetters,
            // Enter opens the application as a journey; `c` still goes
            // straight to the card for someone who knows where they are.
            (VettingTab::Applications, KeyCode::Enter) => V::OpenJourney,
            (VettingTab::Applications, KeyCode::Char('c')) => V::ReviewCard,
            // An application is otherwise permanent, and its persona is fixed
            // for its whole life — so one started as the wrong persona would
            // own that community's vetting route forever.
            (VettingTab::Applications, KeyCode::Char('x') | KeyCode::Delete) => V::ArmAbandon,
            // The join this application was made for. It leaves the panel
            // rather than sending an action, because the join flow owns the
            // screen — and it carries the community, so the DID an application
            // already names is never asked for again.
            (VettingTab::Applications, KeyCode::Char('j')) => {
                let Some(application) = vetting.applications.get(selected) else {
                    return false;
                };
                let _ = self
                    .action_tx
                    .send(Action::StartJoinFor(application.community.clone()));
                return true;
            }
            // Anywhere on the desk: the profile the communities hold, and
            // asking one to reissue a grant that has lapsed.
            (VettingTab::Desk, KeyCode::Char('p')) => V::EditProfile,
            (VettingTab::Desk, KeyCode::Char('g')) => V::AskResend,
            (VettingTab::Desk, KeyCode::Char('e')) => V::AskEventMode,
            (VettingTab::Desk, KeyCode::Char('h')) => V::OpenHiddenVetting,
            // Get tokens: enrol if needed, then draw what has begun — the one key a vetter at a
            // PCS ZKP community needs before `t` can issue a ticket.
            (VettingTab::Desk, KeyCode::Char('k')) => V::DrawNow,
            (VettingTab::Desk, KeyCode::Char('o')) if view == DeskView::Requests => V::OpenSession,
            (VettingTab::Desk, KeyCode::Enter) if view == DeskView::Requests => V::OpenJourney,
            (VettingTab::Desk, KeyCode::Char('a')) if view == DeskView::Requests => V::StartAttest,
            (VettingTab::Desk, KeyCode::Char('x')) if view == DeskView::Requests => V::ArmDecline,
            (VettingTab::Desk, KeyCode::Char('t')) if view == DeskView::Tickets => V::NewTicket,
            (VettingTab::Desk, KeyCode::Enter) if view == DeskView::Tickets => V::ShowTicket,
            (VettingTab::Desk, KeyCode::Char('d')) if view == DeskView::Tickets => V::DeleteTicket,
            (VettingTab::Desk, KeyCode::Char('u' | 'y')) if view == DeskView::Tickets => {
                let Some(status) = vetting
                    .tickets
                    .get(selected)
                    .and_then(|ticket| copy_ticket(ticket, key.code))
                else {
                    return true;
                };
                V::Status(status)
            }
            (VettingTab::Desk, KeyCode::Char('w')) if view == DeskView::Issued => V::ArmWithdraw,
            _ => return false,
        };
        let _ = self.action_tx.send(Action::Vetting(action));
        true
    }
}

/// `y` copies a ticket's code and `u` its link; the status says how it went.
/// `None` for another key, or `u` on a ticket with no link.
fn copy_ticket(
    ticket: &crate::state_handler::main_page::content::TicketRow,
    code: KeyCode,
) -> Option<Status> {
    let (text, what) = match code {
        KeyCode::Char('y') => (ticket.code.clone(), "code"),
        KeyCode::Char('u') => (ticket.uri.clone()?, "link"),
        _ => return None,
    };
    Some(match crate::clipboard::copy_to_clipboard(&text) {
        Ok(method) => Status::success(format!("Ticket {what} copied via {}.", method.label())),
        Err(e) => Status::error(format!("Could not copy the {what}: {e}")),
    })
}
