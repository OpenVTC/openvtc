//! Vetter tickets: whether one may be issued, issuing and minting them,
//! settling those waiting on a mode reading, and deleting them.
//!
//! Issuing and deleting are planned here (`plan_*`), purely, on the state and
//! the book; what they still owe the loop is the [`VettingEffect`] they
//! return. Settling a pending ticket ([`settle_pending_tickets`]) sends
//! nothing: it decides on the book and saves through the scheduler it is
//! handed, from the loop's sweep and its inbound arm.

use crate::state_handler::main_page::status::Status;
use chrono::{DateTime, Utc};
use openvtc_core::config::Config;
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::mode::{ModeFailure, VetterMode};
use openvtc_core::vetting::queries::QUERY_TIMEOUT;
use openvtc_core::vetting::tickets::{DEFAULT_VALIDITY, Ticket};
use openvtc_core::vetting::wire;

use super::desk::Asked;
use super::dispatch::{back, panel, show};
use super::effect::{Step, VettingEffect};
use super::jobs::Sent;
use super::send::{Claim, claimable, give_up, persona_did};
use super::words::{
    clause, community_display, get_tokens_words, pcs_tokens_line, tokens_obtainable_now,
};
use crate::state_handler::dispatch_util::{self, Persist, SyncLog};
use crate::state_handler::main_page::content::{
    DeskView, PendingTicket, VETTING_TICKET_USES, VettingMembership, VettingMode, VettingTab,
};
use crate::state_handler::save_coalesce::SaveScheduler;
use crate::state_handler::state::State;

/// Delete a ticket, once the confirmation has been taken.
///
/// Irreversible and invisible to the people who matter: whoever is holding a
/// copy of this ticket — read off a screen, scanned from a QR code — finds
/// their request refused with `invalidTicket` and no way to tell that the
/// ticket was withdrawn rather than mistyped. That is why it is confirmed, and
/// why the message says what it costs rather than only that it happened.
pub(super) fn plan_delete_ticket(
    state: &mut State,
    config: &mut Config,
    ticket_id: &str,
) -> VettingEffect {
    let Some(ticket) = config
        .private
        .vetting
        .tickets
        .iter()
        .find(|t| t.id == ticket_id)
        .cloned()
    else {
        back(panel(state));
        show(state, Status::warning("That ticket is already gone."));
        return VettingEffect::none();
    };
    config.private.vetting.tickets.retain(|t| t.id != ticket_id);
    back(panel(state));
    panel(state).selected = 0;
    VettingEffect(vec![Step::Persist(format!(
        "Ticket {} deleted — anyone already holding it is now refused, and they are not \
         told why.",
        ticket.code
    ))])
}

/// Why no ticket should be issued for `membership` now, if there is a reason: the community
/// proves vetting with a PCS zero-knowledge proof, and this vetter cannot attest there yet — no
/// credential, or no token. A ticket brings requests, and every one would end at "cannot
/// attest". Asked only once the community's mode has just been read as PCS ZKP
/// ([`ticket_check`]).
fn ticket_refusal(
    book: &VettingBook,
    membership: &VettingMembership,
    now: DateTime<Utc>,
) -> Option<String> {
    let (_, true) = pcs_tokens_line(book, &membership.community, membership.persona, now)? else {
        return None;
    };
    // The full story once, here, where it is acted on — what getting tokens takes now, or what
    // blocks it and until when; the desk header keeps the short line.
    let why = get_tokens_words(
        book,
        &membership.community,
        membership.persona,
        &membership.name,
        now,
    );
    Some(format!(
        "No ticket issued: {} vets by PCS ZKP now, and you cannot attest there yet — {}. A \
         ticket now would bring requests you could not attest.",
        membership.name,
        clause(&why)
    ))
}

/// The longest a ticket waits on its community's answer about how it vets. The question's own
/// reply window ([`QUERY_TIMEOUT`]) normally ends it first, as "no answer"; this is the bound
/// that holds even if that never fires (R1.2).
fn ticket_check_wait() -> chrono::Duration {
    QUERY_TIMEOUT + chrono::Duration::seconds(5)
}

/// Where a pending ticket stands.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TicketCheck {
    /// No answer about the community's mode since it was asked, and still within the wait.
    Waiting,
    /// The community answered: issue the ticket, under this mode.
    Issue(VetterMode),
    /// Not issued: the community runs PCS ZKP and this vetter holds no token to attest with.
    /// What getting tokens takes — or what blocks it, and until when — is said, and the
    /// schedule is run at once so they come without a second key.
    Gated(String),
    /// Not issued, and why.
    Refused(String),
}

/// Decide a pending ticket, on an answer about its community's mode that arrived **after** the
/// ticket was asked for — never on the remembered mode. Named vetting issues with no gate (it
/// does not matter that the community used to run PCS ZKP); PCS ZKP keeps the enrolment and
/// token gate ([`ticket_refusal`]); a failed read refuses, saying how it failed and what was
/// last known, rather than guessing either way.
pub(crate) fn ticket_check(
    book: &VettingBook,
    pending: &PendingTicket,
    now: DateTime<Utc>,
) -> TicketCheck {
    let reading = book.vetter_mode(&pending.membership.community);
    match reading.read_since(pending.asked_at) {
        Some(VetterMode::Named) => TicketCheck::Issue(VetterMode::Named),
        Some(VetterMode::PcsZkp) => match ticket_refusal(book, &pending.membership, now) {
            Some(refusal) => TicketCheck::Gated(refusal),
            None => TicketCheck::Issue(VetterMode::PcsZkp),
        },
        None => {
            let failure = reading.failed_since(pending.asked_at).cloned().or_else(|| {
                (now - pending.asked_at >= ticket_check_wait()).then_some(ModeFailure::Unanswered)
            });
            match failure {
                Some(failure) => TicketCheck::Refused(ticket_unconfirmed(
                    &pending.membership.name,
                    &failure,
                    &reading,
                    now,
                )),
                None => TicketCheck::Waiting,
            }
        }
    }
}

/// No ticket, because how the community vets now could not be read.
fn ticket_unconfirmed(
    name: &str,
    failure: &ModeFailure,
    reading: &openvtc_core::vetting::mode::ModeReading,
    now: DateTime<Utc>,
) -> String {
    format!(
        "No ticket issued: could not confirm how {name} vets now — {}. Last known: {}. A ticket \
         is issued only on a fresh answer, since it brings requests answered under that mode; \
         press t to try again.",
        clause(&failure.words()),
        reading.last_known_words(now)
    )
}

/// `t` on the Tickets view, confirmed: ask the community how it vets **now**, and issue the
/// ticket when it answers ([`settle_pending_tickets`]). Never decided here, from what the client
/// remembers — a community can switch between named vetting and PCS ZKP at any time, and the
/// ticket follows the mode it runs when it is handed out.
///
/// The form closes before the checks, so a refusal is said on the list.
pub(super) fn plan_issue_ticket(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    membership_index: usize,
    uses_index: usize,
) -> VettingEffect {
    let Some(membership) = panel(state).memberships.get(membership_index).cloned() else {
        return VettingEffect::none();
    };
    let uses = VETTING_TICKET_USES[uses_index.min(VETTING_TICKET_USES.len() - 1)];
    panel(state).mode = VettingMode::List;
    if let Some(waiting) = &panel(state).pending_ticket {
        let name = waiting.membership.name.clone();
        show(
            state,
            Status::progress(format!(
                "Still asking {name} how it vets, for the last ticket — a moment."
            )),
        );
        return VettingEffect::none();
    }
    let Some(did) = persona_did(config, membership.persona) else {
        show(
            state,
            Status::error(
                "No ticket issued: the persona you vet for that community as is not available.",
            ),
        );
        return VettingEffect::none();
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    let now = Utc::now();
    let community = membership.community.clone();
    let protocol = config.private.vetting.protocol_for(&community);
    let document = match wire::manifest_request(&did, &community, protocol) {
        Ok(d) => d,
        Err(e) => {
            give_up(
                state,
                config,
                "No ticket issued: could not build the question",
                e,
            );
            return VettingEffect::none();
        }
    };
    config.private.vetting.mode_asked(&community, now);
    let persona = membership.persona;
    VettingEffect(vec![Step::Ask {
        persona,
        document: Box::new(document),
        sent: Box::new(Sent::Manifest { community }),
        claim: Claim::Held,
        then: Asked::Ticket(PendingTicket {
            membership,
            uses,
            asked_at: now,
        }),
    }])
}

/// A ticket's question went: the ticket waits on the answer.
pub(super) fn ticket_sent(state: &mut State, pending: PendingTicket) {
    let name = pending.membership.name.clone();
    panel(state).pending_ticket = Some(pending);
    show(
        state,
        Status::progress(format!(
            "Asking {name} how it vets now — named vetting or PCS ZKP — before issuing the \
             ticket…"
        )),
    );
}

/// A ticket's question could not be signed or handed off: no ticket, said as
/// a mode that could not be read, and logged.
pub(super) fn ticket_unsent(
    state: &mut State,
    config: &mut Config,
    pending: PendingTicket,
    error: String,
) {
    let PendingTicket {
        membership,
        asked_at: now,
        ..
    } = pending;
    let failure = ModeFailure::Unsent(error);
    config
        .private
        .vetting
        .mode_failed(&membership.community, failure.clone(), now);
    let reading = config.private.vetting.vetter_mode(&membership.community);
    let words = ticket_unconfirmed(&membership.name, &failure, &reading, now);
    state.main_page.log(words.clone());
    show(state, Status::error(words));
}

/// What a ticket issued under `mode` promises, in words. A community running PCS ZKP alongside
/// named vetters gets requests of both kinds — an applicant picks its path, and defaults to PCS
/// ZKP — so the ticket says so rather than promising a proof every time. The token gate still
/// holds there: most requests will ask for a proof.
pub(crate) fn ticket_mode_words(book: &VettingBook, community: &str, mode: VetterMode) -> String {
    if mode == VetterMode::PcsZkp && book.named_alongside_hidden(community) {
        format!(
            "{} (named vetting too: a request that asks for a named statement gets one)",
            mode.words()
        )
    } else {
        mode.words().to_string()
    }
}

/// Issue `pending` under `mode`, and show it. `lead` goes first: a switch of mode to say.
fn mint_ticket(
    state: &mut State,
    config: &mut Config,
    save: &mut SaveScheduler,
    pending: &PendingTicket,
    mode: VetterMode,
    lead: Option<&str>,
    now: DateTime<Utc>,
) {
    let membership = &pending.membership;
    let mut ticket = Ticket::issue(
        &membership.community,
        membership.persona,
        vec![],
        pending.uses,
        DEFAULT_VALIDITY,
        now,
    );
    ticket.mode = Some(mode);
    let code = ticket.code.clone();
    config.private.vetting.tickets.push(ticket);
    {
        let v = &mut state.main_page.content_panel.vetting;
        v.mode = VettingMode::List;
        // The new ticket's own view: the message below names `y`, which is a
        // key of that view.
        v.tab = VettingTab::Desk;
        v.desk_view = DeskView::Tickets;
    }
    let uses = pending.uses;
    let message = format!(
        "{}Ticket {code} for {}, under {} — press ⏎ to show its QR code, or u to copy its link. \
         It admits {uses} request{} for 14 days.",
        lead.map(|l| format!("{l} ")).unwrap_or_default(),
        membership.name,
        ticket_mode_words(&config.private.vetting, &membership.community, mode),
        if uses == 1 { "" } else { "s" }
    );
    dispatch_util::save_and_sync(
        &mut state.main_page,
        config,
        save,
        Persist::SaveAndSync(crate::state_handler::main_page::Panels::FROM_VETTING_BOOK),
        |mp| &mut mp.content_panel.vetting.status_message,
        message.clone(),
        SyncLog::Plain(message),
    );
    let v = &mut state.main_page.content_panel.vetting;
    v.selected = v.tickets.len().saturating_sub(1);
}

/// Say each community seen switching mode since last asked, and decide the pending ticket if
/// its answer is in. Run after community answers arrive, and on the loop's sweep — which is
/// what ends a ticket whose question was never answered.
pub(crate) fn settle_pending_tickets(
    state: &mut State,
    config: &mut Config,
    save: &mut SaveScheduler,
    now: DateTime<Utc>,
) {
    let switches = config.private.vetting.take_mode_switches();
    let said: Vec<String> = switches
        .iter()
        .map(|s| s.words(&community_display(config, &s.community)))
        .collect();
    for words in &said {
        state.main_page.log(words.clone());
    }
    let pending = state.main_page.content_panel.vetting.pending_ticket.clone();
    let check = pending
        .as_ref()
        .map(|p| ticket_check(&config.private.vetting, p, now));
    // The switch behind a pending ticket's answer leads its message, named as the ticket is.
    let lead = pending.as_ref().and_then(|p| {
        switches
            .iter()
            .rev()
            .find(|s| s.community == p.membership.community)
            .map(|s| s.words(&p.membership.name))
    });
    match (pending, check) {
        (Some(pending), Some(TicketCheck::Issue(mode))) => {
            state.main_page.content_panel.vetting.pending_ticket = None;
            mint_ticket(state, config, save, &pending, mode, lead.as_deref(), now);
        }
        (Some(pending), Some(TicketCheck::Gated(why))) => {
            let membership = &pending.membership;
            let obtainable = tokens_obtainable_now(
                &config.private.vetting,
                &membership.community,
                membership.persona,
                now,
            );
            // The one action that gets tokens, run now rather than offered: enrol if needed,
            // then draw every window that has begun (the loop takes the flag within seconds).
            // Nothing is drawn ahead of the schedule, so this says no more about the vetter's
            // activity than the schedule does. When there is nothing to run — a lost enrolment,
            // or this window drawn already — the words above say until when, and what to do.
            let then = if !obtainable {
                ""
            } else {
                config.private.vetting.vetter_refresh_due = true;
                " Getting them now — press t again once they arrive (k does this by hand)."
            };
            let words = match lead {
                Some(lead) => format!("{lead} {why}{then}"),
                None => format!("{why}{then}"),
            };
            let v = &mut state.main_page.content_panel.vetting;
            v.pending_ticket = None;
            v.status_message = Some(Status::warning(words.clone()));
            state.main_page.log(words);
        }
        (Some(_), Some(TicketCheck::Refused(why))) => {
            let words = match lead {
                Some(lead) => format!("{lead} {why}"),
                None => why,
            };
            let v = &mut state.main_page.content_panel.vetting;
            v.pending_ticket = None;
            v.status_message = Some(Status::error(words.clone()));
            state.main_page.log(words);
        }
        _ => {
            if !said.is_empty() {
                state.main_page.content_panel.vetting.status_message =
                    Some(Status::info(said.join(" ")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::VettingMembership;
    use crate::state_handler::save_coalesce::SaveScheduler;
    use crate::state_handler::state::State;
    use crate::state_handler::vetting_actions::test_support::{
        first_vtc_book, hidden_vetter_book, manifest_payload, pending_for, read_as,
    };
    use crate::state_handler::vetting_actions::words::{mode_note, standing_tokens};
    use chrono::Utc;
    use openvtc_core::vetting::VettingBook;
    use openvtc_core::vetting::mode::{ModeFailure, VetterMode};

    /// A community that switched from PCS ZKP to named vetting gets a named ticket, with no
    /// enrolment gate — even though this vetter's PCS ZKP enrolment would have refused one — and
    /// the switch is said.
    #[test]
    fn a_switch_to_named_vetting_issues_a_named_ticket_with_no_gate() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let asked = now - chrono::Duration::seconds(2);
        let (mut book, persona) = hidden_vetter_book(0, false);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::days(3),
        );
        let pending = pending_for(persona, asked);
        assert_eq!(
            ticket_check(&book, &pending, now),
            TicketCheck::Waiting,
            "the three-day-old reading decides nothing"
        );
        book.learn_mode(
            community,
            &manifest_payload(false),
            Some(VetterMode::PcsZkp),
            now,
        );
        assert_eq!(
            ticket_check(&book, &pending, now),
            TicketCheck::Issue(VetterMode::Named)
        );

        let mut state = State::default();
        let mut config = test_config();
        let mut save = SaveScheduler::new("test");
        config.private.vetting = book;
        state.main_page.content_panel.vetting.pending_ticket = Some(pending);
        settle_pending_tickets(&mut state, &mut config, &mut save, now);
        let tickets = &config.private.vetting.tickets;
        assert_eq!(tickets.len(), 1);
        assert_eq!(tickets[0].mode, Some(VetterMode::Named));
        let v = &state.main_page.content_panel.vetting;
        assert!(v.pending_ticket.is_none());
        let said = v
            .status_message
            .as_ref()
            .map(|s| s.text.as_str())
            .unwrap_or_default();
        assert!(
            said.starts_with("first-vtc switched from PCS ZKP to named vetting."),
            "{said}"
        );
        assert!(said.contains("under named vetting"), "{said}");
    }

    /// A community that switched from named vetting to PCS ZKP gates the ticket on enrolment.
    #[test]
    fn a_switch_to_pcs_zkp_gates_the_ticket() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let (mut book, persona) = hidden_vetter_book(0, false);
        book.hidden_vetter.clear();
        read_as(
            &mut book,
            community,
            VetterMode::Named,
            now - chrono::Duration::days(1),
        );
        let pending = pending_for(persona, now - chrono::Duration::seconds(1));
        book.learn_mode(
            community,
            &manifest_payload(true),
            Some(VetterMode::Named),
            now,
        );
        let TicketCheck::Gated(why) = ticket_check(&book, &pending, now) else {
            panic!("a vetter not enrolled under PCS ZKP is not given a ticket");
        };
        assert!(why.contains("first-vtc vets by PCS ZKP now"), "{why}");
        assert!(why.contains("enrolling you now"), "{why}");
        assert!(!why.contains(".."), "{why}");
        let switches = book.take_mode_switches();
        assert_eq!(switches.len(), 1);
        assert_eq!(switches[0].from, VetterMode::Named);
        assert_eq!(switches[0].to, VetterMode::PcsZkp);
    }

    /// A read that fails is said — which kind of failure, and what was last known — and no ticket
    /// is issued on the remembered mode either way.
    #[test]
    fn a_failed_mode_read_is_said_not_assumed() {
        let community = "did:web:first-vtc.example";
        let now = Utc::now();
        let asked = now - chrono::Duration::seconds(31);
        let (mut book, persona) = hidden_vetter_book(3, true);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::hours(2),
        );
        let pending = pending_for(persona, asked);
        book.mode_failed(community, ModeFailure::Unanswered, now);
        let TicketCheck::Refused(why) = ticket_check(&book, &pending, now) else {
            panic!("a ticket is not issued on a remembered mode");
        };
        assert!(
            why.contains("could not confirm how first-vtc vets now"),
            "{why}"
        );
        assert!(why.contains("no answer within 30 seconds"), "{why}");
        assert!(why.contains("Last known: PCS ZKP, read 2 h ago"), "{why}");
        assert!(!why.contains(".."), "{why}");

        // The desk header says the same of the community.
        let note = mode_note(&book, community, now).expect("a failure is shown");
        assert!(note.contains("could not read how it vets now"), "{note}");

        // A contract mismatch reads differently from silence (R6.4).
        book.mode_failed(
            community,
            ModeFailure::Unreadable("missing field `criteria`".into()),
            now,
        );
        let TicketCheck::Refused(why) = ticket_check(&book, &pending, now) else {
            panic!("refused");
        };
        assert!(why.contains("cannot read"), "{why}");

        // And with nothing recorded at all, the wait is still bounded (R1.2).
        let (mut book, persona) = hidden_vetter_book(3, true);
        read_as(
            &mut book,
            community,
            VetterMode::PcsZkp,
            now - chrono::Duration::hours(2),
        );
        let pending = pending_for(persona, now - chrono::Duration::seconds(10));
        assert_eq!(ticket_check(&book, &pending, now), TicketCheck::Waiting);
        let pending = pending_for(persona, now - chrono::Duration::seconds(60));
        assert!(matches!(
            ticket_check(&book, &pending, now),
            TicketCheck::Refused(_)
        ));
    }

    /// The enrolment whose answer was lost: the desk header says so briefly, the refusal says it
    /// once in full — with the date the next label can start and what to do meanwhile — and no
    /// sentence ends twice.
    #[test]
    fn a_lost_enrolment_is_said_once_in_full_with_the_next_label_date() {
        let community = "did:web:first-vtc.example";
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let membership = |persona| VettingMembership {
            community: community.into(),
            name: "first-vtc".into(),
            persona,
            accent: None,
        };
        // As recorded now, and as an older record has it: only the refusal, no lost label.
        for recorded in [true, false] {
            let (mut book, persona) = hidden_vetter_book(0, false);
            let held = &mut book.hidden_vetter[0];
            if recorded {
                held.lost_enrolment = Some("2026-10".into());
                held.lost_reasked = true;
            }
            held.last_refusal = Some(openvtc_core::vetting::book::HiddenRefusal {
                what: "your hidden-vetting credential".into(),
                code: "vtc/vetting/vetters/pcs-root:alreadyEnrolled".into(),
                at: now,
            });
            let (short, warn) = standing_tokens(&book, community, persona, now).unwrap();
            assert!(warn);
            assert!(
                short.contains("answer to your enrolment was lost"),
                "{short}"
            );
            assert!(
                !short.contains("already enrolled you"),
                "the header keeps it short: {short}"
            );
            let refusal = ticket_refusal(&book, &membership(persona), now).expect("refused");
            assert!(!refusal.contains(".."), "{refusal}");
            assert!(refusal.contains("vetter/2026-11"), "{refusal}");
            assert!(refusal.contains("Sun 01 Nov 2026"), "{refusal}");
            assert!(refusal.contains("Meanwhile"), "{refusal}");
            assert_eq!(
                refusal.matches("already enrolled you").count(),
                1,
                "said once: {refusal}"
            );
            assert!(
                !refusal.contains(&short),
                "the short line is not repeated: {refusal}"
            );
        }
    }

    /// A vetter that cannot attest under PCS ZKP is not given a ticket that would bring requests
    /// it cannot honour; one with tokens is.
    #[test]
    fn no_ticket_is_issued_for_requests_that_cannot_be_attested() {
        // Pinned, as in `t_without_tokens_gets_them_when_it_can`: how many windows are owed
        // depends on the date, so a wall-clock `now` made this pass only on 2026-10-05.
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 10, 5, 15, 14, 0).unwrap();
        let membership = |persona| VettingMembership {
            community: "did:web:first-vtc.example".into(),
            name: "first-vtc".into(),
            persona,
            accent: None,
        };
        let (book, persona) = hidden_vetter_book(0, true);
        let refusal = ticket_refusal(&book, &membership(persona), now).expect("refused");
        assert!(refusal.contains("first-vtc"), "{refusal}");
        assert!(
            refusal.contains("drawing 2 windows of tokens now (0 tokens usable already)"),
            "{refusal}"
        );
        let (book, persona) = hidden_vetter_book(0, false);
        assert!(ticket_refusal(&book, &membership(persona), now).is_some());
        let (book, persona) = hidden_vetter_book(2, true);
        assert!(ticket_refusal(&book, &membership(persona), now).is_none());
        // A named community is never gated on tokens.
        let named = VettingMembership {
            community: "did:web:named.example".into(),
            ..membership(persona)
        };
        assert!(ticket_refusal(&book, &named, now).is_none());
    }

    /// A ticket where PCS ZKP runs alongside named vetting does not promise a proof every time.
    #[test]
    fn a_ticket_in_a_community_offering_both_paths_says_so() {
        let (book, community) = first_vtc_book();
        let words = ticket_mode_words(&book, &community, VetterMode::PcsZkp);
        assert!(words.starts_with("PCS ZKP (named vetting too"), "{words}");
        assert_eq!(
            ticket_mode_words(&VettingBook::default(), &community, VetterMode::PcsZkp),
            "PCS ZKP"
        );
    }

    // ---- the plans: pure, so no runtime ----

    fn ticket_form(state: &mut State, persona: openvtc_core::config::account::PersonaId) {
        let v = &mut state.main_page.content_panel.vetting;
        v.memberships = vec![VettingMembership {
            community: "did:web:vtc".into(),
            name: "VTC".into(),
            persona,
            accent: None,
        }]
        .into();
        v.mode = VettingMode::NewTicket {
            membership_index: 0,
            uses_index: 1,
            field: 0,
        };
    }

    /// A persona the config does not hold is said before the busy check, and
    /// the form is closed before either.
    #[test]
    fn a_ticket_as_a_persona_not_held_is_refused_before_the_busy_check() {
        let mut config = test_config();
        let mut state = State::default();
        ticket_form(&mut state, openvtc_core::config::account::PersonaId::new());

        let effect = plan_issue_ticket(&mut state, &mut config, true, 0, 1);

        assert!(effect.0.is_empty());
        let v = &state.main_page.content_panel.vetting;
        assert!(matches!(v.mode, VettingMode::List));
        assert_eq!(
            v.status_message.as_ref().map(|s| s.text.as_str()),
            Some("No ticket issued: the persona you vet for that community as is not available.")
        );
        assert!(
            !config
                .private
                .vetting
                .manifest_recently_asked("did:web:vtc", Utc::now())
        );
    }

    /// Deleting takes the ticket out of the book and saves; nothing is sent.
    #[test]
    fn deleting_a_ticket_plans_only_the_save() {
        let mut config = test_config();
        let mut state = State::default();
        let ticket = Ticket::issue(
            "did:web:vtc",
            openvtc_core::config::account::PersonaId::new(),
            vec![],
            1,
            DEFAULT_VALIDITY,
            Utc::now(),
        );
        config.private.vetting.tickets.push(ticket.clone());
        state.main_page.content_panel.vetting.selected = 4;

        let effect = plan_delete_ticket(&mut state, &mut config, &ticket.id);

        assert!(config.private.vetting.tickets.is_empty());
        assert_eq!(state.main_page.content_panel.vetting.selected, 0);
        let [Step::Persist(said)] = effect.0.as_slice() else {
            panic!("only the save");
        };
        assert!(said.starts_with(&format!("Ticket {} deleted", ticket.code)));
    }
}
