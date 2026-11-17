//! The applicant side: starting and abandoning applications, switching
//! vetting path, requesting a vetter, and searching the vetter directory.
//!
//! Each action is planned here (`plan_*`), purely, on the state and the book;
//! what it still owes the loop — saving, signing, the send — is the
//! [`VettingEffect`] it returns. The form changes that read the book and touch
//! nothing else are plain functions [`super::dispatch::reduce`] calls.

use crate::state_handler::main_page::status::Status;
use chrono::Utc;
use openvtc_core::config::Config;
use openvtc_core::config::community_context::{self, ContextKind, ContextOption};
use openvtc_core::vetting::VettingBook;
use openvtc_core::vetting::applicant::{Application, RequestDraft, VettingPath};
use openvtc_core::vetting::book::CriterionPaths;
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::wire;
use vta_sdk::protocols::vetting::{VETTING_REQUEST_TYPE, request};

use super::dispatch::{back, panel, show};
use super::effect::{Abort, Followup, Step, Undo, VettingEffect};
use super::jobs::Sent;
use super::send::{Claim, claimable, give_up, persona_did};
use super::words::community_display;
use crate::state_handler::background_dispatch::{DispatchDomain, InFlight};
use crate::state_handler::main_page::content::{
    DIRECTORY_LABELS, DIRECTORY_METHODS, DirectoryView, VettingMode, VettingTab, row_of,
};
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::state::State;

/// The criterion `app` gathers for and the path it takes, in words, and a note when one is
/// owed. `None` before its requirements are known.
pub(crate) fn criterion_words(
    book: &VettingBook,
    app: &Application,
) -> Option<(String, Option<String>)> {
    let shown = book.application_vetting(&app.id)?;
    let mut line = shown.criterion_id.clone();
    if let Some(description) = &shown.description {
        line.push_str(&format!(" — {}", sanitize_display(description, 120)));
    }
    line.push_str(&format!(" · {}", shown.path.words()));
    let options = book.vetting_options(&app.community);
    if options.len() > 1 {
        line.push_str(&format!(
            " · {} ways to be vetted here{}",
            options.len(),
            if app.holds_evidence() {
                ""
            } else {
                ", p switches"
            }
        ));
    }
    let note = if let Some(previous) = &app.criterion_repicked {
        Some(format!(
            "The community no longer publishes criterion {previous}; this application now \
             gathers for {} instead.",
            shown.criterion_id
        ))
    } else if shown.path == VettingPath::Named && shown.paths == CriterionPaths::Either {
        Some(format!(
            "This criterion also accepts PCS ZKP, which names no vetter; this application uses \
             named vetting{}.",
            if app.holds_evidence() {
                " — the statements it holds were made that way"
            } else if app.under_way() {
                " (its requests went out named). p switches to PCS ZKP; then send your vetter a \
                 new request"
            } else {
                ". p switches to PCS ZKP"
            }
        ))
    } else if shown.path == VettingPath::Named && book.pcs_zkp(&app.community) {
        Some(format!(
            "This community also accepts PCS ZKP vetting; your application uses criterion {} \
             (named).",
            shown.criterion_id
        ))
    } else {
        None
    };
    Some((line, note))
}

/// `p` on an application: move it to the next way its community offers to be vetted, and say
/// what that means for the requests already out.
pub(super) fn plan_switch_vetting_path(state: &mut State, config: &mut Config) -> VettingEffect {
    let v = panel(state);
    let Some(row) = v.applications.get(v.selected).cloned() else {
        return VettingEffect::none();
    };
    let had_requests = config
        .private
        .vetting
        .applications
        .iter()
        .any(|a| a.id == row.id && !a.requests.is_empty());
    match config.private.vetting.switch_vetting(&row.id) {
        Ok(now) => {
            let resend = if had_requests {
                match now.path {
                    VettingPath::Hidden => {
                        " The requests already sent went out named, so they cannot carry the \
                         identifier a PCS ZKP attestation is made to: send your vetter a new \
                         request (r)."
                    }
                    VettingPath::Named => {
                        " Requests already sent asked for a PCS ZKP attestation: send your \
                         vetter a new request (r)."
                    }
                }
            } else {
                ""
            };
            VettingEffect(vec![Step::Persist(format!(
                "This application now uses criterion {} with {}.{resend}",
                now.criterion_id,
                now.path.words()
            ))])
        }
        Err(why) => {
            show(state, Status::error(why));
            VettingEffect::none()
        }
    }
}

/// Ask `application_id`'s community what it requires.
pub(super) fn plan_refresh_requirements(
    state: &mut State,
    config: &Config,
    busy: bool,
    application_id: &str,
) -> VettingEffect {
    let Some(app) = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .cloned()
    else {
        return VettingEffect::none();
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const WHAT: &str = "Could not ask the community";
    let protocol = config.private.vetting.protocol_for(&app.community);
    let document = match wire::manifest_request(&app.join_did, &app.community, protocol) {
        Ok(d) => d,
        Err(e) => {
            give_up(state, config, WHAT, e);
            return VettingEffect::none();
        }
    };
    show(
        state,
        Status::progress("Asking the community what it requires…"),
    );
    let sent = Sent::Manifest {
        community: app.community.clone(),
    };
    VettingEffect::sign_and_send(
        [],
        app.persona,
        document,
        sent,
        Claim::Held,
        Abort::say(WHAT),
    )
}

/// Recompute the contexts a new application can use, for the community and
/// persona on the form. An application that already exists keeps its own.
pub(super) fn refresh_application_contexts(state: &mut State, config: &Config) {
    let (community, persona) = {
        let v = panel(state);
        let VettingMode::NewApplication {
            community,
            persona_index,
            ..
        } = &v.mode
        else {
            return;
        };
        (
            community.trim().to_string(),
            v.personas.get(*persona_index).map(|p| p.persona),
        )
    };
    let existing = persona
        .and_then(|p| config.private.vetting.application(&community, p))
        .and_then(|a| a.context_id.clone());
    let options = match existing {
        Some(context_id) => vec![ContextOption {
            context_id,
            kind: ContextKind::Existing,
            communities: Vec::new(),
            holds_persona_keys: false,
        }],
        None => {
            let record = persona.and_then(|p| config.account.personas.get(&p));
            let suggested = openvtc_core::join::sequence::suggested_context(config, &community);
            community_context::context_options(&config.account, record, &suggested)
        }
    };
    if let VettingMode::NewApplication {
        context_options,
        context_index,
        ..
    } = &mut panel(state).mode
    {
        if *context_options != options {
            *context_index = 0;
        }
        *context_options = options;
    }
}

/// Start an application to `community` as the persona at `persona_index`,
/// save it, then ask the community what it requires ([`Followup::Started`]).
pub(super) fn plan_start_application(
    state: &mut State,
    config: &mut Config,
    community: &str,
    persona_index: usize,
    context: Option<String>,
) -> VettingEffect {
    if !community.starts_with("did:") {
        show(
            state,
            Status::warning("Enter the community's DID (it starts with did:)."),
        );
        return VettingEffect::none();
    }
    let Some(persona) = panel(state).personas.get(persona_index).cloned() else {
        show(
            state,
            Status::warning("Choose the persona you will join with."),
        );
        return VettingEffect::none();
    };
    let application_id = match config.private.vetting.start_application(
        community,
        persona.persona,
        &persona.did,
        Utc::now(),
    ) {
        Ok(app) => {
            if app.context_id.is_none() {
                app.context_id = context;
            }
            app.id.clone()
        }
        Err(e) => {
            show(
                state,
                Status::error(format!("Could not start the application: {e}")),
            );
            return VettingEffect::none();
        }
    };
    // Said, not dropped (R6.4): a criterion this build cannot honour is the one thing that
    // makes this application gather evidence the community will not count.
    let unadopted = config
        .private
        .vetting
        .adopt_known_requirements(&application_id)
        .err()
        .map(|e| format!(" Its requirements could not be taken up: {e}."))
        .unwrap_or_default();
    {
        let v = panel(state);
        v.mode = VettingMode::List;
        v.tab = VettingTab::Applications;
    }
    let started = format!("Application started.{unadopted}");
    VettingEffect(vec![
        Step::Persist(started.clone()),
        Step::Then(Followup::Started {
            application_id,
            started,
        }),
    ])
}

/// [`Followup::Started`]: the saved application's row is on the page now, so
/// select it, then ask its community what it requires. On a busy domain the
/// question waits, and the status keeps `started` — the application is saved
/// — with why its requirements were not asked for.
pub(super) fn plan_started(
    state: &mut State,
    config: &Config,
    busy: bool,
    application_id: &str,
    started: &str,
) -> VettingEffect {
    if let Some(i) = panel(state)
        .applications
        .iter()
        .position(|a| a.id == application_id)
    {
        panel(state).selected = i;
    }
    if busy {
        show(state, Status::warning(started_while_busy(started)));
        return VettingEffect::none();
    }
    plan_refresh_requirements(state, config, busy, application_id)
}

/// What an application started while another vetting send holds the domain
/// says: that it started, and that its requirements are still to be asked.
fn started_while_busy(started: &str) -> String {
    format!(
        "{started} Its requirements were not asked for yet: {} Press m to ask once it finishes.",
        InFlight::busy_message(DispatchDomain::Vetting)
    )
}

/// Send a vetting request carrying the ticket from a `vetting-ticket:` link.
///
/// `entry` is the one field; `vetter` and `ticket` are what a paste already
/// read out of it. Enter with neither of those set — someone typed or pasted
/// without the paste hook firing — reads `entry` here, so the form behaves the
/// same whichever way the text arrived.
pub(super) fn plan_request_vetter(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    application_id: &str,
    entry: &str,
    vetter: &str,
    ticket: Option<request::v0_1::Ticket>,
) -> VettingEffect {
    // Not yet read (typed rather than pasted): read it now, which also reports
    // a link for the wrong community or one that cannot be decoded.
    let (vetter, presentation) = match (ticket, vetter.starts_with("did:")) {
        (Some(ticket), true) => (vetter.to_string(), ticket),
        _ => {
            let Some(app) = config
                .private
                .vetting
                .applications
                .iter()
                .find(|a| a.id == application_id)
            else {
                return VettingEffect::none();
            };
            match app.ticket_from_uri(entry) {
                Ok(ticket) => (ticket.vetter, ticket.presentation),
                Err(_) if entry.is_empty() => {
                    show(
                        state,
                        Status::warning(
                            "Paste the link from the vetter's QR code — it carries their ticket, \
                         and a request without one is never answered.",
                        ),
                    );
                    return VettingEffect::none();
                }
                Err(e) => {
                    show(state, Status::error(sanitize_display(&e.to_string(), 400)));
                    return VettingEffect::none();
                }
            }
        }
    };
    let vetter = vetter.as_str();
    // Under a hidden criterion the request carries the application's PCS identifier, which the
    // VTA mints. Before it has, a request would ask the vetter for a named statement this
    // application cannot use.
    if config
        .private
        .vetting
        .application_by_id(application_id)
        .is_some_and(Application::hidden_app_owed)
    {
        config.private.vetting.pcs_due = true;
        show(
            state,
            Status::error(openvtc_core::vetting::hidden::HiddenError::NotReady.to_string()),
        );
        return VettingEffect::none();
    }
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const WHAT: &str = "Could not send the request";
    let document_id = wire::new_id();
    let Some(app) = config.private.vetting.application_by_id_mut(application_id) else {
        give_up(state, config, WHAT, "the application is gone");
        return VettingEffect::none();
    };
    let (persona, join_did) = (app.persona, app.join_did.clone());
    let body = match app.prepare_request(
        &document_id,
        vetter,
        presentation,
        RequestDraft::default(),
        Utc::now(),
    ) {
        Ok(body) => body,
        Err(e) => {
            give_up(state, config, WHAT, e);
            return VettingEffect::none();
        }
    };
    // From here the book holds the prepared request: any failure before it
    // goes out forgets it again.
    let abort = Abort::undoing(
        WHAT,
        vec![Undo::ForgetUnsent {
            application_id: application_id.to_string(),
            document_id: document_id.clone(),
        }],
    );
    let document = match wire::document(
        VETTING_REQUEST_TYPE,
        &join_did,
        vetter,
        document_id.clone(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => {
            abort.apply(state, config, e);
            return VettingEffect::none();
        }
    };
    panel(state).mode = VettingMode::List;
    let sent = Sent::Request {
        application_id: application_id.to_string(),
        document_id,
        vetter: vetter.to_string(),
    };
    VettingEffect::sign_and_send(
        [Step::Persist("Sending your request…".to_string())],
        persona,
        document,
        sent,
        Claim::Held,
        abort,
    )
}

/// Fill the request form from a pasted `vetting-ticket:` link — the vetter's
/// DID and the scanned ticket — or say why it cannot be used.
pub(super) fn paste_ticket(state: &mut State, config: &Config, text: &str) {
    let VettingMode::RequestVetter { application_id, .. } = &panel(state).mode else {
        return;
    };
    let application_id = application_id.clone();
    let Some(app) = config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
    else {
        return;
    };
    let pasted = text.trim().to_string();
    match app.ticket_from_uri(text) {
        Ok(ticket) => {
            let shown = shorten_did(&ticket.vetter, 64);
            if let VettingMode::RequestVetter {
                entry,
                vetter,
                ticket: slot,
                ..
            } = &mut panel(state).mode
            {
                *entry = pasted;
                *vetter = ticket.vetter;
                *slot = Some(ticket.presentation);
            }
            show(
                state,
                Status::info(format!(
                    "Read the ticket link. It goes to {shown} — Enter sends the request."
                )),
            );
        }
        Err(e) => show(state, Status::error(sanitize_display(&e.to_string(), 400))),
    }
}

pub(super) fn open_directory(state: &mut State) {
    let v = panel(state);
    if v.directory_communities.is_empty() {
        return show(
            state,
            Status::warning(
                "The vetter directory is searched per community: start an application (n) or join a \
             community first.",
            ),
        );
    }
    // Opened from an application — the list, or its journey — the search
    // starts as that application, by id: two applications to one community
    // are two different personas asking.
    let from_application = (v.tab == VettingTab::Applications)
        .then(|| v.applications.get(v.selected))
        .flatten()
        .map(|a| (a.id.clone(), a.community.clone()));
    let community_index = from_application
        .and_then(|(id, community)| {
            v.directory_communities
                .iter()
                .position(|d| d.application_id.as_deref() == Some(id.as_str()))
                .or_else(|| {
                    v.directory_communities
                        .iter()
                        .position(|d| d.community == community)
                })
        })
        .unwrap_or(0);
    v.mode = VettingMode::Directory(Box::new(DirectoryView {
        community_index,
        ..DirectoryView::default()
    }));
    v.status_message = None;
}

/// Ask the directory's community for one page. `cursors` is what the view's
/// page stack becomes once the answer arrives; its last entry is the cursor
/// sent.
pub(super) fn plan_search_directory(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    cursors: Vec<Option<String>>,
) -> VettingEffect {
    let prepared = {
        let v = panel(state);
        let VettingMode::Directory(view) = &mut v.mode else {
            return VettingEffect::none();
        };
        if view.pending.is_some() {
            return VettingEffect::none();
        }
        let Some(target) = v.directory_communities.get(view.community_index).cloned() else {
            return VettingEffect::none();
        };
        let mut filter = view.filter.clone();
        filter.method = DIRECTORY_METHODS[view.method_index.min(DIRECTORY_METHODS.len() - 1)];
        match filter.to_body(cursors.last().cloned().flatten()) {
            Ok(body) => (target, body),
            Err(e) => {
                // The cursor goes to the row the message names — the filters
                // are nine rows, and a search is run from whichever one the
                // cursor happens to be on.
                if let Some(row) = e.row().and_then(|l| row_of(&DIRECTORY_LABELS, l)) {
                    view.field = row;
                }
                view.error = Some(e.to_string());
                return VettingEffect::none();
            }
        }
    };
    let (target, body) = prepared;
    let Some(asker) = persona_did(config, target.persona) else {
        show(
            state,
            Status::error("The persona the directory would be searched as is not available."),
        );
        return VettingEffect::none();
    };
    if !claimable(state, busy) {
        return VettingEffect::none();
    }
    const WHAT: &str = "Could not search the directory";
    let document = match wire::vetter_list_request(&asker, &target.community, &body) {
        Ok(d) => d,
        Err(e) => {
            give_up(state, config, WHAT, e);
            return VettingEffect::none();
        }
    };
    let document_id = document.id.clone();
    config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: target.community.clone(),
        persona: target.persona,
        kind: QueryKind::VetterList,
        sent_at: Utc::now(),
    });
    if let VettingMode::Directory(view) = &mut panel(state).mode {
        view.pending = Some(document_id.clone());
        view.pending_cursors = Some(cursors);
        view.error = None;
    }
    show(
        state,
        Status::progress(format!("Asking {} for its vetter directory…", target.name)),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: target.community.clone(),
        kind: QueryKind::VetterList,
    };
    VettingEffect::sign_and_send(
        [],
        target.persona,
        document,
        sent,
        Claim::Held,
        Abort::undoing(
            WHAT,
            vec![Undo::ForgetQuery(document_id), Undo::DirectoryNotPending],
        ),
    )
}

pub(super) fn plan_directory_page(
    state: &mut State,
    config: &mut Config,
    busy: bool,
    forward: bool,
) -> VettingEffect {
    let (mut cursors, next) = match &panel(state).mode {
        VettingMode::Directory(view) if view.pending.is_none() => {
            (view.cursors.clone(), view.next_cursor.clone())
        }
        _ => return VettingEffect::none(),
    };
    if forward {
        let Some(next) = next else {
            show(state, Status::warning("That is the last page."));
            return VettingEffect::none();
        };
        cursors.push(Some(next));
    } else {
        if cursors.len() <= 1 {
            show(state, Status::warning("This is the first page."));
            return VettingEffect::none();
        }
        cursors.pop();
    }
    plan_search_directory(state, config, busy, cursors)
}

/// Open the request form for the highlighted directory vetter. The directory
/// finds a vetter; it does not let anyone skip the ticket, so the form says
/// how this vetter hands them out.
pub(super) fn ask_listed_vetter(state: &mut State) {
    let v = panel(state);
    let VettingMode::Directory(view) = &v.mode else {
        return;
    };
    let Some(row) = view
        .result_index()
        .and_then(|i| view.results.get(i))
        .cloned()
    else {
        return;
    };
    let Some(target) = v.directory_communities.get(view.community_index).cloned() else {
        return;
    };
    let Some(application_id) = target.application_id.clone() else {
        return show(
            state,
            Status::warning(format!(
                "To ask {} you need an application to {} — start one on the Applications tab (n), \
                 then find them here again.",
                row.name, target.name
            )),
        );
    };
    let how = match &row.contact_hint {
        Some(hint) => format!("they say: {hint}"),
        None => "they have not said how, so ask them".to_string(),
    };
    let v = panel(state);
    v.mode = VettingMode::RequestVetter {
        application_id,
        entry: String::new(),
        // Left empty on purpose. The directory knows who they are, but the
        // request goes to whoever the *ticket* names, and showing a vetter the
        // form is not going to use would be a claim about where this is going.
        vetter: String::new(),
        ticket: None,
        note: Some(format!(
            "{} still has to give you a ticket before they answer — {how}. Paste the link from \
             their QR code here.",
            row.name
        )),
    };
    v.tab = VettingTab::Applications;
}

/// Local only: vetting is client-side until the join is submitted, so nothing
/// was sent to the community and there is nothing to withdraw from it. What the
/// message says instead is the part that is *not* tidied — a vetter who already
/// accepted a request still holds it, and this cannot reach them.
pub(super) fn plan_abandon_application(state: &mut State, config: &mut Config) -> VettingEffect {
    let VettingMode::ConfirmAbandon { application_id } = panel(state).mode.clone() else {
        return VettingEffect::none();
    };
    let Some(app) = config.private.vetting.abandon_application(&application_id) else {
        back(panel(state));
        show(state, Status::warning("That application is already gone."));
        return VettingEffect::none();
    };
    let community = community_display(config, &app.community);
    let asked = app.requests.len();
    back(panel(state));
    panel(state).selected = 0;
    state.main_page.sync_panels(
        config,
        crate::state_handler::main_page::Panels::FROM_VETTING_BOOK,
    );
    VettingEffect(vec![
        Step::MarkDirty,
        Step::Status(Status::success(if asked == 0 {
            format!("Abandoned your application to {community}.")
        } else {
            format!(
                "Abandoned your application to {community}. {asked} vetter{} still \
                 hold{} your request — tell them, or they will open a session with \
                 nothing to answer.",
                if asked == 1 { "" } else { "s" },
                if asked == 1 { "s" } else { "" }
            )
        })),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_handler::vetting_actions::test_support::first_vtc_book;
    use chrono::Utc;
    use openvtc_core::config::account::PersonaId;

    /// The application names its criterion and path, and a named one under a criterion that
    /// also offers PCS ZKP says so — the two badges no longer contradict each other unexplained.
    #[test]
    fn an_application_shows_its_criterion_and_path() {
        let (mut book, community) = first_vtc_book();
        let persona = PersonaId::new();
        let id = book
            .start_application(&community, persona, "did:key:zA", Utc::now())
            .unwrap()
            .id
            .clone();
        book.adopt_known_requirements(&id).unwrap();
        let app = book.applications[0].clone();
        let (line, note) = criterion_words(&book, &app).unwrap();
        assert_eq!(
            line,
            "vetted-member — One vetter must confirm who you are · PCS ZKP · 2 ways to be \
             vetted here, p switches"
        );
        assert!(note.is_none());

        // The live case: a named application whose request already went out.
        book.switch_vetting(&id).unwrap();
        let app = book.applications[0].clone();
        let (line, note) = criterion_words(&book, &app).unwrap();
        assert!(line.contains("· named vetting ·"), "{line}");
        let note = note.expect("named where PCS ZKP is on offer is explained");
        assert!(note.contains("also accepts PCS ZKP"), "{note}");
    }

    // ---- the plans: pure, so no runtime ----

    use crate::state_handler::background_dispatch::{DispatchDomain, InFlight};
    use crate::state_handler::dispatch_util::test_config;
    use crate::state_handler::main_page::content::VettingPersona;
    use crate::state_handler::main_page::status::Severity;

    const VTC: &str = "did:web:vtc.example";

    /// A config holding one application to [`VTC`], shown on the page.
    fn applying() -> (State, Config, String, PersonaId) {
        let mut config = test_config();
        let persona = PersonaId::new();
        let id = config
            .private
            .vetting
            .start_application(VTC, persona, "did:key:zApplicant", Utc::now())
            .unwrap()
            .id
            .clone();
        let mut state = State::default();
        state.main_page.sync_from_config(&config);
        (state, config, id, persona)
    }

    fn status(state: &mut State) -> Status {
        panel(state).status_message.clone().expect("a status")
    }

    fn busy_refusal() -> Status {
        Status::warning(InFlight::busy_message(DispatchDomain::Vetting))
    }

    /// The signing and the send at the end of `effect`: who signs, and how a
    /// failure of either gives up.
    fn signed_send(effect: &VettingEffect) -> (PersonaId, &Sent, &Abort) {
        let [.., sign, send] = effect.0.as_slice() else {
            panic!("a signing and a send");
        };
        let Step::Sign {
            persona,
            abort: sign_abort,
            ..
        } = sign
        else {
            panic!("the signing comes first");
        };
        let Step::Send { sent, claim, abort } = send else {
            panic!("then the send");
        };
        assert!(
            matches!(claim, Claim::Held),
            "a person's send holds the domain"
        );
        assert_eq!(sign_abort, abort, "either failing gives up the same way");
        (*persona, sent, abort)
    }

    #[test]
    fn a_refresh_on_a_busy_domain_is_refused_before_anything_is_built() {
        let (mut state, config, id, _) = applying();
        let effect = plan_refresh_requirements(&mut state, &config, true, &id);
        assert!(effect.0.is_empty());
        assert_eq!(status(&mut state), busy_refusal());
    }

    #[test]
    fn a_refresh_signs_and_sends_a_manifest_question_as_the_applicant() {
        let (mut state, config, id, persona) = applying();
        let effect = plan_refresh_requirements(&mut state, &config, false, &id);
        assert_eq!(effect.0.len(), 2);
        let (signer, sent, abort) = signed_send(&effect);
        assert_eq!(signer, persona);
        assert!(matches!(sent, Sent::Manifest { community } if community == VTC));
        assert_eq!(abort, &Abort::say("Could not ask the community"));
        assert_eq!(
            status(&mut state),
            Status::progress("Asking the community what it requires…")
        );
        // Filed by the send, once signed — not by the plan.
        assert!(config.private.vetting.queries.is_empty());
    }

    #[test]
    fn starting_an_application_records_it_then_saves_before_the_followup() {
        let mut config = test_config();
        let mut state = State::default();
        let persona = PersonaId::new();
        panel(&mut state).personas = vec![VettingPersona {
            persona,
            did: "did:key:zApplicant".into(),
            label: "me".into(),
        }]
        .into();
        let effect =
            plan_start_application(&mut state, &mut config, VTC, 0, Some("openvtc/vtc".into()));
        let app = &config.private.vetting.applications[0];
        assert_eq!(app.context_id.as_deref(), Some("openvtc/vtc"));
        let [Step::Persist(message), Step::Then(followup)] = effect.0.as_slice() else {
            panic!("a save, then the followup");
        };
        assert!(message.starts_with("Application started."), "{message}");
        assert_eq!(
            followup,
            &Followup::Started {
                application_id: app.id.clone(),
                started: message.clone(),
            }
        );
        assert!(matches!(panel(&mut state).mode, VettingMode::List));
        assert_eq!(panel(&mut state).tab, VettingTab::Applications);
    }

    #[test]
    fn the_started_followup_selects_the_row_then_plans_the_refresh() {
        let (mut state, mut config, _, _) = applying();
        let second = config
            .private
            .vetting
            .start_application(
                "did:web:other.example",
                PersonaId::new(),
                "did:key:zB",
                Utc::now(),
            )
            .unwrap()
            .id
            .clone();
        state.main_page.sync_from_config(&config);
        let effect = plan_started(&mut state, &config, true, &second, "Application started.");
        let v = panel(&mut state);
        assert_eq!(v.applications[v.selected].id, second);
        assert!(effect.0.is_empty(), "the refresh waits on the busy domain");
        // The start is still said, with why the requirements wait.
        let said = status(&mut state);
        assert_eq!(said.severity, Severity::Warning);
        assert!(
            said.text.starts_with("Application started. "),
            "{}",
            said.text
        );
        assert!(
            said.text
                .contains(&InFlight::busy_message(DispatchDomain::Vetting))
        );
    }

    fn code_ticket() -> request::v0_1::Ticket {
        request::v0_1::Ticket::ShortCodeTicket(
            request::v0_1::ShortCodeTicket::try_from(
                request::v0_1::ShortCodeTicket::builder().code("0000-0000"),
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_request_on_a_busy_domain_records_nothing() {
        let (mut state, mut config, id, _) = applying();
        let effect = plan_request_vetter(
            &mut state,
            &mut config,
            true,
            &id,
            "",
            "did:key:zVetter",
            Some(code_ticket()),
        );
        assert!(effect.0.is_empty());
        assert_eq!(status(&mut state), busy_refusal());
        assert!(config.private.vetting.applications[0].requests.is_empty());
    }

    #[test]
    fn a_request_is_recorded_saved_signed_and_sent_and_forgotten_if_unsent() {
        let (mut state, mut config, id, persona) = applying();
        panel(&mut state).mode = VettingMode::RequestVetter {
            application_id: id.clone(),
            entry: String::new(),
            vetter: "did:key:zVetter".into(),
            ticket: None,
            note: None,
        };
        let effect = plan_request_vetter(
            &mut state,
            &mut config,
            false,
            &id,
            "",
            "did:key:zVetter",
            Some(code_ticket()),
        );
        let requests = &config.private.vetting.applications[0].requests;
        assert_eq!(requests.len(), 1);
        let document_id = requests[0].document_id.clone();
        assert!(matches!(
            effect.0.first(),
            Some(Step::Persist(m)) if m == "Sending your request…"
        ));
        assert_eq!(effect.0.len(), 3);
        let (signer, sent, abort) = signed_send(&effect);
        assert_eq!(signer, persona);
        assert!(matches!(sent, Sent::Request { vetter, .. } if vetter == "did:key:zVetter"));
        assert_eq!(
            abort,
            &Abort::undoing(
                "Could not send the request",
                vec![Undo::ForgetUnsent {
                    application_id: id,
                    document_id,
                }],
            )
        );
        assert!(matches!(panel(&mut state).mode, VettingMode::List));
    }

    /// The abort a request is planned with — the one its document build
    /// applies too, should it fail — forgets the prepared request, so a
    /// failure at any step leaves nothing of the attempt in the book.
    #[test]
    fn a_request_that_fails_before_it_goes_out_leaves_nothing_prepared() {
        let (mut state, mut config, id, _) = applying();
        let effect = plan_request_vetter(
            &mut state,
            &mut config,
            false,
            &id,
            "",
            "did:key:zVetter",
            Some(code_ticket()),
        );
        let (_, _, abort) = signed_send(&effect);
        let abort = abort.clone();
        assert_eq!(config.private.vetting.applications[0].requests.len(), 1);

        abort.apply(&mut state, &mut config, "the document could not be built");

        assert!(config.private.vetting.applications[0].requests.is_empty());
        assert_eq!(
            status(&mut state),
            Status::error("Could not send the request: the document could not be built")
        );
    }

    #[test]
    fn a_request_with_no_link_is_refused_before_the_busy_check() {
        let (mut state, mut config, id, _) = applying();
        let effect = plan_request_vetter(&mut state, &mut config, true, &id, "", "", None);
        assert!(effect.0.is_empty());
        let s = status(&mut state);
        assert_eq!(s.severity, Severity::Warning);
        assert!(s.text.starts_with("Paste the link"), "{}", s.text);
    }

    #[test]
    fn abandoning_removes_the_application_then_marks_the_save_and_says_so() {
        let (mut state, mut config, id, _) = applying();
        panel(&mut state).mode = VettingMode::ConfirmAbandon { application_id: id };
        panel(&mut state).selected = 2;
        let effect = plan_abandon_application(&mut state, &mut config);
        assert!(config.private.vetting.applications.is_empty());
        assert!(panel(&mut state).applications.is_empty(), "synced");
        assert_eq!(panel(&mut state).selected, 0);
        let [Step::MarkDirty, Step::Status(said)] = effect.0.as_slice() else {
            panic!("the save marked, then the status");
        };
        assert_eq!(
            said,
            &Status::success(format!("Abandoned your application to {VTC}."))
        );
    }

    #[test]
    fn switching_path_saves_what_the_application_now_uses() {
        let (book, community) = first_vtc_book();
        let mut config = test_config();
        config.private.vetting = book;
        let id = config
            .private
            .vetting
            .start_application(&community, PersonaId::new(), "did:key:zA", Utc::now())
            .unwrap()
            .id
            .clone();
        config
            .private
            .vetting
            .adopt_known_requirements(&id)
            .unwrap();
        let mut state = State::default();
        state.main_page.sync_from_config(&config);
        let effect = plan_switch_vetting_path(&mut state, &mut config);
        let [Step::Persist(message)] = effect.0.as_slice() else {
            panic!("a save");
        };
        assert_eq!(
            message,
            "This application now uses criterion vetted-member with named vetting."
        );
    }

    #[test]
    fn a_directory_search_as_a_persona_not_held_is_refused_before_the_busy_check() {
        use crate::state_handler::main_page::content::DirectoryCommunity;
        let (mut state, mut config, _, _) = applying();
        let persona = PersonaId::new();
        let v = panel(&mut state);
        v.directory_communities = vec![DirectoryCommunity {
            community: VTC.into(),
            name: "VTC".into(),
            accent: None,
            persona,
            application_id: None,
        }]
        .into();
        v.mode = VettingMode::Directory(Box::default());
        let effect = plan_search_directory(&mut state, &mut config, true, vec![None]);
        assert!(effect.0.is_empty());
        assert_eq!(
            status(&mut state),
            Status::error("The persona the directory would be searched as is not available.")
        );
        assert!(config.private.vetting.queries.is_empty());
    }
}
