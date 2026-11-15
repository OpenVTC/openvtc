//! The applicant side: starting and abandoning applications, switching
//! vetting path, requesting a vetter, and searching the vetter directory.

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

use super::dispatch::{back, page, persist, status};
use super::jobs::Sent;
use super::send::{abandon, begin, persona_did, sign_and_send};
use super::words::community_display;
use crate::state_handler::main_page::content::{
    DIRECTORY_LABELS, DIRECTORY_METHODS, DirectoryView, VettingMode, VettingTab, row_of,
};
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::runtime_actions::ActionCtx;

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
pub(super) fn switch_vetting_path(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
    let Some(row) = v.applications.get(v.selected).cloned() else {
        return;
    };
    let had_requests = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .any(|a| a.id == row.id && !a.requests.is_empty());
    match ctx.config.private.vetting.switch_vetting(&row.id) {
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
            persist(
                ctx,
                format!(
                    "This application now uses criterion {} with {}.{resend}",
                    now.criterion_id,
                    now.path.words()
                ),
            );
        }
        Err(why) => status(ctx, Status::error(why)),
    }
}

pub(super) async fn refresh_requirements(ctx: &mut ActionCtx<'_>, application_id: &str) {
    let Some(app) = ctx
        .config
        .private
        .vetting
        .applications
        .iter()
        .find(|a| a.id == application_id)
        .cloned()
    else {
        return;
    };
    if !begin(ctx) {
        return;
    }
    let protocol = ctx.config.private.vetting.protocol_for(&app.community);
    let document = match wire::manifest_request(&app.join_did, &app.community, protocol) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not ask the community", e),
    };
    status(
        ctx,
        Status::progress("Asking the community what it requires…"),
    );
    let sent = Sent::Manifest {
        community: app.community.clone(),
    };
    if let Err(e) = sign_and_send(ctx, app.persona, document, sent).await {
        abandon(ctx, "Could not ask the community", e);
    }
}

/// Recompute the contexts a new application can use, for the community and
/// persona on the form. An application that already exists keeps its own.
pub(super) fn refresh_application_contexts(ctx: &mut ActionCtx<'_>) {
    let (community, persona) = {
        let v = page(ctx);
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
    let config: &Config = ctx.config;
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
    } = &mut page(ctx).mode
    {
        if *context_options != options {
            *context_index = 0;
        }
        *context_options = options;
    }
}

pub(super) async fn start_application(
    ctx: &mut ActionCtx<'_>,
    community: &str,
    persona_index: usize,
    context: Option<String>,
) {
    if !community.starts_with("did:") {
        return status(
            ctx,
            Status::warning("Enter the community's DID (it starts with did:)."),
        );
    }
    let Some(persona) = page(ctx).personas.get(persona_index).cloned() else {
        return status(
            ctx,
            Status::warning("Choose the persona you will join with."),
        );
    };
    let application_id = match ctx.config.private.vetting.start_application(
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
            return status(
                ctx,
                Status::error(format!("Could not start the application: {e}")),
            );
        }
    };
    // Said, not dropped (R6.4): a criterion this build cannot honour is the one thing that
    // makes this application gather evidence the community will not count.
    let unadopted = ctx
        .config
        .private
        .vetting
        .adopt_known_requirements(&application_id)
        .err()
        .map(|e| format!(" Its requirements could not be taken up: {e}."))
        .unwrap_or_default();
    {
        let v = page(ctx);
        v.mode = VettingMode::List;
        v.tab = VettingTab::Applications;
    }
    persist(ctx, format!("Application started.{unadopted}"));
    if let Some(i) = page(ctx)
        .applications
        .iter()
        .position(|a| a.id == application_id)
    {
        page(ctx).selected = i;
    }
    refresh_requirements(ctx, &application_id).await;
}

/// Send a vetting request carrying the ticket from a `vetting-ticket:` link.
///
/// `entry` is the one field; `vetter` and `ticket` are what a paste already
/// read out of it. Enter with neither of those set — someone typed or pasted
/// without the paste hook firing — reads `entry` here, so the form behaves the
/// same whichever way the text arrived.
pub(super) async fn request_vetter(
    ctx: &mut ActionCtx<'_>,
    application_id: &str,
    entry: &str,
    vetter: &str,
    ticket: Option<request::v0_1::Ticket>,
) {
    // Not yet read (typed rather than pasted): read it now, which also reports
    // a link for the wrong community or one that cannot be decoded.
    let (vetter, presentation) = match (ticket, vetter.starts_with("did:")) {
        (Some(ticket), true) => (vetter.to_string(), ticket),
        _ => {
            let Some(app) = ctx
                .config
                .private
                .vetting
                .applications
                .iter()
                .find(|a| a.id == application_id)
            else {
                return;
            };
            match app.ticket_from_uri(entry) {
                Ok(ticket) => (ticket.vetter, ticket.presentation),
                Err(_) if entry.is_empty() => {
                    return status(
                        ctx,
                        Status::warning(
                            "Paste the link from the vetter's QR code — it carries their ticket, \
                         and a request without one is never answered.",
                        ),
                    );
                }
                Err(e) => return status(ctx, Status::error(sanitize_display(&e.to_string(), 400))),
            }
        }
    };
    let vetter = vetter.as_str();
    // Under a hidden criterion the request carries the application's PCS identifier, which the
    // VTA mints. Before it has, a request would ask the vetter for a named statement this
    // application cannot use.
    if ctx
        .config
        .private
        .vetting
        .application_by_id(application_id)
        .is_some_and(Application::hidden_app_owed)
    {
        ctx.config.private.vetting.pcs_due = true;
        return status(
            ctx,
            Status::error(openvtc_core::vetting::hidden::HiddenError::NotReady.to_string()),
        );
    }
    if !begin(ctx) {
        return;
    }
    let document_id = wire::new_id();
    let Some(app) = ctx
        .config
        .private
        .vetting
        .application_by_id_mut(application_id)
    else {
        return abandon(ctx, "Could not send the request", "the application is gone");
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
        Err(e) => return abandon(ctx, "Could not send the request", e),
    };
    let document = match wire::document(
        VETTING_REQUEST_TYPE,
        &join_did,
        vetter,
        document_id.clone(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not send the request", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Sending your request…");
    let sent = Sent::Request {
        application_id: application_id.to_string(),
        document_id: document_id.clone(),
        vetter: vetter.to_string(),
    };
    if let Err(e) = sign_and_send(ctx, persona, document, sent).await {
        if let Some(app) = ctx
            .config
            .private
            .vetting
            .application_by_id_mut(application_id)
        {
            app.forget_unsent(&document_id);
        }
        abandon(ctx, "Could not send the request", e);
    }
}

/// Fill the request form from a pasted `vetting-ticket:` link — the vetter's
/// DID and the scanned ticket — or say why it cannot be used.
pub(super) fn paste_ticket(ctx: &mut ActionCtx<'_>, text: &str) {
    let VettingMode::RequestVetter { application_id, .. } = &page(ctx).mode else {
        return;
    };
    let application_id = application_id.clone();
    let Some(app) = ctx
        .config
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
            } = &mut page(ctx).mode
            {
                *entry = pasted;
                *vetter = ticket.vetter;
                *slot = Some(ticket.presentation);
            }
            status(
                ctx,
                Status::info(format!(
                    "Read the ticket link. It goes to {shown} — Enter sends the request."
                )),
            );
        }
        Err(e) => status(ctx, Status::error(sanitize_display(&e.to_string(), 400))),
    }
}

pub(super) fn open_directory(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
    if v.directory_communities.is_empty() {
        return status(
            ctx,
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
pub(super) async fn search_directory(ctx: &mut ActionCtx<'_>, cursors: Vec<Option<String>>) {
    let prepared = {
        let v = page(ctx);
        let VettingMode::Directory(view) = &mut v.mode else {
            return;
        };
        if view.pending.is_some() {
            return;
        }
        let Some(target) = v.directory_communities.get(view.community_index).cloned() else {
            return;
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
                return;
            }
        }
    };
    let (target, body) = prepared;
    let Some(asker) = persona_did(ctx.config, target.persona) else {
        return status(
            ctx,
            Status::error("The persona the directory would be searched as is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let document = match wire::vetter_list_request(&asker, &target.community, &body) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not search the directory", e),
    };
    let document_id = document.id.clone();
    ctx.config.private.vetting.ask(CommunityQuery {
        document_id: document_id.clone(),
        community: target.community.clone(),
        persona: target.persona,
        kind: QueryKind::VetterList,
        sent_at: Utc::now(),
    });
    if let VettingMode::Directory(view) = &mut page(ctx).mode {
        view.pending = Some(document_id.clone());
        view.pending_cursors = Some(cursors);
        view.error = None;
    }
    status(
        ctx,
        Status::progress(format!("Asking {} for its vetter directory…", target.name)),
    );
    let sent = Sent::Query {
        document_id: document_id.clone(),
        community: target.community.clone(),
        kind: QueryKind::VetterList,
    };
    if let Err(e) = sign_and_send(ctx, target.persona, document, sent).await {
        ctx.config.private.vetting.forget_query(&document_id);
        if let VettingMode::Directory(view) = &mut page(ctx).mode {
            view.pending = None;
            view.pending_cursors = None;
        }
        abandon(ctx, "Could not search the directory", e);
    }
}

pub(super) async fn directory_page(ctx: &mut ActionCtx<'_>, forward: bool) {
    let (mut cursors, next) = match &page(ctx).mode {
        VettingMode::Directory(view) if view.pending.is_none() => {
            (view.cursors.clone(), view.next_cursor.clone())
        }
        _ => return,
    };
    if forward {
        let Some(next) = next else {
            return status(ctx, Status::warning("That is the last page."));
        };
        cursors.push(Some(next));
    } else {
        if cursors.len() <= 1 {
            return status(ctx, Status::warning("This is the first page."));
        }
        cursors.pop();
    }
    search_directory(ctx, cursors).await;
}

/// Open the request form for the highlighted directory vetter. The directory
/// finds a vetter; it does not let anyone skip the ticket, so the form says
/// how this vetter hands them out.
pub(super) fn ask_listed_vetter(ctx: &mut ActionCtx<'_>) {
    let v = page(ctx);
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
        return status(
            ctx,
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
    let v = page(ctx);
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
pub(super) fn abandon_application(ctx: &mut ActionCtx<'_>) {
    let VettingMode::ConfirmAbandon { application_id } = page(ctx).mode.clone() else {
        return;
    };
    let Some(app) = ctx
        .config
        .private
        .vetting
        .abandon_application(&application_id)
    else {
        back(page(ctx));
        return status(ctx, Status::warning("That application is already gone."));
    };
    let community = community_display(ctx.config, &app.community);
    let asked = app.requests.len();
    back(page(ctx));
    ctx.state.main_page.content_panel.vetting.selected = 0;
    ctx.state.main_page.sync_from_config(ctx.config);
    ctx.save.mark_dirty();
    status(
        ctx,
        Status::success(if asked == 0 {
            format!("Abandoned your application to {community}.")
        } else {
            format!(
                "Abandoned your application to {community}. {asked} vetter{} still \
                 hold{} your request — tell them, or they will open a session with \
                 nothing to answer.",
                if asked == 1 { "" } else { "s" },
                if asked == 1 { "s" } else { "" }
            )
        }),
    );
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
}
