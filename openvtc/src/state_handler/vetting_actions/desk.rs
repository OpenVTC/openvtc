//! The vetter desk: opening sessions, attesting, declining and withdrawing,
//! and keeping the vetter side current with its communities.

use crate::state_handler::main_page::status::Status;
use chrono::Utc;
use openvtc_core::config::account::PersonaId;
use openvtc_core::vetting::book::RequestVetting;
use openvtc_core::vetting::mode::{ModeFailure, VetterMode};
use openvtc_core::vetting::queries::{CommunityQuery, QueryKind};
use openvtc_core::vetting::vetter::{Attestation, DeskState};
use openvtc_core::vetting::wire;
use vta_sdk::protocols::vetting::{
    VETTING_DECLINE_TYPE, VETTING_REVOKE_STATEMENT_TYPE, VETTING_SESSION_TYPE, VettingMethod,
    documentation,
};
use vta_sdk::vetting::statement::sign_statement;

use super::dispatch::{page, persist, status};
use super::hidden::{attest_hidden, hidden_vetting_tick};
use super::jobs::Sent;
use super::pcs::start_pcs_work;
use super::send::{abandon, begin, persona_did, resolver, sign_and_send, spawn_send};
use super::words::{community_display, hidden_without_id_words, hides_vetters};
use crate::state_handler::main_page::content::{
    AttestForm, VETTING_METHODS, VETTING_RELATIONSHIPS, VETTING_WITHDRAWAL_REASONS, VettingMode,
    VettingTab,
};
use crate::state_handler::main_page::menu::MainMenu;
use crate::state_handler::runtime_actions::ActionCtx;
use crate::state_handler::state::State;

pub(super) async fn open_session(ctx: &mut ActionCtx<'_>, request_id: &str, method_index: usize) {
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            Status::error("The persona this request was made to is not available."),
        );
    };
    let (required, known) = ctx.config.private.vetting.required_claims_for(
        &entry.community,
        entry
            .request
            .requirements_digest
            .as_ref()
            .map(|d| d.as_str()),
    );
    let asked = page(ctx).requirements_requested.contains(&entry.community);
    if !known && !asked {
        // Every vetter of one application must ask for the same claims, or the
        // cards commit to different identities. Ask the community first.
        if !begin(ctx) {
            return;
        }
        page(ctx)
            .requirements_requested
            .push(entry.community.clone());
        let protocol = ctx.config.private.vetting.protocol_for(&entry.community);
        let document = match wire::manifest_request(&vetter_did, &entry.community, protocol) {
            Ok(d) => d,
            Err(e) => return abandon(ctx, "Could not ask the community", e),
        };
        status(
            ctx,
            Status::progress(
                "Asking the community which claims it requires — open the session again in a moment.",
            ),
        );
        let sent = Sent::Manifest {
            community: entry.community.clone(),
        };
        if let Err(e) = sign_and_send(ctx, entry.persona, document, sent).await {
            abandon(ctx, "Could not ask the community", e);
        }
        return;
    }
    if !begin(ctx) {
        return;
    }
    let session_id = wire::new_id();
    let method: VettingMethod = VETTING_METHODS[method_index.min(VETTING_METHODS.len() - 1)];
    let body = match ctx.config.private.vetting.open_session(
        request_id,
        method,
        required,
        vec![],
        &session_id,
        Utc::now(),
    ) {
        Ok(body) => body,
        Err(e) => return abandon(ctx, "Could not open the session", e),
    };
    let document = match wire::document(
        VETTING_SESSION_TYPE,
        &vetter_did,
        &entry.applicant,
        session_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not open the session", e),
    };
    // Signed here rather than in `sign_and_send`, because the desk keeps the
    // document exactly as it goes out: the Vetting Statement that closes this
    // session cites it by `taskDigestMultibase`, which `vetted/1` requires.
    // Signed and kept before `persist`, so the saved desk holds it.
    let mut document = document;
    let keys = match ctx
        .config
        .get_persona_keys_for(entry.persona, ctx.tdk)
        .await
    {
        Ok(keys) => keys,
        Err(e) => return abandon(ctx, "Could not send the session", e),
    };
    if let Err(e) = wire::sign(&mut document, &keys.authentication.secret).await {
        return abandon(ctx, "Could not send the session", e);
    }
    let recorded = serde_json::to_value(&document)
        .map_err(|e| e.to_string())
        .and_then(|value| {
            ctx.config
                .private
                .vetting
                .record_session_document(request_id, value)
                .map_err(|e| e.to_string())
        });
    if let Err(e) = recorded {
        return abandon(ctx, "Could not send the session", e);
    }
    let code = ctx
        .config
        .private
        .vetting
        .desk_entry(request_id)
        .and_then(|e| e.match_code().map(str::to_string))
        .unwrap_or_default();
    page(ctx).mode = VettingMode::List;
    persist(
        ctx,
        format!(
            "Session open. Read the match code {code} to each other{}.",
            if known {
                ""
            } else {
                " — the community's requirements are still unknown, so this asks for a legal name only"
            }
        ),
    );
    let sent = Sent::Session {
        request_id: request_id.to_string(),
    };
    let message = match wire::to_message(&document) {
        Ok(message) => message,
        Err(e) => return abandon(ctx, "Could not send the session", e),
    };
    let from = document.issuer.clone().unwrap_or_default();
    let to = document.recipient.clone().unwrap_or_default();
    spawn_send(ctx, message, &from, &to, sent);
}

/// Keep this account's vetter side current with the communities it vets for: read each one's
/// requirements again, and run whatever its hidden-vetting schedule owes — enrolment the first
/// time, the ticks of the token drip after.
///
/// A community that turns on PCS ZKP vetting says so only in its manifest, and a month's new
/// labels are published there too, so this re-reads it every time. Run by the schedule
/// (`hidden_vetting_poll`) at each tick window and at least hourly, and by `m` / `d` by hand.
pub(crate) async fn refresh_vetter_side(ctx: &mut ActionCtx<'_>) {
    // A vetter has no application, so nothing else would ever fetch the manifest of a
    // community it vets for — and the manifest is where a community says it hides its
    // vetters, and which labels are live this month.
    refresh_vetter_communities(ctx, false).await;
    // And whatever each community's vetter schedule owes us — enrolment or the ticks of the
    // drip. On a schedule, never in response to a balance (design §5.1).
    //
    // Over the communities that publish the mode as well as those we already hold an engine
    // for: the first pass through has no engine yet, and `hidden_vetting_tick` is what makes one.
    let mut communities: Vec<String> = ctx
        .config
        .private
        .vetting
        .hidden_vetter
        .iter()
        .map(|h| h.community.clone())
        .collect();
    for community in ctx.config.private.vetting.hidden_published.keys() {
        if !communities.contains(community) {
            communities.push(community.clone());
        }
    }
    // Not a community that has switched to named vetting: the engine is kept — a credential
    // does not become worthless because the advertisement moved — but drawing tokens it no
    // longer counts would only collect refusals.
    communities
        .retain(|c| ctx.config.private.vetting.vetter_mode(c).mode() != Some(VetterMode::Named));
    // Where the community refused us as another key, ask it which key it bound us to — or, while
    // an admin's reset is awaited, how that reset stands.
    ask_bindings(ctx).await;
    let mut work = Vec::new();
    for community in communities {
        hidden_vetting_tick(ctx, &community, &mut work);
    }
    // One job for the whole pass. Busy with another: the sweep runs the schedule again shortly,
    // and what is owed is planned afresh then.
    if !work.is_empty() && !start_pcs_work(ctx, work) {
        ctx.config.private.vetting.vetter_refresh_due = true;
    }
}

/// Ask each community that refused our enrolment as another key which key it bound us to
/// (`vtc/vetting/vetters/pcs-binding/show`), where the engine's key check wants it read
/// ([`HiddenVetterState::binding_read_due`](openvtc_core::vetting::book::HiddenVetterState::binding_read_due)): once to start the check, then at most every
/// [`BINDING_REASK`](openvtc_core::vetting::binding::BINDING_REASK) while a reset is awaited, and
/// never while a question is open or the community's silence is being backed off (R1.4).
async fn ask_bindings(ctx: &mut ActionCtx<'_>) {
    let now = Utc::now();
    // A record kept before this client could recover a key: its last word from the community
    // is `identifierRebound` and no check is running. Start one rather than wait for the next
    // enrolment to collect the same refusal.
    for held in &mut ctx.config.private.vetting.hidden_vetter {
        if held.key.is_none() && held.recheck_key(now) {
            ctx.save.mark_dirty();
        }
    }
    let due: Vec<(String, PersonaId)> = {
        let book = &ctx.config.private.vetting;
        book.hidden_vetter
            .iter()
            .filter(|h| h.binding_read_due(now))
            .filter(|h| h.retry_at.is_none_or(|t| t <= now))
            .filter(|h| {
                book.waiting_on(&h.community, QueryKind::PcsBinding)
                    .is_none()
            })
            .map(|h| (h.community.clone(), h.persona))
            .collect()
    };
    for (community, persona) in due {
        let Some(did) = persona_did(ctx.config, persona) else {
            continue;
        };
        let document = match wire::pcs_binding_show_request(&did, &community) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(community = %community, error = %e, "could not build the binding question");
                continue;
            }
        };
        let document_id = document.id.clone();
        if let Some(held) = ctx
            .config
            .private
            .vetting
            .hidden_vetter_mut(&community, persona)
        {
            held.binding_asked(now);
        }
        ctx.config.private.vetting.ask(CommunityQuery {
            document_id: document_id.clone(),
            community: community.clone(),
            persona,
            kind: QueryKind::PcsBinding,
            sent_at: now,
        });
        ctx.save.mark_dirty();
        let sent = Sent::Query {
            document_id,
            community: community.clone(),
            kind: QueryKind::PcsBinding,
        };
        if let Err(e) = sign_and_send(ctx, persona, document, sent).await {
            status(
                ctx,
                Status::error(format!(
                    "Could not ask {} which hidden-vetting key it holds for you: {e}",
                    community_display(ctx.config, &community)
                )),
            );
        }
    }
}

/// Read again how each community we vet for vets, where the last reading is stale — on opening
/// the desk, and while it stays open. Bounded: a community is asked at most once per
/// [`MODE_REASK_AFTER`](openvtc_core::vetting::mode::MODE_REASK_AFTER), answered or not (R1.4).
pub(crate) async fn refresh_stale_modes(ctx: &mut ActionCtx<'_>) {
    refresh_vetter_communities(ctx, true).await;
}

/// Whether the vetter desk is what the operator is looking at — the one place a stale mode is
/// worth reading again outside the schedule.
pub(crate) fn desk_open(state: &State) -> bool {
    state.main_page.menu_panel.selected_menu == MainMenu::Vetting
        && state.main_page.content_panel.vetting.tab == VettingTab::Desk
}

/// Ask every community that has named us a vetter what it requires.
///
/// An applicant refreshes a manifest because it is applying. A vetter has no application, so
/// without this nothing ever asks — and a community that hides its vetters says so in its
/// manifest and nowhere else. The answer is what [`ensure_hidden_vetter`](crate::state_handler::vetting_actions::hidden::ensure_hidden_vetter) acts on.
///
/// Including the communities we already hold an engine for: the manifest is where a new month's
/// labels appear, and an engine that never re-read it never moved past the month it enrolled
/// in. What changes there reaches the engine as the answer lands
/// ([`VettingBook::learn_mode`](openvtc_core::vetting::VettingBook::learn_mode) → [`HiddenVetterState::take_reading`](openvtc_core::vetting::book::HiddenVetterState::take_reading)), keeping the keys we
/// enrolled under.
///
/// `only_stale` asks only where how the community vets is older than
/// [`MODE_TTL`](openvtc_core::vetting::mode::MODE_TTL) and was not asked lately
/// ([`VettingBook::mode_refresh_due`](openvtc_core::vetting::VettingBook::mode_refresh_due)) — what opening the desk, and keeping it open, need.
async fn refresh_vetter_communities(ctx: &mut ActionCtx<'_>, only_stale: bool) {
    let standing: Vec<(String, PersonaId)> = {
        let book = &ctx.config.private.vetting;
        let now = Utc::now();
        book.vetter_standing(now)
            .into_iter()
            .filter(|s| s.live)
            .filter(|s| !only_stale || book.mode_refresh_due(&s.community, now))
            // Not again within seconds of the last ask or answer: `d` pressed three times, or a
            // pass chained on an answer, used to fetch the same manifest each time (R1.4). Unless
            // a draw was refused as over the community's rate since: that read is owed now, once.
            .filter(|s| {
                !book.manifest_recently_asked(&s.community, now)
                    || book.params_reread_owed(&s.community)
            })
            .map(|s| (s.community, s.persona))
            .collect()
    };
    for (community, persona) in standing {
        // A community we vet for as two personas is one manifest, asked once.
        let book = &ctx.config.private.vetting;
        if book.manifest_recently_asked(&community, Utc::now())
            && !book.params_reread_owed(&community)
        {
            continue;
        }
        let Some(did) = persona_did(ctx.config, persona) else {
            continue;
        };
        let protocol = ctx.config.private.vetting.protocol_for(&community);
        let Ok(document) = wire::manifest_request(&did, &community, protocol) else {
            continue;
        };
        let sent = Sent::Manifest {
            community: community.clone(),
        };
        let now = Utc::now();
        ctx.config.private.vetting.mode_asked(&community, now);
        match sign_and_send(ctx, persona, document, sent).await {
            Ok(()) => ctx.config.private.vetting.vetter_refresh_failures = 0,
            Err(e) => {
                tracing::warn!(community = %community, error = %e, "could not ask a community what it requires");
                ctx.config.private.vetting.mode_failed(
                    &community,
                    ModeFailure::Unsent(e.clone()),
                    now,
                );
                // Usually the listener is not up yet (start-up). Ask again on
                // the five-second sweep, a bounded number of times.
                let book = &mut ctx.config.private.vetting;
                if book.vetter_refresh_failures
                    < openvtc_core::vetting::book::VETTER_REFRESH_RETRIES
                {
                    book.vetter_refresh_failures += 1;
                    book.vetter_refresh_due = true;
                }
            }
        }
    }
}

/// The session id a desk entry is at, if it has one.
pub(super) fn session_id_of(entry: &openvtc_core::vetting::vetter::DeskEntry) -> Option<String> {
    match &entry.state {
        DeskState::Session { session, .. } | DeskState::CardReceived { session, .. } => {
            Some(session.id.clone())
        }
        _ => None,
    }
}

pub(super) async fn attest(ctx: &mut ActionCtx<'_>, request_id: &str, form: &AttestForm) {
    if !form.attested {
        return status(
            ctx,
            Status::warning(
                "Tick the attestation (the last line) — signing is attributable to you in this community.",
            ),
        );
    }
    let now = Utc::now();
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let DeskState::CardReceived { session, .. } = &entry.state else {
        return status(
            ctx,
            Status::warning("You can attest once their card has arrived."),
        );
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            Status::error("The persona this request was made to is not available."),
        );
    };
    let method = VETTING_METHODS[form.method_index.min(VETTING_METHODS.len() - 1)];
    let documentation_choice = page(ctx)
        .documentation
        .get(form.documentation_index)
        .cloned()
        .unwrap_or_else(|| documentation::NONE.to_string());
    // `none` is never listed in a statement: no document is the empty list. So
    // choosing it means relying on nothing, whichever method was used — and a
    // documentary method with nothing to rely on is refused by the desk.
    let document_classes = if documentation_choice == documentation::NONE {
        Vec::new()
    } else {
        vec![documentation_choice]
    };
    let attestation = Attestation {
        method,
        document_classes,
        claims_verified: session.required_claims.clone(),
        liveness_confirmed: form.liveness_confirmed,
        declared_relationship: VETTING_RELATIONSHIPS
            [form.relationship_index.min(VETTING_RELATIONSHIPS.len() - 1)],
        attestation_text_digest: None,
    };
    // Hidden vetting: this community counts a proof, not a signature. The desk builds the same
    // draft from the same checklist and then does not sign it — what goes to the applicant
    // carries a tag where an issuer would be, and nothing on the way names this persona.
    //
    // Only while the community runs PCS ZKP now: an engine says we enrolled once, and a
    // community that has switched back to named vetting counts signed statements, not proofs.
    //
    // And only for a request that asked for it. A community may publish hidden vetting
    // alongside named vetters, so the request decides, not the community: one carrying the
    // applicant's PCS identifier gets a proof, one without gets a named statement — unless the
    // criterion it names takes the proof alone, when there is nothing to attest to.
    let book = &ctx.config.private.vetting;
    let hidden_request = match book.request_vetting(request_id) {
        RequestVetting::Hidden => hides_vetters(book, &entry.community),
        RequestVetting::Named { .. } => false,
        RequestVetting::HiddenWithoutId { criterion } => {
            return status(ctx, Status::warning(hidden_without_id_words(&criterion)));
        }
        RequestVetting::Unreadable(e) => {
            return status(ctx, Status::error(format!("Cannot attest: {e}")));
        }
    };
    if hidden_request
        && book
            .hidden_vetter(&entry.community, entry.persona)
            .is_some()
    {
        return attest_hidden(ctx, request_id, &entry, &vetter_did, attestation, now).await;
    }
    // The request asks for a proof but this vetter is not enrolled yet:
    // signing now would make a named statement — one the applicant's
    // hidden-vetting application cannot use, carrying this vetter's DID to a
    // community that promised not to need it. Enrol first.
    if hidden_request {
        page(ctx).mode = VettingMode::List;
        status(
            ctx,
            Status::warning(
                "This community proves vetting with a PCS zero-knowledge proof, and you are not \
             enrolled for it yet, so nothing was signed. Enrolling now — attest again in a \
             moment.",
            ),
        );
        refresh_vetter_side(ctx).await;
        return;
    }

    let draft =
        match ctx
            .config
            .private
            .vetting
            .statement_draft(request_id, &vetter_did, attestation, now)
        {
            Ok(draft) => draft,
            Err(e) => return status(ctx, Status::error(format!("Cannot attest yet: {e}"))),
        };
    if !begin(ctx) {
        return;
    }
    let keys = match ctx
        .config
        .get_persona_keys_for(entry.persona, ctx.tdk)
        .await
    {
        Ok(keys) => keys,
        Err(e) => return abandon(ctx, "Could not sign the statement", e),
    };
    let statement = match sign_statement(draft, &keys.signing.secret).await {
        Ok(statement) => statement,
        Err(e) => return abandon(ctx, "Could not sign the statement", e),
    };
    let resolver = resolver(ctx);
    let issued = match ctx
        .config
        .private
        .vetting
        .record_statement(request_id, &statement, &resolver, now)
        .await
    {
        Ok(issued) => issued,
        Err(e) => return abandon(ctx, "The statement did not verify", e),
    };
    // The statement is signed with the assertionMethod key (a credential); the
    // delivery document carrying it with the authentication key, like every
    // other document this persona sends.
    let message = match wire::credential_delivery(
        &vetter_did,
        &entry.applicant,
        &statement,
        &session.id,
        &keys.authentication.secret,
    )
    .await
    {
        Ok(message) => message,
        Err(e) => {
            ctx.config
                .private
                .vetting
                .issued
                .retain(|s| s.id != issued.id);
            if let Some(e2) = ctx.config.private.vetting.desk_entry_mut(request_id) {
                e2.state = entry.state.clone();
            }
            return abandon(ctx, "Could not send the statement", e);
        }
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Sending your statement…");
    let sent = Sent::Statement {
        request_id: request_id.to_string(),
        statement_id: issued.id,
        previous: entry.state.clone(),
    };
    spawn_send(ctx, message, &vetter_did, &entry.applicant, sent);
}

/// Decline a desk request, with the reason and note the vetter chose — both
/// optional, and sent to the applicant only, never the community.
pub(super) async fn decline(
    ctx: &mut ActionCtx<'_>,
    request_id: &str,
    code: Option<vta_sdk::protocols::vetting::decline::v0_1::PayloadCode>,
    message: Option<String>,
) {
    let Some(entry) = ctx.config.private.vetting.desk_entry(request_id).cloned() else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, entry.persona) else {
        return status(
            ctx,
            Status::error("The persona this request was made to is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let body = match ctx
        .config
        .private
        .vetting
        .decline(request_id, code, message, Utc::now())
    {
        Ok(body) => body,
        Err(e) => return abandon(ctx, "Could not decline", e),
    };
    let document = match wire::document(
        VETTING_DECLINE_TYPE,
        &vetter_did,
        &entry.applicant,
        wire::new_id(),
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not decline", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Declining…");
    let sent = Sent::Decline {
        request_id: request_id.to_string(),
        previous: entry.state.clone(),
    };
    if let Err(e) = sign_and_send(ctx, entry.persona, document, sent).await {
        if let Some(desk) = ctx.config.private.vetting.desk_entry_mut(request_id) {
            desk.state = entry.state;
        }
        abandon(ctx, "Could not send the decline", e);
    }
}

pub(super) async fn withdraw(ctx: &mut ActionCtx<'_>, statement_id: &str, reason_index: usize) {
    let Some(issued) = ctx
        .config
        .private
        .vetting
        .issued
        .iter()
        .find(|s| s.id == statement_id)
        .cloned()
    else {
        return;
    };
    let Some(vetter_did) = persona_did(ctx.config, issued.persona) else {
        return status(
            ctx,
            Status::error("The persona that signed this statement is not available."),
        );
    };
    if !begin(ctx) {
        return;
    }
    let document_id = wire::new_id();
    let reason = VETTING_WITHDRAWAL_REASONS[reason_index.min(VETTING_WITHDRAWAL_REASONS.len() - 1)];
    let body = match ctx.config.private.vetting.withdrawal(
        statement_id,
        Some(reason),
        &document_id,
        Utc::now(),
    ) {
        Ok((body, _)) => body,
        Err(e) => return abandon(ctx, "Could not withdraw", e),
    };
    let document = match wire::document(
        VETTING_REVOKE_STATEMENT_TYPE,
        &vetter_did,
        &issued.community,
        document_id,
        &body,
    ) {
        Ok(d) => d,
        Err(e) => return abandon(ctx, "Could not withdraw", e),
    };
    page(ctx).mode = VettingMode::List;
    persist(ctx, "Telling the community…");
    let sent = Sent::Withdrawal {
        statement_id: statement_id.to_string(),
    };
    if let Err(e) = sign_and_send(ctx, issued.persona, document, sent).await {
        if let Some(s) = ctx
            .config
            .private
            .vetting
            .issued
            .iter_mut()
            .find(|s| s.id == statement_id)
        {
            s.withdrawal = None;
        }
        abandon(ctx, "Could not send the withdrawal", e);
    }
}
