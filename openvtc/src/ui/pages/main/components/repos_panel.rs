//! Repos panel — a community's git repositories (`git-ns/*`), opened from the
//! Communities panel with `r`.
//!
//! Three screens over one `git-ns/view` answer: *My repos* with the forge
//! account and commit-signing health beside it, one repository's people and
//! rights (or its creation steps), and the new-repository form.
//!
//! Beside the community's record, each repository shows what is on this
//! machine: whether it is checked out, where, and whether a commit made there
//! would be signed as this persona — with the one key that fixes it.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::content::ContentPanelState;
use crate::state_handler::main_page::repos::{
    AccountForm, AccountOption, AddPersonForm, CheckoutView, EXPIRY_CHOICES, HookHealth, LinkPhase,
    LinkedAccount, NewRepoForm, ReposPhase, ReposScreen, ReposView, Severity, SignerHealth, Status,
    WorkspaceChange, WorkspaceForm, expiry_label,
};
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::repos_workspace;
use crate::state_handler::state::ConnectionState;
use openvtc_core::forge_credential::ForgeCredential;
use openvtc_core::git_ns::{self, BreakGlassState, GitRight, RepoStatus};
use openvtc_core::git_signing::{BinaryStatus, CheckoutSigning, MIN_BINARY};
use openvtc_core::git_workspace::{self, CheckoutFacts, CredentialScope, RepoCoords};

use super::panel::Panel;

pub struct ReposPanel;

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_DARK_GRAY))
}

fn text(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_TEXT_DEFAULT))
}

fn heading(lines: &mut Vec<Line<'static>>, title: &str) {
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {title}"),
        Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
    )));
}

fn hints(lines: &mut Vec<Line<'static>>, hints: &str) {
    lines.push(Line::from(""));
    lines.push(Line::from(dim(format!("    {hints}"))));
}

fn status_style(status: &RepoStatus) -> Style {
    Style::default().fg(match status {
        RepoStatus::Ok => COLOR_SUCCESS,
        RepoStatus::Creating { .. } | RepoStatus::Checking => COLOR_SOFT_PURPLE,
        RepoStatus::Drift { .. } | RepoStatus::Orphaned => COLOR_ORANGE,
        RepoStatus::Detached => COLOR_WARNING_ACCESSIBLE_RED,
        RepoStatus::Archived | RepoStatus::Unmanaged => COLOR_DARK_GRAY,
    })
}

/// A status line in the colour its severity names — never guessed from its
/// words.
fn push_status(lines: &mut Vec<Line<'static>>, status: &Status) {
    let style = match status.severity {
        Severity::Info | Severity::Progress => Style::default().fg(COLOR_TEXT_DEFAULT),
        Severity::Success => Style::default().fg(COLOR_SUCCESS),
        Severity::Warning => Style::default().fg(COLOR_ORANGE),
        Severity::Error => Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
    };
    for part in super::status::wrap_text(
        &status.text,
        super::status::content_width().saturating_sub(6).max(20),
    ) {
        lines.push(Line::from(Span::styled(format!("    {part}"), style)));
    }
}

fn error(lines: &mut Vec<Line<'static>>, text: &str) {
    push_status(
        lines,
        &Status {
            text: text.to_string(),
            severity: Severity::Error,
        },
    );
}

fn date(at: &chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%d").to_string()
}

impl Panel for ReposPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        let Some(view) = &state.repos.view else {
            return vec![Line::from("no repos view open")];
        };
        let mut lines = Vec::new();
        let crumb = match &view.screen {
            ReposScreen::List => String::new(),
            ReposScreen::Repo { resource } => format!(" › {}", git_ns::short_resource(resource)),
            ReposScreen::NewRepo(_) => " › New repo".into(),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("  Repos — {}{crumb}", view.community_name),
                Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            dim(format!("    as {}", shorten_did(&view.me, 40))),
        ]));

        match &view.phase {
            ReposPhase::Loading => {
                lines.push(Line::from(""));
                lines.push(Line::from(dim(
                    "    asking the community what it governs on the forges…",
                )));
                hints(&mut lines, "r retry   Esc back");
                return lines;
            }
            ReposPhase::Failed(detail) => {
                lines.push(Line::from(""));
                error(&mut lines, detail);
                hints(&mut lines, "r retry   Esc back");
                return lines;
            }
            ReposPhase::Loaded => {}
        }

        render_break_glass(&mut lines, view, chrono::Utc::now());

        match &view.screen {
            ReposScreen::List => render_list(&mut lines, view, &state.repos.linked),
            ReposScreen::Repo { resource } => {
                render_repo(&mut lines, view, resource, &state.repos.linked)
            }
            ReposScreen::NewRepo(form) => render_new(&mut lines, view, form),
        }
        render_workspace_overlay(&mut lines, view);

        if let Some(armed) = &view.confirm {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("    {}", armed.summary),
                Style::default().fg(COLOR_ORANGE).bold(),
            )));
            let class = armed.request.consent_class();
            lines.push(Line::from(dim(format!(
                "    {} change · signed by this persona · y confirm · any other key cancels",
                class.label()
            ))));
        }

        if let Some(status) = &view.status {
            lines.push(Line::from(""));
            push_status(&mut lines, status);
        }
        lines
    }
}

// ****************************************************************************
// Break-glass banner
// ****************************************************************************

/// How many records the banner lists by name before it summarises the rest.
const BREAK_GLASS_LISTED: usize = 5;

/// The banner every screen of the panel opens with while any break-glass
/// record awaits ratification (`git-ns/right/break-glass`): someone gave
/// themselves an elevated right nobody else granted, and until another
/// administrator ratifies or revokes it, it stays in front of them.
///
/// The VTC chooses who receives these records (`git-ns/view` 0.4 returns them
/// to every administrator of the namespace, the resource's owners and the
/// subject), so the banner shows every one the view holds.
fn render_break_glass(
    lines: &mut Vec<Line<'static>>,
    view: &ReposView,
    now: chrono::DateTime<chrono::Utc>,
) {
    let alerts = view.break_glass(now);
    if alerts.is_empty() {
        return;
    }
    let alarm = Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "  ⚠ BREAK-GLASS — {} self-granted right{} awaiting ratification",
            alerts.len(),
            if alerts.len() == 1 { "" } else { "s" }
        ),
        alarm,
    )));
    for a in alerts.iter().take(BREAK_GLASS_LISTED) {
        let who = if a.mine {
            "You".to_string()
        } else {
            shorten_did(&view.name_of(&a.subject), 32)
        };
        let pending = a
            .pending_until
            .map(|e| format!(" · takes effect {}", e.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled("    ● ", alarm),
            text(format!(
                "{who} gave {} {} on {} · {}{pending}",
                if a.mine { "yourself" } else { "themselves" },
                a.right,
                a.resource,
                a.at.format("%Y-%m-%d %H:%M UTC"),
            )),
        ]));
        lines.push(Line::from(dim(format!(
            "      why: {}",
            sanitize_display(&a.justification, 2048)
        ))));
    }
    if alerts.len() > BREAK_GLASS_LISTED {
        lines.push(Line::from(dim(format!(
            "    … and {} more",
            alerts.len() - BREAK_GLASS_LISTED
        ))));
    }
    match alerts.iter().find(|a| !a.mine) {
        Some(first) => {
            lines.push(Line::from(dim(
                "    Another administrator ratifies or revokes each one — in the admin console \
                 (Repos → Break-glass grants), or with cnm:",
            )));
            lines.push(Line::from(text(format!(
                "      {}",
                first.ratify_command()
            ))));
            lines.push(Line::from(text(format!(
                "      {}",
                first.revoke_command()
            ))));
        }
        None => lines.push(Line::from(dim(
            "    Another community administrator or namespace admin must ratify or revoke it; \
             it stays flagged, and in front of every administrator, until one does.",
        ))),
    }
}

// ****************************************************************************
// My repos
// ****************************************************************************

fn render_list(lines: &mut Vec<Line<'static>>, view: &ReposView, linked: &[LinkedAccount]) {
    heading(lines, "My repos");
    let mine = view.my_repos();
    if mine.is_empty() {
        lines.push(Line::from(dim(
            "    You hold no right on any repository this community governs.",
        )));
    } else {
        lines.push(Line::from(dim(format!(
            "      {:<34}{:<18}{:<14}{}",
            "REPOSITORY", "MY RIGHT", "STATUS", "THIS MACHINE"
        ))));
        for (i, repo) in mine.iter().enumerate() {
            let selected = i == view.selected;
            let name_style = if selected {
                Style::default().fg(COLOR_SUCCESS).bold()
            } else {
                Style::default().fg(COLOR_TEXT_DEFAULT)
            };
            lines.push(Line::from(vec![
                Span::raw(if selected { "    ▸ " } else { "      " }),
                Span::styled(
                    format!("{:<34}", git_ns::short_resource(&repo.resource)),
                    name_style,
                ),
                text(format!("{:<18}", repo.right.label())),
                Span::styled(
                    format!("{:<14}", repo.status.label()),
                    status_style(&repo.status),
                ),
                local_summary(view, &repo.resource),
            ]));
            if selected && let Some(c) = view.workspace.checkouts.get(&repo.resource) {
                lines.push(Line::from(dim(format!(
                    "        {}",
                    checkout_brief(&c.facts)
                ))));
            }
        }
    }
    for c in view.creatable() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            dim("    You can create repos in "),
            text(git_ns::namespace_resource(&c.namespace)),
            dim(format!(
                " (granted by {}, {}).",
                shorten_did(&view.name_of(&c.granted_by), 32),
                date(&c.granted_at)
            )),
        ]));
        if git_ns::is_manual(&c.namespace) {
            lines.push(Line::from(dim(
                "    No bot creates repositories there: the community answers a new repo with \
                 the steps to take by hand.",
            )));
        }
    }

    render_accounts(lines, view, linked);
    render_signing(lines, view);

    if view.workspace.form.is_some() {
        return;
    }
    let mut keys = vec!["↑/↓ navigate", "⏎ open"];
    if !view.creatable().is_empty() {
        keys.push("n new repo");
    }
    keys.extend(["l link account", "r refresh", "Esc back"]);
    hints(lines, &keys.join("   "));
    local_hints(lines, view);
}

fn render_accounts(lines: &mut Vec<Line<'static>>, view: &ReposView, linked: &[LinkedAccount]) {
    heading(lines, "Forge account");
    let forges = view
        .data
        .as_deref()
        .map(git_ns::linkable_forges)
        .unwrap_or_default();
    if forges.is_empty() {
        lines.push(Line::from(dim(
            "    No bridge serves a forge for this community yet, so there is no account to \
             link. Rights still work: they are checked on your commits, not your forge login.",
        )));
    }
    for forge in &forges {
        match view.linked_on(linked, forge) {
            Some(account) => lines.push(Line::from(vec![
                Span::styled("    ● ", Style::default().fg(COLOR_SUCCESS)),
                text(format!("{forge}  linked  @{}", sanitize_display(&account.login, 100))),
                dim(format!("  id {}", sanitize_display(&account.id, 64))),
            ])),
            None => lines.push(Line::from(vec![
                dim("    ○ "),
                text(forge.clone()),
                dim("  not linked this session — l to link. It gives you your forge role on repos you own or maintain."),
            ])),
        }
    }
    if let Some(link) = &view.link {
        lines.push(Line::from(""));
        match &link.phase {
            LinkPhase::Starting => lines.push(Line::from(dim(format!(
                "    Asking the community's bridge to start a {} link…",
                link.forge
            )))),
            LinkPhase::Waiting => {
                // Only an https URL on the link's own forge reaches here (the
                // reply is checked when it lands); sanitised all the same.
                let url = sanitize_display(link.url.as_deref().unwrap_or_default(), 2048);
                match &link.user_code {
                    // Device flow: a code typed at a fixed URL.
                    Some(code) => {
                        lines.push(Line::from(vec![text("    Open  "), text(url)]));
                        lines.push(Line::from(vec![
                            text("    and enter  "),
                            Span::styled(
                                sanitize_display(code, 64),
                                Style::default().fg(COLOR_SUCCESS).bold(),
                            ),
                        ]));
                    }
                    // Authorisation code: a URL to open, and its QR for a phone.
                    None => {
                        lines.push(Line::from(text(format!(
                            "    Open this link to authorise on {}:",
                            link.forge
                        ))));
                        lines.push(Line::from(text(format!("    {url}"))));
                        let width = super::status::content_width().saturating_sub(6);
                        let height = super::status::content_height().saturating_sub(4) / 2;
                        if let Ok(qr) = super::qr::qr_lines(&url, width, height) {
                            for row in qr {
                                let mut spans = vec![Span::raw("    ")];
                                spans.extend(row.spans);
                                lines.push(Line::from(spans));
                            }
                        }
                    }
                }
                let expiry = link
                    .expires_at
                    .map(|e| format!("; the attempt lapses at {}", e.format("%H:%M UTC")))
                    .unwrap_or_default();
                lines.push(Line::from(dim(format!(
                    "    Waiting for {} to confirm — checking every {}s{expiry}.",
                    link.forge,
                    git_ns::LINK_POLL_INTERVAL.as_secs()
                ))));
            }
            LinkPhase::Linked { login, .. } => lines.push(Line::from(vec![
                Span::styled("    ✓ ", Style::default().fg(COLOR_SUCCESS)),
                text(format!(
                    "Linked @{} on {}.",
                    sanitize_display(login, 100),
                    link.forge
                )),
                dim("  d dismiss"),
            ])),
            LinkPhase::Expired => lines.push(Line::from(vec![
                Span::styled("    ✗ ", Style::default().fg(COLOR_ORANGE)),
                text("The link attempt lapsed before it was authorised."),
                dim("  l try again · d dismiss"),
            ])),
            LinkPhase::Failed(why) => {
                error(lines, why);
                lines.push(Line::from(dim("    l try again · d dismiss")));
            }
        }
    }
}

fn wrapped(lines: &mut Vec<Line<'static>>, glyph: &str, color: Color, line: &str) {
    let parts = super::status::wrap_text(
        line,
        super::status::content_width().saturating_sub(8).max(20),
    );
    for (i, part) in parts.into_iter().enumerate() {
        let lead = if i == 0 {
            format!("    {glyph} ")
        } else {
            "      ".into()
        };
        lines.push(Line::from(vec![
            Span::styled(lead, Style::default().fg(color)),
            text(part),
        ]));
    }
}

/// A fix on a line of its own: a command broken across a wrap can be neither
/// read in one pass nor selected in one drag.
fn fix(lines: &mut Vec<Line<'static>>, what: &str) {
    lines.push(Line::from(vec![
        dim("      fix: "),
        Span::styled(what.to_string(), Style::default().fg(COLOR_ORANGE).bold()),
    ]));
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Info | Severity::Progress => COLOR_DARK_GRAY,
        Severity::Success => COLOR_SUCCESS,
        Severity::Warning => COLOR_ORANGE,
        Severity::Error => COLOR_WARNING_ACCESSIBLE_RED,
    }
}

/// The list's "this machine" cell.
fn local_summary(view: &ReposView, resource: &str) -> Span<'static> {
    let (label, severity) = repos_workspace::summary(view, resource);
    Span::styled(label, Style::default().fg(severity_color(severity)))
}

/// Where a checkout is and what state it is in, in one line.
fn checkout_brief(facts: &CheckoutFacts) -> String {
    let mut parts = vec![sanitize_display(
        &git_workspace::display_path(&facts.path),
        512,
    )];
    if facts.is_repo {
        parts.push(match &facts.branch {
            Some(b) => sanitize_display(b, 128),
            None => "detached HEAD".into(),
        });
        if facts.upstream && (facts.ahead > 0 || facts.behind > 0) {
            parts.push(format!("↑{} ↓{}", facts.ahead, facts.behind));
        }
        if facts.changed > 0 {
            parts.push(format!("{} changed", facts.changed));
        }
    }
    parts.join(" · ")
}

fn hook_line(health: &SignerHealth) -> Option<(&'static str, Color, String, Option<&'static str>)> {
    let at = health
        .hook_path
        .as_deref()
        .map(|p| format!(" ({})", sanitize_display(p, 512)))
        .unwrap_or_default();
    Some(match &health.hook {
        HookHealth::Current { version } => (
            "●",
            COLOR_SUCCESS,
            format!("commit-msg hook v{version}: writes the Signed-by-DID claim CI checks"),
            None,
        ),
        HookHealth::Outdated { installed, current } => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!(
                "commit-msg hook OUTDATED (v{installed}, current v{current}){at}. Older hooks put \
                 the Signed-by-DID claim above any `---` line, where verify-trust does not read \
                 it, and those commits fail."
            ),
            Some("s rewrites the hook"),
        ),
        HookHealth::Newer { installed, current } => (
            "●",
            COLOR_SOFT_PURPLE,
            format!(
                "commit-msg hook v{installed} is newer than this openvtc knows (v{current}) — \
                 fine if did-git-sign was upgraded"
            ),
            None,
        ),
        HookHealth::Foreign => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!(
                "the commit-msg hook{at} is not did-git-sign's, so nothing writes the \
                 Signed-by-DID claim."
            ),
            Some("s rewrites the hook"),
        ),
        // Before anything is set up, the missing hook is not news.
        HookHealth::Missing if !health.identity.any() => return None,
        HookHealth::Missing => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!("no commit-msg hook{at}, so no Signed-by-DID claim is written."),
            Some("s writes the hook"),
        ),
        HookHealth::NowhereToLook => (
            "○",
            COLOR_ORANGE,
            "no config directory to find did-git-sign's hook in".into(),
            None,
        ),
    })
}

fn render_signing(lines: &mut Vec<Line<'static>>, view: &ReposView) {
    heading(lines, "Commit signing");
    let ws = &view.workspace;
    let signer = match &ws.signer {
        None => {
            lines.push(Line::from(dim("    … reading this persona's signing key")));
            return;
        }
        Some(Err(e)) => {
            wrapped(lines, "○", COLOR_ORANGE, &sanitize_display(e, 512));
            return;
        }
        Some(Ok(signer)) => signer,
    };
    let Some(health) = &ws.health else {
        lines.push(Line::from(dim("    … checking did-git-sign")));
        return;
    };
    let id = &health.identity;
    if id.ready() {
        wrapped(
            lines,
            "●",
            COLOR_SUCCESS,
            &format!(
                "Signs as {} (profile '{}') — {}",
                sanitize_display(&signer.label, 64),
                sanitize_display(id.profile.as_deref().unwrap_or_default(), 64),
                shorten_did(&signer.did_key_id, 56)
            ),
        );
    } else if id.any() {
        wrapped(
            lines,
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            &format!(
                "did-git-sign's identity for this persona is incomplete ({}).",
                match (&id.profile, &id.credential_did, &id.include) {
                    (_, None, _) => "no credential in the keyring",
                    (None, _, _) => "no profile names it",
                    (_, _, None) => "its signing settings are missing",
                    _ => "unknown",
                }
            ),
        );
        fix(lines, "s sets it up again");
    } else {
        wrapped(
            lines,
            "○",
            COLOR_ORANGE,
            &format!(
                "did-git-sign is not set up for {}. s sets it up — openvtc grants it a \
                 credential that can use this persona's key and nothing else. Cloning (c) or \
                 signing a checkout (e) does it for you.",
                sanitize_display(&signer.label, 64)
            ),
        );
    }
    match &health.binary {
        BinaryStatus::Found { version } => wrapped(
            lines,
            "●",
            COLOR_SUCCESS,
            &format!("did-git-sign {} on PATH", sanitize_display(version, 32)),
        ),
        BinaryStatus::TooOld { version } => {
            wrapped(
                lines,
                "▲",
                COLOR_WARNING_ACCESSIBLE_RED,
                &format!(
                    "did-git-sign {} is too old to be managed from here (needs {}.{} or later).",
                    sanitize_display(version, 32),
                    MIN_BINARY.0,
                    MIN_BINARY.1
                ),
            );
            fix(lines, "cargo install did-git-sign");
        }
        BinaryStatus::Missing => {
            wrapped(
                lines,
                "▲",
                COLOR_WARNING_ACCESSIBLE_RED,
                "did-git-sign is not on PATH, and git runs it to sign every commit.",
            );
            fix(lines, "cargo install did-git-sign");
        }
    }
    if let Some((glyph, color, line, remedy)) = hook_line(health) {
        wrapped(lines, glyph, color, &line);
        if let Some(remedy) = remedy {
            fix(lines, remedy);
        }
    }
    // The protocol for the highlighted repository's forge, when there is one.
    let (protocol, source) = repos_workspace::target(view)
        .and_then(|r| RepoCoords::parse(&r).ok())
        .map_or_else(
            || {
                git_workspace::effective_protocol(
                    ws.settings.protocol,
                    &ForgeCredential::GitDefault,
                    None,
                )
            },
            |c| ws.protocol_for(&view.vtc_did, &c),
        );
    lines.push(Line::from(dim(format!(
        "    Checkouts go under {}, cloned over {}{} — w to change.",
        sanitize_display(&git_workspace::display_path(&ws.settings.root), 512),
        protocol.label(),
        source.note()
    ))));
}

/// The local keys that apply to the highlighted or open repository.
fn local_hints(lines: &mut Vec<Line<'static>>, view: &ReposView) {
    let ws = &view.workspace;
    let target = repos_workspace::target(view);
    let checkout = target.as_ref().and_then(|r| ws.checkouts.get(r));
    let mut keys = Vec::new();
    match checkout {
        None if target.is_some() => keys.extend(["c clone", "u use existing"]),
        None => {}
        Some(c) => {
            if ws.signs_as_me(c) != Some(true) {
                keys.push("e sign here");
            }
            if !matches!(c.signing, CheckoutSigning::Off) {
                keys.push("E stop signing");
            }
            keys.push("p copy path");
        }
    }
    keys.push("s set up signing");
    if ws.health.as_ref().is_some_and(|h| h.identity.any()) {
        keys.push("S remove");
    }
    if let Some(t) = &target {
        keys.push("f forge account");
        if ws.push_access.get(t).is_some_and(|(_, can)| !can) {
            keys.push("F fork");
        }
        if checkout.is_some_and(|c| push_needs_username(view, t, &c.facts)) {
            keys.push("R remotes to SSH");
        }
    }
    keys.push("w workspace");
    lines.push(Line::from(dim(format!("    {}", keys.join("   ")))));
}

/// Whether `git push` in this checkout would stop at "Username for
/// 'https://…'": it pushes over HTTPS, no credential helper applies, and no
/// gh account is chosen for it.
fn push_needs_username(view: &ReposView, resource: &str, facts: &CheckoutFacts) -> bool {
    let Ok(coords) = RepoCoords::parse(resource) else {
        return false;
    };
    facts.is_repo
        && facts.https_push_without_helper(&coords.host)
        && view
            .workspace
            .settings
            .credential_for(&view.vtc_did, &coords)
            .credential
            .gh_login()
            .is_none()
}

/// `HEAD`, and whether it would pass `verify-trust` as this persona.
fn head_line(view: &ReposView, facts: &CheckoutFacts) -> Option<(&'static str, Color, String)> {
    let head = facts.head.as_ref()?;
    let me = view.workspace.did_key_id();
    let subject = sanitize_display(&head.subject, 72);
    let commit = format!("HEAD {} {subject}", sanitize_display(&head.short, 16));
    let claim = head.signed_by_did.as_deref();
    Some(match (head.signature, claim) {
        ('N', _) => ("○", COLOR_ORANGE, format!("{commit} — not signed")),
        ('B', _) => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!("{commit} — BAD signature"),
        ),
        (_, None) => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!("{commit} — signed, but carries no Signed-by-DID claim (CI: noSignerDid)"),
        ),
        (_, Some(c)) if Some(c) == me => ("●", COLOR_SUCCESS, format!("{commit} — signed as you")),
        (_, Some(c)) => (
            "▲",
            COLOR_ORANGE,
            format!("{commit} — signed as {}", shorten_did(c, 48)),
        ),
    })
}

/// Which forge account the repository uses, where that was chosen, and —
/// for a checkout — whether the checkout itself has it.
fn account_line(
    lines: &mut Vec<Line<'static>>,
    view: &ReposView,
    resource: &str,
    linked: &[LinkedAccount],
) {
    let Ok(coords) = RepoCoords::parse(resource) else {
        return;
    };
    let ws = &view.workspace;
    let choice = ws.settings.credential_for(&view.vtc_did, &coords);
    let from = match choice.scope {
        Some(CredentialScope::Repo) => " (this repository's choice)".to_string(),
        Some(CredentialScope::Forge) => format!(" (this community's choice for {})", coords.host),
        None => " (nothing chosen — your git config, credential helpers and ssh-agent)".into(),
    };
    lines.push(Line::from(vec![
        dim("    forge account: "),
        text(sanitize_display(&choice.credential.label(), 256)),
        dim(from),
    ]));
    if let Some(login) = choice.credential.gh_login() {
        // The community's bridge closes pull requests from an account not
        // linked to a member.
        match view.linked_on(linked, &coords.host) {
            Some(account) if !account.login.eq_ignore_ascii_case(login) => wrapped(
                lines,
                "▲",
                COLOR_ORANGE,
                &format!(
                    "This membership is linked to {}, not {login}: pull requests from {login} \
                     will be closed by the community unless it is linked — press l to link it.",
                    sanitize_display(&account.login, 100)
                ),
            ),
            Some(_) => {}
            None => lines.push(Line::from(dim(format!(
                "      The community accepts pull requests only from a linked account; l \
                 links {login}."
            )))),
        }
        if let Some((who, false)) = ws.push_access.get(resource)
            && who == login
        {
            wrapped(
                lines,
                "▲",
                COLOR_ORANGE,
                &format!(
                    "{login} can read {} but not push to it, so a push here is refused. F \
                     forks it to {login} and sends pushes there; open the pull request from \
                     {login}:<branch>.",
                    git_ns::short_resource(resource)
                ),
            );
        }
    }
    let Some(facts) = ws.checkouts.get(resource).map(|c| &c.facts) else {
        return;
    };
    if !facts.is_repo {
        return;
    }
    if facts.author_name.is_some() || facts.author_email.is_some() {
        lines.push(Line::from(vec![
            dim("    commits authored as: "),
            text(format!(
                "{} <{}>",
                sanitize_display(facts.author_name.as_deref().unwrap_or("?"), 128),
                sanitize_display(facts.author_email.as_deref().unwrap_or("?"), 256)
            )),
        ]));
    }
    let applied = facts
        .credential
        .clone()
        .unwrap_or(ForgeCredential::GitDefault);
    if !applied.same_account(&choice.credential) {
        wrapped(
            lines,
            "▲",
            COLOR_ORANGE,
            &format!(
                "This checkout is set to {}. f, then ⏎, writes the choice into it.",
                sanitize_display(&applied.label(), 256)
            ),
        );
    }
}

/// A repository's checkout on this machine, on its own screen.
fn render_local(
    lines: &mut Vec<Line<'static>>,
    view: &ReposView,
    resource: &str,
    linked: &[LinkedAccount],
) {
    heading(lines, "On this machine");
    account_line(lines, view, resource, linked);
    let ws = &view.workspace;
    let Some(checkout) = ws.checkouts.get(resource) else {
        let coords = RepoCoords::parse(resource).ok();
        let dest = coords
            .as_ref()
            .map(|c| git_workspace::display_path(&c.default_path(&ws.settings.root)))
            .unwrap_or_default();
        // The account decides the protocol (a gh token is HTTPS, a key SSH),
        // then `w`, then gh's setting.
        let (protocol, source) = coords.as_ref().map_or_else(
            || {
                git_workspace::effective_protocol(
                    ws.settings.protocol,
                    &ForgeCredential::GitDefault,
                    None,
                )
            },
            |c| ws.protocol_for(&view.vtc_did, c),
        );
        wrapped(
            lines,
            "○",
            COLOR_DARK_GRAY,
            &format!(
                "Not checked out here. c clones it into {} over {}{} and makes it sign as you; \
                 u uses a checkout you already have.",
                sanitize_display(&dest, 512),
                protocol.label(),
                source.note()
            ),
        );
        if let Some(warning) = coords
            .as_ref()
            .and_then(|c| ws.https_clone_warning(&view.vtc_did, c))
        {
            wrapped(lines, "▲", COLOR_ORANGE, &warning);
        }
        return;
    };
    let CheckoutView { facts, signing } = checkout;
    lines.push(Line::from(vec![dim("    "), text(checkout_brief(facts))]));
    if !facts.is_repo {
        wrapped(
            lines,
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            "This is not a git checkout.",
        );
        return;
    }
    if !facts.origin_matches {
        wrapped(
            lines,
            "▲",
            COLOR_ORANGE,
            &match &facts.origin {
                Some(o) => format!(
                    "origin is {}, not this repository.",
                    sanitize_display(o, 256)
                ),
                None => "no origin remote.".into(),
            },
        );
    }
    if push_needs_username(view, resource, facts) {
        let host = RepoCoords::parse(resource)
            .map(|c| c.host)
            .unwrap_or_default();
        wrapped(
            lines,
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            &format!("git will ask for a username when you push: no credential helper for {host}."),
        );
        fix(
            lines,
            "f chooses an account (a gh account or an SSH key), or R switches this checkout's \
             remotes to SSH",
        );
    }
    match (signing, ws.signs_as_me(checkout)) {
        (CheckoutSigning::On { here, .. }, Some(true)) => wrapped(
            lines,
            "●",
            COLOR_SUCCESS,
            &format!(
                "Commits are signed as you{}",
                if *here {
                    ""
                } else {
                    " (through a directory or global setting)"
                }
            ),
        ),
        (
            CheckoutSigning::On {
                did_key_id,
                profile,
                ..
            },
            _,
        ) => {
            wrapped(
                lines,
                "▲",
                COLOR_WARNING_ACCESSIBLE_RED,
                &format!(
                    "Commits are signed as {}{} — not this community's persona, so CI refuses \
                     them.",
                    shorten_did(did_key_id, 48),
                    profile
                        .as_deref()
                        .map(|p| format!(" (profile '{}')", sanitize_display(p, 64)))
                        .unwrap_or_default()
                ),
            );
            fix(lines, "e signs here as you");
        }
        (CheckoutSigning::NoClaim { hooks_path, .. }, _) => {
            wrapped(
                lines,
                "▲",
                COLOR_WARNING_ACCESSIBLE_RED,
                &format!(
                    "Signed, but core.hooksPath is {}, so did-git-sign's hook never runs and no \
                     Signed-by-DID claim is written.",
                    sanitize_display(hooks_path, 256)
                ),
            );
        }
        (CheckoutSigning::Off, _) => {
            wrapped(
                lines,
                "○",
                COLOR_ORANGE,
                "Commits here are not signed by did-git-sign; the community's check refuses them.",
            );
            fix(lines, "e signs here as you");
        }
    }
    if let Some((glyph, color, line)) = head_line(view, facts) {
        wrapped(lines, glyph, color, &line);
    }
}

/// The workspace overlays: a form, or an armed removal.
fn render_workspace_overlay(lines: &mut Vec<Line<'static>>, view: &ReposView) {
    match &view.workspace.form {
        Some(WorkspaceForm::Settings {
            root,
            protocol,
            error: why,
        }) => {
            heading(lines, "Workspace");
            field_label(lines, "Clone repositories under", true);
            input(lines, root, true, "~/src");
            lines.push(Line::from(vec![
                dim("      protocol: "),
                text(protocol.map_or("automatic", |p| p.label())),
                dim(match protocol {
                    None => "  (the forge account's, else your gh setting, else HTTPS)",
                    Some(git_workspace::CloneProtocol::Https) => {
                        "  (a push needs a git credential helper)"
                    }
                    Some(git_workspace::CloneProtocol::Ssh) => {
                        "  (uses the SSH key your forge account knows, from ssh-agent)"
                    }
                }),
            ]));
            lines.push(Line::from(dim(
                "      Each repository goes in <dir>/<forge>/<owner>/<repo>.",
            )));
            if let Some(why) = why {
                error(lines, why);
            }
            hints(lines, "⏎ save   Tab automatic/HTTPS/SSH   Esc cancel");
        }
        Some(WorkspaceForm::Account(form)) => render_account_form(lines, form),
        Some(WorkspaceForm::UsePath {
            resource,
            path,
            error: why,
        }) => {
            heading(
                lines,
                &format!(
                    "Use an existing checkout of {}",
                    git_ns::short_resource(resource)
                ),
            );
            field_label(lines, "Path", true);
            input(lines, path, true, "~/code/widgets");
            lines.push(Line::from(dim(
                "      Its origin must be this repository. It is remembered, and set to sign as you.",
            )));
            if let Some(why) = why {
                error(lines, why);
            }
            hints(lines, "⏎ use   Esc cancel");
        }
        None => {}
    }
    if let Some(WorkspaceChange::RemoveIdentity) = &view.workspace.confirm {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "    Remove did-git-sign's identity for this persona? Checkouts using it stop \
             signing, and its credential is revoked at the VTA.",
            Style::default().fg(COLOR_ORANGE).bold(),
        )));
        lines.push(Line::from(dim("    y confirm · any other key cancels")));
    }
}

/// One row of the forge-account picker, in words.
fn account_option_label(form: &AccountForm, option: &AccountOption) -> String {
    match option {
        AccountOption::Inherit => format!(
            "Same as this community's choice for {} (now: {})",
            form.forge,
            form.forge_choice.label()
        ),
        AccountOption::GitDefault => {
            "Git default — your git config, credential helpers and ssh-agent".into()
        }
        AccountOption::Gh { login, active } => format!(
            "gh account {login}{}",
            if *active {
                " (gh's active account)"
            } else {
                ""
            }
        ),
        AccountOption::SshKey(path) => format!("SSH key {}", git_workspace::display_path(path)),
        AccountOption::EnterPath => "Another SSH key (type its path)".into(),
    }
}

/// `f`: pick the forge account.
fn render_account_form(lines: &mut Vec<Line<'static>>, form: &AccountForm) {
    heading(
        lines,
        &format!(
            "Forge account for {}",
            match form.scope {
                CredentialScope::Repo => git_ns::short_resource(&form.resource).to_string(),
                CredentialScope::Forge =>
                    format!("every {} repository of this community", form.forge),
            }
        ),
    );
    lines.push(Line::from(dim(
        "      Used for clone, fetch and push. Commit signing is separate (did-git-sign).",
    )));
    for (i, option) in form.visible().into_iter().enumerate() {
        let picked = i == form.pick;
        lines.push(Line::from(Span::styled(
            format!(
                "    {} {}",
                if picked { "▸" } else { " " },
                sanitize_display(&account_option_label(form, option), 256)
            ),
            if picked {
                Style::default().fg(COLOR_SUCCESS).bold()
            } else {
                Style::default().fg(COLOR_TEXT_DEFAULT)
            },
        )));
        if picked && *option == AccountOption::EnterPath {
            input(lines, &form.path, true, "~/.ssh/id_ed25519_work");
        }
        if let (true, AccountOption::Gh { login, .. }) = (picked, option) {
            lines.push(Line::from(dim(if form.keep_author {
                format!("        commits keep your own git identity (a: author them as {login})")
            } else {
                format!(
                    "        commits are authored as {login} <id+{login}@users.noreply…> \
                     (a: keep your own identity)"
                )
            })));
        }
    }
    if let Some(note) = &form.gh_note {
        lines.push(Line::from(dim(format!(
            "      {}",
            sanitize_display(note, 256)
        ))));
    }
    if let Some(why) = &form.error {
        error(lines, why);
    }
    hints(
        lines,
        &format!(
            "↑↓ choose   Tab {}   ⏎ save and apply   Esc cancel",
            match form.scope {
                CredentialScope::Repo => format!("all of {} in this community", form.forge),
                CredentialScope::Forge => "this repository only".to_string(),
            }
        ),
    );
}

// ****************************************************************************
// One repository
// ****************************************************************************

fn render_repo(
    lines: &mut Vec<Line<'static>>,
    view: &ReposView,
    resource: &str,
    linked: &[LinkedAccount],
) {
    let Some(repo) = view.repo(resource) else {
        lines.push(Line::from(""));
        lines.push(Line::from(dim(format!(
            "    The community's view has no {resource} — r to refresh."
        ))));
        hints(lines, "r refresh   Esc back");
        return;
    };
    let status = RepoStatus::of(repo);
    lines.push(Line::from(vec![
        dim(format!("    {resource} · {} · ", repo.visibility)),
        Span::styled(status.label(), status_style(&status)),
        dim(match view.my_right(resource) {
            Some(r) => format!(" · you: {}", r.label()),
            None => String::new(),
        }),
    ]));

    render_local(lines, view, resource, linked);

    // Creation, while it runs: the §5.3 steps as the record reports them.
    if matches!(status, RepoStatus::Creating { .. }) {
        heading(lines, "Setting up");
        for (step, done) in git_ns::creation_steps(repo) {
            lines.push(Line::from(if done {
                vec![
                    Span::styled("    ✓ ", Style::default().fg(COLOR_SUCCESS)),
                    text(step),
                ]
            } else {
                vec![dim("    ○ "), dim(step)]
            }));
        }
        if let Some(created) = view.created.as_ref().filter(|c| c.resource == resource)
            && !created.manual_steps.is_empty()
        {
            heading(lines, "Steps to take by hand");
            for (i, step) in created.manual_steps.iter().enumerate() {
                push_status(
                    lines,
                    &Status {
                        text: format!("{}. {}", i + 1, sanitize_display(step, 1024)),
                        severity: Severity::Info,
                    },
                );
            }
        } else {
            lines.push(Line::from(dim(
                "    Safe to leave this screen: the repo is listed as creating until every step \
                 is done.",
            )));
        }
    }

    heading(lines, "People");
    let people = view.people(resource);
    lines.push(Line::from(dim(format!(
        "      {:<34}{:<14}{}",
        "PERSON", "RIGHT", "GRANTED"
    ))));
    for (i, p) in people.iter().enumerate() {
        let selected = i == view.selected && view.add.is_none();
        let name_style = if selected {
            Style::default().fg(COLOR_SUCCESS).bold()
        } else {
            Style::default().fg(COLOR_TEXT_DEFAULT)
        };
        let mut granted = match (&p.granted_by, &p.granted_at) {
            (Some(by), Some(at)) => {
                format!("{} · {}", shorten_did(&view.name_of(by), 24), date(at))
            }
            _ => "owner record not visible to you".into(),
        };
        if let Some(e) = &p.expires_at {
            granted.push_str(&format!(" · expires {}", date(e)));
        }
        if p.namespace_wide {
            granted.push_str(" · namespace-wide");
        }
        let mut row = vec![
            Span::raw(if selected { "    ▸ " } else { "      " }),
            Span::styled(
                format!("{:<34}", shorten_did(&view.name_of(&p.did), 32)),
                name_style,
            ),
            text(format!("{:<14}", p.right.label())),
            dim(granted),
        ];
        if let Some(bg) = p.break_glass {
            row.push(Span::styled(
                format!(" · {}", bg.label()),
                match bg {
                    BreakGlassState::Unratified => {
                        Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold()
                    }
                    BreakGlassState::Ratified => Style::default().fg(COLOR_DARK_GRAY),
                },
            ));
        }
        lines.push(Line::from(row));
        if selected && let Some(reason) = &p.reason {
            lines.push(Line::from(dim(format!(
                "        reason: {}",
                sanitize_display(reason, 1024)
            ))));
        }
    }

    // Drift after the people, so the highlight runs on from the last person
    // into it (↓), in the order the view reported it.
    let drift = view.drift(resource);
    if !drift.is_empty() {
        heading(lines, "Drift from the forge");
        for (i, d) in drift.iter().enumerate() {
            let selected = people.len() + i == view.selected && view.add.is_none();
            let observed = d
                .observed
                .as_ref()
                .map(|o| format!(" · forge shows {}", sanitize_display(o, 256)))
                .unwrap_or_default();
            let expected = d
                .expected
                .as_ref()
                .map(|e| format!(" · rights call for {}", sanitize_display(e, 256)))
                .unwrap_or_default();
            lines.push(Line::from(vec![
                Span::raw(if selected { "    ▸ " } else { "      " }),
                Span::styled("▲ ", Style::default().fg(COLOR_ORANGE)),
                Span::styled(
                    format!("{}{observed}{expected}", d.describe()),
                    if selected {
                        Style::default().fg(COLOR_SUCCESS).bold()
                    } else {
                        Style::default().fg(COLOR_TEXT_DEFAULT)
                    },
                ),
            ]));
        }
        lines.push(Line::from(dim(if view.governs(resource) {
            "      v reverts the highlighted item (the bridge re-applies the community's rights). \
             Adopting a forge role as a right names the member who linked the account, which \
             this panel cannot see: do it from the admin console or cnm."
        } else {
            "      An owner of this repository or a namespace admin reverts or adopts drift."
        })));
    }

    if let Some(form) = &view.add {
        render_add(lines, view, form);
        return;
    }
    if view.workspace.form.is_some() {
        return;
    }
    let keys = if view.governs(resource) && !drift.is_empty() {
        "↑/↓ navigate   a add   x revoke   t transfer   A archive   v revert drift   l link account   r refresh   Esc back"
    } else if view.governs(resource) {
        "↑/↓ navigate   a add   x revoke   t transfer   A archive   l link account   r refresh   Esc back"
    } else {
        "↑/↓ navigate   x resign your right   l link account   r refresh   Esc back"
    };
    hints(lines, keys);
    local_hints(lines, view);
}

fn field_label(lines: &mut Vec<Line<'static>>, label: &str, focused: bool) {
    lines.push(Line::from(Span::styled(
        format!("    {} {label}", if focused { "▸" } else { " " }),
        if focused {
            Style::default().fg(COLOR_SUCCESS).bold()
        } else {
            Style::default().fg(COLOR_DARK_GRAY)
        },
    )));
}

fn input(lines: &mut Vec<Line<'static>>, value: &str, focused: bool, placeholder: &str) {
    let shown = if value.is_empty() {
        dim(placeholder.to_string())
    } else {
        text(value.to_string())
    };
    lines.push(Line::from(vec![
        Span::raw("        "),
        shown,
        Span::raw(if focused { "▏" } else { "" }),
    ]));
}

fn render_add(lines: &mut Vec<Line<'static>>, view: &ReposView, form: &AddPersonForm) {
    heading(
        lines,
        &format!("Add person to {}", git_ns::short_resource(&form.resource)),
    );
    // Person
    if form.external {
        field_label(lines, "DID of someone not listed", form.field == 0);
        input(lines, &form.query, form.field == 0, "did:…");
        lines.push(Line::from(dim(
            "        An outside contributor may hold a repository right only if the community's \
             policy allows it; the community says so if it does not.   Ctrl+D pick from people",
        )));
    } else {
        field_label(lines, "Person", form.field == 0);
        input(lines, &form.query, form.field == 0, "type to filter");
        let candidates = view.candidates(&form.query);
        if candidates.is_empty() {
            lines.push(Line::from(dim(
                "        nobody you can see matches — Ctrl+D to paste a DID",
            )));
        }
        for (i, did) in candidates.iter().enumerate().take(6) {
            let picked = i == form.pick;
            let name = view.name_of(did);
            let label = if name == *did {
                shorten_did(did, 56)
            } else {
                format!("{name}  {}", shorten_did(did, 40))
            };
            lines.push(Line::from(vec![
                Span::raw(if picked { "      ▸ " } else { "        " }),
                Span::styled(
                    label,
                    if picked {
                        Style::default().fg(COLOR_SUCCESS)
                    } else {
                        Style::default().fg(COLOR_TEXT_DEFAULT)
                    },
                ),
            ]));
        }
        lines.push(Line::from(dim(
            "        Ctrl+D: paste a DID for an external signer (if community policy allows)",
        )));
    }
    // Right
    field_label(lines, "Right", form.field == 1);
    for (i, right) in GitRight::REPO_RIGHTS.iter().enumerate() {
        let on = i == form.right;
        let mut spans = vec![
            Span::styled(
                if on { "        (●) " } else { "        ( ) " },
                Style::default().fg(if on { COLOR_SUCCESS } else { COLOR_DARK_GRAY }),
            ),
            text(format!("{:<12}", right.label())),
            dim(right.meaning()),
        ];
        if *right == GitRight::RepoOwn {
            spans.push(Span::styled(
                " · elevated, asks to confirm",
                Style::default().fg(COLOR_ORANGE),
            ));
        }
        lines.push(Line::from(spans));
    }
    // Expiry
    field_label(lines, "Expires", form.field == 2);
    let choices: Vec<Span<'static>> = EXPIRY_CHOICES
        .iter()
        .enumerate()
        .flat_map(|(i, c)| {
            let label = expiry_label(*c);
            [
                Span::raw(if i == 0 { "        " } else { "   " }),
                if i == form.expiry {
                    Span::styled(format!("[{label}]"), Style::default().fg(COLOR_SUCCESS))
                } else {
                    dim(label)
                },
            ]
        })
        .collect();
    lines.push(Line::from(choices));
    // Reason
    field_label(
        lines,
        "Reason (seen by owners and namespace admins only)",
        form.field == 3,
    );
    input(lines, &form.reason, form.field == 3, "optional");

    let who = if form.external {
        form.query.trim().to_string()
    } else {
        view.candidates(&form.query)
            .get(form.pick)
            .map(|d| view.name_of(d))
            .unwrap_or_else(|| "…".into())
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        dim("    Publishes "),
        text(format!(
            "{} · {} · {}",
            shorten_did(&who, 40),
            form.right().as_str(),
            form.resource
        )),
        dim(" to the Trust Registry (public)."),
    ]));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        push_status(lines, err);
    }
    hints(lines, "Tab next field   ↑/↓ choose   ⏎ grant   Esc cancel");
}

// ****************************************************************************
// New repository
// ****************************************************************************

fn render_new(lines: &mut Vec<Line<'static>>, view: &ReposView, form: &NewRepoForm) {
    heading(lines, "New repository");
    let creatable = view.creatable();
    field_label(lines, "Namespace", form.field == 0);
    let ns = creatable.get(form.namespace);
    lines.push(Line::from(vec![
        Span::raw("        "),
        text(
            ns.map(|c| git_ns::namespace_resource(&c.namespace))
                .unwrap_or_default(),
        ),
        dim(ns
            .and_then(|c| c.namespace.kind.as_ref())
            .map(|k| format!("  ({k})"))
            .unwrap_or_default()),
        dim(if creatable.len() > 1 {
            format!("   ←/→ {} of {}", form.namespace + 1, creatable.len())
        } else {
            String::new()
        }),
    ]));
    let manual = ns.is_some_and(|c| git_ns::is_manual(&c.namespace));
    if manual {
        lines.push(Line::from(Span::styled(
            "        No bot can create repositories here (a manual namespace or a personal \
             account). The name is reserved, and the community answers with the steps to take \
             — create it, run `vgi repo init`, then adopt it.",
            Style::default().fg(COLOR_ORANGE),
        )));
    }
    field_label(lines, "Name", form.field == 1);
    input(
        lines,
        &form.name,
        form.field == 1,
        "lowercase, e.g. gadgets",
    );
    field_label(lines, "Visibility", form.field == 2);
    let public = form.visibility == git_ns::Visibility::Public;
    lines.push(Line::from(vec![
        Span::styled(
            if public {
                "        (●) "
            } else {
                "        ( ) "
            },
            Style::default().fg(if public {
                COLOR_SUCCESS
            } else {
                COLOR_DARK_GRAY
            }),
        ),
        text("public   "),
        Span::styled(
            if public { "( ) " } else { "(●) " },
            Style::default().fg(if public {
                COLOR_DARK_GRAY
            } else {
                COLOR_SUCCESS
            }),
        ),
        text("private"),
    ]));
    field_label(
        lines,
        "Description (the forge shows it publicly)",
        form.field == 3,
    );
    input(lines, &form.description, form.field == 3, "optional");
    field_label(lines, "Owners (besides you)", form.field == 4);
    if form.owners.is_empty() {
        lines.push(Line::from(dim(
            "        none — you alone become owner (only if you already hold repo creator by \
             grant, not only by namespace admin)",
        )));
    } else {
        let named = form
            .owners
            .iter()
            .map(|d| view.name_of(d))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(Line::from(vec![Span::raw("        "), text(named)]));
    }
    if form.field == 4 {
        if form.owner_external {
            input(
                lines,
                &form.owner_query,
                true,
                "did:… — Ctrl+A add, Ctrl+D pick from people",
            );
        } else {
            input(lines, &form.owner_query, true, "type to filter, Ctrl+A add");
            let candidates = view.candidates(&form.owner_query);
            if candidates.is_empty() {
                lines.push(Line::from(dim(
                    "        nobody you can see matches — Ctrl+D to paste a DID",
                )));
            }
            for (i, did) in candidates.iter().enumerate().take(6) {
                let picked = i == form.owner_pick;
                let name = view.name_of(did);
                let label = if name == *did {
                    shorten_did(did, 56)
                } else {
                    format!("{name}  {}", shorten_did(did, 40))
                };
                lines.push(Line::from(vec![
                    Span::raw(if picked { "      ▸ " } else { "        " }),
                    Span::styled(
                        label,
                        if picked {
                            Style::default().fg(COLOR_SUCCESS)
                        } else {
                            Style::default().fg(COLOR_TEXT_DEFAULT)
                        },
                    ),
                ]));
            }
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(dim(if form.owners.is_empty() {
        "    You become owner. Commit trust is on from the first push: the check runs on every \
         pull request, with no bypass."
            .to_string()
    } else {
        format!(
            "    {} become owner — not you, unless you add yourself above too. Commit trust is \
             on from the first push: the check runs on every pull request, with no bypass.",
            form.owners
                .iter()
                .map(|d| view.name_of(d))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })));
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        push_status(lines, err);
    }
    hints(
        lines,
        "Tab next field   ←/→ choose   Ctrl+A add owner   ⏎ create   Esc cancel",
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::state_handler::main_page::repos::{ReposState, Workspace};
    use openvtc_core::config::account::PersonaId;
    use openvtc_core::git_signing::{IdentityStatus, PersonaSigner};
    use openvtc_core::git_workspace::{CloneProtocol, HeadCommit, WorkspaceSettings};
    use serde_json::json;
    use std::sync::Arc;

    const BOB: &str = "did:webvh:QmBobScid2:acme-vtc.example:bob";

    fn rendered(view: ReposView) -> String {
        let state = ContentPanelState {
            repos: ReposState {
                view: Some(view),
                linked: Vec::new(),
            },
            ..Default::default()
        };
        ReposPanel
            .render(&state, &ConnectionState::default())
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn loaded() -> ReposView {
        let mut v = ReposView::new(
            "did:webvh:vtc".into(),
            PersonaId(uuid::Uuid::nil()),
            BOB.into(),
            "Acme".into(),
        );
        v.data = Some(Arc::new(
            serde_json::from_value(json!({
                "accounts": [],
                "namespaces": [{"id": "ns_1", "forge": "github.com", "owner": "acme",
                                "kind": "organization", "mode": "bridge", "state": "bound"}],
                "repos": [{"resource": "github.com/acme/gadgets", "visibility": "public",
                           "state": "pendingCreate", "owners": [BOB],
                           "bootstrap": {"workflow": true, "keyring": true, "variables": false, "requiredCheck": false},
                           "sync": {"state": "pending", "drift": []}}],
                "rights": [{"subject": BOB, "right": "git.repo.create", "resource": "github.com/acme",
                            "grantedBy": BOB, "grantedAt": "2026-09-01T00:00:00Z"}]
            }))
            .unwrap(),
        ));
        v.phase = ReposPhase::Loaded;
        v
    }

    #[test]
    fn my_repos_shows_the_badge_and_creation_progress() {
        let out = rendered(loaded());
        assert!(out.contains("acme/gadgets"), "{out}");
        assert!(out.contains("owner"), "{out}");
        assert!(out.contains("creating 3/6"), "{out}");
        assert!(
            out.contains("You can create repos in github.com/acme"),
            "{out}"
        );
        assert!(out.contains("n new repo"), "{out}");
    }

    const KEY: &str = "did:webvh:QmBobScid2:acme-vtc.example:bob#key-0";

    fn with_workspace(mut v: ReposView, identity: IdentityStatus, hook: HookHealth) -> ReposView {
        v.workspace = Workspace {
            settings: WorkspaceSettings {
                root: "/w".into(),
                protocol: Some(CloneProtocol::Https),
                ..WorkspaceSettings::default()
            },
            signer: Some(Ok(PersonaSigner {
                did_key_id: KEY.into(),
                vta_key_id: "k-1".into(),
                verifying_key: [0; 32],
                context: "openvtc/bob".into(),
                label: "Bob".into(),
            })),
            health: Some(SignerHealth {
                identity,
                binary: BinaryStatus::Found {
                    version: "0.15.1".into(),
                },
                hook,
                hook_path: Some("/home/me/.config/did-git-sign/hooks/commit-msg".into()),
            }),
            ..Workspace::default()
        };
        v
    }

    fn ready() -> IdentityStatus {
        IdentityStatus {
            profile: Some("bob".into()),
            credential_did: Some("did:key:z6Mk".into()),
            include: Some("/home/me/.config/did-git-sign/gitconfig/bob.gitconfig".into()),
            default: true,
        }
    }

    fn checkout(signing: CheckoutSigning, head: Option<HeadCommit>) -> CheckoutView {
        CheckoutView {
            facts: CheckoutFacts {
                path: "/w/github.com/acme/gadgets".into(),
                is_repo: true,
                origin: Some("https://github.com/acme/gadgets.git".into()),
                origin_matches: true,
                branch: Some("main".into()),
                upstream: true,
                ahead: 2,
                changed: 1,
                head,
                ..CheckoutFacts::default()
            },
            signing,
        }
    }

    #[test]
    fn an_outdated_hook_says_s_rewrites_it() {
        let v = with_workspace(
            loaded(),
            ready(),
            HookHealth::Outdated {
                installed: 1,
                current: 2,
            },
        );
        let out = rendered(v);
        assert!(out.contains("Signs as Bob (profile 'bob')"), "{out}");
        assert!(out.contains("did-git-sign 0.15.1 on PATH"), "{out}");
        assert!(out.contains("OUTDATED (v1, current v2)"), "{out}");
        assert!(out.contains("fix: s rewrites the hook"), "{out}");
        assert!(
            out.contains("Checkouts go under /w, cloned over HTTPS"),
            "{out}"
        );
    }

    #[test]
    fn nothing_set_up_says_how_and_hides_the_missing_hook() {
        let out = rendered(with_workspace(
            loaded(),
            IdentityStatus::default(),
            HookHealth::Missing,
        ));
        assert!(
            out.contains("did-git-sign is not set up for Bob. s sets it up"),
            "{out}"
        );
        assert!(!out.contains("no commit-msg hook"), "{out}");
        assert!(!out.contains("S remove"), "{out}");
    }

    #[test]
    fn a_missing_binary_says_how_to_install_it() {
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        if let Some(h) = v.workspace.health.as_mut() {
            h.binary = BinaryStatus::Missing;
        }
        let out = rendered(v);
        assert!(out.contains("not on PATH"), "{out}");
        assert!(out.contains("fix: cargo install did-git-sign"), "{out}");
    }

    #[test]
    fn the_list_says_what_is_on_this_machine() {
        let v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        let out = rendered(v.clone());
        assert!(out.contains("THIS MACHINE"), "{out}");
        assert!(out.contains("not cloned"), "{out}");
        assert!(out.contains("c clone   u use existing"), "{out}");

        let mut cloned = v;
        cloned.workspace.checkouts.insert(
            "github.com/acme/gadgets".into(),
            checkout(
                CheckoutSigning::On {
                    did_key_id: KEY.into(),
                    profile: Some("bob".into()),
                    here: true,
                },
                None,
            ),
        );
        let out = rendered(cloned);
        assert!(out.contains("signed"), "{out}");
        assert!(
            out.contains("/w/github.com/acme/gadgets · main · ↑2 ↓0 · 1 changed"),
            "{out}"
        );
        assert!(out.contains("E stop signing   p copy path"), "{out}");
        assert!(!out.contains("e sign here"), "{out}");
    }

    #[test]
    fn a_repository_shows_its_checkout_and_head() {
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        let out = rendered(v.clone());
        assert!(out.contains("On this machine"), "{out}");
        let dest = std::path::Path::new("/w")
            .join("github.com")
            .join("acme")
            .join("gadgets")
            .display()
            .to_string();
        assert!(out.contains(&format!("c clones it into {dest}")), "{out}");

        v.workspace.checkouts.insert(
            "github.com/acme/gadgets".into(),
            checkout(
                CheckoutSigning::Off,
                Some(HeadCommit {
                    short: "abc1234".into(),
                    subject: "wip".into(),
                    signature: 'G',
                    signed_by_did: None,
                }),
            ),
        );
        let out = rendered(v.clone());
        assert!(out.contains("not signed by did-git-sign"), "{out}");
        assert!(out.contains("fix: e signs here as you"), "{out}");
        assert!(out.contains("noSignerDid"), "{out}");

        v.workspace.checkouts.insert(
            "github.com/acme/gadgets".into(),
            checkout(
                CheckoutSigning::On {
                    did_key_id: KEY.into(),
                    profile: Some("bob".into()),
                    here: true,
                },
                Some(HeadCommit {
                    short: "def5678".into(),
                    subject: "feat: thing".into(),
                    signature: 'G',
                    signed_by_did: Some(KEY.into()),
                }),
            ),
        );
        let out = rendered(v);
        assert!(out.contains("Commits are signed as you"), "{out}");
        assert!(
            out.contains("HEAD def5678 feat: thing — signed as you"),
            "{out}"
        );
    }

    #[test]
    fn another_identity_in_a_checkout_is_called_out() {
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        v.workspace.checkouts.insert(
            "github.com/acme/gadgets".into(),
            checkout(
                CheckoutSigning::On {
                    did_key_id: "did:webvh:other:example#key-0".into(),
                    profile: Some("work".into()),
                    here: false,
                },
                None,
            ),
        );
        let out = rendered(v);
        assert!(out.contains("not this community's persona"), "{out}");
        assert!(out.contains("(profile 'work')"), "{out}");
    }

    #[test]
    fn the_forge_account_is_shown_and_picked() {
        use crate::state_handler::main_page::repos::AccountForm;
        use openvtc_core::forge_credential::GhAccount;
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        let resource = "github.com/acme/gadgets";
        v.screen = ReposScreen::Repo {
            resource: resource.into(),
        };
        let out = rendered(v.clone());
        assert!(out.contains("forge account: git default"), "{out}");
        assert!(out.contains("nothing chosen"), "{out}");

        let coords = RepoCoords::parse(resource).unwrap();
        let vtc = v.vtc_did.clone();
        v.workspace.settings.set_credential(
            &vtc,
            &coords,
            CredentialScope::Forge,
            Some(ForgeCredential::SshKey {
                path: "/k/id_work".into(),
            }),
        );
        let out = rendered(v.clone());
        assert!(out.contains("forge account: SSH key /k/id_work"), "{out}");
        assert!(
            out.contains("this community's choice for github.com"),
            "{out}"
        );
        assert!(out.contains("over SSH"), "a key clones over SSH: {out}");

        // A checkout openvtc set up before the choice changed says so.
        let mut c = checkout(CheckoutSigning::Off, None);
        c.facts.credential = Some(ForgeCredential::gh("alice".into()));
        v.workspace.checkouts.insert(resource.into(), c);
        let out = rendered(v.clone());
        assert!(
            out.contains("This checkout is set to gh account alice"),
            "{out}"
        );
        assert!(out.contains("f forge account"), "{out}");

        v.workspace.form = Some(WorkspaceForm::Account(AccountForm::new(
            resource.into(),
            "github.com".into(),
            None,
            None,
            Ok(vec![GhAccount {
                host: "github.com".into(),
                login: "alice-work".into(),
                active: false,
            }]),
            vec!["/h/.ssh/id_ed25519".into()],
            Some("alice-work"),
        )));
        let out = rendered(v);
        assert!(
            out.contains("Forge account for every github.com repository"),
            "{out}"
        );
        assert!(
            out.contains("▸ gh account alice-work"),
            "preselected: {out}"
        );
        assert!(out.contains("SSH key /h/.ssh/id_ed25519"), "{out}");
        assert!(out.contains("Another SSH key"), "{out}");
        assert!(out.contains("Tab this repository only"), "{out}");
        assert!(out.contains("a: keep your own identity"), "{out}");
    }

    /// A gh account that is not the linked one, cannot push, and authors
    /// commits as itself: each said in words.
    #[test]
    fn a_gh_account_says_who_it_is_to_the_community() {
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        let resource = "github.com/acme/gadgets";
        v.screen = ReposScreen::Repo {
            resource: resource.into(),
        };
        let vtc = v.vtc_did.clone();
        v.workspace.settings.set_credential(
            &vtc,
            &RepoCoords::parse(resource).unwrap(),
            CredentialScope::Repo,
            Some(ForgeCredential::gh("alice-work".into())),
        );
        let render = |v: &ReposView, linked: &[LinkedAccount]| {
            let mut lines = Vec::new();
            render_repo(&mut lines, v, resource, linked);
            lines
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|s| s.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
                // A wrapped line continues on the next, indented.
                .replace("\n      ", " ")
        };
        let out = render(&v, &[]);
        assert!(
            out.contains("only from a linked account; l links alice-work"),
            "{out}"
        );

        let linked = [LinkedAccount {
            vtc_did: vtc.clone(),
            forge: "github.com".into(),
            login: "alice".into(),
            id: "1".into(),
        }];
        let out = render(&v, &linked);
        assert!(
            out.contains("pull requests from alice-work will be closed by the community"),
            "{out}"
        );
        assert!(out.contains("press l to link it"), "{out}");

        let mut c = checkout(CheckoutSigning::Off, None);
        c.facts.author_name = Some("alice-work".into());
        c.facts.author_email = Some("7+alice-work@users.noreply.github.com".into());
        c.facts.credential = Some(ForgeCredential::gh("alice-work".into()));
        v.workspace.checkouts.insert(resource.into(), c);
        v.workspace
            .push_access
            .insert(resource.into(), ("alice-work".into(), false));
        let out = render(&v, &linked);
        assert!(
            out.contains("commits authored as: alice-work <7+alice-work@users.noreply.github.com>"),
            "{out}"
        );
        assert!(
            out.contains("can read acme/gadgets but not push to it"),
            "{out}"
        );
        assert!(out.contains("F fork"), "{out}");
        assert!(!out.contains("This checkout is set to"), "{out}");
    }

    #[test]
    fn the_workspace_forms_and_removal_render() {
        let mut v = with_workspace(loaded(), ready(), HookHealth::Current { version: 2 });
        v.workspace.form = Some(WorkspaceForm::Settings {
            root: "~/code".into(),
            protocol: Some(CloneProtocol::Ssh),
            error: Some("Use an absolute path".into()),
        });
        let out = rendered(v.clone());
        assert!(out.contains("Clone repositories under"), "{out}");
        assert!(out.contains("~/code"), "{out}");
        assert!(out.contains("protocol: SSH"), "{out}");
        assert!(out.contains("Use an absolute path"), "{out}");
        assert!(out.contains("⏎ save"), "{out}");
        assert!(!out.contains("⏎ open"), "a form owns the footer: {out}");

        v.workspace.form = None;
        v.workspace.confirm = Some(WorkspaceChange::RemoveIdentity);
        let out = rendered(v);
        assert!(out.contains("revoked at the VTA"), "{out}");
        assert!(out.contains("y confirm"), "{out}");
    }

    /// Everything the VTC supplies is cleaned before it is drawn: a reason
    /// carrying a bidi override or a zero-width character cannot reorder or
    /// hide what the member reads. A DID carrying one no longer gets this far:
    /// `git-ns/view` 0.4 pins `_shared/0.4`, whose DID-core pattern refuses it
    /// when the answer is parsed (below).
    #[test]
    fn peer_text_is_sanitised_before_it_is_drawn() {
        let evil = "did:webvh:Qm\u{202E}evil\u{200B}:x.example";
        let refused: Result<git_ns::view::RightRecord, _> = serde_json::from_value(json!({
            "subject": evil, "right": "git.commit.sign",
            "resource": "github.com/acme/gadgets",
            "grantedBy": BOB, "grantedAt": "2026-09-01T00:00:00Z"
        }));
        assert!(refused.is_err(), "a DID with a bidi override is not a DID");
        let evil = "did:webvh:QmEvilScid9:x.example";
        let mut v = loaded();
        let mut data = (**v.data.as_ref().unwrap()).clone();
        data.rights.push(
            serde_json::from_value(json!({
                "subject": evil, "right": "git.commit.sign",
                "resource": "github.com/acme/gadgets",
                "grantedBy": BOB, "grantedAt": "2026-09-01T00:00:00Z",
                "reason": "fine\u{202E}enif\u{200D} \u{1b}[31mred"
            }))
            .unwrap(),
        );
        v.data = Some(Arc::new(data));
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        v.selected = 1;
        let out = rendered(v);
        for bad in ['\u{202E}', '\u{200B}', '\u{200D}', '\u{1b}'] {
            assert!(!out.contains(bad), "{bad:?} reached the screen: {out}");
        }
        assert!(out.contains("reason: fineenif"), "{out}");
    }

    /// The colour of a status line comes from its severity.
    #[test]
    fn a_refusal_is_drawn_in_the_error_colour() {
        let mut v = loaded();
        v.note(Severity::Error, "The community refused.");
        let state = ContentPanelState {
            repos: ReposState {
                view: Some(v),
                linked: Vec::new(),
            },
            ..Default::default()
        };
        let lines = ReposPanel.render(&state, &ConnectionState::default());
        let span = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .find(|s| s.content.contains("The community refused."))
            .unwrap();
        assert_eq!(span.style.fg, Some(COLOR_WARNING_ACCESSIBLE_RED));
    }

    #[test]
    fn a_device_flow_shows_the_code() {
        let mut v = loaded();
        let mut link =
            crate::state_handler::main_page::repos::LinkFlow::starting("github.com".into());
        link.phase = LinkPhase::Waiting;
        link.url = Some("https://github.com/login/device".into());
        link.user_code = Some("WDJB-MJHT".into());
        v.link = Some(link);
        let out = rendered(v);
        assert!(out.contains("https://github.com/login/device"), "{out}");
        assert!(out.contains("WDJB-MJHT"), "{out}");
    }

    #[test]
    fn a_repo_being_created_lists_its_steps() {
        let mut v = loaded();
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        let out = rendered(v);
        assert!(out.contains("✓ Name reserved in the community"), "{out}");
        assert!(
            out.contains("○ TRUST_REGISTRY_DID and VTC_DID set"),
            "{out}"
        );
    }

    #[test]
    fn a_manual_namespace_says_so_in_the_form() {
        let mut v = loaded();
        let mut data = (**v.data.as_ref().unwrap()).clone();
        data.namespaces[0].mode = git_ns::view::GitNamespaceMode::Manual;
        v.data = Some(Arc::new(data));
        v.screen = ReposScreen::NewRepo(NewRepoForm::default());
        let out = rendered(v);
        assert!(out.contains("No bot can create repositories here"), "{out}");
    }

    /// With no owners named, the form says the requester alone becomes
    /// owner. Naming one shows them instead — never the requester, who is
    /// not automatically included.
    #[test]
    fn the_new_repo_form_shows_named_owners() {
        const DAN: &str = "did:webvh:QmDanScid4:dan.example";
        let mut v = loaded();
        v.screen = ReposScreen::NewRepo(NewRepoForm::default());
        let out = rendered(v.clone());
        assert!(out.contains("you alone become owner"), "{out}");

        v.screen = ReposScreen::NewRepo(NewRepoForm {
            owners: vec![DAN.into()],
            ..NewRepoForm::default()
        });
        let out = rendered(v);
        assert!(out.contains(DAN), "{out}");
        assert!(out.contains("become owner"), "{out}");
        assert!(!out.contains("you alone become owner"), "{out}");
    }

    #[test]
    fn an_owner_sees_drift_as_rows_to_revert_and_where_to_adopt() {
        let mut v = loaded();
        let mut data = serde_json::to_value(&**v.data.as_ref().unwrap()).unwrap();
        data["repos"][0]["state"] = json!("active");
        data["repos"][0]["sync"] = json!({"state": "drift", "drift": [
            {"type": "protectionWeakened", "resource": "github.com/acme/gadgets",
             "observed": "force-push allowed"}
        ]});
        v.data = Some(Arc::new(serde_json::from_value(data).unwrap()));
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        // Bob is the one person; the drift item is the next row.
        v.selected = 1;
        let out = rendered(v);
        assert!(
            out.contains("▸ ▲ protection weakened · forge shows force-push allowed"),
            "{out}"
        );
        assert!(out.contains("v revert drift   l link account"), "{out}");
        assert!(!out.contains("o adopt"), "{out}");
        assert!(out.contains("do it from the admin console or cnm"), "{out}");
    }

    const CAROL: &str = "did:webvh:QmCarolScid3:acme-vtc.example:carol";

    /// `loaded()`, plus Carol's unratified break-glass ownership of
    /// `gadgets`, as `git-ns/view` 0.4 returns it to an administrator.
    fn with_break_glass(me: &str, justification: &str) -> ReposView {
        let mut v = loaded();
        v.me = me.into();
        let mut data = serde_json::to_value(v.data.as_deref().unwrap()).unwrap();
        data["rights"].as_array_mut().unwrap().push(json!({
            "subject": CAROL, "right": "git.repo.own", "resource": "github.com/acme/gadgets",
            "grantedBy": CAROL, "grantedAt": "2026-09-25T02:10:31Z",
            "breakGlass": {"by": CAROL, "at": "2026-09-25T02:10:31Z", "justification": justification}
        }));
        v.data = Some(Arc::new(serde_json::from_value(data).unwrap()));
        v
    }

    #[test]
    fn no_banner_without_a_break_glass() {
        let out = rendered(loaded());
        assert!(!out.contains("BREAK-GLASS"), "{out}");
    }

    #[test]
    fn an_administrator_sees_the_banner_with_the_commands() {
        let out = rendered(with_break_glass(BOB, "CVE fix; owners unreachable"));
        assert!(
            out.contains("BREAK-GLASS — 1 self-granted right awaiting ratification"),
            "{out}"
        );
        assert!(
            out.contains("gave themselves git.repo.own on github.com/acme/gadgets"),
            "{out}"
        );
        assert!(out.contains("why: CVE fix; owners unreachable"), "{out}");
        assert!(out.contains("admin console"), "{out}");
        assert!(
            out.contains(&format!(
                "cnm git ratify --subject={CAROL} --right=git.repo.own \
                 --resource=github.com/acme/gadgets --break-glass-at=2026-09-25T02:10:31Z"
            )),
            "{out}"
        );
        assert!(out.contains("cnm git revoke --subject="), "{out}");
    }

    #[test]
    fn the_subject_is_told_someone_else_must_ratify() {
        let out = rendered(with_break_glass(CAROL, "CVE fix"));
        assert!(out.contains("You gave yourself git.repo.own"), "{out}");
        assert!(!out.contains("cnm git ratify"), "{out}");
        assert!(out.contains("must ratify or revoke it"), "{out}");
    }

    #[test]
    fn the_justification_is_sanitised_before_it_is_drawn() {
        let out = rendered(with_break_glass(BOB, "evil\u{1b}[2Jtext"));
        assert!(!out.contains('\u{1b}'), "{out:?}");
    }

    #[test]
    fn a_repo_view_flags_the_break_glass_right() {
        let mut v = with_break_glass(BOB, "CVE fix");
        v.screen = ReposScreen::Repo {
            resource: "github.com/acme/gadgets".into(),
        };
        let out = rendered(v);
        let row = out
            .lines()
            .find(|l| l.contains("carol") && l.contains(" owner "))
            .unwrap_or_default();
        assert!(row.contains("BREAK-GLASS"), "{out}");
    }
}
