//! Repos panel — a community's git repositories (`git-ns/*`), opened from the
//! Communities panel with `r`.
//!
//! Three screens over one `git-ns/view` answer: *My repos* with the forge
//! account and commit-signing health beside it, one repository's people and
//! rights (or its creation steps), and the new-repository form.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
    COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::content::ContentPanelState;
use crate::state_handler::main_page::repos::{
    AddPersonForm, EXPIRY_CHOICES, HookCheck, HookHealth, HookScope, LinkPhase, LinkedAccount,
    NewRepoForm, ReposPhase, ReposScreen, ReposView, Severity, Status, expiry_label,
};
use crate::state_handler::main_page::{sanitize_display, shorten_did};
use crate::state_handler::state::ConnectionState;
use openvtc_core::git_ns::{self, GitRight, RepoStatus};

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

        match &view.screen {
            ReposScreen::List => render_list(&mut lines, view, &state.repos.linked),
            ReposScreen::Repo { resource } => render_repo(&mut lines, view, resource),
            ReposScreen::NewRepo(form) => render_new(&mut lines, view, form),
        }

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
            "      {:<34}{:<18}{}",
            "REPOSITORY", "MY RIGHT", "STATUS"
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
                Span::styled(repo.status.label(), status_style(&repo.status)),
            ]));
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

    let mut keys = vec!["↑/↓ navigate", "⏎ open"];
    if !view.creatable().is_empty() {
        keys.push("n new repo");
    }
    keys.extend(["l link account", "r refresh", "Esc back"]);
    hints(lines, &keys.join("   "));
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

fn hook_line(check: &HookCheck) -> (&'static str, Color, String, bool) {
    let at = check
        .path
        .as_deref()
        .map(|p| format!(" at {}", sanitize_display(p, 512)))
        .unwrap_or_default();
    let scope = check.scope.label();
    match &check.health {
        HookHealth::Current { version } => (
            "●",
            COLOR_SUCCESS,
            format!("{scope}: commit-msg hook v{version} OK{at}"),
            false,
        ),
        HookHealth::Outdated { installed, current } => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!(
                "{scope}: commit-msg hook OUTDATED (v{installed}, current v{current}){at}. Older \
                 hooks put the Signed-by-DID trailer above any `---` line, where verify-trust \
                 does not read it, and those commits fail."
            ),
            true,
        ),
        HookHealth::Newer { installed, current } => (
            "●",
            COLOR_SOFT_PURPLE,
            format!(
                "{scope}: commit-msg hook v{installed}{at} is newer than this openvtc knows \
                 (v{current}) — fine if did-git-sign was upgraded"
            ),
            false,
        ),
        HookHealth::Foreign => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!(
                "{scope}: the commit-msg hook{at} is not did-git-sign's, so nothing writes the \
                 Signed-by-DID trailer."
            ),
            true,
        ),
        HookHealth::Missing => (
            "▲",
            COLOR_WARNING_ACCESSIBLE_RED,
            format!("{scope}: no commit-msg hook{at}."),
            true,
        ),
        HookHealth::NowhereToLook => (
            "○",
            COLOR_DARK_GRAY,
            match check.scope {
                HookScope::Global => "global: no global core.hooksPath is set".to_string(),
                _ => format!(
                    "{scope}: openvtc was not started in a repository, so there is no \
                     repository hook to check"
                ),
            },
            false,
        ),
        HookHealth::Unknown(why) => (
            "○",
            COLOR_ORANGE,
            format!(
                "{scope}: could not check the commit-msg hook: {}",
                sanitize_display(why, 256)
            ),
            false,
        ),
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

fn render_signing(lines: &mut Vec<Line<'static>>, view: &ReposView) {
    heading(lines, "Commit signing");
    let Some(checked) = &view.signing.checked else {
        lines.push(Line::from(dim("    … checking did-git-sign")));
        return;
    };
    // The install, wherever did-git-sign put it.
    for i in &checked.installs {
        let (glyph, color, what) = if i.this_persona {
            ("●", COLOR_SUCCESS, "did-git-sign set up for this persona")
        } else {
            ("▲", COLOR_ORANGE, "did-git-sign set up for a different key")
        };
        wrapped(
            lines,
            glyph,
            color,
            &format!(
                "{what} ({} config {}) — key {}",
                i.scope,
                sanitize_display(&i.path, 512),
                shorten_did(&i.key_id, 48)
            ),
        );
    }
    if !checked.set_up() {
        wrapped(
            lines,
            "○",
            COLOR_ORANGE,
            &format!(
                "did-git-sign is not set up for this persona (looked in {}). Run `did-git-sign \
                 init` with this persona's DID; commits signed otherwise will not pass the check.",
                if checked.looked.is_empty() {
                    "no config location".to_string()
                } else {
                    checked
                        .looked
                        .iter()
                        .map(|p| sanitize_display(p, 512))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        );
    }
    // The hook at each scope, the worst first; the fix, where there is one,
    // goes on a line of its own: a command broken across a wrap can be neither
    // read in one pass nor selected in one drag.
    let headline = checked.headline();
    let hooks: Vec<&HookCheck> = headline
        .into_iter()
        .chain(
            checked
                .hooks
                .iter()
                .filter(|h| !headline.is_some_and(|top| std::ptr::eq(*h, top))),
        )
        .collect();
    let mut needs_fix = false;
    for check in hooks {
        let (glyph, color, line, fix) = hook_line(check);
        needs_fix |= fix;
        wrapped(lines, glyph, color, &line);
    }
    if needs_fix {
        lines.push(Line::from(vec![
            dim("      fix: "),
            Span::styled(
                "re-run `did-git-sign init`",
                Style::default().fg(COLOR_ORANGE).bold(),
            ),
        ]));
    }
}

// ****************************************************************************
// One repository
// ****************************************************************************

fn render_repo(lines: &mut Vec<Line<'static>>, view: &ReposView, resource: &str) {
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
        lines.push(Line::from(vec![
            Span::raw(if selected { "    ▸ " } else { "      " }),
            Span::styled(
                format!("{:<34}", shorten_did(&view.name_of(&p.did), 32)),
                name_style,
            ),
            text(format!("{:<14}", p.right.label())),
            dim(granted),
        ]));
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
            "      v reverts the highlighted item (the bridge re-applies the community's rights); \
             o adopts a forge role as a right."
        } else {
            "      An owner of this repository or a namespace admin reverts or adopts drift."
        })));
    }

    if let Some(form) = &view.add {
        render_add(lines, view, form);
        return;
    }
    let keys = if view.governs(resource) && !drift.is_empty() {
        "↑/↓ navigate   a add   x revoke   t transfer   A archive   v revert drift   o adopt drift   l link account   r refresh   Esc back"
    } else if view.governs(resource) {
        "↑/↓ navigate   a add   x revoke   t transfer   A archive   l link account   r refresh   Esc back"
    } else {
        "↑/↓ navigate   x resign your right   l link account   r refresh   Esc back"
    };
    hints(lines, keys);
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
    use crate::state_handler::main_page::repos::{
        InstallFound, ReposState, SigningChecked, SigningHealth,
    };
    use openvtc_core::config::account::PersonaId;
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

    #[test]
    fn an_outdated_hook_says_to_rerun_init() {
        let mut v = loaded();
        v.signing = SigningHealth {
            checked: Some(SigningChecked {
                installs: vec![InstallFound {
                    scope: "repository",
                    path: "/repo/.did-git-sign.json".into(),
                    key_id: format!("{BOB}#key-0"),
                    this_persona: true,
                }],
                looked: Vec::new(),
                hooks: vec![
                    HookCheck {
                        scope: HookScope::Here,
                        path: Some("/repo/.git/did-git-sign-hooks/commit-msg".into()),
                        health: HookHealth::Current { version: 2 },
                    },
                    HookCheck {
                        scope: HookScope::Global,
                        path: Some("/home/me/.config/did-git-sign/hooks/commit-msg".into()),
                        health: HookHealth::Outdated {
                            installed: 1,
                            current: 2,
                        },
                    },
                ],
            }),
        };
        let out = rendered(v);
        assert!(out.contains("OUTDATED"), "{out}");
        assert!(out.contains("did-git-sign init"), "{out}");
        // Both scopes, each with the file looked at; the worst first.
        let global = out.find("global: commit-msg hook OUTDATED").unwrap();
        let here = out.find("here: commit-msg hook v2 OK").unwrap();
        assert!(global < here, "{out}");
        assert!(
            out.contains("/home/me/.config/did-git-sign/hooks/commit-msg"),
            "{out}"
        );
        assert!(
            out.contains("/repo/.git/did-git-sign-hooks/commit-msg"),
            "{out}"
        );
        // A repository-only install is set up, not "not set up".
        assert!(
            out.contains("set up for this persona (repository config"),
            "{out}"
        );
        assert!(!out.contains("not set up"), "{out}");
    }

    /// Everything the VTC supplies is cleaned before it is drawn: a DID or
    /// a reason carrying a bidi override or a zero-width character cannot
    /// reorder or hide what the member reads.
    #[test]
    fn peer_text_is_sanitised_before_it_is_drawn() {
        let evil = "did:webvh:Qm\u{202E}evil\u{200B}:x.example";
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
    fn an_owner_sees_drift_as_rows_with_revert_and_adopt() {
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
        assert!(out.contains("v revert drift   o adopt drift"), "{out}");
        assert!(!out.contains("admin console"), "{out}");
    }
}
