//! Repos panel key handling — the view's key map, opened from the
//! Communities panel with `r`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The Repos view's key map. `None` when the key means nothing here.
///
/// Innermost first: an armed change takes only `y`/`⏎` (anything else
/// disarms it), then an open form, then the screen.
pub(in crate::ui::pages::main) fn repos_key(
    key: KeyEvent,
    view: &crate::state_handler::main_page::repos::ReposView,
) -> Option<crate::state_handler::actions::ReposAction> {
    use crate::state_handler::actions::ReposAction as R;
    use crate::state_handler::main_page::repos::{
        AddPersonForm, EXPIRY_CHOICES, LinkPhase, NewRepoForm, ReposScreen,
    };
    use openvtc_core::git_ns::GitRight;

    // Only `y` confirms: Enter is what submitted the form that armed the
    // change, and a key held a moment too long must not also confirm it.
    if view.confirm.is_some() {
        return Some(match key.code {
            KeyCode::Char('y') => R::Confirm,
            _ => R::Cancel,
        });
    }
    use crate::state_handler::actions::WorkspaceAction as W;
    use crate::state_handler::main_page::repos::WorkspaceForm;
    if view.workspace.confirm.is_some() {
        return Some(R::Workspace(match key.code {
            KeyCode::Char('y') => W::Confirm,
            _ => W::Cancel,
        }));
    }
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    if let Some(WorkspaceForm::Account(form)) = &view.workspace.form {
        return match key.code {
            KeyCode::Esc => Some(R::Workspace(W::Cancel)),
            KeyCode::Enter => Some(R::Workspace(W::AccountSubmit)),
            KeyCode::Tab | KeyCode::BackTab => Some(R::Workspace(W::AccountScope)),
            KeyCode::Char('a')
                if matches!(
                    form.picked(),
                    Some(crate::state_handler::main_page::repos::AccountOption::Gh { .. })
                ) =>
            {
                Some(R::Workspace(W::AccountAuthor))
            }
            KeyCode::Up => Some(R::Workspace(W::AccountPick(form.pick.saturating_sub(1)))),
            KeyCode::Down => Some(R::Workspace(W::AccountPick(form.pick + 1))),
            KeyCode::Backspace if form.typing() => {
                let mut v = form.path.clone();
                v.pop();
                Some(R::Workspace(W::AccountInput(v)))
            }
            KeyCode::Char(c) if form.typing() && !ctrl => {
                Some(R::Workspace(W::AccountInput(format!("{}{c}", form.path))))
            }
            _ => None,
        };
    }
    if let Some(form) = &view.workspace.form {
        let (value, settings) = match form {
            WorkspaceForm::Settings { root, .. } => (root, true),
            WorkspaceForm::UsePath { path, .. } => (path, false),
            WorkspaceForm::Account(_) => return None,
        };
        let edit = |v: String| {
            if settings {
                W::SettingsInput(v)
            } else {
                W::UseInput(v)
            }
        };
        return match key.code {
            KeyCode::Esc => Some(R::Workspace(W::Cancel)),
            KeyCode::Enter => Some(R::Workspace(if settings {
                W::SettingsSubmit
            } else {
                W::UseSubmit
            })),
            KeyCode::Tab | KeyCode::BackTab if settings => Some(R::Workspace(W::SettingsProtocol)),
            KeyCode::Backspace => {
                let mut v = value.clone();
                v.pop();
                Some(R::Workspace(edit(v)))
            }
            KeyCode::Char(c) if !ctrl => Some(R::Workspace(edit(format!("{value}{c}")))),
            _ => None,
        };
    }
    if let Some(form) = &view.add {
        let n = AddPersonForm::FIELDS;
        return match (form.field, key.code) {
            (_, KeyCode::Esc) => Some(R::Back),
            (_, KeyCode::Enter) => Some(R::AddSubmit),
            (_, KeyCode::Tab) => Some(R::AddField((form.field + 1) % n)),
            (_, KeyCode::BackTab) => Some(R::AddField((form.field + n - 1) % n)),
            (0, KeyCode::Char('d')) if ctrl => Some(R::AddToggleExternal),
            (0, KeyCode::Up) if !form.external => Some(R::AddPick(form.pick.saturating_sub(1))),
            (0, KeyCode::Down) if !form.external => Some(R::AddPick(form.pick + 1)),
            (1, KeyCode::Up | KeyCode::Left) => Some(R::AddRight(form.right.saturating_sub(1))),
            (1, KeyCode::Down | KeyCode::Right) => Some(R::AddRight(
                (form.right + 1).min(GitRight::REPO_RIGHTS.len() - 1),
            )),
            (2, KeyCode::Left) => Some(R::AddExpiry(form.expiry.saturating_sub(1))),
            (2, KeyCode::Right) => Some(R::AddExpiry(
                (form.expiry + 1).min(EXPIRY_CHOICES.len() - 1),
            )),
            (f @ (0 | 3), KeyCode::Backspace) => {
                let mut value = if f == 0 {
                    form.query.clone()
                } else {
                    form.reason.clone()
                };
                value.pop();
                Some(R::AddInput { field: f, value })
            }
            (f @ (0 | 3), KeyCode::Char(c)) if !ctrl => {
                let current = if f == 0 { &form.query } else { &form.reason };
                Some(R::AddInput {
                    field: f,
                    value: format!("{current}{c}"),
                })
            }
            _ => None,
        };
    }
    if let ReposScreen::NewRepo(form) = &view.screen {
        let n = NewRepoForm::FIELDS;
        return match (form.field, key.code) {
            (_, KeyCode::Esc) => Some(R::Back),
            (_, KeyCode::Enter) => Some(R::NewSubmit),
            (_, KeyCode::Tab) => Some(R::NewField((form.field + 1) % n)),
            (_, KeyCode::BackTab) => Some(R::NewField((form.field + n - 1) % n)),
            (0, KeyCode::Left | KeyCode::Up) => {
                Some(R::NewNamespace(form.namespace.saturating_sub(1)))
            }
            (0, KeyCode::Right | KeyCode::Down) => Some(R::NewNamespace(form.namespace + 1)),
            (2, KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')) => Some(R::NewVisibility),
            (f @ (1 | 3), KeyCode::Backspace) => {
                let mut value = if f == 1 {
                    form.name.clone()
                } else {
                    form.description.clone()
                };
                value.pop();
                Some(R::NewInput { field: f, value })
            }
            (f @ (1 | 3), KeyCode::Char(c)) if !ctrl => {
                let current = if f == 1 {
                    &form.name
                } else {
                    &form.description
                };
                Some(R::NewInput {
                    field: f,
                    value: format!("{current}{c}"),
                })
            }
            (4, KeyCode::Char('d')) if ctrl => Some(R::NewOwnerToggleExternal),
            (4, KeyCode::Char('a')) if ctrl => Some(R::NewOwnerAdd),
            (4, KeyCode::Up) if !form.owner_external => {
                Some(R::NewOwnerPick(form.owner_pick.saturating_sub(1)))
            }
            (4, KeyCode::Down) if !form.owner_external => {
                Some(R::NewOwnerPick(form.owner_pick + 1))
            }
            (4, KeyCode::Backspace) => {
                if form.owner_query.is_empty() {
                    Some(R::NewOwnerRemoveLast)
                } else {
                    let mut value = form.owner_query.clone();
                    value.pop();
                    Some(R::NewOwnerQuery(value))
                }
            }
            (4, KeyCode::Char(c)) if !ctrl => {
                Some(R::NewOwnerQuery(format!("{}{c}", form.owner_query)))
            }
            _ => None,
        };
    }
    let link_settled = view.link.as_ref().is_some_and(|l| {
        matches!(
            l.phase,
            LinkPhase::Linked { .. } | LinkPhase::Expired | LinkPhase::Failed(_)
        )
    });
    let on_repo = matches!(view.screen, ReposScreen::Repo { .. });
    match key.code {
        KeyCode::Esc => Some(R::Back),
        KeyCode::Up => Some(R::Select(view.selected.saturating_sub(1))),
        KeyCode::Down => Some(R::Select(view.selected + 1)),
        KeyCode::Char('r') => Some(R::Refresh),
        KeyCode::Char('l') => Some(R::LinkStart),
        KeyCode::Char('d') if link_settled => Some(R::LinkDismiss),
        KeyCode::Enter if !on_repo => Some(R::OpenRepo),
        KeyCode::Char('n') if !on_repo => Some(R::NewStart),
        KeyCode::Char('a') if on_repo => Some(R::AddStart),
        KeyCode::Char('x') | KeyCode::Delete if on_repo => Some(R::RevokeArm),
        KeyCode::Char('t') if on_repo => Some(R::TransferArm),
        KeyCode::Char('A') if on_repo => Some(R::ArchiveArm),
        KeyCode::Char('v') if on_repo => Some(R::DriftRevertArm),
        KeyCode::Char('o') if on_repo => Some(R::DriftAdoptArm),
        // This machine: checkouts and signing.
        KeyCode::Char('c') => Some(R::Workspace(W::Clone)),
        KeyCode::Char('e') => Some(R::Workspace(W::Sign)),
        KeyCode::Char('E') => Some(R::Workspace(W::Unsign)),
        KeyCode::Char('s') => Some(R::Workspace(W::SetUp)),
        KeyCode::Char('S') => Some(R::Workspace(W::RemoveArm)),
        KeyCode::Char('u') => Some(R::Workspace(W::UseStart)),
        KeyCode::Char('w') => Some(R::Workspace(W::SettingsStart)),
        KeyCode::Char('f') => Some(R::Workspace(W::AccountStart)),
        KeyCode::Char('F') => Some(R::Workspace(W::Fork)),
        KeyCode::Char('R') => Some(R::Workspace(W::RemotesToSsh)),
        _ => None,
    }
}

/// [`repos_key`] as the view takes it: an armed change and an open form keep
/// every key `repos_key` maps, but the screen takes exactly the keys its
/// footer lists ([`screen_bindings`](super::screen_bindings)) — so a key for
/// this machine that does not apply to the highlighted repository is not
/// taken, and says so, rather than answering with a refusal.
pub(in crate::ui::pages::main) fn repos_view_key(
    key: KeyEvent,
    view: &crate::state_handler::main_page::repos::ReposView,
) -> Option<crate::state_handler::actions::ReposAction> {
    use crate::state_handler::main_page::repos::ReposScreen;
    let on_screen = view.confirm.is_none()
        && view.workspace.confirm.is_none()
        && view.workspace.form.is_none()
        && view.add.is_none()
        && !matches!(view.screen, ReposScreen::NewRepo(_));
    if on_screen && !super::screen_bindings(view).iter().any(|b| b.matches(&key)) {
        return None;
    }
    repos_key(key, view)
}

/// The checkout path `p` copies: the highlighted or open repository's, when
/// it is checked out and nothing else has the keys.
pub(in crate::ui::pages::main) fn repos_copy_path(
    view: &crate::state_handler::main_page::repos::ReposView,
) -> Option<String> {
    if view.confirm.is_some()
        || view.add.is_some()
        || view.workspace.form.is_some()
        || view.workspace.confirm.is_some()
    {
        return None;
    }
    let resource = crate::state_handler::repos_workspace::target(view)?;
    view.workspace
        .checkouts
        .get(&resource)
        .map(|c| c.facts.path.display().to_string())
}
