//! "Can I actually commit here?" — did-git-sign's install and its commit-msg
//! hook, for the Repos panel.
//!
//! Two scopes are checked, and both are reported with the file looked at:
//!
//! - **here** — the hook git would run for a commit in the directory openvtc
//!   was started in, as did-git-sign's own
//!   `did_git_sign::init::commit_msg_hook_status` finds it (honouring
//!   `core.hooksPath` at every scope; the global one outside a repository);
//! - **global** — the global `core.hooksPath`, which `did-git-sign init
//!   --global` sets and every repository without its own hooks path uses.
//!
//! The worst of the two is the headline. The global file is classified
//! against the library's own published hook (`COMMIT_MSG_HOOK` and
//! `COMMIT_MSG_HOOK_VERSION`): did-git-sign exposes no classifier that takes
//! a path, so the version marker is read off the line of the library's hook
//! that carries the version, rather than copied here as a string.
//!
//! The install is looked for in both places did-git-sign writes it — the
//! global config and a repository's `.did-git-sign.json` — so a
//! repository-only install is not reported as "not set up".

use std::path::{Path, PathBuf};
use std::process::Command;

use did_git_sign::config::SigningConfig;
use did_git_sign::init::{
    COMMIT_MSG_HOOK, COMMIT_MSG_HOOK_VERSION, CommitMsgHookStatus, commit_msg_hook_status,
};

use super::main_page::repos::{
    HookCheck, HookHealth, HookScope, InstallFound, SigningChecked, SigningHealth,
};

/// Translate the library's answer for "here" into a check.
pub(crate) fn here_check(status: Result<CommitMsgHookStatus, String>) -> HookCheck {
    let (path, health) = match status {
        Ok(CommitMsgHookStatus::Current { path }) => (
            Some(path),
            HookHealth::Current {
                version: COMMIT_MSG_HOOK_VERSION,
            },
        ),
        Ok(CommitMsgHookStatus::Outdated {
            path,
            installed,
            current,
        }) => (Some(path), HookHealth::Outdated { installed, current }),
        Ok(CommitMsgHookStatus::Newer {
            path,
            installed,
            current,
        }) => (Some(path), HookHealth::Newer { installed, current }),
        Ok(CommitMsgHookStatus::Foreign { path }) => (Some(path), HookHealth::Foreign),
        Ok(CommitMsgHookStatus::Missing { path }) => (Some(path), HookHealth::Missing),
        Ok(CommitMsgHookStatus::Unknown) => (None, HookHealth::NowhereToLook),
        Err(e) => (None, HookHealth::Unknown(e)),
    };
    HookCheck {
        scope: HookScope::Here,
        path: path.map(|p| p.display().to_string()),
        health,
    }
}

/// The version-marker prefix, read off the library's own hook: the comment
/// line that ends in `COMMIT_MSG_HOOK_VERSION`.
fn version_marker() -> Option<&'static str> {
    let version = COMMIT_MSG_HOOK_VERSION.to_string();
    COMMIT_MSG_HOOK
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with('#') && l.ends_with(&format!(" {version}")))
        .and_then(|l| l.strip_suffix(version.as_str()))
        .map(str::trim_end)
}

/// Classify a hook file's text against the library's published hook.
pub(crate) fn classify(content: Option<&str>) -> HookHealth {
    let Some(content) = content else {
        return HookHealth::Missing;
    };
    let current = COMMIT_MSG_HOOK_VERSION;
    if content == COMMIT_MSG_HOOK {
        return HookHealth::Current { version: current };
    }
    let marked = version_marker().and_then(|marker| {
        content
            .lines()
            .find_map(|l| l.trim().strip_prefix(marker))
            .map(|v| v.trim().parse::<u32>().unwrap_or(0))
    });
    // Every did-git-sign hook, the unversioned first one included, says so in
    // its opening comment.
    let ours = marked.is_some()
        || content
            .lines()
            .take(3)
            .any(|l| l.starts_with('#') && l.contains("did-git-sign"));
    if !ours {
        return HookHealth::Foreign;
    }
    let installed = marked.unwrap_or(1);
    match installed.cmp(&current) {
        std::cmp::Ordering::Equal => HookHealth::Current { version: current },
        std::cmp::Ordering::Less => HookHealth::Outdated { installed, current },
        std::cmp::Ordering::Greater => HookHealth::Newer { installed, current },
    }
}

fn git(args: &[&str]) -> Result<Option<String>, String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Ok(None);
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((!v.is_empty()).then_some(v))
}

/// The global scope's hook check.
fn global_check() -> HookCheck {
    let dir = match git(&["config", "--global", "--get", "core.hooksPath"]) {
        Ok(Some(dir)) => dir,
        Ok(None) => {
            return HookCheck {
                scope: HookScope::Global,
                path: None,
                health: HookHealth::NowhereToLook,
            };
        }
        Err(e) => {
            return HookCheck {
                scope: HookScope::Global,
                path: None,
                health: HookHealth::Unknown(e),
            };
        }
    };
    // git expands a leading `~/` in this key; do the same.
    let dir = match dir.strip_prefix("~/") {
        Some(rest) => dirs::home_dir().map_or_else(|| PathBuf::from(&dir), |h| h.join(rest)),
        None => PathBuf::from(&dir),
    };
    let path = dir.join("commit-msg");
    let content = std::fs::read_to_string(&path).ok();
    HookCheck {
        scope: HookScope::Global,
        path: Some(path.display().to_string()),
        health: classify(content.as_deref()),
    }
}

/// Merge the two checks: one entry when they name the same file.
pub(crate) fn merge(here: HookCheck, global: HookCheck) -> Vec<HookCheck> {
    if here.path.is_some() && here.path == global.path {
        return vec![HookCheck {
            scope: HookScope::HereAndGlobal,
            ..here
        }];
    }
    vec![here, global]
}

fn install_at(scope: &'static str, path: &Path, persona_did: &str) -> Option<InstallFound> {
    let cfg = SigningConfig::load(path).ok()?;
    Some(InstallFound {
        scope,
        path: path.display().to_string(),
        this_persona: cfg.did_key_id.starts_with(&format!("{persona_did}#")),
        key_id: cfg.did_key_id,
    })
}

/// did-git-sign's installs for `persona_did`, and its hook at both scopes.
/// Blocking (runs `git`, reads files); call off the loop thread.
pub(crate) fn probe(persona_did: &str) -> SigningHealth {
    let mut installs = Vec::new();
    let mut looked = Vec::new();
    if let Ok(global) = SigningConfig::default_global_path() {
        looked.push(global.display().to_string());
        installs.extend(install_at("global", &global, persona_did));
    }
    if let Ok(Some(top)) = git(&["rev-parse", "--show-toplevel"]) {
        let local = PathBuf::from(top).join(SigningConfig::repo_local_path());
        looked.push(local.display().to_string());
        installs.extend(install_at("repository", &local, persona_did));
    }
    let here = here_check(commit_msg_hook_status().map_err(|e| format!("{e:#}")));
    SigningHealth {
        checked: Some(SigningChecked {
            installs,
            looked,
            hooks: merge(here, global_check()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at() -> PathBuf {
        PathBuf::from("/home/me/.config/did-git-sign/hooks/commit-msg")
    }

    #[test]
    fn the_librarys_answer_keeps_its_path() {
        let c = here_check(Ok(CommitMsgHookStatus::Outdated {
            path: at(),
            installed: 1,
            current: 2,
        }));
        assert_eq!(c.path, Some(at().display().to_string()));
        assert_eq!(
            c.health,
            HookHealth::Outdated {
                installed: 1,
                current: 2
            }
        );
        assert_eq!(
            here_check(Ok(CommitMsgHookStatus::Unknown)).health,
            HookHealth::NowhereToLook
        );
        assert!(matches!(
            here_check(Err("failed to run git".into())).health,
            HookHealth::Unknown(m) if m.contains("git")
        ));
    }

    /// The global file is judged against the library's own hook.
    #[test]
    fn the_librarys_hook_is_current_and_older_ones_are_not() {
        assert_eq!(
            classify(Some(COMMIT_MSG_HOOK)),
            HookHealth::Current {
                version: COMMIT_MSG_HOOK_VERSION
            }
        );
        let marker = version_marker().expect("the library's hook carries its version");
        let v1_marked = COMMIT_MSG_HOOK.replace(
            &format!("{marker} {COMMIT_MSG_HOOK_VERSION}"),
            &format!("{marker} 1"),
        );
        assert!(matches!(
            classify(Some(&v1_marked)),
            HookHealth::Outdated { installed: 1, .. }
        ));
        // The first hook had no marker at all.
        let unversioned: String = COMMIT_MSG_HOOK
            .lines()
            .filter(|l| !l.trim().starts_with(marker))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            classify(Some(&unversioned)),
            HookHealth::Outdated { installed: 1, .. }
        ));
        assert_eq!(
            classify(Some("#!/bin/sh\nexec husky\n")),
            HookHealth::Foreign
        );
        assert_eq!(classify(None), HookHealth::Missing);
    }

    /// Both scopes are reported, the worst is the headline, and one file is
    /// reported once.
    #[test]
    fn both_scopes_are_reported_and_the_worst_leads() {
        let here = HookCheck {
            scope: HookScope::Here,
            path: Some("/repo/.git/did-git-sign-hooks/commit-msg".into()),
            health: HookHealth::Current { version: 2 },
        };
        let global = HookCheck {
            scope: HookScope::Global,
            path: Some(at().display().to_string()),
            health: HookHealth::Outdated {
                installed: 1,
                current: 2,
            },
        };
        let checked = SigningChecked {
            installs: Vec::new(),
            looked: Vec::new(),
            hooks: merge(here.clone(), global),
        };
        assert_eq!(checked.hooks.len(), 2);
        assert_eq!(checked.headline().unwrap().scope, HookScope::Global);

        let same = merge(
            here.clone(),
            HookCheck {
                scope: HookScope::Global,
                ..here
            },
        );
        assert_eq!(same.len(), 1);
        assert_eq!(same[0].scope, HookScope::HereAndGlobal);
    }

    /// A repository-only install counts as set up.
    #[test]
    fn a_repository_install_is_set_up() {
        let checked = SigningChecked {
            installs: vec![InstallFound {
                scope: "repository",
                path: "/repo/.did-git-sign.json".into(),
                key_id: "did:webvh:me#key-0".into(),
                this_persona: true,
            }],
            looked: Vec::new(),
            hooks: Vec::new(),
        };
        assert!(checked.set_up());
    }
}
