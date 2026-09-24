//! "Can I actually commit here?" — did-git-sign's install and its commit-msg
//! hook, for the Repos panel.
//!
//! The install is read the way the Help/Status panel reads it
//! ([`super::main_page::detect_did_git_sign_info`]). The hook is read by
//! did-git-sign itself: `did_git_sign::init::commit_msg_hook_status` finds the
//! hook git would run (from the current directory, honouring `core.hooksPath`
//! at every scope, or the global one outside a repository) and compares its
//! `# did-git-sign-hook-version:` marker with `COMMIT_MSG_HOOK_VERSION`.
//! Installed hooks are only replaced by re-running `did-git-sign init`, so an
//! upgraded binary still runs the old hook until then — version 1 wrote the
//! `Signed-by-DID:` trailer above any `---` line, where verify-trust does not
//! read it — and this is what says so. Reading the marker here instead would be
//! a second copy of a contract did-git-sign owns.

use did_git_sign::init::{CommitMsgHookStatus, commit_msg_hook_status};

use super::main_page::repos::{HookHealth, SigningHealth};

/// Translate did-git-sign's answer into what the panel shows.
pub(crate) fn health_of(status: Result<CommitMsgHookStatus, String>) -> HookHealth {
    match status {
        Ok(CommitMsgHookStatus::Current { .. }) => HookHealth::Current {
            version: did_git_sign::init::COMMIT_MSG_HOOK_VERSION,
        },
        Ok(CommitMsgHookStatus::Outdated {
            installed, current, ..
        }) => HookHealth::Outdated { installed, current },
        Ok(CommitMsgHookStatus::Newer {
            installed, current, ..
        }) => HookHealth::Newer { installed, current },
        Ok(CommitMsgHookStatus::Foreign { path }) => HookHealth::Foreign {
            path: path.display().to_string(),
        },
        Ok(CommitMsgHookStatus::Missing { path }) => HookHealth::Missing {
            path: path.display().to_string(),
        },
        Ok(CommitMsgHookStatus::Unknown) => HookHealth::NoGlobalHooks,
        Err(e) => HookHealth::Unknown(e),
    }
}

/// did-git-sign's install for `persona_did`, and its hook. Blocking (runs
/// `git`); call off the loop thread.
pub(crate) fn probe(persona_did: &str) -> SigningHealth {
    SigningHealth {
        key_id: super::main_page::detect_did_git_sign_info(persona_did).map(|i| i.did_key_id),
        hook: health_of(commit_msg_hook_status().map_err(|e| format!("{e:#}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn at() -> PathBuf {
        PathBuf::from("/home/me/.config/did-git-sign/hooks/commit-msg")
    }

    #[test]
    fn a_current_hook_reports_this_releases_version() {
        assert_eq!(
            health_of(Ok(CommitMsgHookStatus::Current { path: at() })),
            HookHealth::Current {
                version: did_git_sign::init::COMMIT_MSG_HOOK_VERSION
            }
        );
    }

    #[test]
    fn an_outdated_hook_keeps_both_versions() {
        assert_eq!(
            health_of(Ok(CommitMsgHookStatus::Outdated {
                path: at(),
                installed: 1,
                current: 2
            })),
            HookHealth::Outdated {
                installed: 1,
                current: 2
            }
        );
    }

    #[test]
    fn nowhere_to_look_and_a_failure_are_told_apart() {
        assert_eq!(
            health_of(Ok(CommitMsgHookStatus::Unknown)),
            HookHealth::NoGlobalHooks
        );
        assert!(matches!(
            health_of(Err("failed to run git".into())),
            HookHealth::Unknown(m) if m.contains("git")
        ));
        assert!(matches!(
            health_of(Ok(CommitMsgHookStatus::Foreign { path: at() })),
            HookHealth::Foreign { .. }
        ));
    }
}
