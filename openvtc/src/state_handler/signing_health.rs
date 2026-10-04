//! did-git-sign's commit-msg hook, for the Repos panel.
//!
//! The hook is what writes the `Signed-by-DID:` claim `verify-trust` reads, so
//! an outdated or missing one fails CI however good the signature is. Since
//! did-git-sign 0.14 every repository that signs includes settings pointing
//! `core.hooksPath` at did-git-sign's own hook directory, so there is one file
//! to judge — wherever openvtc happens to have been started.
//!
//! The file is classified against the library's own published hook
//! (`COMMIT_MSG_HOOK` and `COMMIT_MSG_HOOK_VERSION`): did-git-sign exposes no
//! classifier that takes a path, so the version marker is read off the line of
//! the library's hook that carries the version, rather than copied here as a
//! string.

use did_git_sign::init::{COMMIT_MSG_HOOK, COMMIT_MSG_HOOK_VERSION};

use super::main_page::repos::HookHealth;

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

/// The hook did-git-sign's include files point git at, and what it is.
/// Blocking (reads a file); call off the loop thread.
pub(crate) fn hook_health() -> (Option<String>, HookHealth) {
    let Some(path) = openvtc_core::git_signing::hook_file() else {
        return (None, HookHealth::NowhereToLook);
    };
    let content = std::fs::read_to_string(&path).ok();
    (
        Some(path.display().to_string()),
        classify(content.as_deref()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
