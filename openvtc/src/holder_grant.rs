//! The one VTA refusal that has a specific answer, and what to say about it.
//!
//! Reaching the holder's attribute pool — the ten `persona/*` tasks, and so the
//! faces built over them — needs authority that **no role carries**. The VTA's
//! `PersonaHolder` capability is additive: an administrator scoped to a context
//! does not derive it, because the pool sits above every context and deriving
//! it would hand the pool to every context-scoped administrator on upgrade.
//! It exists only where an operator granted it by name, and only a super-admin
//! can grant it.
//!
//! That makes it the one refusal an operator can always fix, and always in the
//! same way — which is why it is worth recognising rather than passing the
//! agent's sentence through. The agent's sentence is accurate and says nothing
//! about what to type.
//!
//! Shared because the same refusal reaches more than one screen. The Identity
//! pane recognised it; the Vetting pane, where choosing the face a vetter is
//! shown reads the very same pool, did not — so the same failure was guidance
//! in one place and a wall of agent text in another.

/// Whether a read failed because the caller lacks holder authority, as opposed
/// to the agent being unreachable or the request being malformed.
///
/// Matched on the phrase both the current and the pre-capability VTA use, since
/// an operator may be pointing at either: the older one refuses with "unscoped
/// holder credential" and names no capability, because there was none to name.
/// A false negative here costs a hint; a false positive would tell someone to
/// run a grant that is not their problem, so the match is on the specific
/// phrase rather than on "forbidden".
#[must_use]
pub fn needs_holder_grant(error: &str) -> bool {
    let e = error.to_ascii_lowercase();
    e.contains("holder credential") || e.contains("persona-holder")
}

/// The command that fixes it, with the subject filled in when we know it.
///
/// We usually do: the DID this install authenticates as is in the config every
/// caller is already holding, so the command is emitted complete rather than
/// with a placeholder the reader has to go and resolve on another pane. The
/// placeholder survives only for the case where there is genuinely nothing to
/// substitute — a BIP32 account, which has no agent credential at all (and,
/// having no agent, will not have produced this refusal in the first place).
#[must_use]
pub fn grant_command(credential_did: Option<&str>) -> String {
    let subject = credential_did.unwrap_or("<this install's DID>");
    format!("pnm acl update {subject} --capabilities persona-holder")
}

/// What to do about it, as lines.
///
/// Lines rather than a paragraph because the middle one is a command an
/// operator has to read character by character — and, when we know it, retype
/// or copy into another terminal.
#[must_use]
pub fn holder_grant_hint(credential_did: Option<&str>) -> Vec<String> {
    vec![
        " Your agent credential administers this context. Your attributes, and the faces"
            .to_string(),
        " over them, sit above every context — reaching them is a separate grant:".to_string(),
        String::new(),
        format!("   {}", grant_command(credential_did)),
        String::new(),
        " It adds authority over your own identity without giving this install any".to_string(),
        " authority over other contexts.".to_string(),
    ]
}

/// The same thing in one sentence, for a surface that has a status line rather
/// than a panel.
///
/// Says what is missing, what to run, and that running it does not widen this
/// install's authority — the question an operator asks before pasting a command
/// that contains the word `admin`.
#[must_use]
pub fn holder_grant_sentence(credential_did: Option<&str>) -> String {
    format!(
        "Your faces sit above every context, and your agent credential administers only one. \
         Grant it holder authority with:  {}  — it adds authority over your own identity \
         without giving this install any over other contexts.",
        grant_command(credential_did)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both the current VTA's wording and the pre-capability one, because an
    /// operator may be pointing at either.
    #[test]
    fn the_refusal_is_recognised_in_both_wordings() {
        assert!(needs_holder_grant(
            "forbidden: this task reads or writes the holder's attribute pool … It requires an \
             unscoped holder credential, or an ACL entry granted the `persona-holder` capability"
        ));
        assert!(needs_holder_grant(
            "forbidden: requires an unscoped holder credential"
        ));
    }

    /// A false positive would tell someone to run a grant that is not their
    /// problem, so anything else is left alone.
    #[test]
    fn other_failures_are_not_mistaken_for_it() {
        for other in [
            "connection refused",
            "forbidden: you are not an administrator of this context",
            "malformed request: missing field `id`",
            "not found",
        ] {
            assert!(!needs_holder_grant(other), "{other}");
        }
    }

    /// The command is emitted complete when the subject is known, because it is
    /// retyped into another terminal.
    #[test]
    fn the_command_names_the_subject_when_it_is_known() {
        assert_eq!(
            grant_command(Some("did:key:z6MkThisInstall")),
            "pnm acl update did:key:z6MkThisInstall --capabilities persona-holder"
        );
        assert!(grant_command(None).contains("<this install's DID>"));
        // The sentence carries the same command, so the two cannot drift.
        assert!(
            holder_grant_sentence(Some("did:key:z6MkThisInstall"))
                .contains(&grant_command(Some("did:key:z6MkThisInstall")))
        );
        assert!(
            holder_grant_hint(Some("did:key:z6MkThisInstall"))
                .join("\n")
                .contains(&grant_command(Some("did:key:z6MkThisInstall")))
        );
    }
}
