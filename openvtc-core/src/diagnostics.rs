//! Turning a startup failure into something the user can act on.
//!
//! # Why this module exists
//!
//! Every startup failure used to render the same line — *"Check your network
//! and that your VTA/mediator are reachable, then restart OpenVTC"* — including
//! failures with no network in them at all. A user whose OS keychain no longer
//! held their profile was told to check their network, which is both useless
//! and misleading: it points away from the machine the problem is on.
//!
//! The stack development guide's **R6.4** says error text must let an operator
//! tell network-unreachable from auth-rejected from contract-mismatch, and
//! forbids exactly the one fixed hint for all failures that we had. This module
//! is that rule applied to startup: [`diagnose`] maps a typed [`OpenVTCError`]
//! to a [`Diagnosis`] carrying what failed, the state of the things it depends
//! on, commands to confirm it, and remedies in the order they should be tried.
//!
//! Two rules shape the content:
//!
//! - **Never advise a reset before a restore.** Deleting a profile destroys
//!   keys, so "restore a backup" always precedes "start over", and a diagnosis
//!   that is unsure which failure it has does not recommend either.
//! - **Say where you looked.** Most of these failures are a mismatch between a
//!   config file and a credential store, so the context block always names both
//!   and reports whether the credential is actually there.

use crate::{
    config::public_config::profile_dir,
    errors::{OpenVTCError, SecureStoreFault},
    secure_store::{self, EntryStatus},
};

/// A user-facing explanation of one failure.
#[derive(Debug, Clone, Default)]
pub struct Diagnosis {
    /// One line naming what failed, in the user's terms rather than the code's.
    pub headline: String,
    /// The underlying error text, verbatim.
    pub error: String,
    /// What that error means — the inference the user cannot make themselves.
    pub cause: String,
    /// Facts about the environment: profile, paths, store, credential state.
    pub context: Vec<(String, String)>,
    /// Commands that confirm or refute the diagnosis, on this platform.
    pub checks: Vec<String>,
    /// What to do, most-preferred first. Never a destructive step first.
    pub remedies: Vec<String>,
}

impl Diagnosis {
    /// Render the whole report as plain text.
    ///
    /// The TUI shows this scrolled inside a terminal; a user filing a bug needs
    /// it as something they can paste. Same content either way — a support
    /// channel that sees a different report from the one the user saw is worse
    /// than no report.
    #[must_use]
    pub fn render_plain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}\n\n{}\n", self.headline, self.error));
        if !self.cause.is_empty() {
            out.push_str(&format!("\n{}\n", self.cause));
        }
        if !self.context.is_empty() {
            let width = self.context.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            out.push_str("\nDetails\n");
            for (k, v) in &self.context {
                out.push_str(&format!("  {k:<width$}  {v}\n"));
            }
        }
        if !self.checks.is_empty() {
            out.push_str("\nCheck for yourself\n");
            for c in &self.checks {
                out.push_str(&format!("  $ {c}\n"));
            }
        }
        if !self.remedies.is_empty() {
            out.push_str("\nWhat to try, in order\n");
            for (i, r) in self.remedies.iter().enumerate() {
                out.push_str(&format!("  {}. {r}\n", i + 1));
            }
        }
        out
    }

    /// Write the report beside the profile's config and return its path.
    ///
    /// Best-effort: a profile whose directory is unwritable is already having a
    /// bad day, and failing to save the explanation must not replace the
    /// explanation. Overwrites any previous report *for this profile* — the
    /// current failure is the one being asked about.
    ///
    /// The filename carries the profile (`last-startup-failure-{profile}.txt`,
    /// unsuffixed for `default`) because the profile directory is shared across
    /// profiles; a fixed name would let one profile's crash report overwrite
    /// another's.
    #[must_use]
    pub fn write_report(&self, profile: &str) -> Option<std::path::PathBuf> {
        let name = if profile.is_empty() || profile == "default" {
            "last-startup-failure.txt".to_string()
        } else {
            format!("last-startup-failure-{profile}.txt")
        };
        let path = profile_dir(profile).ok()?.join(name);
        std::fs::write(&path, self.render_plain()).ok()?;
        Some(path)
    }
}

/// What was being attempted, for context the error itself doesn't carry.
#[derive(Debug, Clone)]
pub struct DiagnosisContext {
    /// Config profile in play.
    pub profile: String,
}

impl DiagnosisContext {
    /// Context for a named profile.
    #[must_use]
    pub fn new(profile: impl Into<String>) -> Self {
        DiagnosisContext {
            profile: profile.into(),
        }
    }
}

/// The `security`/`keyctl`/`cmdkey` invocation that lists this profile's
/// credential on the current platform, so the user can see for themselves
/// rather than take our word for it.
fn store_inspect_commands(profile: &str) -> Vec<String> {
    #[cfg(target_os = "macos")]
    {
        vec![format!(
            "security find-generic-password -s openvtc -a {profile} 2>&1 | head -5"
        )]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            format!("secret-tool search service openvtc username {profile}"),
            "keyctl show @us 2>/dev/null; keyctl show @s".to_string(),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        let _ = profile;
        vec!["cmdkey /list | findstr openvtc".to_string()]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = profile;
        Vec::new()
    }
}

/// Describe the active store and the profile's credential within it.
///
/// Runs live: on a startup failure the most valuable fact is whether the store
/// answers at all, and that cannot be inferred from the error that just came
/// back from one call against it.
fn store_context(profile: &str, context: &mut Vec<(String, String)>) {
    if let Some(store) = secure_store::describe_active() {
        context.push(("Secure store".to_string(), store.label.clone()));
        context.push(("Store location".to_string(), store.location.clone()));
    }

    let probe = secure_store::probe(profile);
    let status = match &probe.status {
        EntryStatus::Present => format!("present ({})", probe.durability.lifetime_phrase()),
        EntryStatus::Missing => "NOT FOUND for this profile".to_string(),
        EntryStatus::Unavailable(e) => format!("could not be read: {e}"),
    };
    context.push(("Stored credential".to_string(), status));
    if let Some(path) = &probe.path {
        context.push(("Credential file".to_string(), path.clone()));
    }
}

/// Add the profile's on-disk locations, which are half of every
/// config-file-without-credential mismatch.
fn path_context(profile: &str, context: &mut Vec<(String, String)>) {
    context.push(("Profile".to_string(), profile.to_string()));
    if let Ok(dir) = profile_dir(profile) {
        let file = if profile == "default" {
            "config.json".to_string()
        } else {
            format!("config-{profile}.json")
        };
        let path = dir.join(&file);
        context.push((
            "Config file".to_string(),
            format!(
                "{} ({})",
                path.display(),
                if path.exists() { "present" } else { "missing" }
            ),
        ));
    }
}

/// Build a [`Diagnosis`] for a startup failure.
///
/// The match is on the *typed* error, which is why [`OpenVTCError`] grew
/// [`OpenVTCError::SecureStore`]: a formatted string cannot distinguish a
/// credential that was never there from a keychain that is merely locked, and
/// those two have opposite remedies.
#[must_use]
pub fn diagnose(err: &OpenVTCError, ctx: &DiagnosisContext) -> Diagnosis {
    let profile = ctx.profile.as_str();
    let mut context = Vec::new();
    path_context(profile, &mut context);

    match err {
        OpenVTCError::SecureStore { fault, .. } => {
            store_context(profile, &mut context);
            let mut d = Diagnosis {
                headline: String::new(),
                error: err.to_string(),
                cause: String::new(),
                context,
                checks: store_inspect_commands(profile),
                remedies: Vec::new(),
            };
            match fault {
                SecureStoreFault::Missing => {
                    d.headline = "This profile's configuration exists, but its stored keys do not."
                        .to_string();
                    d.cause = "OpenVTC keeps a profile in two halves: a config file on disk \
                               and its secret key material in the OS credential store. The \
                               file is here; the credential store has nothing under this \
                               profile name. Nothing on the network is involved."
                        .to_string();
                    d.remedies = vec![
                        "If you have an encrypted export, restore it: run OpenVTC, then \
                         Settings -> Import / Restore Backup."
                            .to_string(),
                        "If the config was copied from another machine or user account, the \
                         credential did not come with it — export it from the original \
                         machine instead of copying the file."
                            .to_string(),
                        "On Linux without a Secret Service daemon, a profile with no \
                         passphrase is held in the kernel keyring, which is RAM-only and \
                         is emptied by a reboot. If that is what happened the keys are \
                         gone; set a passphrase on the new profile so it is stored on \
                         disk instead."
                            .to_string(),
                        "Check you are on the intended profile — OPENVTC_CONFIG_PROFILE and \
                         --profile select which credential is looked up."
                            .to_string(),
                        "Only if none of the above apply: `openvtc --setup` starts over. \
                         This mints new keys and DIDs, and every community must be \
                         re-joined. The old keys cannot be recovered afterwards."
                            .to_string(),
                    ];
                }
                SecureStoreFault::Unavailable => {
                    d.headline = "The OS credential store could not be opened.".to_string();
                    d.cause = "The store itself did not answer — it is locked, not running, \
                               or refused access. Your keys are most likely still there; \
                               OpenVTC just cannot reach them right now. Do not reset the \
                               profile to fix this."
                        .to_string();
                    d.remedies = vec![
                        "Unlock your login keychain / keyring and retry.".to_string(),
                        "On Linux, confirm a Secret Service daemon is running \
                         (gnome-keyring-daemon, kwalletd, KeePassXC) and that \
                         DBUS_SESSION_BUS_ADDRESS is set — over SSH or in a container it \
                         usually is not."
                            .to_string(),
                        "If you are running OpenVTC under a different user (sudo, a service \
                         account), that user has a different credential store."
                            .to_string(),
                        "On a headless machine with no keyring at all, choose durable file \
                         storage deliberately: OPENVTC_SECURE_STORE=file. OpenVTC will not \
                         pick a weaker store for you — where your keys live is your \
                         decision, not a side effect of what happened to be installed."
                            .to_string(),
                        "Do NOT run setup again — that would replace keys that are still \
                         present but temporarily unreachable."
                            .to_string(),
                    ];
                }
                SecureStoreFault::Ambiguous => {
                    d.headline = "More than one credential matches this profile.".to_string();
                    d.cause = "The credential store holds several entries for the same \
                               service and profile, so OpenVTC cannot tell which is current. \
                               This usually follows a restore that merged two keychains."
                        .to_string();
                    d.remedies = vec![
                        "Inspect the duplicates with the command above and delete the stale \
                         one, keeping the most recently modified."
                            .to_string(),
                        "Export a backup first if you are unsure which is which.".to_string(),
                    ];
                }
                SecureStoreFault::Corrupt => {
                    d.headline = "The stored credential could not be read.".to_string();
                    d.cause = "A credential exists for this profile but its contents are not \
                               a SecuredConfig envelope OpenVTC understands — a truncated \
                               write, or an entry written by another tool under the same \
                               name."
                        .to_string();
                    d.remedies = vec![
                        "Restore an encrypted export if you have one (Settings -> Import / \
                         Restore Backup)."
                            .to_string(),
                        "Check whether another tool writes to the `openvtc` service in your \
                         credential store."
                            .to_string(),
                        "If no backup exists, `openvtc --setup` starts over — new keys, and \
                         every community re-joined."
                            .to_string(),
                    ];
                }
                SecureStoreFault::Rejected => {
                    d.headline = "The credential store refused to hold this secret.".to_string();
                    d.cause = "The durable file-backed store only accepts an encrypted \
                               blob, so an unprotected profile is not written to disk in \
                               the clear."
                        .to_string();
                    d.remedies = vec![
                        "Set a passphrase under Settings -> Config Protection; the profile \
                         then stores durably."
                            .to_string(),
                    ];
                }
            }
            d
        }

        OpenVTCError::Decrypt(reason) => Diagnosis {
            headline: "The stored keys were found but could not be decrypted.".to_string(),
            error: err.to_string(),
            cause: format!(
                "The credential is present, so nothing is lost — the unlock material did \
                 not match it. ({reason})"
            ),
            context,
            checks: Vec::new(),
            remedies: vec![
                "Re-enter the passphrase; check caps lock and keyboard layout.".to_string(),
                "If this profile is protected by a hardware token, confirm the right card \
                 is inserted and the PIN is correct."
                    .to_string(),
                "Do NOT reset the profile — the keys are intact, only the passphrase is \
                 wrong."
                    .to_string(),
            ],
        },

        OpenVTCError::ConfigNotFound(path, e) => Diagnosis {
            headline: "No configuration file for this profile.".to_string(),
            error: err.to_string(),
            cause: format!("Nothing to load at {path} ({e}). This is normal on a first run."),
            context,
            checks: Vec::new(),
            remedies: vec![
                "Run `openvtc --setup` to create the profile.".to_string(),
                "If you expected an existing profile, check OPENVTC_CONFIG_PATH and \
                 --profile / OPENVTC_CONFIG_PROFILE point where you think they do."
                    .to_string(),
            ],
        },

        OpenVTCError::ConfigVersionUnsupported { found, expected } => Diagnosis {
            headline: "This configuration predates the current account model.".to_string(),
            error: err.to_string(),
            cause: format!(
                "The config on disk is format v{found}; this build requires v{expected}, \
                 and the two cannot be migrated in place."
            ),
            context,
            checks: Vec::new(),
            remedies: vec![
                "Export a backup from the older OpenVTC build first if you still have it."
                    .to_string(),
                "Then restart: OpenVTC will offer to delete the old config and run setup."
                    .to_string(),
            ],
        },

        // The genuinely network-shaped failures — the only ones the old fixed
        // hint was ever right about.
        OpenVTCError::Vta(reason) => Diagnosis {
            headline: "Could not reach or use the VTA.".to_string(),
            error: err.to_string(),
            cause: format!(
                "Your local configuration and keys loaded fine; the failure is between this \
                 machine and the VTA/mediator. ({reason})"
            ),
            context,
            checks: vec![
                format!("openvtc health --profile {profile}"),
                "check DNS/proxy/VPN reachability to the VTA host".to_string(),
            ],
            remedies: vec![
                "Confirm the VTA and mediator are up and reachable from this network.".to_string(),
                "Run `openvtc health` for a per-DID resolution and transport map.".to_string(),
                "Retry — a mediator restart invalidates in-flight sessions.".to_string(),
            ],
        },

        OpenVTCError::Auth(reason) => Diagnosis {
            headline: "The VTA rejected this identity.".to_string(),
            error: err.to_string(),
            cause: format!(
                "The VTA was reached, so the network is fine; it declined the \
                 authentication handshake. ({reason})"
            ),
            context,
            checks: vec![format!("openvtc health --profile {profile}")],
            remedies: vec![
                "Confirm this profile's DID is still registered with that VTA.".to_string(),
                "Check the VTA's own logs for the rejection reason — the client is only \
                 told that it failed."
                    .to_string(),
                "Do NOT reset the profile; the keys are intact.".to_string(),
            ],
        },

        OpenVTCError::Resolver(reason) => Diagnosis {
            headline: "A DID could not be resolved.".to_string(),
            error: err.to_string(),
            cause: format!(
                "Resolution failed, which is a network or DID-document problem rather than \
                 a local one. ({reason})"
            ),
            context,
            checks: vec![format!("openvtc health --profile {profile}")],
            remedies: vec![
                "Check that the did:webvh host is reachable and serving its did.jsonl.".to_string(),
                "Run `openvtc health` to see which DIDs resolve and which do not.".to_string(),
            ],
        },

        // Anything else: say plainly that it is unclassified rather than
        // guessing, and never suggest a destructive remedy on a guess.
        other => Diagnosis {
            headline: "Startup failed.".to_string(),
            error: other.to_string(),
            cause: "This failure is not one OpenVTC has specific guidance for.".to_string(),
            context,
            checks: vec![
                format!("openvtc health --profile {profile}"),
                "OPENVTC_DEBUG_LOG=/tmp/openvtc.log openvtc   # full trace".to_string(),
            ],
            remedies: vec![
                "Re-run with OPENVTC_DEBUG_LOG set and check the log for the first error."
                    .to_string(),
                "Report the error text above with that log.".to_string(),
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> DiagnosisContext {
        DiagnosisContext::new("default")
    }

    /// The regression this module exists for: a missing credential is a local
    /// failure and must not be described as a network one.
    #[test]
    fn missing_credential_does_not_mention_the_network() {
        let err = OpenVTCError::SecureStore {
            fault: SecureStoreFault::Missing,
            profile: "default".to_string(),
            detail: "No matching credential found".to_string(),
        };
        let d = diagnose(&err, &ctx());
        // The cause may *rule out* the network ("nothing on the network is
        // involved") — what must never happen is the remedies sending the user
        // off to check it, which is what the old fixed hint did.
        let advice = format!("{} {:?}", d.headline, d.remedies).to_lowercase();
        assert!(!advice.contains("network"), "advice: {advice}");
        assert!(!advice.contains("mediator"), "advice: {advice}");
        assert!(!advice.contains("reachable"), "advice: {advice}");
        assert!(d.cause.to_lowercase().contains("credential store"));
        // And a restore must be offered before the destructive reset.
        let reset = d
            .remedies
            .iter()
            .position(|r| r.contains("--setup"))
            .expect("reset remedy present");
        let restore = d
            .remedies
            .iter()
            .position(|r| r.to_lowercase().contains("restore"))
            .expect("restore remedy present");
        assert!(
            restore < reset,
            "reset must never be offered before restore"
        );
    }

    /// A locked store must never advise a reset: the keys are still there.
    #[test]
    fn unavailable_store_never_advises_a_reset_first() {
        let err = OpenVTCError::SecureStore {
            fault: SecureStoreFault::Unavailable,
            profile: "default".to_string(),
            detail: "keyring is locked".to_string(),
        };
        let d = diagnose(&err, &ctx());
        assert!(!d.remedies.is_empty());
        assert!(
            !d.remedies[0].to_lowercase().contains("setup"),
            "a locked store must not lead with a destructive remedy"
        );
    }

    /// A wrong passphrase is recoverable; the advice must say so.
    #[test]
    fn decrypt_failure_says_nothing_is_lost() {
        let err = OpenVTCError::Decrypt("bad tag".to_string());
        let d = diagnose(&err, &ctx());
        assert!(d.cause.to_lowercase().contains("nothing is lost"));
    }

    /// A genuine VTA failure is the one case that *should* talk about the
    /// network — the old blanket hint was not wrong here, only everywhere else.
    #[test]
    fn vta_failure_still_points_at_the_network() {
        let err = OpenVTCError::Vta("connect timed out".to_string());
        let d = diagnose(&err, &ctx());
        let blob = format!("{} {:?}", d.cause, d.remedies).to_lowercase();
        assert!(blob.contains("network") || blob.contains("reachable"));
    }

    /// The pasteable report and the on-screen report must not diverge: both
    /// are built from the same fields, and this pins the ones that matter.
    #[test]
    fn plain_report_carries_every_section() {
        let err = OpenVTCError::SecureStore {
            fault: SecureStoreFault::Missing,
            profile: "default".to_string(),
            detail: "No matching credential found".to_string(),
        };
        let d = diagnose(&err, &ctx());
        let text = d.render_plain();
        assert!(text.contains(&d.headline));
        assert!(text.contains("No matching credential found"));
        assert!(text.contains("Details"));
        assert!(text.contains("What to try, in order"));
        for remedy in &d.remedies {
            assert!(text.contains(remedy.as_str()), "missing remedy: {remedy}");
        }
    }

    /// Every diagnosis must carry the profile, or the user cannot tell which
    /// of several profiles the message is about.
    #[test]
    fn every_diagnosis_names_the_profile() {
        let errs = [
            OpenVTCError::SecureStore {
                fault: SecureStoreFault::Corrupt,
                profile: "work".to_string(),
                detail: "bad json".to_string(),
            },
            OpenVTCError::Auth("rejected".to_string()),
            OpenVTCError::MutexPoisoned("x".to_string()),
        ];
        for err in &errs {
            let d = diagnose(err, &DiagnosisContext::new("work"));
            assert!(
                d.context.iter().any(|(k, v)| k == "Profile" && v == "work"),
                "{err} lost the profile"
            );
            assert!(!d.headline.is_empty());
            assert!(!d.remedies.is_empty(), "{err} offered no remedy");
        }
    }
}
