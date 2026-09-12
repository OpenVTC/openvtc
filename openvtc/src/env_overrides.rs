//! Environment overrides for a loaded [`Config`].
//!
//! `OPENVTC_VTA_URL`, `OPENVTC_VTA_DID` and `OPENVTC_MEDIATOR_DID` name the
//! parties this client authenticates to, so they are trust anchors, not
//! preferences. Only a build compiled with the `dev-overrides` feature honours
//! them, and then only for the current run:
//!
//! - each value is validated (a DID must parse, the URL must be http(s));
//! - it is applied to the runtime config only, and every save keeps writing the
//!   persisted value ([`Config::runtime_trust_overrides`],
//!   [`Config::set_active_mediator_did_runtime`]);
//! - the TUI shows a persistent `DEV OVERRIDE` indicator for the session.
//!
//! A build without the feature never applies them. Each one that is set is
//! reported as ignored, on stderr before the TUI starts and in the activity log.
//!
//! `OPENVTC_FRIENDLY_NAME` is cosmetic and honoured by every build.

use crate::state_handler::main_page::MainPageState;
use openvtc_core::config::Config;

/// Pins the VTA REST base URL (and, in the setup wizard, skips DID resolution).
pub(crate) const VTA_URL_VAR: &str = "OPENVTC_VTA_URL";
/// Replaces the VTA DID.
pub(crate) const VTA_DID_VAR: &str = "OPENVTC_VTA_DID";
/// Replaces the active persona's mediator DID.
pub(crate) const MEDIATOR_DID_VAR: &str = "OPENVTC_MEDIATOR_DID";
/// Cosmetic display name; not a trust anchor.
const FRIENDLY_NAME_VAR: &str = "OPENVTC_FRIENDLY_NAME";

/// Every variable that can move a trust anchor.
pub(crate) const TRUST_ANCHOR_VARS: [&str; 3] = [VTA_URL_VAR, VTA_DID_VAR, MEDIATOR_DID_VAR];

/// Why a set variable was not applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IgnoreReason {
    /// This build was compiled without `dev-overrides`.
    #[cfg_attr(
        feature = "dev-overrides",
        allow(dead_code, reason = "only a release build constructs it")
    )]
    ReleaseBuild,
    /// The value did not validate.
    #[cfg(feature = "dev-overrides")]
    Invalid(String),
    /// The profile has nowhere to apply it.
    #[cfg(feature = "dev-overrides")]
    NotApplicable(&'static str),
}

/// A trust-anchor variable that was set but not applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Ignored {
    pub var: &'static str,
    pub reason: IgnoreReason,
}

impl Ignored {
    /// One line for stderr, the activity log and the setup wizard.
    pub(crate) fn message(&self) -> String {
        match &self.reason {
            IgnoreReason::ReleaseBuild => format!(
                "{} is set but ignored: release builds do not accept trust-anchor overrides.",
                self.var
            ),
            #[cfg(feature = "dev-overrides")]
            IgnoreReason::Invalid(why) => format!("{} is set but ignored: {why}.", self.var),
            #[cfg(feature = "dev-overrides")]
            IgnoreReason::NotApplicable(why) => {
                format!("{} is set but ignored: {why}.", self.var)
            }
        }
    }
}

/// What [`apply_from`] did with the trust-anchor variables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OverrideReport {
    /// Variables applied to the runtime config, with the value used. Only ever
    /// non-empty in a `dev-overrides` build.
    pub applied: Vec<(&'static str, String)>,
    /// Variables that were set but not applied.
    pub ignored: Vec<Ignored>,
}

impl OverrideReport {
    /// The persistent indicator text, when any override is in effect.
    pub(crate) fn banner(&self) -> Option<String> {
        if self.applied.is_empty() {
            return None;
        }
        let parts: Vec<String> = self
            .applied
            .iter()
            .map(|(var, value)| format!("{} → {value}", label(var)))
            .collect();
        Some(format!("DEV OVERRIDE: {}", parts.join(" · ")))
    }
}

fn label(var: &str) -> &str {
    match var {
        VTA_URL_VAR => "VTA",
        VTA_DID_VAR => "VTA DID",
        MEDIATOR_DID_VAR => "mediator",
        other => other,
    }
}

/// A set, non-blank value. An exported-but-empty variable reads as unset.
fn non_blank(env: &impl Fn(&str) -> Option<String>, var: &str) -> Option<String> {
    env(var)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Apply the `OPENVTC_*` overrides read from the process environment.
pub(crate) fn apply_env_overrides(config: &mut Config) -> OverrideReport {
    apply_from(config, |k| std::env::var(k).ok())
}

/// Apply overrides read through `env`, so tests supply their own environment
/// instead of mutating the process's.
pub(crate) fn apply_from(
    config: &mut Config,
    env: impl Fn(&str) -> Option<String>,
) -> OverrideReport {
    let mut report = OverrideReport::default();
    for var in TRUST_ANCHOR_VARS {
        if let Some(value) = non_blank(&env, var) {
            apply_trust_anchor(config, var, value, &mut report);
        }
    }
    if let Some(name) = env(FRIENDLY_NAME_VAR) {
        config.public.friendly_name = name;
    }
    report
}

#[cfg(not(feature = "dev-overrides"))]
fn apply_trust_anchor(
    _config: &mut Config,
    var: &'static str,
    _value: String,
    report: &mut OverrideReport,
) {
    report.ignored.push(Ignored {
        var,
        reason: IgnoreReason::ReleaseBuild,
    });
}

#[cfg(feature = "dev-overrides")]
fn apply_trust_anchor(
    config: &mut Config,
    var: &'static str,
    value: String,
    report: &mut OverrideReport,
) {
    const NOT_VTA: IgnoreReason = IgnoreReason::NotApplicable("this profile is not VTA-managed");
    let outcome = match var {
        VTA_URL_VAR => parse_vta_url(&value).and_then(|url| {
            if config.override_vta_url_runtime(&url) {
                Ok(url)
            } else {
                Err(NOT_VTA)
            }
        }),
        VTA_DID_VAR => parse_did(&value).and_then(|did| {
            if config.override_vta_did_runtime(&did) {
                Ok(did)
            } else {
                Err(NOT_VTA)
            }
        }),
        MEDIATOR_DID_VAR => parse_did(&value).and_then(|did| {
            if config.set_active_mediator_did_runtime(&did) {
                Ok(did)
            } else {
                Err(IgnoreReason::NotApplicable(
                    "this profile has no persona to set a mediator on",
                ))
            }
        }),
        _ => return,
    };
    match outcome {
        Ok(value) => report.applied.push((var, value)),
        Err(reason) => report.ignored.push(Ignored { var, reason }),
    }
}

/// Accept only an absolute http(s) URL with a host. The value is returned as
/// given (trimmed): `Url`'s own rendering adds a trailing `/`, which would turn
/// `{base}/auth/challenge` into `//auth/challenge`.
#[cfg(feature = "dev-overrides")]
pub(crate) fn parse_vta_url(raw: &str) -> Result<String, IgnoreReason> {
    let url = url::Url::parse(raw)
        .map_err(|e| IgnoreReason::Invalid(format!("not a valid URL ({e})")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none_or(str::is_empty) {
        return Err(IgnoreReason::Invalid(
            "must be an http:// or https:// URL with a host".to_string(),
        ));
    }
    Ok(raw.to_string())
}

#[cfg(feature = "dev-overrides")]
fn parse_did(raw: &str) -> Result<String, IgnoreReason> {
    raw.parse::<affinidi_tdk::did_common::DID>()
        .map(|_| raw.to_string())
        .map_err(|e| IgnoreReason::Invalid(format!("not a valid DID ({e})")))
}

/// The setup wizard's view of `OPENVTC_VTA_URL`, which it reads on its own
/// before any config exists.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WizardUrlOverride {
    /// Not set (or blank).
    Unset,
    /// Set, but not used; the message says why.
    Ignored(String),
    /// Use this REST base URL (`dev-overrides` builds only).
    #[cfg_attr(
        not(feature = "dev-overrides"),
        allow(dead_code, reason = "only a dev-overrides build constructs it")
    )]
    Active(String),
}

/// Gate an already-normalized `OPENVTC_VTA_URL` value for the setup wizard.
pub(crate) fn wizard_vta_url_override(normalized: Option<String>) -> WizardUrlOverride {
    let Some(raw) = normalized else {
        return WizardUrlOverride::Unset;
    };
    #[cfg(not(feature = "dev-overrides"))]
    {
        let _ = raw;
        WizardUrlOverride::Ignored(
            Ignored {
                var: VTA_URL_VAR,
                reason: IgnoreReason::ReleaseBuild,
            }
            .message(),
        )
    }
    #[cfg(feature = "dev-overrides")]
    match parse_vta_url(&raw) {
        Ok(url) => WizardUrlOverride::Active(url),
        Err(reason) => WizardUrlOverride::Ignored(
            Ignored {
                var: VTA_URL_VAR,
                reason,
            }
            .message(),
        ),
    }
}

/// One stderr line to print before the TUI takes the terminal, or `None` when
/// no trust-anchor variable is set.
pub(crate) fn startup_notice(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    let set: Vec<&str> = TRUST_ANCHOR_VARS
        .into_iter()
        .filter(|var| non_blank(&env, var).is_some())
        .collect();
    if set.is_empty() {
        return None;
    }
    let names = set.join(", ");
    if cfg!(feature = "dev-overrides") {
        Some(format!(
            "DEV OVERRIDE: {names} will be applied for this run only and never saved \
             (dev-overrides build)."
        ))
    } else {
        let verb = if set.len() == 1 { "is" } else { "are" };
        Some(format!(
            "{names} {verb} set but ignored: release builds do not accept trust-anchor overrides."
        ))
    }
}

/// Put the report in front of the user: every ignored variable goes to the
/// activity log, and an applied override becomes the persistent indicator.
pub(crate) fn surface(report: &OverrideReport, main_page: &mut MainPageState) {
    for ignored in &report.ignored {
        let message = ignored.message();
        tracing::warn!("{message}");
        main_page.log(message);
    }
    if let Some(banner) = report.banner() {
        tracing::warn!("{banner}");
        main_page.log(format!("{banner} (this run only, not saved)"));
        main_page.dev_override = Some(banner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_tdk::messaging::profiles::{ATMProfile, ATMProfileInner};
    use openvtc_core::config::secured_config::SecuredConfig;
    use openvtc_core::config::{
        KeyBackend,
        account::{PersonaId, PersonaRecord},
    };
    use openvtc_core::identity::IdentityContext;
    use secrecy::{SecretBox, SecretString};
    use std::sync::Arc;

    const LEGIT_URL: &str = "https://legit-vta.affinidi.example";
    const LEGIT_DID: &str = "did:webvh:legit-vta.example";
    const OVERRIDE_URL: &str = "http://127.0.0.1:9099";
    const OVERRIDE_DID: &str = "did:web:127.0.0.1%3A9099";
    const PERSISTED_MEDIATOR: &str = "did:web:mediator.example.com";
    const OVERRIDE_MEDIATOR: &str = "did:web:127.0.0.1%3A7037";

    /// A VTA-managed config, as the regression harness built it.
    fn vta_config(vta_url: &str, vta_did: &str) -> Config {
        Config {
            public: Default::default(),
            private: Default::default(),
            key_backend: KeyBackend::Vta {
                credential_bundle: SecretString::new("".into()),
                credential_did: String::new(),
                credential_private_key: SecretString::new("".into()),
                vta_did: vta_did.to_string(),
                vta_url: vta_url.to_string(),
                mediator_did: None,
                encryption_seed: SecretBox::new(Box::new(vec![0u8; 32])),
            },
            key_info: Default::default(),
            protection_method: Default::default(),
            #[cfg(feature = "openpgp-card")]
            token_admin_pin: None,
            #[cfg(feature = "openpgp-card")]
            token_user_pin: SecretString::new("".into()),
            unlock_code: None,
            account: Default::default(),
            protected_key: None,
            integrity: Default::default(),
            identities: Default::default(),
            active_persona: None,
            runtime_trust_overrides: None,
        }
    }

    /// Add one persona, with matching account record and runtime identity, whose
    /// mediator is `PERSISTED_MEDIATOR`.
    fn with_persona(mut config: Config) -> (Config, PersonaId) {
        let pid = PersonaId::new();
        let did = "did:web:alice.example.com";
        config.account.personas.insert(
            pid,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id: pid,
                did: did.to_string(),
                did_document: None,
                key_refs: vec![],
                mediator_did: Some(PERSISTED_MEDIATOR.to_string()),
                origin_context_id: "openvtc/alice".into(),
                created_at: chrono::Utc::now(),
                label: None,
            },
        );
        config.identities.insert(
            pid,
            IdentityContext {
                persona_id: pid,
                did: did.to_string(),
                document: serde_json::from_value(serde_json::json!({ "id": did }))
                    .expect("minimal DID document deserializes"),
                profile: Arc::new(ATMProfile {
                    inner: Arc::new(ATMProfileInner {
                        did: did.to_string(),
                        alias: did.to_string(),
                        mediator: Arc::new(None),
                    }),
                }),
                mediator_did: Some(PERSISTED_MEDIATOR.to_string()),
            },
        );
        (config, pid)
    }

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.to_string())
        }
    }

    fn vta_of(backend: &KeyBackend) -> (String, String) {
        match backend {
            KeyBackend::Vta {
                vta_url, vta_did, ..
            } => (vta_url.clone(), vta_did.clone()),
            KeyBackend::Bip32 { .. } => panic!("expected a VTA key backend"),
        }
    }

    fn ignored_vars(report: &OverrideReport) -> Vec<&'static str> {
        report.ignored.iter().map(|i| i.var).collect()
    }

    fn account_mediator(config: &Config, pid: PersonaId) -> Option<String> {
        config
            .account
            .personas
            .get(&pid)
            .and_then(|p| p.mediator_did.clone())
    }

    #[cfg(not(feature = "dev-overrides"))]
    #[test]
    fn release_build_ignores_trust_anchor_env() {
        let mut config = vta_config(LEGIT_URL, LEGIT_DID);

        let report = apply_from(
            &mut config,
            env_of(&[(VTA_URL_VAR, OVERRIDE_URL), (VTA_DID_VAR, OVERRIDE_DID)]),
        );

        assert_eq!(
            vta_of(&config.key_backend),
            (LEGIT_URL.to_string(), LEGIT_DID.to_string()),
            "a release build must not move the VTA trust anchor"
        );
        assert!(report.applied.is_empty());
        assert_eq!(ignored_vars(&report), vec![VTA_URL_VAR, VTA_DID_VAR]);
        assert!(
            report
                .ignored
                .iter()
                .all(|i| i.reason == IgnoreReason::ReleaseBuild)
        );
        assert_eq!(
            report.ignored[0].message(),
            "OPENVTC_VTA_URL is set but ignored: release builds do not accept trust-anchor overrides."
        );
        assert_eq!(config.runtime_trust_overrides, None);
        assert_eq!(report.banner(), None);
    }

    /// The persistence half of the same finding, in the build that ships.
    ///
    /// An override did not merely point the running process at another VTA: the
    /// next save wrote it, through `Config::save` -> `SecuredConfig::from` ->
    /// `SecuredConfig::save` -> the keyring, so one launch with the variable set
    /// re-anchored the profile for every launch after it. That chain is why an
    /// unchanged live config is only half the guarantee — what a save *would*
    /// write has to carry the legitimate anchors too.
    ///
    /// Asserted on the two values a save reads, the coalesced-save snapshot and
    /// the `SecuredConfig` built from the live config, rather than on the
    /// keyring: the keyring is the operator's, and a test has no business in it.
    #[cfg(not(feature = "dev-overrides"))]
    #[test]
    fn release_build_override_never_reaches_the_save_snapshot() {
        let mut config = vta_config(LEGIT_URL, LEGIT_DID);

        let report = apply_from(
            &mut config,
            env_of(&[(VTA_URL_VAR, OVERRIDE_URL), (VTA_DID_VAR, OVERRIDE_DID)]),
        );
        assert_eq!(ignored_vars(&report), vec![VTA_URL_VAR, VTA_DID_VAR]);

        let snapshot = config.clone_for_save().expect("snapshot");
        assert_eq!(
            vta_of(&snapshot.key_backend),
            (LEGIT_URL.to_string(), LEGIT_DID.to_string()),
            "a save taken after an ignored override must still write the persisted anchor"
        );

        let secured = SecuredConfig::from(&config);
        assert_eq!(
            secured.vta_url.as_deref(),
            Some(LEGIT_URL),
            "the keyring record must keep the persisted VTA URL"
        );
        assert_eq!(
            secured.vta_did.as_deref(),
            Some(LEGIT_DID),
            "the keyring record must keep the persisted VTA DID"
        );
    }

    #[cfg(not(feature = "dev-overrides"))]
    #[test]
    fn release_build_still_honours_the_friendly_name() {
        let mut config = vta_config(LEGIT_URL, LEGIT_DID);

        let report = apply_from(&mut config, env_of(&[(FRIENDLY_NAME_VAR, "Dev Box")]));

        assert_eq!(config.public.friendly_name, "Dev Box");
        assert_eq!(report, OverrideReport::default());
    }

    #[cfg(not(feature = "dev-overrides"))]
    #[test]
    fn release_build_startup_notice_says_the_variables_are_ignored() {
        let notice = startup_notice(env_of(&[(VTA_URL_VAR, OVERRIDE_URL)]));
        assert_eq!(
            notice.as_deref(),
            Some(
                "OPENVTC_VTA_URL is set but ignored: release builds do not accept trust-anchor overrides."
            )
        );
        assert_eq!(startup_notice(env_of(&[])), None);
    }

    #[cfg(not(feature = "dev-overrides"))]
    #[test]
    fn release_build_wizard_ignores_the_url_override() {
        assert!(matches!(
            wizard_vta_url_override(Some(OVERRIDE_URL.to_string())),
            WizardUrlOverride::Ignored(message) if message.contains("release builds")
        ));
        assert_eq!(wizard_vta_url_override(None), WizardUrlOverride::Unset);
    }

    #[cfg(feature = "dev-overrides")]
    #[test]
    fn dev_build_applies_but_does_not_persist() {
        let mut config = vta_config(LEGIT_URL, LEGIT_DID);

        let report = apply_from(
            &mut config,
            env_of(&[(VTA_URL_VAR, OVERRIDE_URL), (VTA_DID_VAR, OVERRIDE_DID)]),
        );

        // Applied at runtime …
        assert_eq!(
            vta_of(&config.key_backend),
            (OVERRIDE_URL.to_string(), OVERRIDE_DID.to_string())
        );
        assert_eq!(
            report.applied,
            vec![
                (VTA_URL_VAR, OVERRIDE_URL.to_string()),
                (VTA_DID_VAR, OVERRIDE_DID.to_string()),
            ]
        );
        assert!(report.ignored.is_empty());
        let banner = report.banner().expect("an applied override has a banner");
        assert!(banner.starts_with("DEV OVERRIDE: VTA → http://127.0.0.1:9099"));

        // … but the coalesced-save snapshot still carries the originals …
        let snapshot = config.clone_for_save().expect("snapshot");
        assert_eq!(
            vta_of(&snapshot.key_backend),
            (LEGIT_URL.to_string(), LEGIT_DID.to_string()),
            "the save snapshot must keep the persisted VTA anchor"
        );
        assert_eq!(snapshot.runtime_trust_overrides, None);

        // … and so does a direct `save` / `export` of the live config.
        let secured = SecuredConfig::from(&config);
        assert_eq!(secured.vta_url.as_deref(), Some(LEGIT_URL));
        assert_eq!(secured.vta_did.as_deref(), Some(LEGIT_DID));
    }

    #[cfg(feature = "dev-overrides")]
    #[test]
    fn dev_build_rejects_values_that_do_not_validate() {
        for (url, did) in [
            ("ftp://127.0.0.1:9099", "not-a-did"),
            ("127.0.0.1:9099", "did:"),
            ("http://", "did:web:"),
        ] {
            let mut config = vta_config(LEGIT_URL, LEGIT_DID);
            let pairs: &'static [(&'static str, &'static str)] =
                Box::leak(Box::new([(VTA_URL_VAR, url), (VTA_DID_VAR, did)]));

            let report = apply_from(&mut config, env_of(pairs));

            assert!(report.applied.is_empty(), "{url} / {did} must not apply");
            assert_eq!(ignored_vars(&report), vec![VTA_URL_VAR, VTA_DID_VAR]);
            assert!(
                report
                    .ignored
                    .iter()
                    .all(|i| matches!(i.reason, IgnoreReason::Invalid(_)))
            );
            assert_eq!(
                vta_of(&config.key_backend),
                (LEGIT_URL.to_string(), LEGIT_DID.to_string())
            );
            assert_eq!(config.runtime_trust_overrides, None);
        }
    }

    #[cfg(feature = "dev-overrides")]
    #[test]
    fn dev_build_wizard_validates_the_url_override() {
        assert_eq!(
            wizard_vta_url_override(Some(OVERRIDE_URL.to_string())),
            WizardUrlOverride::Active(OVERRIDE_URL.to_string())
        );
        assert!(matches!(
            wizard_vta_url_override(Some("file:///etc/passwd".to_string())),
            WizardUrlOverride::Ignored(_)
        ));
    }

    #[test]
    fn mediator_env_override_never_touches_account_record() {
        let (mut config, pid) = with_persona(vta_config(LEGIT_URL, LEGIT_DID));

        let report = apply_from(
            &mut config,
            env_of(&[(MEDIATOR_DID_VAR, OVERRIDE_MEDIATOR)]),
        );

        assert_eq!(
            account_mediator(&config, pid).as_deref(),
            Some(PERSISTED_MEDIATOR),
            "the persisted account record must never carry an env-supplied mediator"
        );
        let snapshot = config.clone_for_save().expect("snapshot");
        assert_eq!(
            account_mediator(&snapshot, pid).as_deref(),
            Some(PERSISTED_MEDIATOR)
        );

        #[cfg(feature = "dev-overrides")]
        {
            assert_eq!(config.mediator_did(), OVERRIDE_MEDIATOR);
            assert_eq!(
                report.applied,
                vec![(MEDIATOR_DID_VAR, OVERRIDE_MEDIATOR.to_string())]
            );
        }
        #[cfg(not(feature = "dev-overrides"))]
        {
            assert_eq!(config.mediator_did(), PERSISTED_MEDIATOR);
            assert_eq!(ignored_vars(&report), vec![MEDIATOR_DID_VAR]);
        }
    }

    #[test]
    fn blank_values_read_as_unset() {
        let mut config = vta_config(LEGIT_URL, LEGIT_DID);

        let report = apply_from(
            &mut config,
            env_of(&[
                (VTA_URL_VAR, "  "),
                (VTA_DID_VAR, ""),
                (MEDIATOR_DID_VAR, "\t"),
            ]),
        );

        assert_eq!(report, OverrideReport::default());
        assert_eq!(
            vta_of(&config.key_backend),
            (LEGIT_URL.to_string(), LEGIT_DID.to_string())
        );
    }

    #[test]
    fn surfacing_logs_ignored_and_pins_the_banner() {
        let mut main_page = MainPageState::default();
        let report = OverrideReport {
            applied: vec![(VTA_URL_VAR, OVERRIDE_URL.to_string())],
            ignored: vec![Ignored {
                var: VTA_DID_VAR,
                reason: IgnoreReason::ReleaseBuild,
            }],
        };

        surface(&report, &mut main_page);

        assert_eq!(
            main_page.dev_override.as_deref(),
            Some("DEV OVERRIDE: VTA → http://127.0.0.1:9099")
        );
        let log: Vec<&str> = main_page
            .activity_log
            .iter()
            .map(|e| e.summary.as_str())
            .collect();
        assert!(
            log.iter()
                .any(|l| l.contains("OPENVTC_VTA_DID is set but ignored"))
        );
        assert!(log.iter().any(|l| l.contains("DEV OVERRIDE")));
    }
}
