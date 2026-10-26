//! What the headless subcommands (`setup --vta-did`, `join`, `repos`,
//! `signing`) share: loading the account, the persona's mediator socket, the
//! `--persona` and `--wait` arguments, and progress output.

use std::time::Duration;

use affinidi_tdk::TDK;
use anyhow::{Context, Result, anyhow, bail};
use console::style;
use openvtc_core::config::Config;
use openvtc_core::config::account::PersonaId;
use openvtc_core::didcomm::{self, DIDCommEvent, Messaging};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use vta_sdk::client::VtaClient;

use crate::colors::{CLI_CAUTION, CLI_INFO, Themed};
use crate::redact_paths;
use crate::state_handler::DeferredLoad;

/// What to do with the admin VTA session a load opens.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Admin {
    /// Close it: the command never talks to the VTA as admin.
    Drop,
    /// Keep it, opening one when the load did not (as the TUI does).
    Open,
}

/// Decrypt the account the way the TUI does, failing hard.
pub async fn load_account(
    deferred: DeferredLoad,
    admin: Admin,
) -> Result<(Config, TDK, Option<VtaClient>)> {
    let mut tdk = TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()
            .map_err(|e| anyhow!("TDK config failed: {e}"))?,
        None,
    )
    .await
    .map_err(|e| anyhow!("TDK init failed: {e}"))?;

    #[cfg(feature = "openpgp-card")]
    struct TouchPrompt;
    #[cfg(feature = "openpgp-card")]
    impl openvtc_core::config::TokenInteractions for TouchPrompt {
        fn touch_notify(&self) {
            eprintln!("Touch your security token to continue…");
        }
        fn touch_completed(&self) {}
    }
    #[cfg(feature = "openpgp-card")]
    let no_token_pin = secrecy::SecretString::new(String::new().into());

    let (mut config, session) = Config::load_step2(
        &mut tdk,
        &deferred.profile,
        deferred.public_config,
        deferred.unlock_passphrase.as_ref(),
        #[cfg(feature = "openpgp-card")]
        deferred.user_pin.as_ref().unwrap_or(&no_token_pin),
        #[cfg(feature = "openpgp-card")]
        &TouchPrompt,
        None,
    )
    .await
    .map_err(|e| {
        anyhow!(
            "couldn't load the account: {}",
            redact_paths(&e.to_string())
        )
    })?;
    let _ = crate::env_overrides::apply_env_overrides(&mut config);

    let session = match (admin, session) {
        (Admin::Drop, Some(s)) => {
            s.shutdown().await;
            None
        }
        (Admin::Drop, None) => None,
        (Admin::Open, Some(s)) => Some(s),
        (Admin::Open, None) => {
            match openvtc_core::config::build_runtime_vta_client(&config.key_backend).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::debug!(error = %e, "no admin VTA session");
                    None
                }
            }
        }
    };
    Ok((config, tdk, session))
}

/// A messaging runtime with no listeners yet, holding the account's TSP
/// relationships. Shut it down with [`Messaging::shutdown`].
pub async fn start_messaging(config: &Config) -> (Messaging, UnboundedReceiver<DIDCommEvent>) {
    let (event_tx, events) = unbounded_channel();
    // Shut down explicitly; the token is never cancelled.
    let messaging =
        didcomm::start_empty_service(event_tx, tokio_util::sync::CancellationToken::new());
    messaging
        .tsp_store()
        .hydrate(&config.private.tsp_relationships)
        .await;
    (messaging, events)
}

/// Bring the persona's mediator socket up, so its replies are streamed.
pub async fn connect_persona(
    messaging: &Messaging,
    config: &Config,
    tdk: &TDK,
    persona: PersonaId,
    timeout: Duration,
) -> Result<()> {
    let spec = didcomm::persona_listener_config_for(config, tdk, persona)
        .await
        .ok_or_else(|| anyhow!("the persona has no messaging identity"))?;
    if !messaging.has_listener(&spec.id).await {
        didcomm::add_listener(messaging, &spec).await?;
    }
    messaging
        .wait_connected(&spec.id, timeout)
        .await
        .map_err(|e| anyhow!("the persona's mediator socket did not come up: {e}"))
}

/// `--persona`: a persona by DID, label (any case) or verified agent name.
pub fn find_persona(config: &Config, name: &str) -> Result<PersonaId> {
    let name = name.trim();
    let found: Vec<PersonaId> = config
        .account
        .personas
        .values()
        .filter(|p| {
            p.did == name
                || p.label
                    .as_deref()
                    .is_some_and(|l| l.eq_ignore_ascii_case(name))
                || config.agent_name_for(&p.did) == Some(name)
        })
        .map(|p| p.persona_id)
        .collect();
    match found.as_slice() {
        [one] => Ok(*one),
        [] => bail!("no persona '{name}'. {}", persona_listing(config)),
        _ => bail!(
            "more than one persona is called '{name}'; name it by DID. {}",
            persona_listing(config)
        ),
    }
}

/// The account's personas, for an error that asks to choose one.
pub fn persona_listing(config: &Config) -> String {
    let mut rows: Vec<String> = config
        .account
        .personas
        .values()
        .map(|p| {
            format!(
                "\n  {}  {}",
                p.label.as_deref().unwrap_or("(unlabelled)"),
                p.did
            )
        })
        .collect();
    if rows.is_empty() {
        return "The account has no personas.".into();
    }
    rows.sort();
    format!("Personas:{}", rows.concat())
}

/// An active membership a command acts in.
pub struct Membership {
    pub vtc_did: String,
    pub persona: PersonaId,
    pub label: String,
}

fn active_memberships(config: &Config) -> Vec<Membership> {
    config
        .account
        .memberships()
        .filter(|c| c.status.is_active())
        .map(|c| Membership {
            vtc_did: c.vtc_did.clone(),
            persona: c.persona_ref,
            label: crate::state_handler::community_label(
                config,
                &c.vtc_did,
                c.display_name.as_deref(),
                256,
            ),
        })
        .collect()
}

/// `--community`: an active membership by VTC DID or name; with none, the only one.
pub fn pick_community(config: &Config, wanted: Option<&str>) -> Result<Membership> {
    let active = active_memberships(config);
    let keys: Vec<(&str, &str)> = active
        .iter()
        .map(|m| (m.vtc_did.as_str(), m.label.as_str()))
        .collect();
    let i = match_community(&keys, wanted).map_err(|e| anyhow!(e))?;
    Ok(active.into_iter().nth(i).expect("index from the same list"))
}

/// The persona holding the account's active memberships, when only one does.
pub fn only_member(config: &Config) -> Result<PersonaId> {
    let mut members: Vec<PersonaId> = active_memberships(config)
        .into_iter()
        .map(|m| m.persona)
        .collect();
    members.sort();
    members.dedup();
    match members.as_slice() {
        [one] => Ok(*one),
        [] => bail!("{NO_MEMBERSHIP}"),
        _ => bail!(
            "several personas hold an active membership; choose one with --persona. {}",
            persona_listing(config)
        ),
    }
}

const NO_MEMBERSHIP: &str = "this account holds no active community membership";

/// Which of `(vtc_did, label)` a `--community` names; with none, the only one.
fn match_community(active: &[(&str, &str)], wanted: Option<&str>) -> Result<usize, String> {
    let names = || {
        active
            .iter()
            .map(|(did, label)| format!("\n  {label}  {did}"))
            .collect::<String>()
    };
    if active.is_empty() {
        return Err(NO_MEMBERSHIP.into());
    }
    let Some(wanted) = wanted.map(str::trim) else {
        return if active.len() == 1 {
            Ok(0)
        } else {
            Err(format!(
                "this account is in several communities; choose one with --community. \
                 Communities:{}",
                names()
            ))
        };
    };
    if let Some(i) = active.iter().position(|(did, _)| *did == wanted) {
        return Ok(i);
    }
    let by_name: Vec<usize> = active
        .iter()
        .enumerate()
        .filter(|(_, (_, label))| label.eq_ignore_ascii_case(wanted))
        .map(|(i, _)| i)
        .collect();
    match by_name.as_slice() {
        [i] => Ok(*i),
        [] => Err(format!("no community '{wanted}'. Communities:{}", names())),
        _ => Err(format!(
            "more than one community is called '{wanted}'; name it by VTC DID. Communities:{}",
            names()
        )),
    }
}

/// `--wait`: `90`, `90s`, `30m` or `2h`.
pub fn parse_wait(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    let (digits, unit) = match raw.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => raw.split_at(i),
        None => (raw, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("`{raw}` is not a duration (try 90s, 30m or 2h)"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => return Err(format!("`{raw}`: unit must be s, m or h")),
    };
    if secs == 0 {
        return Err("the wait must be longer than zero".to_string());
    }
    Ok(Duration::from_secs(secs))
}

/// Save the account, as the TUI does after a change.
pub fn save(config: &Config, profile: &str) -> Result<()> {
    config
        .save(
            profile,
            #[cfg(feature = "openpgp-card")]
            &|| eprintln!("Touch confirmation needed for decryption"),
        )
        .context("failed to save the account")
}

/// A step of the run.
pub fn step(line: impl std::fmt::Display) {
    eprintln!("{} {line}", style("•").themed(CLI_INFO));
}

/// Detail under a step.
pub fn progress(line: impl std::fmt::Display) {
    eprintln!("  {}", style(line).dim());
}

pub fn warn(line: impl std::fmt::Display) {
    eprintln!("{}", style(format!("warning: {line}")).themed(CLI_CAUTION));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_durations_parse() {
        assert_eq!(parse_wait("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_wait("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_wait(" 30m "), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_wait("2h"), Ok(Duration::from_secs(7200)));
        assert!(parse_wait("0").is_err());
        assert!(parse_wait("0m").is_err());
        assert!(parse_wait("5d").is_err());
        assert!(parse_wait("m").is_err());
        assert!(parse_wait("-1m").is_err());
        assert!(parse_wait("").is_err());
    }

    #[test]
    fn a_community_is_picked_by_did_name_or_being_the_only_one() {
        let one = [("did:web:a", "Alpha")];
        assert_eq!(match_community(&one, None), Ok(0));
        let two = [("did:web:a", "Alpha"), ("did:web:b", "Beta")];
        assert!(match_community(&two, None).is_err());
        assert_eq!(match_community(&two, Some("did:web:b")), Ok(1));
        assert_eq!(match_community(&two, Some("alpha")), Ok(0));
        assert!(match_community(&two, Some("Gamma")).is_err());
        let dup = [("did:web:a", "Same"), ("did:web:b", "Same")];
        assert!(match_community(&dup, Some("same")).is_err());
        assert!(match_community(&[], None).is_err());
    }
}
