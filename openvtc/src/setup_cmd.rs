/*! `openvtc setup --vta-did …` — the wizard's "new account with a VTA" route,
 * headless.
 *
 * Same steps, same core calls: unlock code, resolve the VTA and mint the setup
 * DID, print the PNM grant command, poll provisioning until the grant lands,
 * create the State-A account, then re-load it to prove it was saved.
 */

use crate::state_handler::{
    setup_sequence::{
        Completion, ConfigProtection, MessageType,
        config::ConfigExtension,
        provision_failure::{self, ProvisionFailure},
    },
    setup_vta_actions,
    state::State,
};
use anyhow::{Context, Result, bail};
use clap::{Arg, ArgMatches};
use openvtc_core::{
    config::{Config, KeyBackend, UnlockCode, public_config::PublicConfig},
    context_probe::ProbeOutcome,
    errors::OpenVTCError,
};
use secrecy::SecretBox;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use vta_sdk::provision_client::Protocol;

/// The wizard's default context id (`vta_acl_instructions.rs`).
const DEFAULT_CONTEXT_ID: &str = "openvtc";
const DEFAULT_WAIT: &str = "30m";
/// Pause between provisioning attempts while the grant is missing: starts
/// short, doubles, capped.
const POLL_FIRST: Duration = Duration::from_secs(5);
const POLL_MAX: Duration = Duration::from_secs(30);

/// Arguments of the headless path, added to the `setup` subcommand.
pub fn args() -> Vec<Arg> {
    vec![
        Arg::new("vta-did")
            .long("vta-did")
            .value_name("DID")
            .requires("unlock-code-file")
            .help(
                "Run setup without the wizard: create a new account on this VTA. \
                 Prints the PNM command for the VTA admin, waits for the grant, \
                 then saves the account.",
            ),
        Arg::new("unlock-code-file")
            .long("unlock-code-file")
            .value_name("PATH")
            .requires("vta-did")
            .help(
                "Headless setup: the new unlock passphrase, from the first line of \
                 PATH (or standard input when PATH is `-`). At least 8 characters.",
            ),
        Arg::new("context")
            .long("context")
            .value_name("ID")
            .requires("vta-did")
            .default_value(DEFAULT_CONTEXT_ID)
            .help("Headless setup: the VTA Trust Context to provision into"),
        Arg::new("transport")
            .long("transport")
            .value_name("TRANSPORT")
            .requires("vta-did")
            .value_parser(["auto", "tsp", "didcomm", "rest"])
            .default_value("auto")
            .help(
                "Headless setup: force one transport the VTA advertises instead of \
                 the automatic TSP > DIDComm > REST choice",
            ),
        Arg::new("wait")
            .long("wait")
            .value_name("DURATION")
            .requires("vta-did")
            .default_value(DEFAULT_WAIT)
            .help(
                "Headless setup: how long to wait for the VTA grant, e.g. 90s, \
                 30m, 1h (the grant itself lasts 1h)",
            ),
    ]
}

/// True when `setup` was given the headless flags.
pub fn requested(args: &ArgMatches) -> bool {
    args.contains_id("vta-did") && args.get_one::<String>("vta-did").is_some()
}

/// Run the headless setup. The caller holds the profile lock.
pub async fn run(args: &ArgMatches, profile: &str) -> Result<()> {
    let vta_did = args
        .get_one::<String>("vta-did")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .context("--vta-did is empty")?;
    let context_id = context_or_default(args.get_one::<String>("context").map(String::as_str));
    let transport = parse_transport(
        args.get_one::<String>("transport")
            .map(String::as_str)
            .unwrap_or("auto"),
    )?;
    let wait = parse_wait(
        args.get_one::<String>("wait")
            .map(String::as_str)
            .unwrap_or(DEFAULT_WAIT),
    )?;
    let unlock_path = args
        .get_one::<String>("unlock-code-file")
        .context("--unlock-code-file is required with --vta-did")?;

    refuse_existing_profile(profile)?;

    // 1. Unlock code (the wizard's unlock_code_set page). Validated here
    // because loading refuses anything shorter.
    let passphrase = zeroize::Zeroizing::new(crate::cli::read_unlock_code_file(unlock_path)?);
    openvtc_core::config::validate_passphrase(&passphrase)?;
    let key = openvtc_core::config::derive_passphrase_key(
        passphrase.as_bytes(),
        b"openvtc-unlock-code-v1",
    )?;

    let mut state = State::default();
    state.setup.protection =
        ConfigProtection::Passcode(Arc::new(SecretBox::new(Box::new(key.to_vec()))));
    // Nothing renders state here; sends to a closed channel are ignored.
    let (state_tx, _) = watch::channel(State::default());

    // 2. Resolve the VTA and mint the setup DID.
    step("Resolving VTA", &vta_did);
    setup_vta_actions::handle_vta_submit_did(&mut state, &state_tx, vta_did.clone()).await?;
    print_messages(&state.setup.vta.messages);
    if !matches!(state.setup.vta.completed, Completion::CompletedOK) {
        bail!("could not resolve the VTA or mint a setup DID");
    }
    let setup_did = state
        .setup
        .vta
        .setup_key
        .as_ref()
        .map(|k| k.did.clone())
        .context("setup DID was not minted")?;

    // 3. What the "ask your admin" page shows.
    println!();
    println!("Setup DID: {setup_did}");
    println!();
    println!("Ask the VTA admin to run this in their PNM session (new context):");
    println!();
    println!("{}", grant_new_context(&setup_did, &context_id));
    println!();
    println!("If context `{context_id}` already exists, use instead:");
    println!();
    println!("{}", grant_existing_context(&setup_did, &context_id));
    println!();
    println!("The grant lasts 1 hour and the setup DID can use it once.");
    println!();

    // 4. Poll provisioning until the grant appears (the wizard's step-2 retry).
    step(
        "Waiting for the grant",
        &format!("up to {}", format_wait(wait)),
    );
    let deadline = Instant::now() + wait;
    let mut pause = POLL_FIRST;
    let client = loop {
        state.setup.vta.messages.clear();
        let attempt = setup_vta_actions::handle_vta_start_provision(
            &mut state,
            &state_tx,
            context_id.clone(),
            transport,
        )
        .await?;
        if let Some(client) = attempt {
            break client;
        }
        let failure = provision_failure::classify(&state.setup.vta);
        match failure {
            ProvisionFailure::NotAuthorised | ProvisionFailure::Unreachable => {
                if Instant::now() + pause > deadline {
                    print_messages(&state.setup.vta.messages);
                    bail!(
                        "timed out after {} waiting for the VTA grant. Re-run `openvtc setup \
                         --vta-did …` — a new setup DID is minted, so the admin must grant that one.",
                        format_wait(wait)
                    );
                }
                let why = if failure == ProvisionFailure::Unreachable {
                    "VTA not reachable yet"
                } else {
                    "not granted yet"
                };
                eprintln!("  … {why}; retrying in {}s", pause.as_secs());
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(POLL_MAX);
            }
            ProvisionFailure::GrantSpent(problem) => {
                print_messages(&state.setup.vta.messages);
                bail!(
                    "the grant for {setup_did} cannot be used ({problem:?}). Ask the admin to \
                     run `pnm acl delete {setup_did}` and then the existing-context command \
                     above, then re-run."
                );
            }
            ProvisionFailure::Other => {
                print_messages(&state.setup.vta.messages);
                bail!("provisioning failed");
            }
        }
    };
    print_messages(&state.setup.vta.messages);

    // 5. An occupied context needs a decision the wizard asks for; refuse.
    if let Some(ProbeOutcome::Occupied(contents)) = &state.setup.vta.context_probe {
        client.shutdown().await;
        bail!(
            "Trust Context `{context_id}` already contains {}. Nothing was saved. Use a new \
             --context, or run the `openvtc setup` wizard to continue into it or recover it.",
            contents.summary()
        );
    }

    // The account is State A: VTA admin + top-level context. A persona is
    // minted later by the join flow, as in the wizard.
    step("Saving account", profile);
    eprintln!("  Your OS may ask to allow access to its secure storage.");
    let created = Config::create_account(&state.setup, profile).await;
    client.shutdown().await;
    created.context("couldn't create the OpenVTC account")?;

    // 6. Prove it was saved: load it back the way the app does.
    step("Verifying saved account", profile);
    let loaded = reload(profile, &passphrase).await?;
    let admin_did = state
        .setup
        .vta
        .admin_credential
        .as_ref()
        .map(|a| a.admin_did.clone())
        .unwrap_or_default();
    let (saved_admin, saved_mediator) = match &loaded.key_backend {
        KeyBackend::Vta {
            credential_did,
            mediator_did,
            ..
        } => (credential_did.clone(), mediator_did.clone()),
        _ => bail!("the saved account has no VTA backend"),
    };
    if saved_admin != admin_did || loaded.account.top_context_id != context_id {
        bail!("the saved account does not match what setup created");
    }

    println!();
    println!("Setup complete (profile `{profile}`).");
    println!("  VTA:         {}", loaded.account.vta_did);
    println!("  VTA context: {}", loaded.account.top_context_id);
    println!("  Admin DID:   {saved_admin}");
    if let Some(med) = saved_mediator {
        println!("  Mediator:    {med}");
    }
    if let Some(p) = state.setup.vta.protocol {
        println!("  Transport:   {}", p.label());
    }
    println!("  Persona:     none yet — one is minted when you join a community");
    Ok(())
}

/// Setup writes a fresh profile; overwriting one silently is not headless-safe.
fn refuse_existing_profile(profile: &str) -> Result<()> {
    match PublicConfig::load(profile) {
        Err(OpenVTCError::ConfigNotFound(_, _)) => Ok(()),
        Ok(_) => {
            bail!("profile `{profile}` already exists. Use another --profile, or remove it first.")
        }
        Err(e) => bail!("profile `{profile}` exists but cannot be read ({e}); not overwriting it"),
    }
}

/// Load the account back exactly as startup does (public config, secured
/// config, then the full account).
async fn reload(profile: &str, passphrase: &str) -> Result<Config> {
    let public_config = Config::load_step1(profile).context("saved account not found")?;
    let unlock = UnlockCode::from_string(passphrase)?;
    let mut tdk = affinidi_tdk::TDK::new(
        affinidi_tdk::common::config::TDKConfig::builder()
            .with_load_environment(false)
            .build()?,
        None,
    )
    .await?;

    #[cfg(feature = "openpgp-card")]
    struct NoToken;
    #[cfg(feature = "openpgp-card")]
    impl openvtc_core::config::TokenInteractions for NoToken {
        fn touch_notify(&self) {}
        fn touch_completed(&self) {}
    }
    #[cfg(feature = "openpgp-card")]
    let no_token_pin = secrecy::SecretString::new(String::new().into());

    let (config, session) = Config::load_step2(
        &mut tdk,
        profile,
        public_config,
        Some(&unlock),
        #[cfg(feature = "openpgp-card")]
        &no_token_pin,
        #[cfg(feature = "openpgp-card")]
        &NoToken,
        None,
    )
    .await
    .context("the saved account could not be loaded back")?;
    if let Some(session) = session {
        session.shutdown().await;
    }
    Ok(config)
}

fn step(what: &str, detail: &str) {
    eprintln!("==> {what}: {detail}");
}

fn print_messages(messages: &[MessageType]) {
    for m in messages {
        match m {
            MessageType::Info(s) => eprintln!("  {s}"),
            MessageType::Error(s) => eprintln!("  error: {s}"),
        }
    }
}

fn context_or_default(raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => DEFAULT_CONTEXT_ID.to_string(),
    }
}

fn parse_transport(raw: &str) -> Result<Option<Protocol>> {
    Ok(match raw {
        "auto" => None,
        "tsp" => Some(Protocol::Tsp),
        "didcomm" => Some(Protocol::DidComm),
        "rest" => Some(Protocol::Rest),
        other => bail!("unknown transport `{other}` (auto, tsp, didcomm, rest)"),
    })
}

/// `90`, `90s`, `30m`, `1h`.
fn parse_wait(raw: &str) -> Result<Duration> {
    let raw = raw.trim();
    let (num, mult) = match raw.char_indices().last() {
        Some((i, 's')) => (&raw[..i], 1),
        Some((i, 'm')) => (&raw[..i], 60),
        Some((i, 'h')) => (&raw[..i], 3600),
        _ => (raw, 1),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --wait `{raw}` (use e.g. 90s, 30m, 1h)"))?;
    let secs = n
        .checked_mul(mult)
        .filter(|s| *s > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid --wait `{raw}`"))?;
    Ok(Duration::from_secs(secs))
}

fn format_wait(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// The wizard's `[F2]` command (`vta_acl_instructions.rs`, `PnmCommands`).
fn grant_new_context(setup_did: &str, ctx: &str) -> String {
    format!(
        "pnm contexts create --id {ctx} --name \"OpenVTC\" \\\n  \
         --admin-did {setup_did} --admin-expires 1h --admin-holder --admin-handoff",
    )
}

/// The wizard's `[F3]` command.
fn grant_existing_context(setup_did: &str, ctx: &str) -> String {
    format!(
        "pnm acl create --did {setup_did} --role admin --contexts {ctx} \\\n  \
         --expires 1h --handoff --capabilities persona-holder",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_parses_units() {
        assert_eq!(parse_wait("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_wait("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_wait("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_wait(" 1h ").unwrap(), Duration::from_secs(3600));
        assert!(parse_wait("").is_err());
        assert!(parse_wait("0m").is_err());
        assert!(parse_wait("m").is_err());
        assert!(parse_wait("5d").is_err());
        assert!(parse_wait("-1m").is_err());
    }

    #[test]
    fn wait_formats_back() {
        assert_eq!(format_wait(Duration::from_secs(1800)), "30m");
        assert_eq!(format_wait(Duration::from_secs(7200)), "2h");
        assert_eq!(format_wait(Duration::from_secs(90)), "90s");
    }

    #[test]
    fn context_defaults_like_the_wizard() {
        assert_eq!(context_or_default(None), "openvtc");
        assert_eq!(context_or_default(Some("  ")), "openvtc");
        assert_eq!(context_or_default(Some(" my-ctx ")), "my-ctx");
    }

    #[test]
    fn transport_choices() {
        assert_eq!(parse_transport("auto").unwrap(), None);
        assert_eq!(parse_transport("tsp").unwrap(), Some(Protocol::Tsp));
        assert_eq!(parse_transport("didcomm").unwrap(), Some(Protocol::DidComm));
        assert_eq!(parse_transport("rest").unwrap(), Some(Protocol::Rest));
        assert!(parse_transport("ws").is_err());
    }

    #[test]
    fn grant_commands_match_the_wizard() {
        let did = "did:key:z6MkTest";
        assert_eq!(
            grant_new_context(did, "openvtc"),
            "pnm contexts create --id openvtc --name \"OpenVTC\" \\\n  \
             --admin-did did:key:z6MkTest --admin-expires 1h --admin-holder --admin-handoff"
        );
        assert!(
            grant_existing_context(did, "c1")
                .starts_with("pnm acl create --did did:key:z6MkTest --role admin --contexts c1 ")
        );
    }

    #[test]
    fn headless_flags_parse() {
        let m = crate::cli::cli()
            .try_get_matches_from([
                "openvtc",
                "setup",
                "--vta-did",
                "did:webvh:x:vta.example.com",
                "--unlock-code-file",
                "-",
            ])
            .expect("headless setup parses");
        let (_, setup) = m.subcommand().expect("setup");
        assert!(requested(setup));
        assert_eq!(setup.get_one::<String>("context").unwrap(), "openvtc");
        assert_eq!(setup.get_one::<String>("wait").unwrap(), "30m");

        let m = crate::cli::cli()
            .try_get_matches_from(["openvtc", "setup"])
            .expect("plain setup parses");
        let (_, setup) = m.subcommand().expect("setup");
        assert!(!requested(setup), "plain setup stays the wizard");

        assert!(
            crate::cli::cli()
                .try_get_matches_from(["openvtc", "setup", "--vta-did", "did:x"])
                .is_err(),
            "--vta-did needs --unlock-code-file"
        );
        assert!(
            crate::cli::cli()
                .try_get_matches_from(["openvtc", "setup", "--context", "c"])
                .is_err(),
            "--context alone is not headless"
        );
    }
}
