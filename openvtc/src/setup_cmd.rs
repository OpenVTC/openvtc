/*! `openvtc setup --vta-did …` — the wizard's "new account with a VTA" route,
 * headless.
 *
 * Same steps, same core calls: unlock code, resolve the VTA and mint the setup
 * DID, print the PNM grant command, poll provisioning until the grant lands,
 * create the State-A account, then re-load it to prove it was saved.
 */

use crate::headless::{self, Admin, progress, step, warn};
use crate::state_handler::{
    DeferredLoad,
    setup_sequence::{
        Completion, ConfigProtection, MessageType,
        config::ConfigExtension,
        provision_failure::{self, ProvisionFailure},
    },
    setup_vta_actions,
    state::State,
};
use crate::ui::pages::setup_flow::vta_acl_instructions::{DEFAULT_CONTEXT_ID, PnmCommands};
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

/// The wizard's default context id (`vta_acl_instructions.rs`).
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
        Arg::new("wait")
            .long("wait")
            .value_name("DURATION")
            .requires("vta-did")
            .default_value("30m")
            .value_parser(headless::parse_wait)
            .help(
                "Headless setup: how long to wait for the VTA grant, e.g. 90s, \
                 30m, 1h (the grant itself lasts 1h)",
            ),
    ]
}

/// True when `setup` was given the headless flags.
pub fn requested(args: &ArgMatches) -> bool {
    args.get_one::<String>("vta-did").is_some()
}

/// Run the headless setup. The caller holds the profile lock.
pub async fn run(args: &ArgMatches, profile: &str) -> Result<()> {
    let vta_did = args
        .get_one::<String>("vta-did")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .context("--vta-did is empty")?;
    let context_id = args
        .get_one::<String>("context")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .context("--context is empty")?;
    let wait = *args.get_one::<Duration>("wait").expect("defaulted");
    let unlock_path = args
        .get_one::<String>("unlock-code-file")
        .expect("required with --vta-did");

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
    step(format!("Resolving VTA {vta_did}"));
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
    let pnm = PnmCommands::for_did(&setup_did, &context_id);
    println!("Ask the VTA admin to run this in their PNM session (new context):");
    println!();
    println!("{}", pnm.create_context);
    println!();
    println!("If context `{context_id}` already exists, use instead:");
    println!();
    println!("{}", pnm.grant_existing);
    println!();
    println!("The grant lasts 1 hour and the setup DID can use it once.");
    println!();

    // 4. Poll provisioning until the grant appears (the wizard's step-2 retry).
    step(format!("Waiting up to {}s for the grant", wait.as_secs()));
    let deadline = Instant::now() + wait;
    let mut pause = POLL_FIRST;
    let client = loop {
        state.setup.vta.messages.clear();
        let attempt = setup_vta_actions::handle_vta_start_provision(
            &mut state,
            &state_tx,
            context_id.clone(),
            None,
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
                        "timed out after {}s waiting for the VTA grant. Re-run `openvtc setup \
                         --vta-did …` — a new setup DID is minted, so the admin must grant that one.",
                        wait.as_secs()
                    );
                }
                let why = if failure == ProvisionFailure::Unreachable {
                    "VTA not reachable yet"
                } else {
                    "not granted yet"
                };
                progress(format!("{why}; retrying in {}s", pause.as_secs()));
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
    step(format!("Saving account `{profile}`"));
    progress("Your OS may ask to allow access to its secure storage.");
    let created = Config::create_account(&state.setup, profile).await;
    client.shutdown().await;
    created.context("couldn't create the OpenVTC account")?;

    // 6. Prove it was saved: load it back the way the app does.
    step("Verifying the saved account");
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

/// Load the account back exactly as startup does.
async fn reload(profile: &str, passphrase: &str) -> Result<Config> {
    let deferred = DeferredLoad {
        profile: profile.to_string(),
        public_config: Config::load_step1(profile).context("saved account not found")?,
        unlock_passphrase: Some(UnlockCode::from_string(passphrase)?),
        #[cfg(feature = "openpgp-card")]
        user_pin: None,
    };
    let (config, _, _) = headless::load_account(deferred, Admin::Drop)
        .await
        .context("the saved account could not be loaded back")?;
    Ok(config)
}

fn print_messages(messages: &[MessageType]) {
    for m in messages {
        match m {
            MessageType::Info(s) => progress(s),
            MessageType::Error(s) => warn(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            setup.get_one::<Duration>("wait"),
            Some(&Duration::from_secs(1800))
        );

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
