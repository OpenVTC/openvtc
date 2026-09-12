//! Standalone persona-DID minting.
//!
//! Mints a fresh, self-contained persona `did:webvh` into the account (D6)
//! *without* a join — the use case is handing the DID to a VTC so it can issue a
//! Verifiable Invitation Credential (VIC) bound to it; a later join then redeems
//! that VIC on the clean join-as-subject path (the VIC subject is one of our own
//! personas, so no subject-linkage proof is needed).
//!
//! This is the join flow's mint sub-sequence (`join_flow::run_join_sequence`)
//! minus the community/submit parts: pick a WebVH server, mint the DID via the
//! VTA, then persist through the shared [`ConfigExtension::mint_persona_into`].
//! The minted persona is an orphan (no community) until a join reuses it, and
//! shows in the identity pane's Personas list.
//!
//! Like a join, the mint asks where the persona lives: a new sub-context named
//! from its label (the default), a context already in use, or the top context.
//! Its keys and DID are minted in that context, which is recorded as the
//! persona's origin — so a later join with this persona is presented from it
//! ([`community_context`]).

use affinidi_tdk::TDK;
use anyhow::Result;
use vta_sdk::{client::VtaClient, protocols::did_management::create::WebvhPathMode};

use openvtc_core::config::{
    Config, KeyBackend,
    account::PersonaId,
    community_context::{self, ContextKind, ContextOption},
    context_path::parse_sub_context_id,
};
use openvtc_core::errors::OpenVTCError;

use crate::state_handler::join_flow;
use crate::state_handler::setup_sequence::{SetupState, config::ConfigExtension, vta};

/// What a new sub-context is called when the label has nothing a path segment
/// can hold.
const FALLBACK_SLUG: &str = "persona";

/// The contexts a standalone persona can be minted into — the choice a join
/// offers a new persona: a new sub-context named from `label` first, then every
/// context already in use, then the top context — and the new sub-context's
/// suggested last segment.
pub(crate) fn context_choice(config: &Config, label: &str) -> (Vec<ContextOption>, String) {
    let top = &config.account.top_context_id;
    let suggested = community_context::suggested_context_id(top, label, FALLBACK_SLUG, |id| {
        join_flow::context_taken(config, id)
    })
    .unwrap_or_else(|_| top.clone());
    let slug = parse_sub_context_id(&suggested)
        .filter(|_| suggested != *top)
        .map(|(_, slug)| slug.to_string())
        .unwrap_or_default();
    (
        community_context::context_options(&config.account, None, &suggested),
        slug,
    )
}

/// The context the highlighted option names. For the new sub-context that is
/// the typed name under the top context, refused when malformed or already
/// claimed — choosing a context in use is a different row.
pub(crate) fn chosen_context(
    config: &Config,
    options: &[ContextOption],
    selected: usize,
    slug: &str,
) -> Result<String, String> {
    let option = options
        .get(selected)
        .ok_or_else(|| "Choose a context.".to_string())?;
    match option.kind {
        ContextKind::New => {
            community_context::new_context_id(&config.account.top_context_id, slug, |id| {
                join_flow::context_taken(config, id)
            })
            .map_err(|e| match e {
                OpenVTCError::Config(message) => message,
                other => other.to_string(),
            })
        }
        ContextKind::Existing | ContextKind::Top => Ok(option.context_id.clone()),
    }
}

/// Mint a standalone persona DID into `config` and persist it, returning its id
/// and `did:webvh`. `progress` receives a human-readable line per network step
/// (so the overlay can show what's happening). Requires the always-on admin VTA
/// session and a configured account context; errors otherwise.
///
/// Mirrors the join flow's persona mint, including using the account's VTA
/// mediator (the minted DID advertises it) and following
/// [`ConfigExtension::mint_persona_into`]'s behaviour of setting
/// `public.friendly_name` to the persona label.
pub(crate) async fn mint_standalone_persona(
    admin_vta: &VtaClient,
    tdk: &TDK,
    inputs: MintInputs,
    label: String,
    mut progress: impl FnMut(&str),
) -> Result<MintedPersona> {
    let MintInputs {
        top_context_id,
        context_id,
        custom_mediator,
    } = inputs;
    if top_context_id.is_empty() {
        anyhow::bail!("No account context yet — finish setup before creating a persona.");
    }

    // The persona's keys and DID live in exactly one context, so it exists
    // before anything is minted into it. A retried mint reuses a context an
    // interrupted one created.
    progress(&format!("Preparing context {context_id}…"));
    match community_context::ensure_context(admin_vta, &top_context_id, &context_id, &label).await {
        Ok(true) => progress(&format!("Created context {context_id}.")),
        Ok(false) => {}
        Err(e) => {
            anyhow::bail!("Could not prepare context {context_id}: {e}. Nothing was minted.")
        }
    }

    // Pick the first WebVH server (serverless mint is a deliberate follow-up,
    // matching the join flow).
    progress("Finding a DID hosting server…");
    let server_id = vta::list_webvh_servers(admin_vta)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No WebVH server available from the VTA (serverless mint not yet supported)."
            )
        })?
        .id;

    // Mint the persona did:webvh via the server (server-generated keys), in the
    // chosen context.
    progress(&format!("Creating persona DID via {server_id}…"));
    let (keys, did, document, _mnemonic) = vta::create_did_via_server(
        admin_vta,
        tdk,
        &context_id,
        &server_id,
        WebvhPathMode::AutoAssign,
    )
    .await?;

    // The VTA may have declined the `#tsp` service we asked for. Report it
    // through the same progress channel the caller is already showing, so a
    // persona that cannot reach a TSP-only community says so at mint time rather
    // than months later as a join nobody answers.
    if let Some(warning) = openvtc_core::config::did::tsp_advertisement_warning(&document) {
        progress(&warning);
    }

    // Persist via the shared mint path. `mint_persona_into` reads the persona
    // keys, DID, document, mediator, and username from a `SetupState`, so build a
    // scratch one carrying just those — no community/sub-context is involved.
    let setup = SetupState {
        did_keys: Some(keys),
        custom_mediator,
        username: label,
        webvh_address: crate::state_handler::setup_sequence::WebVHAddress {
            did: did.clone(),
            document,
        },
        ..Default::default()
    };

    Ok(MintedPersona {
        setup,
        did,
        context_id,
    })
}

/// The `Config` reads a mint needs, taken on the loop thread so the mint itself
/// can run without one.
pub(crate) struct MintInputs {
    pub(crate) top_context_id: String,
    /// The context the persona's keys and DID are minted in.
    pub(crate) context_id: String,
    /// The persona's mediator is the account's VTA mediator: the DID minted via
    /// the VTA's webvh server advertises that mediator, so the persona listener
    /// must use the same one (mirrors the join flow).
    pub(crate) custom_mediator: Option<String>,
}

impl MintInputs {
    /// Read them, for a mint into `context_id`. Pure — no I/O, so it stays on
    /// the loop.
    pub(crate) fn from_config(config: &Config, context_id: String) -> Self {
        Self {
            top_context_id: config.account.top_context_id.clone(),
            context_id,
            custom_mediator: match &config.key_backend {
                KeyBackend::Vta { mediator_did, .. } => mediator_did.clone(),
                _ => None,
            },
        }
    }
}

/// A persona minted at the VTA but not yet written into the config.
///
/// The write is deliberately *not* part of the job:
/// [`ConfigExtension::mint_persona_into`] takes `&mut Config`, and it is shared
/// with the join flow — so rather than restructure a path the riskiest flow in
/// the app depends on, the mint stops at the point where the network work is
/// done and hands this back for the loop to persist. Everything
/// `mint_persona_into` does from here is local: building key info, an
/// `ATMProfile`, `profile_add(.., false)` — registration explicitly without a
/// socket — and secrets-resolver inserts.
pub(crate) struct MintedPersona {
    pub(crate) setup: SetupState,
    pub(crate) did: String,
    /// The context its keys and DID were minted in.
    pub(crate) context_id: String,
}

impl MintedPersona {
    /// Write the persona into the config, recording the context it was minted
    /// in as its origin. Runs on the loop thread, from whichever loop is live —
    /// a first persona is minted in State A.
    pub(crate) async fn persist(
        &self,
        config: &mut Config,
        tdk: &TDK,
        profile: &str,
    ) -> Result<PersonaId> {
        let persona_id = Config::mint_persona_into(config, &self.setup, tdk, profile).await?;
        if let Some(record) = config.account.personas.get_mut(&persona_id) {
            record.origin_context_id = self.context_id.clone();
        }
        Ok(persona_id)
    }
}

// ****************************************************************************
// Off-loop mint (R14)
// ****************************************************************************

/// One standalone mint, resolved on the loop thread.
///
/// Half a dozen VTA trust tasks — find a hosting server, mint the DID, create
/// three keys — awaited inline. The overlay showed each step, so the wait was
/// explained; what was not explained is that the *rest of the application*
/// stopped with it, including the inbound DIDComm channel.
pub(crate) struct MintJob {
    pub(crate) admin_vta: VtaClient,
    pub(crate) tdk: TDK,
    pub(crate) inputs: MintInputs,
    pub(crate) label: String,
    /// Where each step is reported while the job runs.
    pub(crate) progress_tx: tokio::sync::mpsc::UnboundedSender<
        crate::state_handler::background_dispatch::DispatchOutcome,
    >,
}

impl MintJob {
    /// Run the mint, streaming each step. I/O only — the persist is the loop's.
    pub(crate) async fn run(self) -> MintOutcome {
        use crate::state_handler::background_dispatch::{DispatchOutcome, ProgressUpdate};

        let progress_tx = self.progress_tx;
        let result = mint_standalone_persona(
            &self.admin_vta,
            &self.tdk,
            self.inputs,
            self.label,
            |step| {
                // A dropped receiver means the loop has gone; the mint carries
                // on either way, because abandoning a half-minted DID is worse
                // than finishing one nobody is watching.
                let _ = progress_tx.send(DispatchOutcome::Progress(ProgressUpdate::PersonaMint(
                    step.to_string(),
                )));
            },
        )
        .await;

        match result {
            Ok(minted) => MintOutcome {
                minted: Some(minted),
                error: None,
            },
            Err(e) => MintOutcome {
                minted: None,
                error: Some(format!("{e}")),
            },
        }
    }
}

/// What the mint produced. Data only; applied on the loop thread.
pub(crate) struct MintOutcome {
    minted: Option<MintedPersona>,
    error: Option<String>,
}

impl MintOutcome {
    /// Report a failure, or hand the minted persona back for the loop to
    /// persist. The overlay is only moved to `Done` once the persist has
    /// happened — a persona the operator can see but the config does not hold
    /// would be a lie the next launch corrects.
    pub(crate) fn apply(
        self,
        state: &mut crate::state_handler::state::State,
    ) -> Option<MintedPersona> {
        use crate::state_handler::main_page::content::CreatePersonaPhase;

        match (self.minted, self.error) {
            (Some(minted), _) => {
                if let Some(o) = state.main_page.create_persona.as_mut() {
                    o.messages.push("Saving persona…".to_string());
                }
                Some(minted)
            }
            (None, Some(e)) => {
                if let Some(o) = state.main_page.create_persona.as_mut() {
                    o.phase = CreatePersonaPhase::Failed;
                    o.messages.push(format!("Failed: {e}"));
                }
                state
                    .main_page
                    .log_error("Create persona failed", e.as_str());
                None
            }
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod mint_outcome_tests {
    use super::*;
    use crate::state_handler::main_page::content::{CreatePersonaPhase, CreatePersonaState};
    use crate::state_handler::state::State;

    fn working(state: &mut State) {
        state.main_page.create_persona = Some(CreatePersonaState {
            phase: CreatePersonaPhase::Working,
            ..Default::default()
        });
    }

    /// A successful mint does NOT complete the overlay: the persona exists at
    /// the VTA but not yet in the config, and showing "created" before the
    /// persist would be a claim the next launch contradicts. It hands the
    /// persona back for the loop to write.
    #[test]
    fn a_successful_mint_defers_completion_to_the_persist() {
        let mut state = State::default();
        working(&mut state);

        let minted = MintOutcome {
            minted: Some(MintedPersona {
                setup: SetupState::default(),
                did: "did:webvh:QmScid:example.com:new".to_string(),
                context_id: "openvtc/new".to_string(),
            }),
            error: None,
        }
        .apply(&mut state);

        assert!(minted.is_some(), "the persist is still owed");
        let o = state.main_page.create_persona.as_ref().unwrap();
        assert_eq!(o.phase, CreatePersonaPhase::Working, "not done until saved");
        assert!(o.did.is_none(), "no DID shown before it is persisted");
    }

    /// A failed mint is terminal and says why.
    #[test]
    fn a_failed_mint_fails_the_overlay() {
        let mut state = State::default();
        working(&mut state);

        let minted = MintOutcome {
            minted: None,
            error: Some("no hosting server".to_string()),
        }
        .apply(&mut state);

        assert!(minted.is_none());
        let o = state.main_page.create_persona.as_ref().unwrap();
        assert_eq!(o.phase, CreatePersonaPhase::Failed);
        assert!(o.messages.iter().any(|m| m.contains("no hosting server")));
    }
}

#[cfg(test)]
mod context_choice_tests {
    use super::*;
    use crate::state_handler::dispatch_util::test_config;
    use openvtc_core::config::account::PersonaRecord;

    fn config_with_work_context() -> Config {
        let mut config = test_config();
        config.account.top_context_id = "openvtc".into();
        let persona_id = PersonaId::new();
        config.account.personas.insert(
            persona_id,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id,
                did: "did:webvh:scid:example.com:work".into(),
                did_document: None,
                key_refs: vec![],
                mediator_did: None,
                origin_context_id: "openvtc/work".into(),
                created_at: chrono::Utc::now(),
                label: Some("Work".into()),
            },
        );
        config
    }

    /// The same three kinds a join offers, with the new context named from the
    /// label and kept clear of one already in use.
    #[test]
    fn a_standalone_persona_is_offered_new_existing_and_top() {
        let config = config_with_work_context();
        let (options, slug) = context_choice(&config, "Work");
        let kinds: Vec<_> = options.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ContextKind::New, ContextKind::Existing, ContextKind::Top]
        );
        assert_eq!(slug, "work-2");
        assert_eq!(options[1].context_id, "openvtc/work");
        assert_eq!(options[2].context_id, "openvtc");
    }

    #[test]
    fn the_chosen_row_names_the_context_minted_into() {
        let config = config_with_work_context();
        let (options, _) = context_choice(&config, "Laptop");
        assert_eq!(
            chosen_context(&config, &options, 0, "laptop").as_deref(),
            Ok("openvtc/laptop")
        );
        assert_eq!(
            chosen_context(&config, &options, 1, "ignored").as_deref(),
            Ok("openvtc/work")
        );
        assert_eq!(
            chosen_context(&config, &options, 2, "ignored").as_deref(),
            Ok("openvtc")
        );
        assert!(
            chosen_context(&config, &options, 0, "work").is_err(),
            "a new context must be new"
        );
        assert!(chosen_context(&config, &options, 0, "a/b").is_err());
    }
}
