use std::collections::VecDeque;
use std::sync::Arc;

use openvtc_core::{
    config::{Config, KeyBackend, KeyTypes, account::PersonaId},
    display::truncate_did,
    tasks::TaskType,
};

/// Whether an item owned by `item_persona` is in scope for the working community
/// whose persona is `active` (D10 / R-C-6). Tagged items match when their persona
/// is the active one. Untagged items (legacy, pre-attribution) show only when the
/// account has at most one persona, where there is no ambiguity; with multiple
/// personas an untagged item is hidden until re-tagged. With no active selection
/// (no working community), only the single/zero-persona case shows everything.
fn persona_in_scope(
    item_persona: Option<PersonaId>,
    active: Option<PersonaId>,
    persona_count: usize,
) -> bool {
    match active {
        Some(p) => item_persona == Some(p) || (item_persona.is_none() && persona_count <= 1),
        None => persona_count <= 1,
    }
}

use crate::state_handler::main_page::{
    content::{
        ContentPanelState, DidGitSignInfo, RelationshipSummary, TaskKind, TaskSummary, VrcSummary,
    },
    menu::MenuPanelState,
};

pub mod content;
pub mod menu;

/// Maximum number of activity log entries to keep in the UI.
const MAX_ACTIVITY_LOG_ENTRIES: usize = 100;

/// A single activity log entry with a short summary and optional detail.
#[derive(Clone, Debug)]
pub struct ActivityLogEntry {
    /// Short summary shown in the list view (includes timestamp).
    pub summary: String,
    /// Detailed information shown when the entry is expanded.
    /// Includes DIDComm message details, DID addresses, etc.
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct MainPageState {
    /// State related to the menu panel
    pub menu_panel: MenuPanelState,

    /// State related to the content panel
    pub content_panel: ContentPanelState,

    pub config: MainMenuConfigState,

    /// Quick community-switcher overlay (R-C-7). `Some` while the Ctrl+K popup is
    /// open; `None` (the default) when closed. Lives at the page level rather
    /// than in a content panel because it floats over whichever panel is focused.
    pub switcher: Option<content::CommunitySwitcherState>,

    /// "Create a new persona DID" overlay. `Some` while open; `None` (default)
    /// when closed. Page-level (like [`switcher`](Self::switcher)) because it
    /// floats over whichever panel is focused and is reachable from both the
    /// top-level menu and the VTA panel.
    pub create_persona: Option<content::CreatePersonaState>,

    /// "Import an invitation credential" overlay for the VIC manager. `Some`
    /// while open; `None` (default) when closed. Page-level (like
    /// [`create_persona`](Self::create_persona)) because it floats over the panel.
    pub add_vic: Option<content::AddVicState>,

    /// "Manage agent names" overlay for a persona. `Some` while open; `None`
    /// (default) when closed. Page-level (like [`create_persona`](Self::create_persona)),
    /// reachable from the VTA panel's persona/context-identity lists.
    pub agent_names: Option<content::AgentNameManagerState>,

    /// Activity log entries shown in the bottom panel (newest last).
    ///
    /// Entries are wrapped in `Arc` so cloning `MainPageState` (which happens
    /// per frame and per event via the `State` watch channel) shares the
    /// entries by pointer rather than deep-copying each entry's summary and
    /// detail strings. Entries are immutable once written.
    pub activity_log: VecDeque<Arc<ActivityLogEntry>>,
}

impl MainPageState {
    /// Re-check where this profile's secret is actually stored, and warn if
    /// that place will not keep it.
    ///
    /// The Linux kernel keyring is RAM-only by design, and OpenVTC used to keep
    /// a profile's only copy of its seed there — so a reboot destroyed the
    /// account and presented as a corrupt install. Where a durable store cannot
    /// be used (no Secret Service, and no passphrase, so the encrypted-file
    /// store must refuse the blob), the user is at least told, and told the two
    /// things that fix it.
    pub fn refresh_storage_warning(&mut self, profile: &str) {
        let probe = openvtc_core::secure_store::probe(profile);
        self.content_panel.settings.storage_warning = if probe.durability.is_volatile() {
            Some(format!(
                "This profile's keys are {} and are NOT on disk. \
                 Set a passphrase (Protection, above) to store them durably, \
                 and export a backup now.",
                probe.durability.lifetime_phrase()
            ))
        } else {
            None
        };
    }

    /// Push a timestamped entry to the activity log (O(1) bounded insertion).
    pub fn log(&mut self, message: impl Into<String>) {
        self.log_detailed_inner(message.into(), None);
    }

    /// Push a timestamped entry with detailed diagnostic info.
    pub fn log_detailed(&mut self, message: impl Into<String>, detail: impl Into<String>) {
        self.log_detailed_inner(message.into(), Some(detail.into()));
    }

    fn log_detailed_inner(&mut self, message: String, detail: Option<String>) {
        if self.activity_log.len() >= MAX_ACTIVITY_LOG_ENTRIES {
            self.activity_log.pop_front();
        }
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        self.activity_log.push_back(Arc::new(ActivityLogEntry {
            summary: format!("[{}] {}", timestamp, message),
            detail,
        }));
    }

    /// Log an error with a short context line and a detailed pane containing
    /// the full alternate `Display` form (`{err:#}`) plus the `Debug`
    /// representation. Works with any `Display + Debug` error type (anyhow
    /// renders its full cause chain under `{err:#}`).
    pub fn log_error<E>(&mut self, context: impl Into<String>, err: &E)
    where
        E: std::fmt::Display + std::fmt::Debug + ?Sized,
    {
        let context = context.into();
        let summary = format!("{context}: {err}");
        let detail = format_error_detail(&context, err);
        self.log_detailed_inner(summary, Some(detail));
    }
}

/// Format an error for the log detail pane. Includes the context line, the
/// full `Display` (alternate form, which for anyhow expands the cause chain),
/// and the `Debug` representation.
#[must_use]
pub fn format_error_detail<E>(context: &str, err: &E) -> String
where
    E: std::fmt::Display + std::fmt::Debug + ?Sized,
{
    let divider = "─".repeat(context.len().min(60));
    format!("{context}\n{divider}\n\nError: {err:#}\n\nDebug:\n{err:?}")
}

impl MainPageState {
    /// Rebuilds all display state from the current Config.
    ///
    /// Called after Config is loaded at startup and after every Config mutation
    /// (message processing, user actions, etc.).
    pub fn sync_from_config(&mut self, config: &Config) {
        // Update header config
        self.config = MainMenuConfigState::from(config);

        crate::state_handler::vetting_actions::sync(&mut self.content_panel.vetting, config);

        // The working community's persona scopes the relationship/inbox/VRC
        // panels (D10 / R-C-6): only items owned by it (plus untagged legacy
        // items in a single-persona account) are shown.
        let active_persona = config.active_persona;
        let persona_count = config.account.personas.len();

        // Sync inbox tasks
        let mut inbox_tasks: Vec<TaskSummary> = config
            .private
            .tasks
            .tasks
            .values()
            .filter(|task| persona_in_scope(task.our_persona, active_persona, persona_count))
            .map(|task| {
                let kind = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, request, .. } => {
                        TaskKind::RelationshipRequestInbound {
                            from_did: sanitize_display(from, 256),
                            their_did: sanitize_display(&request.did, 256),
                            reason: request.reason.as_deref().map(|r| sanitize_display(r, 256)),
                            name: request.name.as_deref().map(|n| sanitize_display(n, 256)),
                        }
                    }
                    TaskType::RelationshipRequestOutbound { to } => {
                        let our_did = config
                            .private
                            .relationships
                            .relationships
                            .get(to)
                            .map(|rel| rel.our_did.to_string())
                            .unwrap_or_default();
                        let our_agent_name = config
                            .agent_name_for(&our_did)
                            .map(|n| sanitize_display(n, 256));
                        TaskKind::RelationshipRequestOutbound {
                            our_did,
                            our_agent_name,
                        }
                    }
                    TaskType::VRCRequestInbound { request, .. } => TaskKind::VRCRequestInbound {
                        reason: request.reason.as_deref().map(|r| sanitize_display(r, 256)),
                    },
                    TaskType::VRCRequestOutbound { .. } => TaskKind::VRCRequestOutbound,
                    TaskType::VRCIssued { .. } => TaskKind::VRCIssued,
                    TaskType::TrustPing { .. } => TaskKind::TrustPing,
                    TaskType::RelationshipRequestAccepted => {
                        TaskKind::Informational("Accepted".to_string())
                    }
                    TaskType::RelationshipRequestRejected => {
                        TaskKind::Informational("Rejected".to_string())
                    }
                    TaskType::RelationshipRequestFinalized => {
                        TaskKind::Informational("Finalized".to_string())
                    }
                    TaskType::TrustPong => TaskKind::Informational("Pong received".to_string()),
                    TaskType::VRCRequestRejected => {
                        TaskKind::Informational("VRC Rejected".to_string())
                    }
                    _ => TaskKind::Informational("Unknown".to_string()),
                };
                let remote_did = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, request, .. } => {
                        if let Some(ref name) = request.name {
                            sanitize_display(name, 40)
                        } else {
                            shorten_did(from, 60)
                        }
                    }
                    TaskType::RelationshipRequestOutbound { to } => shorten_did(to, 60),
                    TaskType::TrustPing { to, .. } => shorten_did(to, 60),
                    TaskType::VRCRequestInbound { remote_p_did, .. } => {
                        shorten_did(remote_p_did, 60)
                    }
                    TaskType::VRCRequestOutbound { remote_p_did } => shorten_did(remote_p_did, 60),
                    TaskType::VRCIssued { vrc } => sanitize_display(vrc.issuer(), 40),
                    _ => String::new(),
                };
                // The verified name for *exactly* the DID `remote_did` renders,
                // so showing the name in its place can never relabel a different
                // identity. Cache-only (`agent_name_for`) — an unverified
                // `alsoKnownAs` claim never reaches it. A relationship R-DID has
                // no cache entry, so those rows keep showing the DID.
                let remote_agent_name = match &task.type_ {
                    TaskType::RelationshipRequestInbound { from, .. } => {
                        config.agent_name_for(from)
                    }
                    TaskType::RelationshipRequestOutbound { to } => config.agent_name_for(to),
                    TaskType::TrustPing { to, .. } => config.agent_name_for(to),
                    TaskType::VRCRequestInbound { remote_p_did, .. } => {
                        config.agent_name_for(remote_p_did)
                    }
                    TaskType::VRCRequestOutbound { remote_p_did } => {
                        config.agent_name_for(remote_p_did)
                    }
                    TaskType::VRCIssued { vrc } => config.agent_name_for(vrc.issuer()),
                    _ => None,
                }
                .map(|n| sanitize_display(n, 256));
                TaskSummary {
                    id: task.id.to_string(),
                    type_display: task.type_.to_string(),
                    kind,
                    remote_did: sanitize_display(&remote_did, 256),
                    remote_agent_name,
                    created: task.created.format("%Y-%m-%d %H:%M").to_string(),
                }
            })
            .collect();
        // Sort tasks by most recent first
        inbox_tasks.sort_by(|a, b| b.created.cmp(&a.created));
        self.content_panel.inbox.tasks = inbox_tasks.into();

        // Sync relationships (scoped to the working community's persona)
        self.content_panel.relationships.relationships = config
            .private
            .relationships
            .relationships
            .iter()
            .filter(|(_, rel)| persona_in_scope(rel.our_persona, active_persona, persona_count))
            .map(|(remote_p_did, rel)| {
                let alias = config
                    .private
                    .contacts
                    .find_contact(remote_p_did)
                    .and_then(|c| c.alias.clone());
                let vrcs_issued = config
                    .private
                    .vrcs_issued
                    .get(remote_p_did)
                    .map(|m| {
                        m.values()
                            .map(|vrc| content::RelationshipVrc {
                                issuer: shorten_did(vrc.issuer(), 40),
                                issuer_agent_name: config
                                    .agent_name_for(vrc.issuer())
                                    .map(|n| sanitize_display(n, 256)),
                                issuer_full: vrc.issuer().to_string(),
                                subject: shorten_did(vrc.subject(), 40),
                                subject_agent_name: config
                                    .agent_name_for(vrc.subject())
                                    .map(|n| sanitize_display(n, 256)),
                                subject_full: vrc.subject().to_string(),
                                valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                                valid_until: vrc
                                    .valid_until()
                                    .map(|d| d.format("%Y-%m-%d").to_string()),
                                // Defer pretty-printing to detail-view render
                                // time; share the credential by Arc pointer.
                                raw_json: content::RawCredential::Vrc(Arc::clone(vrc)),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let vrcs_received = config
                    .private
                    .vrcs_received
                    .get(remote_p_did)
                    .map(|m| {
                        m.values()
                            .map(|vrc| content::RelationshipVrc {
                                issuer: shorten_did(vrc.issuer(), 40),
                                issuer_agent_name: config
                                    .agent_name_for(vrc.issuer())
                                    .map(|n| sanitize_display(n, 256)),
                                issuer_full: vrc.issuer().to_string(),
                                subject: shorten_did(vrc.subject(), 40),
                                subject_agent_name: config
                                    .agent_name_for(vrc.subject())
                                    .map(|n| sanitize_display(n, 256)),
                                subject_full: vrc.subject().to_string(),
                                valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                                valid_until: vrc
                                    .valid_until()
                                    .map(|d| d.format("%Y-%m-%d").to_string()),
                                // Defer pretty-printing to detail-view render
                                // time; share the credential by Arc pointer.
                                raw_json: content::RawCredential::Vrc(Arc::clone(vrc)),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                RelationshipSummary {
                    remote_p_did: sanitize_display(remote_p_did, 256),
                    alias: alias.as_deref().map(|a| sanitize_display(a, 256)),
                    agent_name: config
                        .agent_name_for(remote_p_did)
                        .map(|n| sanitize_display(n, 256)),
                    state: rel.state.to_string(),
                    our_did: rel.our_did.to_string(),
                    remote_did: sanitize_display(&rel.remote_did, 256),
                    created: rel.created.format("%Y-%m-%d %H:%M").to_string(),
                    vrcs_issued,
                    vrcs_received,
                    needs_reestablishment: rel.needs_reestablishment,
                }
            })
            .collect();

        // Sync credentials (scoped to the working community's persona)
        self.content_panel.credentials.received = collect_vrcs(
            &config.private.vrcs_received,
            config,
            active_persona,
            persona_count,
        )
        .into();
        self.content_panel.credentials.issued = collect_vrcs(
            &config.private.vrcs_issued,
            config,
            active_persona,
            persona_count,
        )
        .into();
        self.content_panel.credentials.membership = collect_membership_creds(config).into();

        // Sync settings
        self.content_panel.settings.friendly_name = config.public.friendly_name.clone();
        self.content_panel.settings.mediator_did = config.mediator_did().to_string();
        self.content_panel.settings.org_did = config.account.org_did.clone();
        self.content_panel.settings.persona_did = config.persona_did().to_string();
        self.content_panel.settings.persona_agent_name = config
            .agent_name_for(config.persona_did())
            .map(str::to_owned);
        self.content_panel.settings.did_git_sign = detect_did_git_sign_info(config.persona_did());
        self.content_panel.settings.context_id = config.account.top_context_id.clone();
        // Sync VTA info
        self.content_panel.vta.persona_did = config.persona_did().to_string();
        self.content_panel.vta.persona_agent_name = config
            .agent_name_for(config.persona_did())
            .map(str::to_owned);
        self.content_panel.vta.mediator_did = config.mediator_did().to_string();
        self.content_panel.vta.mediator_agent_name = config
            .agent_name_for(config.mediator_did())
            .map(str::to_owned);
        match &config.key_backend {
            KeyBackend::Vta {
                vta_url,
                vta_did,
                credential_did,
                mediator_did,
                ..
            } => {
                self.content_panel.vta.vta_url = vta_url.clone();
                self.content_panel.vta.vta_did = vta_did.clone();
                self.content_panel.vta.vta_agent_name =
                    config.agent_name_for(vta_did).map(str::to_owned);
                self.content_panel.vta.credential_did = credential_did.clone();
                self.content_panel.identity.agent_credential_did = Some(credential_did.clone());
                self.content_panel.vta.is_vta_managed = true;
                // Same condition `build_runtime_vta_client` branches on, so the
                // panel names the transport this process actually connects over
                // rather than guessing from the URL being non-empty (it stays
                // populated on the DIDComm path as the REST fallback).
                self.content_panel.vta.transports.in_use = if mediator_did.is_some() {
                    content::VtaTransport::DidComm
                } else {
                    content::VtaTransport::Rest
                };
                self.content_panel.vta.transports.rest_url = vta_url.clone();
            }
            _ => {
                self.content_panel.vta.is_vta_managed = false;
                self.content_panel.identity.agent_credential_did = None;
            }
        }
        self.content_panel.vta.key_count = config.key_info.len();
        // Classify keys by their recorded purpose, not by DID-prefix arithmetic.
        // Counting persona keys with `k.starts_with(active_persona_did)` and
        // calling the remainder "relationship" mislabelled every key belonging to
        // a *different* persona — a two-persona account reported relationship
        // keys it did not have. `KeyInfoConfig::purpose` already says what each
        // key is for; anything outside the two buckets (e.g. webvh update keys)
        // is counted as neither, so the two figures never over-claim.
        let persona_did = config.persona_did();
        self.content_panel.vta.persona_key_count = config
            .key_info
            .values()
            .filter(|info| {
                matches!(
                    info.purpose,
                    KeyTypes::PersonaSigning
                        | KeyTypes::PersonaAuthentication
                        | KeyTypes::PersonaEncryption
                        | KeyTypes::PersonaOther
                )
            })
            .count();
        self.content_panel.vta.relationship_key_count = config
            .key_info
            .values()
            .filter(|info| {
                matches!(
                    info.purpose,
                    KeyTypes::RelationshipVerification | KeyTypes::RelationshipEncryption
                )
            })
            .count();
        // Collect active DIDs — none for a zero-persona (State-A) account.
        let mut active_dids = Vec::new();
        if !persona_did.is_empty() {
            active_dids.push(content::ActiveDid {
                did: persona_did.to_string(),
                agent_name: config
                    .agent_name_for(persona_did)
                    .map(|n| sanitize_display(n, 256)),
                label: "Persona".to_string(),
            });
        }
        for (remote_p_did, rel) in &config.private.relationships.relationships {
            if !config.is_persona_did(rel.our_did.as_str()) {
                let alias = config
                    .private
                    .contacts
                    .find_contact(remote_p_did)
                    .and_then(|c| c.alias.clone())
                    .unwrap_or_else(|| shorten_did(remote_p_did, 30));
                active_dids.push(content::ActiveDid {
                    // An R-DID is a per-relationship pseudonym: there is no
                    // cache entry for it, so this resolves to `None` and the
                    // row keeps showing the DID. Looked up all the same so the
                    // name always belongs to the DID being displayed.
                    agent_name: config
                        .agent_name_for(rel.our_did.as_str())
                        .map(|n| sanitize_display(n, 256)),
                    did: rel.our_did.to_string(),
                    label: format!("R-DID ({})", alias),
                });
            }
        }
        self.content_panel.vta.active_dids = active_dids.into();

        // Personas: every persona in the account, with how many communities
        // present it. A persona bound to zero communities is an orphan (e.g.
        // left by a failed join before the rollback fix) — surfaced so the
        // operator can spot and manage it.
        //
        // These live on the persona pane rather than the VTA panel: a persona
        // DID is the holder's identity, not a property of the agent that
        // happens to host its keys, and the pane that manages it is the pane
        // that should list it.
        let mut personas: Vec<content::ManagedDid> = config
            .account
            .personas
            .values()
            .map(|p| content::ManagedDid {
                agent_name: config
                    .agent_name_for(&p.did)
                    .map(|n| sanitize_display(n, 256)),
                did: p.did.clone(),
                label: p.label.clone().unwrap_or_default(),
                bound_communities: config
                    .account
                    .memberships()
                    .filter(|c| c.persona_ref == p.persona_id)
                    .count(),
                is_active: p.did.as_str() == persona_did,
            })
            .collect();
        personas.sort_by(|a, b| a.did.cmp(&b.did));
        // Clamp the selection to the rebuilt list. Nothing else does: the list is
        // rebuilt wholesale on every sync, so deleting a persona (or loading a
        // profile with fewer than the last one had) could leave the index past
        // the end — where the panel draws no cursor and every list-scoped key
        // (`d`, `g`) silently does nothing, since each is guarded on
        // `persona_selected < persona count`. Restarting "fixed" it only because
        // the index starts at 0.
        let identity = &mut self.content_panel.identity;
        identity.persona_selected = identity
            .persona_selected
            .min(personas.len().saturating_sub(1));
        identity.personas = personas.into();

        // The VIC list is not derived from `Config` (it comes from the VTA
        // credential vault), so it is annotated rather than rebuilt here.
        self.sync_vic_agent_names(config);

        self.content_panel.settings.protection_type = match &config.public.protection {
            openvtc_core::config::ConfigProtectionType::Token(id) => {
                format!(
                    "Hardware Token ({})",
                    openvtc_core::display::truncate_chars(id, 20)
                )
            }
            openvtc_core::config::ConfigProtectionType::Encrypted => {
                "Passphrase Encrypted".to_string()
            }
            openvtc_core::config::ConfigProtectionType::Plaintext => {
                "Keyring Only (no additional encryption)".to_string()
            }
        };

        // Sync the Communities overview (R-C-*): display order from the model,
        // archived excluded, with the actions-required count for the badge.
        let mut community_items = Vec::new();
        let show_archived = self.content_panel.communities.show_archived;
        let now = chrono::Utc::now();
        for c in config.account.communities_for_display(show_archived) {
            let persona = config.account.personas.get(&c.persona_ref);
            // Precedence follows `resolve_did_to_display`: the user's own label
            // wins (explicit, and unspoofable by definition), then a verified
            // agent name, then the truncated DID. The name is read from the
            // cache, which only ever holds round-tripped lookups — an
            // unverified `alsoKnownAs` claim never reaches it.
            let persona_label = persona
                .and_then(|p| p.label.clone())
                .or_else(|| persona.and_then(|p| config.agent_name_for(&p.did).map(str::to_owned)))
                .or_else(|| persona.map(|p| shorten_did(&p.did, 24)))
                .unwrap_or_default();
            let request_id = match &c.status {
                openvtc_core::config::account::CommunityStatus::Pending { request_id } => {
                    request_id.to_string()
                }
                _ => String::new(),
            };
            community_items.push(content::CommunitySummary {
                display_name: c
                    .display_name
                    .clone()
                    .or_else(|| config.agent_name_for(&c.vtc_did).map(str::to_owned))
                    .unwrap_or_else(|| shorten_did(&c.vtc_did, 40)),
                status_label: community_status_label(&c.status),
                persona_label,
                member_since: c
                    .member_since
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_default(),
                favourite: c.favourite,
                is_active: c.status.is_active(),
                is_inactive: c.status.is_inactive(),
                is_pending: matches!(
                    c.status,
                    openvtc_core::config::account::CommunityStatus::Pending { .. }
                ),
                pending_unacknowledged: c.pending_unacknowledged(now),
                submit_transport: c.submit_transport.map(|t| t.to_string()),
                archived: c.archived,
                needs_attention: c.needs_attention(),
                persona_did: persona.map(|p| p.did.clone()).unwrap_or_default(),
                persona_agent_name: persona
                    .and_then(|p| config.agent_name_for(&p.did))
                    .map(|n| sanitize_display(n, 256)),
                vtc_did: c.vtc_did.clone(),
                vtc_agent_name: config
                    .agent_name_for(&c.vtc_did)
                    .map(|n| sanitize_display(n, 256)),
                sub_context_id: c.sub_context_id.clone(),
                context_note: openvtc_core::config::community_context::isolation(
                    &config.account,
                    c,
                )
                .describe(),
                has_own_context: openvtc_core::config::community_context::is_sub_context(
                    &c.sub_context_id,
                    &config.account.top_context_id,
                ),
                request_id,
                has_membership_credential: c
                    .credentials
                    .contains_key(&openvtc_core::CredentialKind::Membership),
                has_role_credential: c
                    .credentials
                    .contains_key(&openvtc_core::CredentialKind::Role),
            });
        }
        let community_count = community_items.len();
        self.content_panel.communities.actions_required = config.account.actions_required_count();
        self.content_panel.communities.items = community_items.into();
        if self.content_panel.communities.selected_index >= community_count {
            self.content_panel.communities.selected_index = community_count.saturating_sub(1);
        }

        // The persona pane's Communities tab: one row per membership, not per
        // community. A community the holder joined twice under two personas is two
        // rows here, because the question this tab answers — which persona does
        // this relationship use, and what does it say — has two different
        // answers in that case.
        //
        // Archived memberships are included, unlike the communities panel's
        // own list. An archived membership still has a live binding in the
        // agent, so hiding it would hide identity the holder is still
        // disclosing.
        let mut memberships = Vec::new();
        for c in config.account.memberships() {
            let persona = config.account.personas.get(&c.persona_ref);
            // How many *other* memberships show this same persona. Computed per
            // row rather than per persona because it is read that way: the
            // holder is looking at one community and asking "who else sees
            // this me".
            let shared_with = config
                .account
                .memberships()
                .filter(|other| other.persona_ref == c.persona_ref)
                .count()
                .saturating_sub(1);
            memberships.push(content::PersonaMembership {
                community_name: c
                    .display_name
                    .clone()
                    .or_else(|| config.agent_name_for(&c.vtc_did).map(str::to_owned))
                    .unwrap_or_else(|| shorten_did(&c.vtc_did, 40)),
                sub_context_id: c.sub_context_id.clone(),
                persona_did: persona.map(|p| p.did.clone()).unwrap_or_default(),
                // Same precedence as everywhere else a DID is named: the
                // holder's own label, then a *verified* agent name, then the
                // DID itself. An unverified `alsoKnownAs` claim never reaches
                // the cache this reads.
                persona_label: persona
                    .and_then(|p| p.label.clone())
                    .or_else(|| {
                        persona.and_then(|p| config.agent_name_for(&p.did).map(str::to_owned))
                    })
                    .or_else(|| persona.map(|p| shorten_did(&p.did, 24)))
                    .unwrap_or_default(),
                status_label: community_status_label(&c.status),
                shared_with,
            });
        }
        // Stable order the holder can predict, and one that puts the rows they
        // are most likely to be reconsidering — the personas shown to several
        // communities — next to each other.
        memberships.sort_by(|a, b| {
            a.persona_label
                .cmp(&b.persona_label)
                .then_with(|| a.community_name.cmp(&b.community_name))
        });
        let personas = &mut self.content_panel.identity;
        personas.membership_selected = personas
            .membership_selected
            .min(memberships.len().saturating_sub(1));
        personas.memberships = memberships.into();
    }

    /// Stitch the verified agent name for each held VIC's issuer onto the VIC
    /// list.
    ///
    /// The list itself comes from the VTA credential vault, not from `Config`
    /// (`VicSummary::from_descriptor` has no `Config` to consult), so the names
    /// are attached here instead of at construction. Called from
    /// [`sync_from_config`](Self::sync_from_config) — so a background agent-name
    /// sweep lands on the list — and again straight after each vault reload, so
    /// a freshly loaded list is named without waiting for the next sync.
    ///
    /// Verified-only: the name always comes from `Config::agent_name_for`, and a
    /// DID with no (or a cached-negative) entry keeps showing its DID.
    pub fn sync_vic_agent_names(&mut self, config: &Config) {
        if self.content_panel.vta.vics.is_empty() {
            return;
        }
        let named: Vec<content::VicSummary> = self
            .content_panel
            .vta
            .vics
            .iter()
            .map(|v| content::VicSummary {
                issuer_agent_name: config
                    .agent_name_for(&v.issuer)
                    .map(|n| sanitize_display(n, 256)),
                ..v.clone()
            })
            .collect();
        self.content_panel.vta.vics = named.into();
    }
}

/// Human-readable label for a community membership status (R-C-2).
fn community_status_label(status: &openvtc_core::config::account::CommunityStatus) -> String {
    use openvtc_core::config::account::CommunityStatus;
    match status {
        CommunityStatus::Pending { .. } => "Pending",
        CommunityStatus::Active => "Active",
        CommunityStatus::Left => "Left",
        CommunityStatus::Withdrawn => "Withdrawn",
        CommunityStatus::Rejected => "Rejected",
        CommunityStatus::Removed => "Removed",
        CommunityStatus::Expired => "Expired",
    }
    .to_string()
}

/// Collect VRC summaries from a Vrcs collection.
#[must_use]
fn collect_vrcs(
    vrcs: &openvtc_core::vrc::Vrcs,
    config: &Config,
    active_persona: Option<PersonaId>,
    persona_count: usize,
) -> Vec<VrcSummary> {
    let mut result = Vec::new();
    for remote_p_did in vrcs.keys() {
        // Scope to the working community: a VRC belongs to the community of the
        // relationship with its remote party (D10 / R-C-6).
        let rel_persona = config
            .private
            .relationships
            .get(remote_p_did)
            .and_then(|r| r.our_persona);
        if !persona_in_scope(rel_persona, active_persona, persona_count) {
            continue;
        }
        let alias = config
            .private
            .contacts
            .find_contact(remote_p_did)
            .and_then(|c| c.alias.clone());
        if let Some(vrc_map) = vrcs.get(remote_p_did) {
            for (vrc_id, vrc) in vrc_map {
                // Defer pretty-printing to detail-view render time; share the
                // credential by Arc pointer (it is already `Arc`-held in config).
                let raw_json = content::RawCredential::Vrc(Arc::clone(vrc));
                result.push(VrcSummary {
                    vrc_id: vrc_id.to_string(),
                    remote_p_did: sanitize_display(remote_p_did, 256),
                    remote_agent_name: config
                        .agent_name_for(remote_p_did)
                        .map(|n| sanitize_display(n, 256)),
                    raw_json,
                    alias: alias.as_deref().map(|a| sanitize_display(a, 256)),
                    issuer: sanitize_display(vrc.issuer(), 256),
                    issuer_agent_name: config
                        .agent_name_for(vrc.issuer())
                        .map(|n| sanitize_display(n, 256)),
                    subject: sanitize_display(vrc.subject(), 256),
                    subject_agent_name: config
                        .agent_name_for(vrc.subject())
                        .map(|n| sanitize_display(n, 256)),
                    validity: {
                        let (v, _) = format_validity_from_dates(
                            vrc.valid_from(),
                            vrc.valid_until(),
                            chrono::Utc::now(),
                        );
                        v
                    },
                    status: {
                        let (_, s) = format_validity_from_dates(
                            vrc.valid_from(),
                            vrc.valid_until(),
                            chrono::Utc::now(),
                        );
                        s
                    },
                    // A peer-to-peer VRC carries no membership/role kind; the
                    // credential's own `type` is visible in the raw JSON.
                    kind: None,
                    subject_is_self: config.is_persona_did(vrc.subject()),
                    valid_from: vrc.valid_from().format("%Y-%m-%d").to_string(),
                    valid_until: vrc.valid_until().map(|d| d.format("%Y-%m-%d").to_string()),
                });
            }
        }
    }
    result
}

/// Build display summaries for a membership edge's credentials: the membership
/// (VMC) + role (VEC) a VTC issued to us, and the VMC we issued back.
///
/// Both halves, because membership is a pair. The community's grant says we were
/// admitted; our acknowledgement is the half that says we agreed, and it was the
/// one credential in the exchange this client could not show — it was signed,
/// sent, and dropped. Reuses [`VrcSummary`]: `alias` carries "`<community>` —
/// Membership/Role/Acknowledgement" and `remote_p_did` the VTC.
fn collect_membership_creds(config: &Config) -> Vec<VrcSummary> {
    let mut result = Vec::new();
    for c in config.account.memberships() {
        let community = crate::state_handler::community_label(
            config,
            &c.vtc_did,
            c.display_name.as_deref(),
            64,
        );
        for kind in openvtc_core::CredentialKind::ALL {
            let Some(vc) = c.credentials.get(kind) else {
                continue;
            };
            // `issuer` may be a bare string or an object `{ id, ... }`.
            let issuer = vc
                .get("issuer")
                .and_then(|i| {
                    i.as_str()
                        .map(str::to_string)
                        .or_else(|| i.get("id").and_then(|x| x.as_str()).map(str::to_string))
                })
                .unwrap_or_default();
            let subject = vc
                .pointer("/credentialSubject/id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_from = vc
                .get("validFrom")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_until = vc
                .get("validUntil")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let vc_id = vc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            // Defer pretty-printing to detail-view render time. Share the
            // already-parsed JSON value by Arc pointer (a `serde_json::Value`
            // pretty-prints identically whether done now or later).
            let raw_json = content::RawCredential::Value(Arc::new(vc.clone()));
            let (validity, status) =
                format_validity(&valid_from, valid_until.as_deref(), chrono::Utc::now());
            result.push(VrcSummary {
                vrc_id: vc_id,
                remote_p_did: sanitize_display(&c.vtc_did, 256),
                remote_agent_name: config
                    .agent_name_for(&c.vtc_did)
                    .map(|n| sanitize_display(n, 256)),
                raw_json,
                alias: Some(community.clone()),
                issuer: sanitize_display(&issuer, 256),
                issuer_agent_name: config
                    .agent_name_for(&issuer)
                    .map(|n| sanitize_display(n, 256)),
                subject: sanitize_display(&subject, 256),
                subject_agent_name: config
                    .agent_name_for(&subject)
                    .map(|n| sanitize_display(n, 256)),
                validity,
                status,
                kind: Some(kind.config_key().to_string()),
                subject_is_self: config.is_persona_did(&subject),
                valid_from,
                valid_until,
            });
        }

        // Our own half of the pair. Rendered from the same shape, so the tab
        // shows one membership edge rather than "credentials we were given" and
        // an invisible obligation.
        if let Some(vc) = &c.member_vmc {
            let issuer = vc
                .get("issuer")
                .and_then(|i| {
                    i.as_str()
                        .map(str::to_string)
                        .or_else(|| i.get("id").and_then(|x| x.as_str()).map(str::to_string))
                })
                .unwrap_or_default();
            let subject = vc
                .pointer("/credentialSubject/id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_from = vc
                .get("validFrom")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let valid_until = vc
                .get("validUntil")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let (validity, status) =
                format_validity(&valid_from, valid_until.as_deref(), chrono::Utc::now());

            // Does it still acknowledge the grant we hold? The digest names one
            // grant; once the community re-issues, ours no longer matches and we
            // owe a fresh one. Saying "stale" here is the only place a member
            // learns that — the community sees it, and until now we did not.
            let stale = c
                .credentials
                .get(&openvtc_core::CredentialKind::Membership)
                .zip(
                    vc.pointer("/credentialSubject/digest")
                        .and_then(|d| d.as_str()),
                )
                .map(|(grant, claimed)| {
                    dtg_credentials::digest_json(grant)
                        .map(|expected| expected != claimed)
                        // Undigestable grant: we cannot say it is stale, so we
                        // do not. R6.3 — claim only what was checked.
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            result.push(VrcSummary {
                vrc_id: vc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                remote_p_did: sanitize_display(&c.vtc_did, 256),
                remote_agent_name: config
                    .agent_name_for(&c.vtc_did)
                    .map(|n| sanitize_display(n, 256)),
                raw_json: content::RawCredential::Value(Arc::new(vc.clone())),
                alias: Some(community.clone()),
                issuer: sanitize_display(&issuer, 256),
                issuer_agent_name: config
                    .agent_name_for(&issuer)
                    .map(|n| sanitize_display(n, 256)),
                subject: sanitize_display(&subject, 256),
                subject_agent_name: config
                    .agent_name_for(&subject)
                    .map(|n| sanitize_display(n, 256)),
                validity,
                // A stale acknowledgement is inside its own window and still
                // completes nothing, so the window's answer would mislead. This
                // is not a revocation check either — no status list is consulted
                // — it is the digest binding, which is the whole of what makes
                // this credential mean anything.
                status: if stale {
                    "superseded — the community re-issued".to_string()
                } else {
                    status
                },
                kind: Some(
                    if stale {
                        "Acknowledgement (stale)"
                    } else {
                        "Acknowledgement"
                    }
                    .to_string(),
                ),
                subject_is_self: false,
                valid_from,
                valid_until,
            });
        }
    }
    result
}

/// Render a credential's validity window for people rather than machines.
///
/// Returns `(validity, status)` — e.g. `("22 Jul 2026 → 21 Aug 2026 · 29 days
/// left", "valid")`. The raw `validFrom`/`validUntil` are RFC 3339 timestamps;
/// read literally they answer "is this still good?" only after mental
/// arithmetic, which is the question the detail view exists to answer.
///
/// `status` reflects the **window only**. A credential can be inside its window
/// and still be revoked; that needs the issuer's status list, which is not
/// consulted here — so this never claims more than it checked.
///
/// Unparseable timestamps fall back to the raw strings rather than being hidden.
fn format_validity(
    valid_from: &str,
    valid_until: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> (String, String) {
    use chrono::DateTime;

    let fmt = |s: &str| -> Option<DateTime<chrono::Utc>> {
        DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&chrono::Utc))
    };
    let human = |d: DateTime<chrono::Utc>| d.format("%-d %b %Y").to_string();

    let from = fmt(valid_from);
    let until = valid_until.and_then(fmt);

    let from_text = from.map_or_else(|| valid_from.to_string(), human);

    let Some(until_text) = until.map(human) else {
        // No expiry: the window is open-ended, so the only state is whether it
        // has started.
        let status = match from {
            Some(f) if f > now => "not yet valid",
            _ => "valid",
        };
        return (format!("from {from_text}"), status.to_string());
    };

    let (status, note) = match (from, until) {
        (Some(f), _) if f > now => ("not yet valid", "starts in the future".to_string()),
        (_, Some(u)) if u <= now => ("expired", "expired".to_string()),
        (_, Some(u)) => {
            let days = (u - now).num_days();
            let note = match days {
                0 => "expires today".to_string(),
                1 => "1 day left".to_string(),
                d => format!("{d} days left"),
            };
            ("valid", note)
        }
        _ => ("valid", String::new()),
    };

    let validity = if note.is_empty() {
        format!("{from_text} → {until_text}")
    } else {
        format!("{from_text} → {until_text}  ·  {note}")
    };
    (validity, status.to_string())
}

/// [`format_validity`] for callers that already hold parsed dates, so a
/// timestamp is not formatted only to be parsed straight back.
fn format_validity_from_dates(
    valid_from: chrono::DateTime<chrono::Utc>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> (String, String) {
    format_validity(
        &valid_from.to_rfc3339(),
        valid_until.map(|d| d.to_rfc3339()).as_deref(),
        now,
    )
}

/// Returns true for unicode codepoints that can spoof or mangle TUI
/// display when rendered: bidirectional overrides, isolates, zero-width
/// spaces/joiners, BOM. These are silently stripped by [`sanitize_display`].
fn is_dangerous_format_char(c: char) -> bool {
    matches!(
        c as u32,
        // Bidi marks, embeddings, overrides
        0x200E | 0x200F |               // LRM, RLM
        0x202A..=0x202E |               // LRE, RLE, PDF, LRO, RLO
        0x2066..=0x2069 |               // LRI, RLI, FSI, PDI
        // Zero-width space / joiner / non-joiner
        0x200B..=0x200D |
        0xFEFF                          // BOM / zero-width non-breaking space
    )
}

/// Sanitize a string from an untrusted source for safe terminal display
/// and persistence (e.g. contact aliases captured from inbound messages).
///
/// Strips, in order:
///   1. ANSI CSI escape sequences (ESC `[` … letter pattern)
///   2. Other ASCII control characters, keeping space
///   3. Bidi-override / zero-width / BOM characters that allow visual
///      spoofing (e.g. RLO-flipping a contact alias to display text the
///      operator didn't approve).
///
/// Truncates to `max_len` *characters* (not bytes).
#[must_use]
pub fn sanitize_display(input: &str, max_len: usize) -> String {
    let mut stripped = String::with_capacity(input.len());
    let mut in_escape = false;
    for c in input.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        stripped.push(c);
    }
    stripped
        .chars()
        .filter(|c| (!c.is_control() || *c == ' ') && !is_dangerous_format_char(*c))
        .take(max_len)
        .collect()
}

/// Detect a did-git-sign install for the given persona DID by reading its
/// global SigningConfig and the matching allowed_signers entry. Returns
/// `None` if did-git-sign is not configured for this persona, or if the
/// state on disk is malformed.
///
/// Reads files synchronously and is cheap (single small file open + read).
/// Sourced from disk rather than re-derived from runtime key material so
/// the help screen reflects what `did-git-sign` itself would actually use
/// — i.e. if the config was hand-edited, the help view stays consistent
/// with the install.
fn detect_did_git_sign_info(persona_did: &str) -> Option<DidGitSignInfo> {
    let config_path = did_git_sign::config::SigningConfig::default_global_path().ok()?;
    let cfg = did_git_sign::config::SigningConfig::load(&config_path).ok()?;

    // Only show on the help screen if the configured signing identity
    // belongs to this persona. Avoids leaking another persona's keys when
    // multiple openvtc profiles share a host.
    let prefix = format!("{persona_did}#");
    if !cfg.did_key_id.starts_with(&prefix) {
        return None;
    }

    // Lift the SSH public key out of allowed_signers, which lives next to
    // the config and is written by `init::install`. Format is one entry
    // per line: `<principal> ssh-ed25519 <base64>`.
    let signers_path = config_path.parent()?.join("allowed_signers");
    let signers = std::fs::read_to_string(&signers_path).ok()?;
    let entry_prefix = format!("{} ssh-ed25519 ", cfg.did_key_id);
    let ssh_public_key = signers.lines().find_map(|line| {
        let line = line.trim();
        line.starts_with(&entry_prefix)
            .then(|| line.trim_start_matches(&cfg.did_key_id).trim().to_string())
    })?;

    Some(DidGitSignInfo {
        did_key_id: cfg.did_key_id,
        ssh_public_key,
        config_path: config_path.display().to_string(),
    })
}

/// Shortens a DID for display, fitting within `max_width` characters.
/// Sanitises first to drop ANSI / control bytes from untrusted input,
/// then delegates to the canonical tail-truncate helper.
#[must_use]
pub(crate) fn shorten_did(did: &str, max_width: usize) -> String {
    let sanitized = sanitize_display(did, 256);
    truncate_did(&sanitized, max_width).into_owned()
}

/// Contains config information that is shown in the main menu header
#[derive(Clone, Debug, Default)]
pub struct MainMenuConfigState {
    pub name: String,
    pub did: Arc<String>,
    /// Verified agent name for the active persona DID, if cached — shown in the
    /// header in place of the truncated DID.
    pub agent_name: Option<String>,
    /// Display name of the working (active) community, shown top-left (R-C-7a).
    /// Empty when there is no active community.
    pub community: String,
}

impl From<&Box<Config>> for MainMenuConfigState {
    fn from(config: &Box<Config>) -> Self {
        MainMenuConfigState::from(config.as_ref())
    }
}

impl From<&Config> for MainMenuConfigState {
    fn from(config: &Config) -> Self {
        // The persona identity is community-scoped: only surface it in the top
        // bar once the user is actually in a community (an Active membership). A
        // State-A account or a still-Pending join shows no persona name/DID up
        // there — the persona belongs to a community context, not the chrome.
        let in_community = config.account.memberships().any(|c| c.status.is_active());
        // The working community (R-C-7a): the Active community whose persona is
        // the active one. `active_persona` is kept in lockstep with the selected
        // working community (set at launch, on reconcile, and on switch), so the
        // header name matches the persona that scopes the panels. In the rare
        // persona-reuse case (one persona across several Active communities) the
        // first in display order is shown — those communities share a context.
        let community = config
            .active_persona
            .and_then(|persona| {
                config
                    .account
                    .communities_for_display(false)
                    .into_iter()
                    .find(|c| c.status.is_active() && c.persona_ref == persona)
                    .map(|c| {
                        crate::state_handler::community_label(
                            config,
                            &c.vtc_did,
                            c.display_name.as_deref(),
                            40,
                        )
                    })
            })
            .unwrap_or_default();
        let did = if in_community {
            config.persona_did_arc()
        } else {
            Arc::new(String::new())
        };
        MainMenuConfigState {
            name: if in_community {
                // The friendly name is user-chosen text, but setup can leave a
                // DID in it. Resolve it when it turns out to be one this account
                // has a verified name for, so the header never announces a
                // `did:webvh:` string it could name instead.
                let friendly = config.public.friendly_name.clone();
                config
                    .agent_name_for(&friendly)
                    .map(str::to_owned)
                    .unwrap_or(friendly)
            } else {
                String::new()
            },
            agent_name: if in_community {
                config.agent_name_for(&did).map(str::to_owned)
            } else {
                None
            },
            did,
            community,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub enum MainPanel {
    #[default]
    MainMenu,
    ContentPanel,
}

impl MainPanel {
    /// Switches to the next panel when pressing `TAB`
    #[allow(dead_code)]
    pub fn switch(&self) -> Self {
        match self {
            MainPanel::MainMenu => MainPanel::ContentPanel,
            MainPanel::ContentPanel => MainPanel::MainMenu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- community row labelling (agent names) ---

    /// Build a config holding one Active membership: persona `persona_did`
    /// presented to community `vtc_did`. `persona_label` and `display_name` are
    /// the explicitly-set names, either of which may be absent.
    fn config_with_membership(
        persona_did: &str,
        persona_label: Option<&str>,
        vtc_did: &str,
        display_name: Option<&str>,
    ) -> Config {
        use openvtc_core::config::account::{CommunityRecord, CommunityStatus, PersonaRecord};

        let mut config = crate::state_handler::dispatch_util::test_config();
        let persona_id = PersonaId::new();
        config.account.personas.insert(
            persona_id,
            PersonaRecord {
                extra: serde_json::Map::new(),
                persona_id,
                did: persona_did.to_string(),
                did_document: None,
                key_refs: vec![],
                mediator_did: None,
                origin_context_id: String::new(),
                created_at: chrono::Utc::now(),
                label: persona_label.map(str::to_owned),
            },
        );
        config.account.communities.insert(
            vtc_did.to_string(),
            vec![CommunityRecord {
                member_vmc: None,
                extra: serde_json::Map::new(),
                vtc_did: vtc_did.to_string(),
                display_name: display_name.map(str::to_owned),
                sub_context_id: String::new(),
                submit_transport: None,
                request_id_confirmed: false,
                persona_ref: persona_id,
                status: CommunityStatus::Active,
                favourite: false,
                archived: false,
                acknowledged: true,
                member_since: None,
                requested_at: None,
                receipt_at: None,
                relationships: Default::default(),
                tasks: Default::default(),
                vrcs_issued: Default::default(),
                vrcs_received: Default::default(),
                credentials: std::collections::BTreeMap::new(),
            }],
        );
        config
    }

    /// With no explicit label and no cached name, both halves of the row fall
    /// back to a truncated DID — the pre-existing behaviour, which must not
    /// change for an account that has no agent names.
    #[test]
    fn community_row_falls_back_to_truncated_dids() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let config = config_with_membership(persona_did, None, vtc_did, None);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(row.persona_label, shorten_did(persona_did, 24));
        assert_eq!(row.display_name, shorten_did(vtc_did, 40));
    }

    /// A verified agent name in the cache labels both the presented persona and
    /// the community, in place of the truncated DID. This is the regression the
    /// panel previously had: it never consulted the cache at all, so an enabled
    /// name could not appear on the communities screen.
    #[test]
    fn community_row_prefers_a_verified_agent_name_over_a_truncated_did() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        let now = chrono::Utc::now();
        config.set_cached_agent_name(persona_did, Some("example.com/@alice".into()), now);
        config.set_cached_agent_name(vtc_did, Some("example.com/@acme".into()), now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(row.persona_label, "example.com/@alice");
        assert_eq!(row.display_name, "example.com/@acme");
    }

    /// Select the account's only persona as the working one. The header's
    /// community slot is keyed off `active_persona`, which the shared
    /// membership helper deliberately leaves unset.
    fn with_active_persona(mut config: Config) -> Config {
        let persona_id = *config
            .account
            .personas
            .keys()
            .next()
            .expect("helper inserts one persona");
        config.active_persona = Some(persona_id);
        config
    }

    /// The header's community slot names the community by its verified agent
    /// name when it has no explicit display name — it used to fall straight to a
    /// shortened DID, so a named community still announced itself as
    /// `did:webvh:QmXi1…` in the top-left.
    #[test]
    fn header_community_falls_back_to_the_agent_name_before_the_did() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config =
            with_active_persona(config_with_membership(persona_did, None, vtc_did, None));
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );

        let header = MainMenuConfigState::from(&config);
        assert_eq!(header.community, "example.com/@acme");
    }

    /// An explicit display name still wins — it is the user's own label.
    #[test]
    fn header_community_prefers_an_explicit_display_name() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = with_active_persona(config_with_membership(
            persona_did,
            None,
            vtc_did,
            Some("Acme Corp"),
        ));
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );

        assert_eq!(MainMenuConfigState::from(&config).community, "Acme Corp");
    }

    /// With no name of any kind the DID is still shown, rather than a blank.
    #[test]
    fn header_community_falls_back_to_the_did_when_unnamed() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let config = with_active_persona(config_with_membership(persona_did, None, vtc_did, None));

        let header = MainMenuConfigState::from(&config);
        assert!(!header.community.is_empty());
        assert!(
            header.community.contains("did:webvh:"),
            "{}",
            header.community
        );
    }

    /// A friendly name that is really a DID resolves to that DID's verified
    /// name, so the header never prints an identifier it could have named.
    #[test]
    fn header_name_resolves_a_did_shaped_friendly_name() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        config.public.friendly_name = vtc_did.to_string();
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );

        assert_eq!(MainMenuConfigState::from(&config).name, "example.com/@acme");
    }

    /// The capabilities view titles itself with the same community label as the
    /// header and the credential list, rather than a raw DID.
    #[test]
    fn community_label_is_shared_across_surfaces() {
        use crate::state_handler::community_label;

        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);

        // No name of any kind: the DID, shortened.
        assert!(community_label(&config, vtc_did, None, 40).contains("did:webvh:"));

        // A verified agent name takes over.
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );
        assert_eq!(
            community_label(&config, vtc_did, None, 40),
            "example.com/@acme"
        );

        // An explicit display name still outranks it.
        assert_eq!(
            community_label(&config, vtc_did, Some("Acme Corp"), 40),
            "Acme Corp"
        );
    }

    /// An ordinary friendly name is left exactly as the user wrote it.
    #[test]
    fn header_name_leaves_a_real_friendly_name_alone() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        config.public.friendly_name = "Glenn".to_string();

        assert_eq!(MainMenuConfigState::from(&config).name, "Glenn");
    }

    /// The point of the summary line: "is this still good, and for how long"
    /// answered without the reader doing date arithmetic on RFC 3339 stamps.
    #[test]
    fn validity_reads_in_human_terms_with_a_relative_note() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (validity, status) =
            format_validity("2026-07-22T01:36:31Z", Some("2026-08-21T01:36:31Z"), now);
        assert_eq!(status, "valid");
        assert!(validity.contains("22 Jul 2026"), "{validity}");
        assert!(validity.contains("21 Aug 2026"), "{validity}");
        assert!(validity.contains("29 days left"), "{validity}");
    }

    /// An elapsed window reads as expired rather than as a countdown.
    #[test]
    fn validity_reports_an_expired_window() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (validity, status) =
            format_validity("2026-07-22T01:36:31Z", Some("2026-08-21T01:36:31Z"), now);
        assert_eq!(status, "expired");
        assert!(validity.contains("expired"), "{validity}");
    }

    /// A window that has not opened yet is neither valid nor expired.
    #[test]
    fn validity_reports_a_future_window() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (_, status) =
            format_validity("2026-07-22T01:36:31Z", Some("2026-08-21T01:36:31Z"), now);
        assert_eq!(status, "not yet valid");
    }

    /// No `validUntil` means open-ended — it must not render as expired, and
    /// must not invent an end date.
    #[test]
    fn validity_handles_an_open_ended_credential() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-07-23T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (validity, status) = format_validity("2026-07-22T01:36:31Z", None, now);
        assert_eq!(status, "valid");
        assert!(validity.starts_with("from "), "{validity}");
        assert!(!validity.contains('→'), "no end date to show: {validity}");
    }

    /// An unparseable timestamp is shown as-is rather than dropped — a
    /// credential with an odd date should still display something truthful.
    #[test]
    fn validity_falls_back_to_the_raw_string() {
        let now = chrono::Utc::now();
        let (validity, _) = format_validity("not-a-date", None, now);
        assert!(validity.contains("not-a-date"), "{validity}");
    }

    /// The detail block's identity rows resolve to a verified agent name, with
    /// the DID kept in the view model as the fallback the renderer uses when
    /// there is no name.
    #[test]
    fn community_detail_carries_agent_names_for_its_identity_rows() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        let now = chrono::Utc::now();
        config.set_cached_agent_name(persona_did, Some("example.com/@alice".into()), now);
        config.set_cached_agent_name(vtc_did, Some("example.com/@acme".into()), now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(
            row.persona_agent_name.as_deref(),
            Some("example.com/@alice")
        );
        assert_eq!(row.vtc_agent_name.as_deref(), Some("example.com/@acme"));
        // The DIDs are untouched — the name is additive, not a replacement.
        assert_eq!(row.persona_did, persona_did);
        assert_eq!(row.vtc_did, vtc_did);
    }

    /// A cached negative leaves the detail rows on the DID alone, with no name
    /// row rendered.
    #[test]
    fn community_detail_ignores_a_cached_negative_lookup() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        let now = chrono::Utc::now();
        config.set_cached_agent_name(persona_did, None, now);
        config.set_cached_agent_name(vtc_did, None, now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(row.persona_agent_name, None);
        assert_eq!(row.vtc_agent_name, None);
    }

    /// The user's own label still wins over an agent name — it is an explicit
    /// labelling choice and unspoofable, matching `resolve_did_to_display`'s
    /// documented precedence. Same for a community's resolved display name.
    #[test]
    fn community_row_keeps_explicit_labels_ahead_of_an_agent_name() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config =
            config_with_membership(persona_did, Some("Work me"), vtc_did, Some("Acme Co"));
        let now = chrono::Utc::now();
        config.set_cached_agent_name(persona_did, Some("example.com/@alice".into()), now);
        config.set_cached_agent_name(vtc_did, Some("example.com/@acme".into()), now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(row.persona_label, "Work me");
        assert_eq!(row.display_name, "Acme Co");
    }

    /// A cached *negative* lookup (the DID has no verifiable name) must not
    /// render as a name — the row falls back to the truncated DID.
    #[test]
    fn community_row_ignores_a_cached_negative_lookup() {
        let persona_did = "did:webvh:QmScidPersonaAAAAAAAAAAAAAAAAAAA:example.com:persona";
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(persona_did, None, vtc_did, None);
        config.set_cached_agent_name(persona_did, None, chrono::Utc::now());

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.communities.items[0];

        assert_eq!(row.persona_label, shorten_did(persona_did, 24));
    }

    // --- agent names on the credential / inbox / VTA-DID view models ---
    //
    // These cover the three panels migrated off raw DIDs. Each asserts the
    // *view model* carries the verified name beside the DID it labels; the
    // panels render it through `openvtc_core::display::display_identifier`,
    // which is unit-tested in `openvtc-core`.

    const ALICE_DID: &str = "did:webvh:QmScidAliceAAAAAAAAAAAAAAAAAAAA:example.com:alice";
    const BOB_DID: &str = "did:webvh:QmScidBobBBBBBBBBBBBBBBBBBBBBBB:example.com:bob";

    /// A minimally-valid *signed* VRC. `Vrcs::insert` keys on the proof value,
    /// so an unsigned credential cannot be stored.
    fn signed_vrc(issuer: &str, subject: &str) -> Arc<dtg_credentials::DTGCredential> {
        let json = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "DTGCredential", "RelationshipCredential"],
            "issuer": issuer,
            "validFrom": "2024-06-18T10:00:00Z",
            "credentialSubject": { "id": subject },
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2024-06-18T10:00:00",
                "verificationMethod": "did:example:test#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "z-test-proof"
            }
        });
        Arc::new(serde_json::from_value(json).expect("valid signed VRC"))
    }

    /// A config holding one received VRC issued by `BOB_DID` to `ALICE_DID`.
    fn config_with_received_vrc() -> Config {
        let mut config = crate::state_handler::dispatch_util::test_config();
        let remote = Arc::new(BOB_DID.to_string());
        config
            .private
            .vrcs_received
            .insert(&remote, signed_vrc(BOB_DID, ALICE_DID))
            .expect("VRC stores");
        config
    }

    /// The credentials panel's view model carries the verified name for every
    /// DID it shows: the remote party, the issuer and the subject.
    #[test]
    fn vrc_summary_carries_verified_agent_names() {
        let mut config = config_with_received_vrc();
        let now = chrono::Utc::now();
        config.set_cached_agent_name(BOB_DID, Some("example.com/@bob".into()), now);
        config.set_cached_agent_name(ALICE_DID, Some("example.com/@alice".into()), now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let vrc = &page.content_panel.credentials.received[0];

        assert_eq!(vrc.remote_agent_name.as_deref(), Some("example.com/@bob"));
        assert_eq!(vrc.issuer_agent_name.as_deref(), Some("example.com/@bob"));
        assert_eq!(
            vrc.subject_agent_name.as_deref(),
            Some("example.com/@alice")
        );
        // The DIDs themselves are unchanged — the name sits beside them.
        assert_eq!(vrc.issuer, BOB_DID);
        assert_eq!(vrc.subject, ALICE_DID);
    }

    /// No cache entry (and a cached *negative* lookup) must leave every name
    /// unset, so the panel keeps rendering the DID.
    #[test]
    fn vrc_summary_has_no_name_without_a_verified_lookup() {
        let mut config = config_with_received_vrc();
        config.set_cached_agent_name(BOB_DID, None, chrono::Utc::now());

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let vrc = &page.content_panel.credentials.received[0];

        assert!(vrc.remote_agent_name.is_none());
        assert!(vrc.issuer_agent_name.is_none());
        // ALICE_DID was never looked up at all.
        assert!(vrc.subject_agent_name.is_none());
    }

    /// Insert one task and return the summary the inbox panel would render.
    fn task_summary_for(config: &mut Config, type_: TaskType) -> TaskSummary {
        let id = Arc::new("task-1".to_string());
        config.private.tasks.new_task(&id, type_);
        let mut page = MainPageState::default();
        page.sync_from_config(config);
        page.content_panel.inbox.tasks[0].clone()
    }

    /// An inbox row carries the verified name for exactly the DID it displays.
    #[test]
    fn inbox_task_carries_verified_agent_name() {
        let mut config = crate::state_handler::dispatch_util::test_config();
        config.set_cached_agent_name(BOB_DID, Some("example.com/@bob".into()), chrono::Utc::now());

        let task = task_summary_for(
            &mut config,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::new(BOB_DID.to_string()),
            },
        );

        assert_eq!(task.remote_agent_name.as_deref(), Some("example.com/@bob"));
        assert_eq!(
            openvtc_core::display::display_identifier(
                task.remote_agent_name.as_deref(),
                &task.remote_did,
                60
            ),
            "example.com/@bob"
        );
    }

    /// A verified name outranks the requester-supplied `name` on an inbound
    /// relationship request: that name is self-asserted and spoofable, so it
    /// must not win over a name that actually round-tripped to this DID.
    #[test]
    fn inbox_verified_name_outranks_a_self_asserted_request_name() {
        use openvtc_core::relationships::RelationshipRequestBody;

        let mut config = crate::state_handler::dispatch_util::test_config();
        config.set_cached_agent_name(BOB_DID, Some("example.com/@bob".into()), chrono::Utc::now());

        let task = task_summary_for(
            &mut config,
            TaskType::RelationshipRequestInbound {
                from: Arc::new(BOB_DID.to_string()),
                to: Arc::new(ALICE_DID.to_string()),
                request: RelationshipRequestBody {
                    reason: None,
                    did: BOB_DID.to_string(),
                    name: Some("Totally Not Bob".to_string()),
                },
            },
        );

        // The self-asserted name is still what the DID slot falls back to...
        assert_eq!(task.remote_did, "Totally Not Bob");
        // ...but the verified name is what gets rendered.
        assert_eq!(
            openvtc_core::display::display_identifier(
                task.remote_agent_name.as_deref(),
                &task.remote_did,
                60
            ),
            "example.com/@bob"
        );
    }

    /// An unresolvable DID leaves the inbox row on its existing display string.
    #[test]
    fn inbox_task_without_a_name_keeps_the_did() {
        let mut config = crate::state_handler::dispatch_util::test_config();
        let task = task_summary_for(
            &mut config,
            TaskType::VRCRequestOutbound {
                remote_p_did: Arc::new(BOB_DID.to_string()),
            },
        );

        assert!(task.remote_agent_name.is_none());
        assert_eq!(task.remote_did, shorten_did(BOB_DID, 60));
    }

    /// The identity pane's Personas list carries the persona's verified name
    /// beside its DID; the persona's own label is a separate line and is left
    /// untouched.
    #[test]
    fn persona_row_carries_verified_agent_name() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, Some("Work me"), vtc_did, None);
        config.set_cached_agent_name(
            ALICE_DID,
            Some("example.com/@alice".into()),
            chrono::Utc::now(),
        );

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let row = &page.content_panel.identity.personas[0];

        assert_eq!(row.agent_name.as_deref(), Some("example.com/@alice"));
        assert_eq!(row.did, ALICE_DID);
        assert_eq!(row.label, "Work me");
    }

    /// A selection left pointing past the end of a shrunken persona list is
    /// clamped back onto a real row.
    ///
    /// Nothing else did this: the list is rebuilt wholesale on every sync, and a
    /// stale index disables every list-scoped key (each is guarded on
    /// `persona_selected < persona count`) while drawing no cursor to show why — a
    /// keyboard that looks broken until the next restart resets the index to 0.
    #[test]
    fn syncing_clamps_a_stale_persona_selection() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let config = config_with_membership(ALICE_DID, Some("Work me"), vtc_did, None);

        let mut page = MainPageState::default();
        // What a deletion (or a smaller profile) leaves behind.
        page.content_panel.identity.persona_selected = 4;
        page.sync_from_config(&config);

        assert_eq!(page.content_panel.identity.personas.len(), 1);
        assert_eq!(
            page.content_panel.identity.persona_selected, 0,
            "the selection must land on a row that exists"
        );
    }

    // --- VTA panel key counts ---

    /// A `KeyInfoConfig` carrying just the purpose the count reads.
    fn key_info(
        purpose: openvtc_core::config::KeyTypes,
    ) -> openvtc_core::config::secured_config::KeyInfoConfig {
        openvtc_core::config::secured_config::KeyInfoConfig {
            path: openvtc_core::config::secured_config::KeySourceMaterial::Derived {
                path: String::new(),
            },
            create_time: chrono::Utc::now(),
            purpose,
        }
    }

    /// Key counts are a classification, not a subtraction. Counting persona keys
    /// by `starts_with(active_persona_did)` and calling everything else
    /// "relationship" reported a second persona's keys as relationship keys — an
    /// account with no relationships at all showed a non-zero relationship
    /// count. `KeyInfoConfig::purpose` already records what each key is for.
    #[test]
    fn key_counts_classify_by_purpose_not_by_active_persona_prefix() {
        use openvtc_core::config::KeyTypes;

        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);

        let mut key = |id: &str, purpose: KeyTypes| {
            config.key_info.insert(id.to_string(), key_info(purpose));
        };
        // Two personas' worth of persona keys. Only ALICE is active, so the old
        // prefix match saw BOB's as "relationship".
        key(&format!("{ALICE_DID}#sign"), KeyTypes::PersonaSigning);
        key(
            &format!("{ALICE_DID}#auth"),
            KeyTypes::PersonaAuthentication,
        );
        key(&format!("{BOB_DID}#sign"), KeyTypes::PersonaSigning);
        key(&format!("{BOB_DID}#auth"), KeyTypes::PersonaAuthentication);
        // A webvh update key belongs to neither bucket.
        key(&format!("{ALICE_DID}#update"), KeyTypes::WebVHManagement);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let vta = &page.content_panel.vta;

        assert_eq!(vta.key_count, 5, "total is every managed key");
        assert_eq!(vta.persona_key_count, 4, "both personas' keys count");
        assert_eq!(
            vta.relationship_key_count, 0,
            "no relationships means no relationship keys"
        );
    }

    #[test]
    fn relationship_keys_are_counted_by_their_own_purposes() {
        use openvtc_core::config::KeyTypes;

        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);
        for (id, purpose) in [
            ("r1#verify", KeyTypes::RelationshipVerification),
            ("r1#encrypt", KeyTypes::RelationshipEncryption),
            (&format!("{ALICE_DID}#sign"), KeyTypes::PersonaSigning),
        ] {
            config.key_info.insert(id.to_string(), key_info(purpose));
        }

        let mut page = MainPageState::default();
        page.sync_from_config(&config);

        assert_eq!(page.content_panel.vta.persona_key_count, 1);
        assert_eq!(page.content_panel.vta.relationship_key_count, 2);
    }

    // --- agent names on the relationship-VRC rows and the VIC list ---

    /// A config holding one relationship with `BOB_DID`, carrying one VRC we
    /// issued (us → Bob) and one we received (Bob → us).
    fn config_with_relationship_vrcs() -> Config {
        use openvtc_core::relationships::{Relationship, RelationshipState};

        let mut config = crate::state_handler::dispatch_util::test_config();
        let remote = Arc::new(BOB_DID.to_string());
        config.private.relationships.relationships.insert(
            remote.clone(),
            Relationship {
                task_id: Arc::new("task-1".to_string()),
                our_did: Arc::new(ALICE_DID.to_string()),
                remote_did: remote.clone(),
                remote_p_did: remote.clone(),
                created: chrono::Utc::now(),
                state: RelationshipState::Established,
                our_persona: None,
                needs_reestablishment: false,
            },
        );
        config
            .private
            .vrcs_issued
            .insert(&remote, signed_vrc(ALICE_DID, BOB_DID))
            .expect("issued VRC stores");
        config
            .private
            .vrcs_received
            .insert(&remote, signed_vrc(BOB_DID, ALICE_DID))
            .expect("received VRC stores");
        config
    }

    /// The relationship detail's VRC rows carry the verified name for the
    /// issuer/subject DID each row displays — the same pair the credentials
    /// panel already carries, one screen behind.
    #[test]
    fn relationship_vrc_rows_carry_verified_agent_names() {
        let mut config = config_with_relationship_vrcs();
        let now = chrono::Utc::now();
        config.set_cached_agent_name(BOB_DID, Some("example.com/@bob".into()), now);
        config.set_cached_agent_name(ALICE_DID, Some("example.com/@alice".into()), now);

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let rel = &page.content_panel.relationships.relationships[0];

        // "To: …" on an issued row renders the subject.
        let issued = &rel.vrcs_issued[0];
        assert_eq!(
            issued.subject_agent_name.as_deref(),
            Some("example.com/@bob")
        );
        assert_eq!(
            issued.issuer_agent_name.as_deref(),
            Some("example.com/@alice")
        );
        // "From: …" on a received row renders the issuer.
        let received = &rel.vrcs_received[0];
        assert_eq!(
            received.issuer_agent_name.as_deref(),
            Some("example.com/@bob")
        );
        assert_eq!(
            received.subject_agent_name.as_deref(),
            Some("example.com/@alice")
        );

        // The shortened DIDs are untouched — the name sits beside them, and
        // that is what the row renders through `display_identifier`.
        assert_eq!(issued.subject, shorten_did(BOB_DID, 40));
        assert_eq!(
            openvtc_core::display::display_identifier(
                issued.subject_agent_name.as_deref(),
                &issued.subject,
                40
            ),
            "example.com/@bob"
        );
        assert_eq!(
            openvtc_core::display::display_identifier(
                received.issuer_agent_name.as_deref(),
                &received.issuer,
                40
            ),
            "example.com/@bob"
        );
    }

    /// A cached *negative* lookup (and an uncached DID) leaves the VRC rows
    /// showing the DID.
    #[test]
    fn relationship_vrc_rows_ignore_a_cached_negative_lookup() {
        let mut config = config_with_relationship_vrcs();
        config.set_cached_agent_name(BOB_DID, None, chrono::Utc::now());

        let mut page = MainPageState::default();
        page.sync_from_config(&config);
        let rel = &page.content_panel.relationships.relationships[0];

        let issued = &rel.vrcs_issued[0];
        let received = &rel.vrcs_received[0];
        assert!(issued.subject_agent_name.is_none());
        assert!(received.issuer_agent_name.is_none());
        // ALICE_DID was never looked up at all.
        assert!(issued.issuer_agent_name.is_none());
        assert!(received.subject_agent_name.is_none());
        assert_eq!(
            openvtc_core::display::display_identifier(
                issued.subject_agent_name.as_deref(),
                &issued.subject,
                40
            ),
            shorten_did(BOB_DID, 40)
        );
    }

    /// Seed the VTA panel's VIC list with one entry issued by `issuer`.
    fn page_with_vic(issuer: &str) -> MainPageState {
        let mut page = MainPageState::default();
        page.content_panel.vta.vics = vec![content::VicSummary {
            id: "urn:vic:1".to_string(),
            issuer: issuer.to_string(),
            issuer_agent_name: None,
            status: "valid".to_string(),
            lifecycle: content::VicLifecycle::Active,
            valid_until: String::new(),
        }]
        .into();
        page
    }

    /// The VIC list is annotated at sync time (it is not derived from `Config`),
    /// so the row can show the issuing community's verified name.
    #[test]
    fn vic_row_carries_the_issuers_verified_agent_name() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );

        let mut page = page_with_vic(vtc_did);
        page.sync_from_config(&config);
        let vic = &page.content_panel.vta.vics[0];

        assert_eq!(vic.issuer_agent_name.as_deref(), Some("example.com/@acme"));
        assert_eq!(vic.issuer, vtc_did);
        assert_eq!(
            openvtc_core::display::display_identifier(
                vic.issuer_agent_name.as_deref(),
                &vic.issuer,
                256
            ),
            "example.com/@acme"
        );
    }

    /// A cached negative lookup leaves the VIC row on the issuer DID.
    #[test]
    fn vic_row_ignores_a_cached_negative_lookup() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);
        config.set_cached_agent_name(vtc_did, None, chrono::Utc::now());

        let mut page = page_with_vic(vtc_did);
        page.sync_from_config(&config);
        let vic = &page.content_panel.vta.vics[0];

        assert!(vic.issuer_agent_name.is_none());
        assert_eq!(
            openvtc_core::display::display_identifier(
                vic.issuer_agent_name.as_deref(),
                &vic.issuer,
                256
            ),
            vtc_did
        );
    }

    /// Re-syncing must not leave a stale name behind: a name that disappears
    /// from the cache (re-checked, no longer verifiable) clears from the row.
    #[test]
    fn vic_row_name_clears_when_the_lookup_turns_negative() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);
        config.set_cached_agent_name(
            vtc_did,
            Some("example.com/@acme".into()),
            chrono::Utc::now(),
        );

        let mut page = page_with_vic(vtc_did);
        page.sync_from_config(&config);
        assert!(page.content_panel.vta.vics[0].issuer_agent_name.is_some());

        config.set_cached_agent_name(vtc_did, None, chrono::Utc::now());
        page.sync_from_config(&config);
        assert!(page.content_panel.vta.vics[0].issuer_agent_name.is_none());
    }

    /// A cached negative lookup leaves the persona row on the DID.
    #[test]
    fn persona_row_ignores_a_cached_negative_lookup() {
        let vtc_did = "did:webvh:QmScidCommunityBBBBBBBBBBBBBBBBBB:example.com:community";
        let mut config = config_with_membership(ALICE_DID, None, vtc_did, None);
        config.set_cached_agent_name(ALICE_DID, None, chrono::Utc::now());

        let mut page = MainPageState::default();
        page.sync_from_config(&config);

        assert!(page.content_panel.identity.personas[0].agent_name.is_none());
    }

    // --- persona_in_scope (community-scoping filter, D10/R-C-6) ---

    #[test]
    fn persona_in_scope_filters_by_active_persona() {
        let a = PersonaId::new();
        let b = PersonaId::new();

        // With a selection, only the active persona's items (and untagged items
        // in a single-persona account) are in scope.
        assert!(persona_in_scope(Some(a), Some(a), 2));
        assert!(!persona_in_scope(Some(b), Some(a), 2));
        // Untagged item: hidden when multiple personas (ambiguous)...
        assert!(!persona_in_scope(None, Some(a), 2));
        // ...but shown in a single-persona account (no ambiguity).
        assert!(persona_in_scope(None, Some(a), 1));

        // No active selection: only the single/zero-persona case shows items.
        assert!(persona_in_scope(Some(a), None, 1));
        assert!(persona_in_scope(None, None, 1));
        assert!(!persona_in_scope(Some(a), None, 2));
        assert!(!persona_in_scope(None, None, 2));
    }

    // --- sanitize_display ---

    #[test]
    fn test_sanitize_display_strips_control_chars() {
        assert_eq!(sanitize_display("hello\x00world", 256), "helloworld");
        assert_eq!(sanitize_display("hello\nworld", 256), "helloworld");
    }

    #[test]
    fn test_sanitize_display_strips_ansi_escapes() {
        assert_eq!(sanitize_display("\x1b[31mred\x1b[0m", 256), "red");
    }

    #[test]
    fn test_sanitize_display_truncates() {
        let long = "a".repeat(300);
        let result = sanitize_display(&long, 10);
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_sanitize_display_preserves_spaces() {
        assert_eq!(sanitize_display("hello world", 256), "hello world");
    }

    #[test]
    fn test_sanitize_display_empty_input() {
        assert_eq!(sanitize_display("", 256), "");
    }

    // --- shorten_did ---

    #[test]
    fn test_shorten_did_short_input() {
        let short = "did:test:abc";
        let result = shorten_did(short, 60);
        assert_eq!(result, short); // fits within 60 chars
    }

    #[test]
    fn test_shorten_did_long_input() {
        let long = "did:test:abcdefghijklmnopqrstuvwxyz";
        let result = shorten_did(long, 20);
        assert!(result.ends_with("..."));
        assert!(result.len() <= 20);
    }

    #[test]
    fn test_shorten_did_exact_fit() {
        let did = "did:test:exactly30charslongXXX";
        let result = shorten_did(did, 30);
        assert_eq!(result.len(), did.len()); // exactly fits
    }

    // --- MainPageState::log ---

    #[test]
    fn test_activity_log_bounded() {
        let mut state = MainPageState::default();
        for i in 0..MAX_ACTIVITY_LOG_ENTRIES + 10 {
            state.log(format!("entry-{}", i));
        }
        assert_eq!(state.activity_log.len(), MAX_ACTIVITY_LOG_ENTRIES);
        // Oldest entries should have been dropped
        assert!(
            state
                .activity_log
                .front()
                .unwrap()
                .summary
                .contains("entry-10")
        );
    }

    // --- MainPanel::switch ---

    #[test]
    fn test_main_panel_switch() {
        let panel = MainPanel::MainMenu;
        assert!(matches!(panel.switch(), MainPanel::ContentPanel));
        let panel = MainPanel::ContentPanel;
        assert!(matches!(panel.switch(), MainPanel::MainMenu));
    }

    // --- RawCredential lazy rendering (Part 2) ---

    /// The lazy `RawCredential::Vrc` path must pretty-print byte-identically to
    /// the previous eager `serde_json::to_string_pretty(vrc.credential())`.
    #[test]
    fn test_raw_credential_vrc_matches_eager_output() {
        use chrono::{TimeZone, Utc};
        use dtg_credentials::DTGCredential;

        let valid_from = Utc.with_ymd_and_hms(2024, 1, 2, 3, 4, 5).unwrap();
        let vrc = DTGCredential::new_vrc(
            "did:test:issuer".to_string(),
            "did:test:subject".to_string(),
            valid_from,
            Some(Utc.with_ymd_and_hms(2025, 6, 7, 8, 9, 10).unwrap()),
        );
        // Old eager output, computed exactly as `sync_from_config` used to.
        let eager = serde_json::to_string_pretty(vrc.credential()).unwrap();

        let lazy = content::RawCredential::Vrc(Arc::new(vrc)).to_pretty_json();
        assert_eq!(lazy, eager, "lazy VRC JSON must match the old eager output");
    }

    /// The lazy `RawCredential::Value` path (membership/role credentials) must
    /// pretty-print byte-identically to the previous eager
    /// `serde_json::to_string_pretty(vc)`.
    #[test]
    fn test_raw_credential_value_matches_eager_output() {
        let vc = serde_json::json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential", "MembershipCredential"],
            "issuer": "did:test:vtc",
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": { "id": "did:test:member", "role": "member" }
        });
        let eager = serde_json::to_string_pretty(&vc).unwrap();

        let lazy = content::RawCredential::Value(Arc::new(vc)).to_pretty_json();
        assert_eq!(
            lazy, eager,
            "lazy membership JSON must match the old eager output"
        );
    }

    // --- Arc pointer-bump cloning (Part 1) ---

    /// Cloning `MainPageState` must share the Arc-wrapped heavy collections by
    /// pointer (a pointer bump), not deep-copy them — that is the whole point of
    /// the per-event clone optimisation.
    #[test]
    fn test_clone_shares_arc_data() {
        let mut state = MainPageState::default();
        // Populate the Arc-wrapped collections with non-empty data so the
        // pointer identity is meaningful.
        state.content_panel.inbox.tasks = vec![TaskSummary {
            id: "t1".to_string(),
            type_display: "Test".to_string(),
            kind: TaskKind::Informational("x".to_string()),
            remote_did: "did:test:remote".to_string(),
            remote_agent_name: None,
            created: "2024-01-01 00:00".to_string(),
        }]
        .into();
        state.log_detailed("summary", "detail");

        let clone = state.clone();

        // Heavy vectors share the same allocation.
        assert!(
            Arc::ptr_eq(
                &state.content_panel.inbox.tasks,
                &clone.content_panel.inbox.tasks
            ),
            "inbox tasks must be shared by pointer after clone"
        );
        // Activity-log entries share the same allocation (per-entry Arc).
        assert!(
            Arc::ptr_eq(
                state.activity_log.front().unwrap(),
                clone.activity_log.front().unwrap()
            ),
            "activity log entries must be shared by pointer after clone"
        );
    }
}
