//! `openvtc health` — resolve the messaging chain and print the map.
//!
//! The command exists for one question: a join went out, nothing came back,
//! and every service involved logged a clean run. Answering it means knowing
//! which DIDs resolve, what each one advertises, which transport any two of
//! them would actually negotiate, and whether they even share a mediator. That
//! is four `did.jsonl` fetches and a service-array diff done by hand, which is
//! why it usually isn't done.
//!
//! Config loading is **best-effort by design**. `--vtc` alone produces a useful
//! report against a community you have not joined (and against one whose join is
//! stuck), and a config that will not decrypt is itself a finding rather than a
//! reason to refuse to run.

use anyhow::Result;
use console::style;
use openvtc_core::config::{Config, KeyBackend};
use openvtc_core::health::{
    HealthReport, LinkOutcome, Party, Probe, ProbeGrade, Role, Step, Subject,
    build_report_with_progress,
};

use crate::colors::{CLI_CAUTION, CLI_ERROR, CLI_EXAMPLE, CLI_INFO, Themed};

/// Build the subject list and render the report.
///
/// `config` is `None` when the account could not be loaded; the report then
/// covers only the `--vtc` DIDs given on the command line.
pub async fn run(
    profile: &str,
    config: Option<&Config>,
    vtc_args: &[String],
    as_json: bool,
    recoverable: bool,
) -> Result<()> {
    let local = local_report(profile);
    let access = config.and_then(vta_access);

    let mut subjects: Vec<Subject> = Vec::new();

    if let Some(config) = config {
        for identity in config.identities.values() {
            subjects.push(Subject::new(
                Role::Persona,
                format!("persona {}", short_tail(&identity.did)),
                identity.did.clone(),
            ));
        }
        if let KeyBackend::Vta { vta_did, .. } = &config.key_backend
            && vta_did.starts_with("did:")
        {
            subjects.push(Subject::new(Role::Vta, "VTA", vta_did.clone()));
        }
        for community in config.account.memberships() {
            let did = community.vtc_did.to_string();
            subjects.push(Subject::new(
                Role::Vtc,
                format!("VTC {} (joined)", short_tail(&did)),
                did,
            ));
        }
    }

    // Command-line VTCs last: `build_report` de-duplicates by DID and keeps the
    // first label, so a community already in the config keeps its "(joined)"
    // label rather than being relabelled by the flag that also named it.
    for did in vtc_args {
        subjects.push(Subject::new(
            Role::Vtc,
            format!("VTC {} (--vtc)", short_tail(did)),
            did.clone(),
        ));
    }

    // `--recoverable` answers a question the local section cannot: if this
    // machine were lost, could the account be rebuilt from its Trust Context?
    // Strictly read-only — the same plan the setup wizard would build, printed
    // rather than applied.
    if recoverable {
        match config {
            Some(config) => report_recoverability(config).await,
            None => eprintln!(
                "{}",
                style("--recoverable needs a loadable account; skipping.").themed(CLI_CAUTION)
            ),
        }
    }

    // No subjects means no *network* checks — but the local section above is
    // exactly what a user with an unloadable profile needs, and it is the run
    // where they need it most. Print it and stop, rather than refusing to
    // report anything because the half that failed is the half we can't check.
    if subjects.is_empty() {
        if as_json {
            let mut value = local.as_json();
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "vta_access".to_string(),
                    VtaAccess::as_json(access.as_ref()),
                );
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            local.render();
            if let Some(access) = &access {
                access.render();
            }
            eprintln!(
                "{}",
                style(
                    "\nNo network checks ran: no account could be loaded and no --vtc was \
                     given. Pass --vtc <did> to check a community directly."
                )
                .themed(CLI_CAUTION)
            );
        }
        if local.is_healthy() {
            return Ok(());
        }
        std::process::exit(1);
    }

    // Progress goes to stderr, the report to stdout. That keeps
    // `openvtc health --json > report.json` piping cleanly while still showing
    // the operator what is being waited on — and progress *is* wanted under
    // `--json`, since that is the run most likely to be watched rather than read.
    let report = build_report_with_progress(&subjects, &|step| trace(&step)).await;

    if as_json {
        // Additive: the existing report keys stay where they are, with the
        // local section alongside them, so anything already parsing this
        // output keeps working.
        let mut value = serde_json::to_value(&report)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("local".to_string(), local.as_json());
            obj.insert(
                "vta_access".to_string(),
                VtaAccess::as_json(access.as_ref()),
            );
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        local.render();
        if let Some(access) = &access {
            access.render();
        }
        render(&report, config.is_none());
    }

    // A broken chain is a failed check: exit non-zero so this is usable in a
    // script or a CI smoke test, not only by eye.
    if report.is_healthy() && local.is_healthy() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// Where this profile's secrets live and whether they are actually there.
///
/// The first question on a failed startup is local, not remote — "are my keys
/// still on this machine?" — and until now `openvtc health` could not answer
/// it. It also reports *durability*, because a store that legitimately holds
/// nothing after a reboot is a different situation from one that lost it.
struct LocalReport {
    profile: String,
    store: Option<&'static openvtc_core::secure_store::StoreDescription>,
    probe: openvtc_core::secure_store::EntryProbe,
    config_path: Option<std::path::PathBuf>,
}

fn local_report(profile: &str) -> LocalReport {
    let config_path = openvtc_core::config::public_config::profile_dir(profile)
        .ok()
        .map(|dir| {
            dir.join(if profile == "default" {
                "config.json".to_string()
            } else {
                format!("config-{profile}.json")
            })
        });
    LocalReport {
        profile: profile.to_string(),
        store: openvtc_core::secure_store::describe_active(),
        probe: openvtc_core::secure_store::probe(profile),
        config_path,
    }
}

impl LocalReport {
    /// Unhealthy when the two halves of a profile disagree: a config file with
    /// no credential behind it, or a store that will not answer. A profile that
    /// does not exist at all is not a fault — that is a first run.
    fn is_healthy(&self) -> bool {
        use openvtc_core::secure_store::EntryStatus;
        let has_config = self.config_path.as_ref().is_some_and(|p| p.exists());
        match &self.probe.status {
            EntryStatus::Present => true,
            EntryStatus::Missing => !has_config,
            EntryStatus::Unavailable(_) => false,
        }
    }

    fn as_json(&self) -> serde_json::Value {
        use openvtc_core::secure_store::EntryStatus;
        serde_json::json!({
            "profile": self.profile,
            "config_file": self.config_path.as_ref().map(|p| p.display().to_string()),
            "config_file_present": self.config_path.as_ref().is_some_and(|p| p.exists()),
            "store": self.store.map(|s| s.label.clone()),
            "store_location": self.store.map(|s| s.location.clone()),
            "credential": match &self.probe.status {
                EntryStatus::Present => "present",
                EntryStatus::Missing => "missing",
                EntryStatus::Unavailable(_) => "unavailable",
            },
            "credential_error": match &self.probe.status {
                EntryStatus::Unavailable(e) => Some(e.clone()),
                _ => None,
            },
            "credential_path": self.probe.path,
            // Durability describes a credential that exists. Reporting the
            // store's lifetime next to "credential: missing" reads as though
            // something durable is sitting there.
            "durability": match &self.probe.status {
                EntryStatus::Present => Some(self.probe.durability.lifetime_phrase()),
                _ => None,
            },
            "volatile": match &self.probe.status {
                EntryStatus::Present => Some(self.probe.durability.is_volatile()),
                _ => None,
            },
            "healthy": self.is_healthy(),
        })
    }

    fn render(&self) {
        use openvtc_core::secure_store::EntryStatus;
        println!("{}", style("Local configuration").themed(CLI_INFO).bold());
        println!("  profile          {}", self.profile);
        if let Some(path) = &self.config_path {
            let mark = if path.exists() { "present" } else { "MISSING" };
            println!("  config file      {} ({mark})", path.display());
        }
        if let Some(store) = self.store {
            println!("  secure store     {}", store.label);
            println!("  store location   {}", store.location);
        }
        match &self.probe.status {
            EntryStatus::Present => {
                println!(
                    "  credential       {} ({})",
                    style("present").themed(CLI_EXAMPLE),
                    self.probe.durability.lifetime_phrase()
                );
                if let Some(path) = &self.probe.path {
                    println!("  credential file  {path}");
                }
                if self.probe.durability.is_volatile() {
                    println!(
                        "  {}",
                        style(
                            "WARNING: this profile's keys are NOT written to disk and will be \
                             lost. Export a backup: Settings -> Export config."
                        )
                        .themed(CLI_CAUTION)
                    );
                }
            }
            EntryStatus::Missing => {
                println!(
                    "  credential       {}",
                    style("NOT FOUND").themed(CLI_ERROR)
                );
            }
            EntryStatus::Unavailable(e) => {
                println!(
                    "  credential       {} ({e})",
                    style("store unavailable").themed(CLI_ERROR)
                );
            }
        }
        if let Some(store) = self.store
            && let Some(hint) = &store.inspect_hint
        {
            println!("  check yourself   $ {hint}");
        }
        println!();
    }
}

/// How this install reaches the VTA, and — the part that was missing — the DID
/// it authenticates *as*.
///
/// The VTA keys its ACL on that DID, so it is the one an operator has to name
/// in `pnm acl get` / `pnm acl update` to see or change what this install may
/// do. It is a `did:key` minted during setup and it never appears in the config
/// file (it lives in the credential bundle in the secure store), so short of
/// reading it out of the TUI's VTA panel there was no way to get at it — while
/// the identity pane's own refusal hint says "`openvtc health` prints the DID".
/// Now it does.
///
/// Everything here is read from the loaded config: no network, so it is
/// answerable on exactly the run where the network leg is the thing that is
/// broken.
struct VtaAccess {
    /// The `did:key` this install authenticates to the VTA as.
    credential_did: String,
    vta_did: String,
    /// Empty for a DIDComm-only VTA.
    vta_url: String,
    /// `Some` when setup reached the VTA over DIDComm; the transport
    /// `build_runtime_vta_client` will pick again at runtime.
    mediator_did: Option<String>,
    context_id: String,
}

/// `None` for a BIP32 profile: there is no VTA and so no ACL to edit.
fn vta_access(config: &Config) -> Option<VtaAccess> {
    let KeyBackend::Vta {
        credential_did,
        vta_did,
        vta_url,
        mediator_did,
        ..
    } = &config.key_backend
    else {
        return None;
    };
    Some(VtaAccess {
        credential_did: credential_did.clone(),
        vta_did: vta_did.clone(),
        vta_url: vta_url.clone(),
        mediator_did: mediator_did.clone(),
        context_id: config.account.top_context_id.clone(),
    })
}

impl VtaAccess {
    /// The transport this profile would open, named the same way
    /// `build_runtime_vta_client` chooses it: a mediator means DIDComm, and a
    /// REST URL alongside it is a fallback rather than the primary.
    fn transport(&self) -> String {
        match (&self.mediator_did, self.vta_url.is_empty()) {
            (Some(_), true) => "DIDComm".to_string(),
            (Some(_), false) => "DIDComm (REST fallback configured)".to_string(),
            (None, false) => "REST".to_string(),
            (None, true) => "none configured".to_string(),
        }
    }

    /// Serialised even when absent, so a script can read `.vta_access` without
    /// having to know whether this profile uses a VTA.
    fn as_json(access: Option<&Self>) -> serde_json::Value {
        let Some(access) = access else {
            return serde_json::Value::Null;
        };
        serde_json::json!({
            // Named for what it is used for rather than for where it is stored:
            // a consumer of this key wants the ACL subject.
            "authenticates_as": access.credential_did,
            "vta_did": access.vta_did,
            "vta_url": (!access.vta_url.is_empty()).then(|| access.vta_url.clone()),
            "mediator_did": access.mediator_did,
            "context_id": access.context_id,
            "transport": access.transport(),
        })
    }

    fn render(&self) {
        println!("{}", style("VTA access").themed(CLI_INFO).bold());
        println!("  VTA              {}", self.vta_did);
        println!("  context          {}", self.context_id);
        println!("  transport        {}", self.transport());
        if let Some(mediator) = &self.mediator_did {
            println!("  mediator         {mediator}");
        }
        if !self.vta_url.is_empty() {
            println!("  REST endpoint    {}", self.vta_url);
        }
        // Printed in full and last, on its own, because it is the one line on
        // this screen that gets copied into another terminal. Truncating it —
        // as the TUI panel must, for width — would make it useless here.
        println!(
            "  authenticates as {}",
            style(&self.credential_did).themed(CLI_EXAMPLE)
        );
        println!();
        println!("  The VTA's ACL is keyed on that last DID: it is what to name when reading");
        println!("  or changing what this install may do. From your PNM session:");
        println!();
        println!(
            "    {}",
            style(format!("pnm acl get {}", self.credential_did)).themed(CLI_CAUTION)
        );
        println!(
            "    {}",
            style(format!(
                "pnm acl update {} --capabilities persona-holder",
                self.credential_did
            ))
            .themed(CLI_CAUTION)
        );
        println!();
        // `--capabilities` narrows everywhere else it appears, and someone
        // pasting that second line deserves to know why this one does not.
        println!("  `persona-holder` is the exception that grants rather than narrows: it adds");
        println!(
            "  authority over your own identity — the attributes and faces that sit above every"
        );
        println!("  context — without widening this install's reach into any other context.");
        println!();
    }
}

/// The last path segment of a `did:webvh`, which is the part humans recognise
/// (`…:dids.example.dev:legend-swear` → `legend-swear`). Falls back to the whole
/// string for DID methods with no path.
fn short_tail(did: &str) -> String {
    did.rsplit(':').next().unwrap_or(did).to_string()
}

/// Render one [`Step`] to stderr, unbuffered.
///
/// `eprintln!` flushes per call, which is what makes this live rather than a
/// batch dumped at exit — the whole point is that the operator sees the slow
/// step *while* it is slow.
///
/// Each wait is announced before it starts and its result carries the time it
/// took, because a chain that pauses nine seconds on one mediator and then
/// succeeds has told you something the final report cannot: the outcome is fine
/// and the host is struggling.
fn trace(step: &Step) {
    // `dim` rather than a palette colour: these lines are scaffolding the
    // operator reads past on a healthy run, and they must not compete with the
    // report that follows on stdout.
    let dim = |s: String| style(s).dim().to_string();
    match step {
        Step::ResolverStarting => {
            eprintln!("{}", dim("  · starting DID resolver…".into()));
        }
        Step::Resolving { role, label, did } => {
            eprintln!(
                "{}",
                dim(format!(
                    "  · resolving {} {label} ({})…",
                    role.as_str(),
                    truncate_did(did)
                ))
            );
        }
        Step::Resolved {
            label,
            services,
            transports,
            elapsed,
        } => {
            let transports = if transports.is_empty() {
                style("no known transport").themed(CLI_CAUTION).to_string()
            } else {
                style(protocols(transports)).themed(CLI_EXAMPLE).to_string()
            };
            eprintln!(
                "    {} {label} — {services} service{}, {transports} {}",
                style("✓").themed(CLI_INFO),
                if *services == 1 { "" } else { "s" },
                dim(secs(elapsed)),
            );
        }
        Step::ResolveFailed {
            label,
            error,
            elapsed,
        } => {
            eprintln!(
                "    {} {label} — {error} {}",
                style("✗").themed(CLI_ERROR).bold(),
                dim(secs(elapsed)),
            );
        }
        Step::FollowingMediators { count } => {
            if *count > 0 {
                eprintln!(
                    "{}",
                    dim(format!(
                        "  · following {count} discovered mediator{}…",
                        if *count == 1 { "" } else { "s" }
                    ))
                );
            }
        }
        Step::Probing { url } => {
            eprintln!("{}", dim(format!("  · probing {url}…")));
        }
        Step::Probed { probe, elapsed } => match probe {
            Probe::Reachable { url, http_status } => {
                let (word, colour) = probe_words(probe);
                let mark = if probe.grade() == Some(ProbeGrade::ServerError) {
                    style("!").themed(CLI_CAUTION).bold()
                } else {
                    style("✓").themed(CLI_INFO)
                };
                eprintln!(
                    "    {mark} {url} — {} (HTTP {http_status}) {}",
                    style(word).themed(colour),
                    dim(secs(elapsed)),
                );
            }
            Probe::Unreachable { url, error } => eprintln!(
                "    {} {url} — {error} {}",
                style("✗").themed(CLI_ERROR).bold(),
                dim(secs(elapsed)),
            ),
        },
        Step::Negotiating { pairs } => {
            if *pairs > 0 {
                eprintln!(
                    "{}",
                    dim(format!(
                        "  · negotiating {pairs} pair{}…",
                        if *pairs == 1 { "" } else { "s" }
                    ))
                );
            }
        }
        Step::Finished { elapsed } => {
            eprintln!(
                "{}",
                dim(format!("  · done in {:.1}s", elapsed.as_secs_f64()))
            );
            eprintln!();
        }
        // `Step` is `#[non_exhaustive]`: a variant added upstream should be
        // silent here rather than stopping the build of a diagnostic tool.
        _ => {}
    }
}

/// A duration at the precision that matters for a network wait — tenths.
/// Anything finer is noise next to a 10s timeout.
fn secs(elapsed: &std::time::Duration) -> String {
    format!("({:.1}s)", elapsed.as_secs_f64())
}

/// Shorten a DID for a progress line: the method, an ellipsis, and the trailing
/// path segment that identifies it. A full `did:webvh` is ~110 characters and
/// wraps the terminal, which is what makes a live trace unreadable.
fn truncate_did(did: &str) -> String {
    if did.len() <= 48 {
        return did.to_string();
    }
    let tail = short_tail(did);
    let head: String = did.chars().take(20).collect();
    format!("{head}…{tail}")
}

fn render(report: &HealthReport, config_missing: bool) {
    if config_missing {
        println!(
            "{}",
            style(
                "No account loaded — reporting only the DIDs given with --vtc. \
                 Persona, VTA and mediator legs are not covered."
            )
            .themed(CLI_CAUTION)
        );
        println!();
    }

    println!("{}", style("PARTIES").themed(CLI_INFO).bold());
    for party in &report.parties {
        render_party(party);
    }

    if !report.links.is_empty() {
        println!();
        println!("{}", style("NEGOTIATED TRANSPORT").themed(CLI_INFO).bold());
        for link in &report.links {
            let arrow = format!("  {} → {}", link.from, link.to);
            match &link.outcome {
                LinkOutcome::Selected {
                    protocol,
                    peer_endpoint,
                } => println!(
                    "{arrow}: {} via {}",
                    style(protocol.as_str()).themed(CLI_EXAMPLE).bold(),
                    style(peer_endpoint).themed(CLI_EXAMPLE),
                ),
                LinkOutcome::NoCommonProtocol { ours, theirs } => println!(
                    "{arrow}: {} (we offer [{}], they offer [{}])",
                    style("no shared transport").themed(CLI_ERROR).bold(),
                    protocols(ours),
                    protocols(theirs),
                ),
                LinkOutcome::Unknown { reason } => println!(
                    "{arrow}: {} ({reason})",
                    style("unknown").themed(CLI_CAUTION)
                ),
            }
        }
    }

    println!();
    if report.notes.is_empty() {
        println!(
            "{}",
            style("No problems found in the messaging chain.").themed(CLI_INFO)
        );
    } else {
        println!("{}", style("FINDINGS").themed(CLI_CAUTION).bold());
        for note in &report.notes {
            println!("  • {note}");
        }
    }
}

fn render_party(party: &Party) {
    println!();
    println!(
        "  {} {}",
        style(format!("[{}]", party.role.as_str())).themed(CLI_EXAMPLE),
        style(&party.label).bold(),
    );
    println!("    did: {}", style(&party.did).themed(CLI_EXAMPLE));

    let Some(resolved) = &party.resolved else {
        println!(
            "    {}: {}",
            style("UNRESOLVED").themed(CLI_ERROR).bold(),
            party.error.as_deref().unwrap_or("unknown error"),
        );
        return;
    };

    if resolved.services.is_empty() {
        println!("    services: {}", style("none").themed(CLI_ERROR));
    } else {
        println!("    services:");
        for service in &resolved.services {
            let types = if service.types.is_empty() {
                "<no type>".to_string()
            } else {
                service.types.join(", ")
            };
            // The `#id` fragment is shown but never matched on — an operator
            // comparing two deployments needs to see that one names it `#tsp`
            // and the other `#tsp-transport` while both are `TSPTransport`.
            println!(
                "      {:<28} {:<22} → {}",
                fragment(&service.id),
                style(types).themed(CLI_INFO),
                service.endpoint,
            );
        }
    }

    for probe in &resolved.probes {
        match probe {
            Probe::Reachable { url, http_status } => {
                let (word, colour) = probe_words(probe);
                println!(
                    "    probe {url} → {} (HTTP {http_status})",
                    style(word).themed(colour),
                );
            }
            Probe::Unreachable { url, error } => println!(
                "    probe {url} → {} ({error})",
                style("unreachable").themed(CLI_ERROR).bold(),
            ),
        }
    }
}

/// The verdict word and colour for a probe.
///
/// "reachable (HTTP 404)" read as a contradiction — the word claimed health and
/// the number denied it, and nothing told the reader which to believe. The word
/// now carries the grade, so a mediator base path answering 404 says
/// "responding", which is exactly what it is: the host is there and that path
/// does not serve GETs.
fn probe_words(probe: &Probe) -> (&'static str, crate::theme::Role) {
    match probe.grade() {
        Some(ProbeGrade::Ok) => ("ok", CLI_INFO),
        Some(ProbeGrade::Responding) => ("responding", CLI_INFO),
        Some(ProbeGrade::ServerError) => ("server error", CLI_CAUTION),
        None => ("unreachable", CLI_ERROR),
    }
}

/// Just the `#fragment` of a service id when it has one — the full DID prefix is
/// already printed above and repeating it per row buries the part that differs.
fn fragment(id: &str) -> String {
    match id.rsplit_once('#') {
        Some((_, frag)) => format!("#{frag}"),
        None => id.to_string(),
    }
}

fn protocols(list: &[vta_sdk::protocol::matching::Protocol]) -> String {
    if list.is_empty() {
        return "none".to_string();
    }
    list.iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Report whether this account could be rebuilt from its Trust Context.
///
/// The question this answers is not "is my config intact" — that is the local
/// section — but "if this machine vanished, is what the VTA holds enough?"
///
/// It runs exactly the plan the setup wizard's Recover option would, and prints
/// it instead of applying it. Nothing is written.
///
/// The part worth watching is the **key mapping**. A rebuilt persona is only
/// usable if each verification method in its DID document can be matched back
/// to a VTA key, and that match only fires when the store's `key_id` *is* a
/// verification-method id of the DID, or when its label is. A deployment that
/// labels keys some other way cannot be rebuilt, and this is where that shows
/// up — before it matters.
async fn report_recoverability(config: &Config) {
    use openvtc_core::config::KeyBackend;

    println!("{}", style("Recoverability").themed(CLI_INFO).bold());

    let KeyBackend::Vta { .. } = &config.key_backend else {
        println!("  This profile does not use a VTA, so there is nothing to rebuild from.\n");
        return;
    };

    let client = match openvtc_core::config::build_runtime_vta_client(&config.key_backend).await {
        Ok(c) => c,
        Err(e) => {
            println!("  Could not open a VTA session: {e}\n");
            return;
        }
    };

    let context_id = config.account.top_context_id.clone();
    let now = chrono::Utc::now();

    let plan = match openvtc_core::rebuild::plan(&client, &context_id, now).await {
        Ok(p) => p,
        Err(e) => {
            println!("  Could not read the context: {e}\n");
            client.shutdown().await;
            return;
        }
    };

    let keys = match client
        .list_keys(0, 500, Some("active"), Some(&context_id))
        .await
    {
        Ok(resp) => resp
            .keys
            .into_iter()
            .filter_map(|k| {
                let key_type = match k.key_type {
                    vta_sdk::keys::KeyType::Ed25519 => {
                        openvtc_core::rebuild_apply::KeyPurposeHint::Signing
                    }
                    vta_sdk::keys::KeyType::X25519 => {
                        openvtc_core::rebuild_apply::KeyPurposeHint::Encryption
                    }
                    _ => return None,
                };
                Some(openvtc_core::rebuild_apply::KeyCandidate {
                    key_id: k.key_id,
                    label: k.label,
                    key_type,
                    created_at: k.created_at,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            println!("  Could not list the context's keys: {e}\n");
            client.shutdown().await;
            return;
        }
    };

    let rebuilt = openvtc_core::rebuild_apply::apply(&plan, &keys, now);
    client.shutdown().await;

    // Held locally vs held at the VTA. Without this line a reader cannot tell
    // "this account has no memberships" from "its memberships have not been
    // stored at the VTA yet", and those need different actions.
    let held_locally = config
        .account
        .memberships()
        .filter(|c| {
            c.credentials
                .contains_key(&openvtc_core::CredentialKind::Membership)
        })
        .count();

    println!("  context          {context_id}");
    println!("  at the VTA       {}", plan.summary());
    println!("  usable keys      {}", keys.len());
    println!("  held locally     {held_locally} membership credential(s)");
    println!("  would restore    {}", rebuilt.summary());

    // The diagnosis, stated rather than left to be inferred from the counts.
    if rebuilt.account.personas.is_empty() && !plan.personas.is_empty() {
        println!(
            "\n  {}",
            style(
                "NOT RECOVERABLE: the VTA holds identities, but none of their keys could \
                 be matched to them, so a rebuilt account could not sign or receive."
            )
            .themed(CLI_ERROR)
        );
        println!(
            "  {}",
            style(
                "A key matches only when its store id — or its label — is a verification \
                 method of the persona's DID. This deployment appears to label them some \
                 other way, so recovery would need a different mapping."
            )
            .themed(CLI_CAUTION)
        );
    } else if rebuilt.account.personas.is_empty() {
        println!(
            "\n  {}",
            style("Nothing to recover: this context holds no identities.").themed(CLI_CAUTION)
        );
    } else if rebuilt.skipped.is_empty() {
        println!(
            "\n  {}",
            style("RECOVERABLE: every identity in this context maps to its keys.")
                .themed(CLI_EXAMPLE)
        );
    } else {
        println!(
            "\n  {}",
            style(format!(
                "PARTIALLY RECOVERABLE: {} of {} identities map to their keys.",
                rebuilt.account.personas.len(),
                plan.personas.len()
            ))
            .themed(CLI_CAUTION)
        );
    }

    // The specific gap this check exists to surface: the credential is held,
    // but not where a rebuild would look for it.
    if held_locally > rebuilt.account.memberships().count() {
        println!(
            "\n  {}",
            style(format!(
                "{} membership credential(s) are held locally but not at the VTA, so they \
                 would NOT be recovered. Launch OpenVTC once while online — it stores them \
                 on connect — then re-run this.",
                held_locally - rebuilt.account.memberships().count()
            ))
            .themed(CLI_CAUTION)
        );
    }

    for s in &rebuilt.skipped {
        println!("    - {} — {}", truncate_did(&s.did), s.reason.summary());
    }
    for r in &plan.rejected {
        println!(
            "    - credential {} — {}",
            r.id.as_deref().unwrap_or("(unnamed)"),
            r.reason.summary()
        );
    }

    println!(
        "\n  {}",
        style("Not restored by a rebuild, whatever the outcome above:").themed(CLI_INFO)
    );
    for gap in openvtc_core::rebuild::RebuildPlan::known_gaps() {
        println!("    - {gap}");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_tail_names_a_webvh_persona_by_its_path() {
        assert_eq!(
            short_tail("did:webvh:QmScid:dids.example.dev:legend-swear"),
            "legend-swear"
        );
    }

    /// A DID with no path must not render as an empty label.
    #[test]
    fn short_tail_falls_back_for_pathless_dids() {
        assert_eq!(short_tail("did:key:z6Mkabc"), "z6Mkabc");
        assert_eq!(short_tail("notadid"), "notadid");
    }

    fn vta_access_fixture() -> VtaAccess {
        VtaAccess {
            credential_did: "did:key:z6MkAuthKeyForThisInstall".to_string(),
            vta_did: "did:webvh:QmScid:vta.example.dev:agent".to_string(),
            vta_url: String::new(),
            mediator_did: Some("did:peer:2.Vz6Mkmediator".to_string()),
            context_id: "openvtc".to_string(),
        }
    }

    /// The point of the section: the DID an operator pastes into `pnm acl`
    /// arrives whole. It is a `did:key`, so a truncation would not merely be
    /// ugly — the remainder is the key, and a shortened one names nobody.
    #[test]
    fn the_authenticating_did_is_serialised_in_full() {
        let access = vta_access_fixture();
        let json = VtaAccess::as_json(Some(&access));
        assert_eq!(
            json["authenticates_as"], "did:key:z6MkAuthKeyForThisInstall",
            "the ACL subject is the key a script reads this report for"
        );
        assert_eq!(json["context_id"], "openvtc");
        assert_eq!(json["transport"], "DIDComm");
        assert!(
            json["vta_url"].is_null(),
            "a DIDComm-only VTA has no REST endpoint to report"
        );
    }

    /// A BIP32 profile has no VTA and no ACL, but the key is still emitted so a
    /// script can read `.vta_access` without branching on the backend first.
    #[test]
    fn a_profile_without_a_vta_serialises_as_null() {
        assert!(VtaAccess::as_json(None).is_null());
    }

    /// Which transport this profile would open is a `build_runtime_vta_client`
    /// rule, not a guess: a mediator means DIDComm, and a REST URL alongside one
    /// is the fallback rather than the primary. Reporting it the other way round
    /// would send an operator to debug the leg that is not being used.
    #[test]
    fn the_transport_is_named_the_way_the_client_picks_it() {
        let mut access = vta_access_fixture();
        assert_eq!(access.transport(), "DIDComm");

        access.vta_url = "https://vta.example.dev".to_string();
        assert_eq!(access.transport(), "DIDComm (REST fallback configured)");

        access.mediator_did = None;
        assert_eq!(access.transport(), "REST");

        access.vta_url = String::new();
        assert_eq!(access.transport(), "none configured");
    }

    /// The fragment is what distinguishes two service entries; the DID prefix is
    /// printed once above and repeating it per row hides the difference.
    #[test]
    fn service_ids_render_as_their_fragment() {
        assert_eq!(fragment("did:webvh:QmScid:example:x#tsp"), "#tsp");
        assert_eq!(
            fragment("did:webvh:QmScid:example:x#tsp-transport"),
            "#tsp-transport",
            "the OWF reference impl names it differently from ours; both are \
             TSPTransport, and an operator comparing deployments must see which"
        );
        assert_eq!(fragment("no-fragment"), "no-fragment");
    }
}
