//! Map the messaging path between OpenVTC and a community, and say where it
//! breaks.
//!
//! A join that goes out and is never answered has, from the client, exactly one
//! symptom: nothing happens. The cause is somewhere in a chain of five or six
//! parties — this persona, its mediator, the VTA, the VTC, *its* mediator — each
//! of which advertises its own transports in its own DID document, and any two
//! of which may sit behind different mediators. Reading that by hand means
//! fetching several `did.jsonl` files and diffing service arrays.
//!
//! This module fetches them and prints the map. It answers four questions:
//!
//! 1. **Does each DID resolve?** For `did:webvh` that is a live HTTPS fetch, so
//!    it doubles as the first reachability check.
//! 2. **What does each advertise?** The full `service` array, verbatim — not
//!    just the transports we recognise, because an unrecognised entry is exactly
//!    what you want to see when a peer looks healthy and isn't.
//! 3. **What would we actually use?** [`select_protocol`] over both sides'
//!    capabilities, which is the same negotiation a real send performs.
//! 4. **Is the transport host reachable?** A bounded HTTP probe of each
//!    mediator's endpoint URL.
//!
//! Deliberately read-only: it resolves, negotiates and probes. It never sends a
//! message, so it is safe to run against production while a join is stuck.
//!
//! The probed URLs come from DID documents, which anyone can publish. By default
//! only public HTTPS endpoints are dialled, redirects are never followed, and
//! the rest are listed as not probed; see [`ProbePolicy`].

use std::collections::BTreeSet;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use serde::Serialize;
use serde_json::Value;
use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};

/// Bound on any single network step. Every step is independently bounded so one
/// unreachable host cannot stall the whole report — a partial map is the useful
/// output here, and a hang is the least useful.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// What a party is in the chain. Ordering is the order they are reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// One of our own persona DIDs — the identity a community knows us by.
    Persona,
    /// The Verifiable Trust Agent that custodies our keys.
    Vta,
    /// A community's VTC.
    Vtc,
    /// A mediator some other party routes through.
    Mediator,
}

impl Role {
    /// Lowercase display name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Persona => "persona",
            Role::Vta => "vta",
            Role::Vtc => "vtc",
            Role::Mediator => "mediator",
        }
    }
}

/// One `service` entry, as published. `types` is a vector because DID-Core
/// permits `type` to be a string or an array, and a party that publishes both
/// `TSPTransport` and something else on one entry is worth seeing as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceEntry {
    pub id: String,
    pub types: Vec<String>,
    pub endpoint: String,
}

/// Result of a bounded HTTP probe of a transport URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Probe {
    /// The host answered. **Any** status counts as the host being up — a 404 or
    /// 405 from a mediator's base path proves DNS, TLS and routing all work,
    /// which is what is being tested; those endpoints take POSTs and websockets,
    /// not bare GETs. Calling that a failure would send an operator hunting a
    /// network fault that is not there.
    ///
    /// The status is still classified for display ([`Self::grade`]) because
    /// "reachable (HTTP 404)" read as a contradiction: the word promised health
    /// and the number said otherwise, and a reader cannot be expected to know
    /// which one to believe. A 5xx *is* worth flagging — the host is up and its
    /// application is broken, which is a different thing from both.
    Reachable { url: String, http_status: u16 },
    /// No answer: DNS, TLS, connection or timeout.
    Unreachable { url: String, error: String },
    /// Not dialled: under the run's [`ProbePolicy`] this is a URL a probe must
    /// not follow — plaintext, carrying credentials, or naming a loopback,
    /// private or link-local host (literally, or through what its name
    /// resolves to).
    ///
    /// The URL comes from a DID document, which anyone can publish. Probing it
    /// as written would let that document aim this machine at services on its
    /// own network and read back whether they answer. An endpoint like that is
    /// also no route a real peer could take, so it is reported, not hidden.
    Blocked { url: String, reason: String },
}

/// Which transport URLs [`build_report_with_progress`] is willing to dial.
///
/// Mirrors `affinidi_did_web::HostPolicy`, which guards DID resolution the same
/// way. The probe URLs come out of the documents that resolution returned, so
/// without a policy of their own they would reopen what the resolver closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbePolicy {
    /// HTTPS only, no userinfo, and never a loopback, private, carrier-grade
    /// NAT or link-local host — refused both when the URL names one literally
    /// and when its hostname resolves to one. The default.
    #[default]
    PublicOnly,
    /// Dial any `http(s)` URL, plaintext and non-routable ones included. For a
    /// development stack on loopback or a private network, where the DIDs
    /// being checked are the operator's own. It reopens the exposure
    /// [`ProbePolicy::PublicOnly`] closes.
    AllowPrivate,
}

/// How to read a probe's status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeGrade {
    /// 2xx/3xx — the endpoint served the request.
    Ok,
    /// 4xx — the host answered and declined, which is the normal answer from an
    /// endpoint that takes POSTs or websockets rather than GETs.
    Responding,
    /// 5xx — the host is up and its application is failing. Worth surfacing.
    ServerError,
}

impl Probe {
    /// Classify a reachable probe's status; `None` when nothing answered or
    /// nothing was asked.
    #[must_use]
    pub fn grade(&self) -> Option<ProbeGrade> {
        match self {
            Probe::Reachable { http_status, .. } => Some(match http_status {
                200..=399 => ProbeGrade::Ok,
                400..=499 => ProbeGrade::Responding,
                _ => ProbeGrade::ServerError,
            }),
            Probe::Unreachable { .. } | Probe::Blocked { .. } => None,
        }
    }
}

/// A resolved party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    /// Every `service` entry the document publishes, in document order.
    pub services: Vec<ServiceEntry>,
    /// The transports we recognise, by service `type`.
    pub tsp_endpoint: Option<String>,
    pub didcomm_endpoint: Option<String>,
    pub rest_endpoint: Option<String>,
    /// Probes of any `http(s)` endpoints above. Mediator DIDs are not probed
    /// here — they are separate parties in the report and probed as themselves.
    pub probes: Vec<Probe>,
}

/// A party in the chain, resolved or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Party {
    pub role: Role,
    /// Where this DID came from — "persona", "VTC (--vtc)", "mediator of
    /// persona joy-ahead". Carries the provenance a bare DID cannot.
    pub label: String,
    pub did: String,
    /// `None` when resolution failed; `error` then says why.
    pub resolved: Option<Resolved>,
    pub error: Option<String>,
}

impl Party {
    /// The capability set for negotiation, or an empty one if unresolved.
    fn caps(&self) -> ServiceCapabilities {
        match &self.resolved {
            Some(r) => ServiceCapabilities {
                tsp: r.tsp_endpoint.clone(),
                didcomm: r.didcomm_endpoint.clone(),
                rest: r.rest_endpoint.clone(),
            },
            None => ServiceCapabilities::default(),
        }
    }
}

/// The negotiated transport between two parties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LinkOutcome {
    /// Both sides advertise it; this is what a send would pick.
    Selected {
        protocol: Protocol,
        /// The peer endpoint for that protocol — a mediator DID for TSP and
        /// DIDComm, a URL for REST.
        peer_endpoint: String,
    },
    /// The advertised sets do not intersect. Both are named so the operator can
    /// see which side to change.
    NoCommonProtocol {
        ours: Vec<Protocol>,
        theirs: Vec<Protocol>,
    },
    /// One side did not resolve, so there is nothing to negotiate over.
    Unknown { reason: String },
}

/// A directed pair whose transport we negotiated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    pub from: String,
    pub to: String,
    #[serde(flatten)]
    pub outcome: LinkOutcome,
}

/// The whole map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthReport {
    pub parties: Vec<Party>,
    pub links: Vec<Link>,
    /// Findings worth an operator's attention — split mediators, dead ends,
    /// unresolvable parties. Empty is the healthy case.
    pub notes: Vec<String>,
}

impl HealthReport {
    /// Whether anything in the chain is broken enough to stop a message.
    ///
    /// Unresolvable parties and empty protocol intersections count; an
    /// unreachable probe does not, because a mediator that refuses a bare GET on
    /// its base path is normal and the DID resolution above already proved the
    /// host answers.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.parties.iter().all(|p| p.resolved.is_some())
            && !self
                .links
                .iter()
                .any(|l| matches!(l.outcome, LinkOutcome::NoCommonProtocol { .. }))
    }
}

/// A step the report is taking, emitted as it starts and as it finishes.
///
// Not an intra-doc link: `STEP_TIMEOUT` is private, and a public item linking
// to it fails `rustdoc -D warnings` — the same trap `config::peer_tsp_mediator`
// carries a note for.
/// The report is mostly waiting on the network — a `did:webvh` resolution is an
/// HTTPS fetch and each probe is bounded by the module's per-step timeout, so a
/// chain with a few mediators and one dead host can sit silent for the better
/// part of a minute. Silence during that is indistinguishable from a hang, and
/// the step
/// that is slow is itself a finding: a resolution that takes nine seconds and
/// then succeeds says something a report listing only the outcome does not.
///
/// Each `…ing` variant is emitted *before* the wait so the operator sees what is
/// being waited on, and each result variant carries the `elapsed` it actually
/// took. Deliberately structured rather than pre-formatted strings: the CLI owns
/// presentation, and `--json` consumers can ignore the stream entirely.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Step {
    /// Bringing up the DID resolver (cheap, but it can fail and that failure
    /// stops everything).
    ResolverStarting,
    /// About to resolve a party.
    Resolving {
        role: Role,
        label: String,
        did: String,
    },
    /// A party resolved.
    Resolved {
        label: String,
        services: usize,
        transports: Vec<Protocol>,
        elapsed: Duration,
    },
    /// A party did not resolve. Not fatal — the report records the dead end.
    ResolveFailed {
        label: String,
        error: String,
        elapsed: Duration,
    },
    /// Moving on to the mediators discovered from the parties above.
    FollowingMediators { count: usize },
    /// About to probe a transport URL.
    Probing { url: String },
    /// A probe finished.
    Probed { probe: Probe, elapsed: Duration },
    /// Resolution done; negotiating transports (local, fast).
    Negotiating { pairs: usize },
    /// The whole report is built.
    Finished { elapsed: Duration },
}

/// Where [`build_report_with_progress`] reports to. `&dyn` rather than a
/// generic so threading it through the helpers costs no monomorphisation and no
/// type parameter on every signature.
pub type ProgressFn<'a> = &'a (dyn Fn(Step) + Send + Sync);

/// A DID to include in the report, with the provenance to label it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub role: Role,
    pub label: String,
    pub did: String,
}

impl Subject {
    pub fn new(role: Role, label: impl Into<String>, did: impl Into<String>) -> Self {
        Self {
            role,
            label: label.into(),
            did: did.into(),
        }
    }
}

/// Resolve every subject, follow each one's mediators, negotiate every link that
/// matters, and probe the transport hosts.
///
/// `subjects` is the chain as the caller knows it — our personas, our VTA, the
/// community's VTC. Mediators are *discovered*, not passed in: which mediator a
/// party uses is a property of its document, and taking it from local config
/// would report what we believe rather than what is published. That difference
/// is one of the things this command exists to expose.
///
/// Probes only public HTTPS endpoints ([`ProbePolicy::PublicOnly`]).
pub async fn build_report(subjects: &[Subject]) -> HealthReport {
    build_report_with_progress(subjects, &|_| {}, ProbePolicy::PublicOnly).await
}

/// [`build_report`], reporting each step to `progress` as it happens, and
/// probing transport URLs under an explicit [`ProbePolicy`].
///
/// The work is almost entirely network waits, so a caller that shows nothing
/// until the end shows nothing for most of the run. See [`Step`].
pub async fn build_report_with_progress(
    subjects: &[Subject],
    progress: ProgressFn<'_>,
    policy: ProbePolicy,
) -> HealthReport {
    let started = std::time::Instant::now();
    progress(Step::ResolverStarting);
    let resolver = match DIDCacheClient::new(
        affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return HealthReport {
                parties: Vec::new(),
                links: Vec::new(),
                notes: vec![format!(
                    "could not start a DID resolver ({e}) — nothing could be checked. \
                     This is a local fault, not a fault in the chain."
                )],
            };
        }
    };

    let http = probe_client(policy);

    let mut parties: Vec<Party> = Vec::new();
    for subject in subjects {
        if subject.did.is_empty() {
            continue;
        }
        if parties.iter().any(|p| p.did == subject.did) {
            continue;
        }
        parties.push(resolve_party(&resolver, http.as_ref(), policy, subject, progress).await);
    }

    // Second pass: every mediator any resolved party routes through, resolved
    // once and labelled with *every* party that named it and for which
    // transports. Mapping who shares a mediator with whom is most of the point —
    // labelling it "TSP mediator of <first party to mention it>" would hide both
    // that it also carries that party's DIDComm and that a second party is
    // behind the same host.
    let referenced = mediator_references(&parties);
    let fresh: Vec<(String, String)> = referenced
        .into_iter()
        .filter(|(did, _)| !parties.iter().any(|p| p.did == *did))
        .collect();
    progress(Step::FollowingMediators { count: fresh.len() });
    for (did, users) in fresh {
        let subject = Subject::new(Role::Mediator, format!("mediator of {users}"), did);
        parties.push(resolve_party(&resolver, http.as_ref(), policy, &subject, progress).await);
    }

    let links = negotiate_links(&parties);
    progress(Step::Negotiating { pairs: links.len() });
    let notes = collect_notes(&parties, &links);
    progress(Step::Finished {
        elapsed: started.elapsed(),
    });
    HealthReport {
        parties,
        links,
        notes,
    }
}

/// Which mediator DIDs the resolved parties route through, and who routes to
/// each — `did:webvh:…:mediator` → `"persona joy-ahead (TSP, DIDComm), VTC acme
/// (DIDComm)"`.
///
/// Keyed by DID so a mediator shared by several parties is resolved and probed
/// once. Only `did:` endpoints qualify: a URL endpoint *is* the transport, and
/// belongs to (and was probed on) the party that published it.
///
/// `BTreeMap` throughout for a stable report; the protocol list is a `Vec` built
/// in preference order rather than a set, because "TSP, DIDComm" reads as the
/// negotiation order and "DIDComm, TSP" (alphabetical) does not.
fn mediator_references(parties: &[Party]) -> std::collections::BTreeMap<String, String> {
    let mut refs: std::collections::BTreeMap<String, Vec<(String, Vec<&'static str>)>> =
        std::collections::BTreeMap::new();

    for party in parties {
        let Some(resolved) = &party.resolved else {
            continue;
        };
        for (protocol, endpoint) in [
            ("TSP", resolved.tsp_endpoint.as_deref()),
            ("DIDComm", resolved.didcomm_endpoint.as_deref()),
        ] {
            let Some(endpoint) = endpoint else { continue };
            if !endpoint.starts_with("did:") {
                continue;
            }
            let users = refs.entry(endpoint.to_string()).or_default();
            match users.iter_mut().find(|(label, _)| *label == party.label) {
                Some((_, protocols)) => protocols.push(protocol),
                None => users.push((party.label.clone(), vec![protocol])),
            }
        }
    }

    refs.into_iter()
        .map(|(did, users)| {
            let described = users
                .into_iter()
                .map(|(label, protocols)| format!("{label} ({})", protocols.join(", ")))
                .collect::<Vec<_>>()
                .join(", ");
            (did, described)
        })
        .collect()
}

/// Resolve one DID and read everything the report needs off its document.
async fn resolve_party(
    resolver: &DIDCacheClient,
    http: Option<&reqwest::Client>,
    policy: ProbePolicy,
    subject: &Subject,
    progress: ProgressFn<'_>,
) -> Party {
    let started = std::time::Instant::now();
    progress(Step::Resolving {
        role: subject.role,
        label: subject.label.clone(),
        did: subject.did.clone(),
    });

    let fail = |error: String| {
        progress(Step::ResolveFailed {
            label: subject.label.clone(),
            error: error.clone(),
            elapsed: started.elapsed(),
        });
        Party {
            role: subject.role,
            label: subject.label.clone(),
            did: subject.did.clone(),
            resolved: None,
            error: Some(error),
        }
    };

    let resolved = match tokio::time::timeout(STEP_TIMEOUT, resolver.resolve(&subject.did)).await {
        Ok(Ok(resolved)) => resolved,
        Ok(Err(e)) => return fail(e.to_string()),
        Err(_) => {
            return fail(format!(
                "resolution timed out after {}s",
                STEP_TIMEOUT.as_secs()
            ));
        }
    };
    let doc = match serde_json::to_value(&resolved.doc) {
        Ok(doc) => doc,
        Err(e) => return fail(format!("document could not be re-serialised: {e}")),
    };

    let caps = ServiceCapabilities::from_did_document(&doc);
    let services = service_entries(&doc);
    progress(Step::Resolved {
        label: subject.label.clone(),
        services: services.len(),
        transports: caps.advertised(),
        elapsed: started.elapsed(),
    });

    // Probe only endpoints that are URLs *and* routable. A DID endpoint is a
    // mediator, which becomes its own party and is probed there — following it
    // here would probe the same host once per party that names it. And a
    // non-routable entry (see `is_routable`) is served by the DID host we just
    // resolved through, so probing it re-tests what resolution already proved
    // and reports a 404 for a path that was never meant to answer a bare GET.
    let mut probes = Vec::new();
    if let Some(client) = http {
        let urls: BTreeSet<&str> = services
            .iter()
            .filter(|s| is_routable(s))
            .map(|s| s.endpoint.as_str())
            .filter(|e| e.starts_with("http://") || e.starts_with("https://"))
            .collect();
        for url in urls {
            progress(Step::Probing {
                url: url.to_string(),
            });
            let probe_started = std::time::Instant::now();
            let result = probe(client, url, policy).await;
            progress(Step::Probed {
                probe: result.clone(),
                elapsed: probe_started.elapsed(),
            });
            probes.push(result);
        }
    }

    Party {
        role: subject.role,
        label: subject.label.clone(),
        did: subject.did.clone(),
        resolved: Some(Resolved {
            services,
            tsp_endpoint: caps.tsp,
            didcomm_endpoint: caps.didcomm,
            rest_endpoint: caps.rest,
            probes,
        }),
        error: None,
    }
}

/// DID-document service types that are **not** routes: entries describing where
/// the document and its attachments live, rather than somewhere a message goes.
///
/// `relativeRef` (`#files`) and `LinkedVerifiablePresentation` (`#whois`) are
/// both served by the same DID host we just fetched `did.jsonl` from, so
/// resolving the DID has already proven that host answers. Probing them again
/// only re-tests a working host and reports a 404 for a path that never serves a
/// bare GET — `#files` points at the *directory*, not `…/did.jsonl`. Four such
/// lines per party drowned the transport probes that do carry information.
const NON_ROUTABLE_SERVICE_TYPES: [&str; 2] = ["relativeRef", "LinkedVerifiablePresentation"];

/// Whether a service entry names somewhere a message or request actually goes.
///
/// A skip-list rather than an allow-list, deliberately: a transport type this
/// build has never heard of should still be probed (the whole point of printing
/// services verbatim is that unknown types matter), whereas the two
/// document-adjacent types are a closed set defined by the DID spec and the
/// webvh hosting convention.
fn is_routable(service: &ServiceEntry) -> bool {
    !service
        .types
        .iter()
        .any(|t| NON_ROUTABLE_SERVICE_TYPES.contains(&t.as_str()))
}

/// Read the `service` array verbatim.
///
/// Deliberately not filtered to the types we understand: a party that publishes
/// a transport this build does not know about looks, through
/// [`ServiceCapabilities`] alone, exactly like a party that publishes nothing —
/// and telling those two apart is most of the value of a map.
fn service_entries(doc: &Value) -> Vec<ServiceEntry> {
    let Some(services) = doc.get("service").and_then(Value::as_array) else {
        return Vec::new();
    };
    services
        .iter()
        .map(|svc| {
            let id = svc
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("<no id>")
                .to_string();
            let types = match svc.get("type") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            };
            let endpoint = svc
                .get("serviceEndpoint")
                .and_then(endpoint_uri)
                .unwrap_or_else(|| "<unreadable>".to_string());
            ServiceEntry {
                id,
                types,
                endpoint,
            }
        })
        .collect()
}

/// The three shapes a `serviceEndpoint` may take: a string, an object with
/// `uri`, or an array of either. Mirrors `vta_sdk`'s private `endpoint_uri`.
fn endpoint_uri(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(endpoint_uri),
        _ => None,
    }
}

/// The client transport probes are sent with.
///
/// Built like `affinidi_did_web`'s own resolver client, because it dials URLs
/// out of the same untrusted documents:
///
/// - **No redirects.** Any 3xx already proves the host answers, and following
///   one would let a public endpoint hand the probe on to an internal one.
/// - **No proxy.** A proxy resolves the name itself, out of reach of the DNS
///   guard below.
/// - **Guarded DNS** under [`ProbePolicy::PublicOnly`]. A hostname that
///   resolves to a non-routable address is refused, and the connection goes to
///   the addresses that were checked, so the answer cannot change in between.
///   `reqwest` never consults a resolver for an IP-literal host, which is why
///   [`probe`] also vets the URL itself.
fn probe_client(policy: ProbePolicy) -> Option<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(STEP_TIMEOUT)
        .connect_timeout(STEP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if policy == ProbePolicy::PublicOnly {
        builder = builder.dns_resolver(affinidi_did_web::guarded_dns_resolver());
    }
    builder.build().ok()
}

/// A bounded GET. Any HTTP answer is reachability — see [`Probe::Reachable`].
///
/// The URL is vetted before any I/O ([`vet_probe_url`]), and what is sent is
/// the parsed form that was vetted, never the string re-parsed.
async fn probe(client: &reqwest::Client, url: &str, policy: ProbePolicy) -> Probe {
    let parsed = match vet_probe_url(url, policy) {
        Ok(parsed) => parsed,
        Err(reason) => {
            return Probe::Blocked {
                url: url.to_string(),
                reason,
            };
        }
    };
    match client.get(parsed).send().await {
        Ok(response) => Probe::Reachable {
            url: url.to_string(),
            http_status: response.status().as_u16(),
        },
        Err(e) => send_failure(url, &e),
    }
}

/// Parse `url` and say why a probe must not dial it under `policy`, if it
/// must not.
///
/// This is the literal half of the guard: the host is classified as the URL
/// names it, after WHATWG canonicalisation, so `https://2130706433/` is
/// `127.0.0.1` here too. A hostname is left to the probe client's DNS guard.
fn vet_probe_url(url: &str, policy: ProbePolicy) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("unparseable URL: {e}"))?;
    match (parsed.scheme(), policy) {
        ("https", _) | ("http", ProbePolicy::AllowPrivate) => {}
        ("http", ProbePolicy::PublicOnly) => {
            return Err("plaintext http".to_string());
        }
        (other, _) => return Err(format!("{other} scheme")),
    }
    // Credentials embedded in a URL someone else published are not ours to
    // send, under either policy.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL carries userinfo".to_string());
    }
    if policy == ProbePolicy::PublicOnly
        && let Some(host) = parsed.host_str()
        && crate::net_guard::is_blocked_host(host)
    {
        return Err(format!("non-public host {host}"));
    }
    Ok(parsed)
}

/// A send that failed: [`Probe::Blocked`] when the probe client's DNS guard
/// refused the name, [`Probe::Unreachable`] for anything else.
fn send_failure(url: &str, error: &reqwest::Error) -> Probe {
    match dns_refusal_in_chain(error) {
        Some(reason) => Probe::Blocked {
            url: url.to_string(),
            reason,
        },
        None => Probe::Unreachable {
            url: url.to_string(),
            error: error.to_string(),
        },
    }
}

/// The refusal `affinidi_did_web::guarded_dns_resolver` raised, if one is
/// anywhere in `error`'s source chain.
///
/// That crate keeps its error type private, so the refusal is recognised by the
/// message it renders (`"<host> resolves to non-routable <addr>"`), walking the
/// chain the way the crate does internally. The innermost match wins, since
/// wrappers may repeat it with their own prefix.
/// `probe_client_dns_guard_refuses_localhost_name` pins the text, so an upstream
/// change to it fails a test rather than quietly turning refusals back into
/// "unreachable".
fn dns_refusal_in_chain(error: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut found = None;
    let mut next = Some(error);
    while let Some(e) = next {
        let message = e.to_string();
        if message.contains(" resolves to non-routable ") {
            found = Some(message);
        }
        next = e.source();
    }
    found
}

/// Negotiate the pairs that decide whether a join can complete: each persona
/// against each VTA and VTC.
///
/// Mediator-to-party pairs are deliberately absent. A mediator is a hop, not a
/// counterparty — nothing negotiates a protocol *with* it — and listing those
/// pairs would bury the two that matter.
fn negotiate_links(parties: &[Party]) -> Vec<Link> {
    let personas: Vec<&Party> = parties.iter().filter(|p| p.role == Role::Persona).collect();
    let peers: Vec<&Party> = parties
        .iter()
        .filter(|p| matches!(p.role, Role::Vta | Role::Vtc))
        .collect();

    let mut links = Vec::new();
    for persona in &personas {
        for peer in &peers {
            let outcome = if persona.resolved.is_none() {
                LinkOutcome::Unknown {
                    reason: format!("{} did not resolve", persona.label),
                }
            } else if peer.resolved.is_none() {
                LinkOutcome::Unknown {
                    reason: format!("{} did not resolve", peer.label),
                }
            } else {
                match select_protocol(&persona.caps(), &peer.caps(), &peer.did) {
                    Ok(m) => LinkOutcome::Selected {
                        protocol: m.protocol,
                        peer_endpoint: m.peer_endpoint,
                    },
                    Err(_) => LinkOutcome::NoCommonProtocol {
                        ours: persona.caps().advertised(),
                        theirs: peer.caps().advertised(),
                    },
                }
            };
            links.push(Link {
                from: persona.label.clone(),
                to: peer.label.clone(),
                outcome,
            });
        }
    }
    links
}

/// Turn the map into the handful of sentences an operator acts on.
fn collect_notes(parties: &[Party], links: &[Link]) -> Vec<String> {
    let mut notes = Vec::new();

    for party in parties {
        if let Some(error) = &party.error {
            notes.push(format!(
                "{} ({}) did not resolve: {error}",
                party.label, party.did
            ));
            continue;
        }
        let Some(resolved) = &party.resolved else {
            continue;
        };
        if resolved.services.is_empty() {
            notes.push(format!(
                "{} publishes no service endpoints at all — nothing can route to it.",
                party.label
            ));
        } else if resolved.tsp_endpoint.is_none()
            && resolved.didcomm_endpoint.is_none()
            && party.role != Role::Mediator
        {
            notes.push(format!(
                "{} advertises no TSP or DIDComm transport (services present, but none of a \
                 recognised type) — it cannot be messaged.",
                party.label
            ));
        }
        for probe in &resolved.probes {
            match probe {
                Probe::Unreachable { url, error } => {
                    notes.push(format!("{}: {url} is unreachable ({error}).", party.label));
                }
                // A 5xx is the case a bare "reachable" hid: the host is up and
                // its application is failing, which no other line in the report
                // would reveal. 4xx is not flagged — that is the expected answer
                // from a POST/websocket endpoint asked for a GET.
                Probe::Reachable { url, http_status }
                    if probe.grade() == Some(ProbeGrade::ServerError) =>
                {
                    notes.push(format!(
                        "{}: {url} answered HTTP {http_status} — the host is up but the \
                         service behind it is failing.",
                        party.label
                    ));
                }
                Probe::Reachable { .. } => {}
                // A transport on plaintext or on a loopback/private address is
                // no route a real peer could take, and it is exactly what a
                // document aimed at this machine's own network would publish.
                // Stated, but not a fault: `is_healthy` does not change.
                Probe::Blocked { url, reason } => {
                    notes.push(format!(
                        "{}: {url} not probed ({reason}) — a DID document advertising a \
                         plaintext or non-public endpoint is itself worth a look.",
                        party.label
                    ));
                }
            }
        }
    }

    for link in links {
        match &link.outcome {
            LinkOutcome::NoCommonProtocol { ours, theirs } => {
                let mut note = format!(
                    "{} and {} share no transport: we offer [{}], they offer [{}]. A message \
                     between them cannot be sent until one side adds the other's.",
                    link.from,
                    link.to,
                    join_protocols(ours),
                    join_protocols(theirs),
                );
                // The specific case this keeps catching, and the one an operator
                // cannot diagnose from the sets alone: a persona minted before
                // the client requested `#tsp` can never reach a TSP-only
                // community, and nothing about it will change on its own — the
                // service is written at mint time and old documents are not
                // revisited. Saying only "no shared transport" leaves the reader
                // to guess whether to change the community, the persona, or the
                // client.
                if ours.as_slice() == [Protocol::Didcomm] && theirs.as_slice() == [Protocol::Tsp] {
                    note.push_str(
                        " This persona's document predates `#tsp` being requested at mint \
                         time, so it advertises DIDComm only; a persona minted by a current \
                         client carries both. Re-minting a persona for this community is the \
                         fix — the existing document will not gain the service on its own.",
                    );
                }
                notes.push(note);
            }
            LinkOutcome::Unknown { reason } => notes.push(format!(
                "{} → {}: transport could not be determined ({reason}).",
                link.from, link.to
            )),
            LinkOutcome::Selected { .. } => {}
        }
    }

    // Split mediators are legal and often deliberate, but they are also the
    // thing an operator most often does not realise is true of their
    // deployment — so it is stated, not warned about.
    let mediators: BTreeSet<&str> = parties
        .iter()
        .filter(|p| p.role == Role::Mediator)
        .map(|p| p.did.as_str())
        .collect();
    if mediators.len() > 1 {
        notes.push(format!(
            "{} distinct mediators are in play; messages cross between them. This is \
             supported, but it means a delivery problem can live in either.",
            mediators.len()
        ));
    }

    notes
}

fn join_protocols(protocols: &[Protocol]) -> String {
    if protocols.is_empty() {
        return "none".to_string();
    }
    protocols
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resolved_party(role: Role, label: &str, did: &str, doc: &Value) -> Party {
        let caps = ServiceCapabilities::from_did_document(doc);
        Party {
            role,
            label: label.to_string(),
            did: did.to_string(),
            resolved: Some(Resolved {
                services: service_entries(doc),
                tsp_endpoint: caps.tsp,
                didcomm_endpoint: caps.didcomm,
                rest_endpoint: caps.rest,
                probes: Vec::new(),
            }),
            error: None,
        }
    }

    /// The shape a persona minted by the VTA's webvh server actually publishes —
    /// taken from a real document, including the `#vta-didcomm` id, because the
    /// matcher must key on `type` and never on the id fragment.
    fn persona_doc(mediator: &str) -> Value {
        json!({
            "service": [
                {
                    "id": "did:webvh:scid:example:persona#tsp",
                    "type": "TSPTransport",
                    "serviceEndpoint": mediator,
                },
                {
                    "id": "did:webvh:scid:example:persona#vta-didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{ "uri": mediator, "accept": ["didcomm/v2"] }],
                },
            ]
        })
    }

    #[test]
    fn services_are_read_verbatim_including_unrecognised_types() {
        let doc = json!({
            "service": [
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m" },
                { "id": "#odd", "type": "SomeFutureTransport", "serviceEndpoint": "https://x/y" },
            ]
        });
        let entries = service_entries(&doc);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].types, vec!["SomeFutureTransport".to_string()]);
        assert_eq!(
            entries[1].endpoint, "https://x/y",
            "an unrecognised transport must still be shown — a party that publishes \
             one looks empty through ServiceCapabilities alone, and telling that \
             apart from publishing nothing is the point of the map"
        );
    }

    /// DID-Core allows `type` as an array and `serviceEndpoint` in three shapes.
    #[test]
    fn endpoint_and_type_shapes_are_all_read() {
        assert_eq!(endpoint_uri(&json!("https://a")), Some("https://a".into()));
        assert_eq!(
            endpoint_uri(&json!({"uri": "did:webvh:m"})),
            Some("did:webvh:m".into())
        );
        assert_eq!(
            endpoint_uri(&json!([{"uri": "did:webvh:m"}])),
            Some("did:webvh:m".into())
        );

        let doc = json!({
            "service": [{
                "id": "#both", "type": ["DIDCommMessaging", "Other"],
                "serviceEndpoint": [{ "uri": "did:webvh:m" }],
            }]
        });
        assert_eq!(service_entries(&doc)[0].types.len(), 2);
    }

    /// Both sides on TSP: the negotiated protocol is TSP, and the endpoint is
    /// the *peer's* mediator (the hop a routed send seals to), not ours.
    #[test]
    fn a_shared_transport_negotiates_and_names_the_peer_mediator() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:our-mediator"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC",
                "did:webvh:v",
                &persona_doc("did:webvh:their-mediator"),
            ),
        ];
        let links = negotiate_links(&parties);
        assert_eq!(links.len(), 1);
        match &links[0].outcome {
            LinkOutcome::Selected {
                protocol,
                peer_endpoint,
            } => {
                assert_eq!(*protocol, Protocol::Tsp, "TSP outranks DIDComm");
                assert_eq!(peer_endpoint, "did:webvh:their-mediator");
            }
            other => panic!("expected a selected protocol, got {other:?}"),
        }
    }

    /// The case worth catching before a send: no intersection. Both sides'
    /// advertised sets must survive into the note, because "add TSP" and "add
    /// DIDComm" are different instructions to different operators.
    #[test]
    fn a_disjoint_pair_reports_both_sides() {
        let tsp_only = json!({
            "service": [{ "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m1" }]
        });
        let didcomm_only = json!({
            "service": [{
                "id": "#dc", "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "uri": "did:webvh:m2" }],
            }]
        });
        let parties = vec![
            resolved_party(Role::Persona, "persona", "did:webvh:p", &tsp_only),
            resolved_party(Role::Vtc, "VTC", "did:webvh:v", &didcomm_only),
        ];
        let links = negotiate_links(&parties);
        assert!(matches!(
            links[0].outcome,
            LinkOutcome::NoCommonProtocol { .. }
        ));

        let notes = collect_notes(&parties, &links);
        let note = notes
            .iter()
            .find(|n| n.contains("share no transport"))
            .expect("a disjoint pair must produce a note");
        assert!(note.contains("tsp"), "our side must be named: {note}");
        assert!(note.contains("didcomm"), "their side must be named: {note}");
        assert!(
            !HealthReport {
                parties,
                links,
                notes,
            }
            .is_healthy()
        );
    }

    /// An unresolvable party is a dead end, not a negotiation failure — the note
    /// must say which DID failed and why, since that is the whole diagnosis.
    #[test]
    fn an_unresolvable_peer_is_named_with_its_reason() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:m"),
            ),
            Party {
                role: Role::Vtc,
                label: "VTC".into(),
                did: "did:webvh:missing".into(),
                resolved: None,
                error: Some("404 fetching did.jsonl".into()),
            },
        ];
        let links = negotiate_links(&parties);
        assert!(matches!(links[0].outcome, LinkOutcome::Unknown { .. }));

        let notes = collect_notes(&parties, &links);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("did:webvh:missing") && n.contains("404")),
            "the failing DID and its reason must both appear: {notes:?}"
        );
        assert!(
            !HealthReport {
                parties,
                links,
                notes
            }
            .is_healthy()
        );
    }

    /// A mediator carrying both transports for a party must say so, and one
    /// shared by two parties must be resolved once and name both.
    ///
    /// Labelling it after the first protocol and the first party to mention it
    /// hid exactly the two facts the map exists to show: that the host carries
    /// both legs, and who else is behind it.
    #[test]
    fn a_shared_mediator_names_every_party_and_transport() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona joy-ahead",
                "did:webvh:p",
                &persona_doc("did:webvh:shared"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC acme",
                "did:webvh:v",
                &json!({
                    "service": [{
                        "id": "#dc", "type": "DIDCommMessaging",
                        "serviceEndpoint": [{ "uri": "did:webvh:shared" }],
                    }]
                }),
            ),
        ];

        let refs = mediator_references(&parties);
        assert_eq!(refs.len(), 1, "one host, resolved once: {refs:?}");
        let label = &refs["did:webvh:shared"];
        assert_eq!(
            label, "persona joy-ahead (TSP, DIDComm), VTC acme (DIDComm)",
            "both parties, and TSP before DIDComm (negotiation order, not \
             alphabetical): {label}"
        );
    }

    /// `#files` and `#whois` live on the DID host we just resolved through, so
    /// probing them re-tests a host already proven and reports a 404 for a path
    /// that never serves a bare GET. Four such lines per party buried the
    /// transport probes that carry information.
    #[test]
    fn document_adjacent_services_are_not_probed() {
        let files = ServiceEntry {
            id: "#files".into(),
            types: vec!["relativeRef".into()],
            endpoint: "https://webvh.storm.ws/army-provide".into(),
        };
        let whois = ServiceEntry {
            id: "#whois".into(),
            types: vec!["LinkedVerifiablePresentation".into()],
            endpoint: "https://webvh.storm.ws/army-provide/whois.vp".into(),
        };
        assert!(
            !is_routable(&files),
            "#files is the document host, not a route"
        );
        assert!(
            !is_routable(&whois),
            "#whois is not somewhere a message goes"
        );
    }

    /// The skip-list must not swallow transports — including one this build has
    /// never heard of, which is exactly the case worth probing.
    #[test]
    fn transports_and_unknown_types_are_still_probed() {
        for types in [
            vec!["TSPTransport".to_string()],
            vec!["DIDCommMessaging".to_string()],
            vec!["Authentication".to_string()],
            vec!["SomeFutureTransport".to_string()],
        ] {
            let entry = ServiceEntry {
                id: "#x".into(),
                types: types.clone(),
                endpoint: "https://example/x".into(),
            };
            assert!(
                is_routable(&entry),
                "{types:?} names a route (or might); it must be probed"
            );
        }
    }

    /// "reachable (HTTP 404)" read as a contradiction. The grade is what lets
    /// the word agree with the number.
    #[test]
    fn probe_status_is_graded_not_flattened() {
        let at = |status| Probe::Reachable {
            url: "https://m/x".into(),
            http_status: status,
        };
        assert_eq!(at(200).grade(), Some(ProbeGrade::Ok));
        assert_eq!(
            at(405).grade(),
            Some(ProbeGrade::Responding),
            "a POST/websocket endpoint declining a GET is the host working"
        );
        assert_eq!(at(404).grade(), Some(ProbeGrade::Responding));
        assert_eq!(
            at(503).grade(),
            Some(ProbeGrade::ServerError),
            "host up, application failing — the case a flat `reachable` hid"
        );
        assert_eq!(
            Probe::Unreachable {
                url: "https://m/x".into(),
                error: "dns".into()
            }
            .grade(),
            None
        );
    }

    /// A 5xx earns a finding; a 4xx does not.
    #[test]
    fn only_a_server_error_becomes_a_finding() {
        let with_probe = |probe: Probe| {
            let mut party = resolved_party(
                Role::Mediator,
                "mediator",
                "did:webvh:m",
                &json!({"service": [{
                    "id": "#tsp", "type": "TSPTransport",
                    "serviceEndpoint": "https://m/x",
                }]}),
            );
            party.resolved.as_mut().expect("resolved").probes = vec![probe];
            collect_notes(&[party], &[])
        };

        let five_hundred = with_probe(Probe::Reachable {
            url: "https://m/x".into(),
            http_status: 502,
        });
        assert!(
            five_hundred.iter().any(|n| n.contains("502")),
            "a 5xx must surface: {five_hundred:?}"
        );

        let four_oh_four = with_probe(Probe::Reachable {
            url: "https://m/x".into(),
            http_status: 404,
        });
        assert!(
            four_oh_four.is_empty(),
            "a 4xx on a non-GET endpoint is normal and must stay quiet: {four_oh_four:?}"
        );
    }

    /// The stranded-persona case: DIDComm-only against TSP-only. The sets alone
    /// don't tell an operator which side to change, so the note must.
    #[test]
    fn a_didcomm_only_persona_is_told_why_it_cannot_reach_a_tsp_community() {
        let didcomm_only = json!({"service": [{
            "id": "#vta-didcomm", "type": "DIDCommMessaging",
            "serviceEndpoint": [{"uri": "did:webvh:m"}],
        }]});
        let tsp_only = json!({"service": [{
            "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m",
        }]});
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona hello-fury",
                "did:webvh:p",
                &didcomm_only,
            ),
            resolved_party(Role::Vtc, "VTC first-vtc", "did:webvh:v", &tsp_only),
        ];
        let links = negotiate_links(&parties);
        let notes = collect_notes(&parties, &links);
        let note = notes
            .iter()
            .find(|n| n.contains("share no transport"))
            .expect("disjoint pair must be reported");
        assert!(
            note.contains("predates") && note.contains("Re-minting"),
            "the note must say why this persona is stuck and what fixes it, not \
             just list the two sets: {note}"
        );
    }

    /// The added guidance is specific to that one direction — a TSP-only *us*
    /// against a DIDComm-only *them* is a different problem with a different fix.
    #[test]
    fn the_remint_advice_is_not_given_for_the_reverse_mismatch() {
        let didcomm_only = json!({"service": [{
            "id": "#dc", "type": "DIDCommMessaging",
            "serviceEndpoint": [{"uri": "did:webvh:m"}],
        }]});
        let tsp_only = json!({"service": [{
            "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:webvh:m",
        }]});
        let parties = vec![
            resolved_party(Role::Persona, "persona", "did:webvh:p", &tsp_only),
            resolved_party(Role::Vtc, "VTC", "did:webvh:v", &didcomm_only),
        ];
        let notes = collect_notes(&parties, &negotiate_links(&parties));
        let note = notes
            .iter()
            .find(|n| n.contains("share no transport"))
            .expect("still reported");
        assert!(
            !note.contains("Re-minting"),
            "re-minting our persona does not fix a DIDComm-only community: {note}"
        );
    }

    /// A URL endpoint is the transport itself, not a mediator to follow.
    #[test]
    fn a_url_endpoint_is_not_followed_as_a_mediator() {
        let parties = vec![resolved_party(
            Role::Mediator,
            "mediator",
            "did:webvh:m",
            &json!({
                "service": [{
                    "id": "#tsp", "type": "TSPTransport",
                    "serviceEndpoint": "https://mediator.example/mediator/v1",
                }]
            }),
        )];
        assert!(
            mediator_references(&parties).is_empty(),
            "following a transport URL as a DID would resolve nothing and add a \
             bogus party to the map"
        );
    }

    /// Two mediators is legal. It must be *stated* (it is the thing operators
    /// most often don't know is true of their deployment) but must not make the
    /// report unhealthy.
    #[test]
    fn split_mediators_are_reported_without_being_called_a_fault() {
        let parties = vec![
            resolved_party(
                Role::Persona,
                "persona",
                "did:webvh:p",
                &persona_doc("did:webvh:m1"),
            ),
            resolved_party(
                Role::Vtc,
                "VTC",
                "did:webvh:v",
                &persona_doc("did:webvh:m2"),
            ),
            resolved_party(
                Role::Mediator,
                "mediator of persona",
                "did:webvh:m1",
                &json!({}),
            ),
            resolved_party(
                Role::Mediator,
                "mediator of VTC",
                "did:webvh:m2",
                &json!({}),
            ),
        ];
        let links = negotiate_links(&parties);
        let notes = collect_notes(&parties, &links);
        assert!(
            notes.iter().any(|n| n.contains("distinct mediators")),
            "split mediators must be surfaced: {notes:?}"
        );
        assert!(
            HealthReport {
                parties,
                links,
                notes
            }
            .is_healthy(),
            "two mediators is a supported topology, not a failure"
        );
    }

    /// A mediator with no recognised transport is normal (its own document
    /// carries a URL, not a mediator DID), so it must not draw the
    /// "cannot be messaged" note that a VTC or persona would.
    #[test]
    fn a_mediator_is_not_faulted_for_advertising_no_mediator() {
        let mediator_doc = json!({
            "service": [{
                "id": "#tsp", "type": "TSPTransport",
                "serviceEndpoint": "https://mediator.example/mediator/v1",
            }]
        });
        let parties = vec![resolved_party(
            Role::Mediator,
            "mediator of persona",
            "did:webvh:m",
            &mediator_doc,
        )];
        let notes = collect_notes(&parties, &[]);
        assert!(
            !notes.iter().any(|n| n.contains("cannot be messaged")),
            "a mediator publishing a transport URL is healthy: {notes:?}"
        );
    }

    // ---- Probe egress policy -------------------------------------------------
    //
    // Probe URLs come from DID documents anyone can publish. These pin that a
    // document cannot point the probe at this machine's own network.

    /// A loopback listener standing in for an internal service.
    async fn loopback_listener() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        (listener, port)
    }

    /// Nothing connected to `listener`. A refused probe must refuse before any
    /// I/O, not after a connection it then discards.
    async fn assert_never_dialled(listener: &tokio::net::TcpListener) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "something connected to the stand-in internal service"
        );
    }

    fn public_client() -> reqwest::Client {
        probe_client(ProbePolicy::PublicOnly).expect("the probe client builds")
    }

    #[tokio::test]
    async fn probe_refuses_loopback_literal_without_dialing() {
        let (listener, port) = loopback_listener().await;
        let url = format!("https://127.0.0.1:{port}/latest/meta-data/");

        let result = probe(&public_client(), &url, ProbePolicy::PublicOnly).await;

        assert!(
            matches!(&result, Probe::Blocked { url: u, reason } if *u == url && reason.contains("127.0.0.1")),
            "a loopback literal must be refused by name: {result:?}"
        );
        assert_eq!(result.grade(), None, "nothing was asked, so nothing grades");
        assert_never_dialled(&listener).await;
    }

    #[tokio::test]
    async fn probe_refuses_plain_http() {
        let (listener, port) = loopback_listener().await;
        let url = format!("http://127.0.0.1:{port}/latest/meta-data/");

        let result = probe(&public_client(), &url, ProbePolicy::PublicOnly).await;

        assert!(
            matches!(&result, Probe::Blocked { reason, .. } if reason.contains("plaintext")),
            "a plaintext endpoint is listed, not dialled: {result:?}"
        );
        assert_never_dialled(&listener).await;
    }

    /// The connect-time half. `reqwest` never asks a resolver about an IP
    /// literal, so the literal check above cannot be the whole guard; this goes
    /// straight to the client, past `vet_probe_url`, to prove the DNS guard is
    /// installed. `localhost` resolves to loopback everywhere without a network.
    #[tokio::test]
    async fn probe_client_dns_guard_refuses_localhost_name() {
        let (listener, port) = loopback_listener().await;
        let url = format!("https://localhost:{port}/");

        let error = public_client()
            .get(&url)
            .send()
            .await
            .expect_err("the guarded resolver must refuse a name resolving to loopback");

        let refusal = dns_refusal_in_chain(&error);
        assert!(
            refusal
                .as_deref()
                .is_some_and(|r| r.contains("localhost resolves to non-routable")),
            "affinidi-did-web's refusal must be recoverable from the error chain: {error:?}"
        );
        assert!(
            matches!(send_failure(&url, &error), Probe::Blocked { .. }),
            "a DNS refusal is a block, not an unreachable host"
        );
        assert_never_dialled(&listener).await;
    }

    /// A 3xx proves the host answers; following it would let a public endpoint
    /// hand the probe on to an internal one. `AllowPrivate` only so the first
    /// hop (a local mock) is dialled at all.
    #[tokio::test]
    async fn probe_does_not_follow_redirects() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let target = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&target)
            .await;

        let redirector = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/latest/meta-data/", target.uri())),
            )
            .mount(&redirector)
            .await;

        let client = probe_client(ProbePolicy::AllowPrivate).expect("the probe client builds");
        let result = probe(&client, &redirector.uri(), ProbePolicy::AllowPrivate).await;

        assert_eq!(
            result,
            Probe::Reachable {
                url: redirector.uri(),
                http_status: 302,
            }
        );
        assert!(
            target
                .received_requests()
                .await
                .expect("request recording is on")
                .is_empty(),
            "the redirect target must never be requested"
        );
    }

    /// The end-to-end case: a `did:peer:2` carries its service inline and
    /// resolves offline, so a DID alone is enough to name an internal endpoint.
    /// Both a plaintext and an HTTPS form must come back not probed, with a
    /// finding each and no connection made.
    #[tokio::test]
    async fn health_report_blocks_did_peer_inline_internal_service() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let (listener, port) = loopback_listener().await;
        let did_with_service = |endpoint: String| {
            let service = json!({ "t": "dm", "s": endpoint }).to_string();
            format!(
                "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.S{}",
                URL_SAFE_NO_PAD.encode(service)
            )
        };

        let report = build_report(&[
            Subject::new(
                Role::Vtc,
                "plaintext",
                did_with_service(format!("http://127.0.0.1:{port}/latest/meta-data/")),
            ),
            Subject::new(
                Role::Vtc,
                "https",
                did_with_service(format!("https://127.0.0.1:{port}/latest/meta-data/")),
            ),
        ])
        .await;

        assert_eq!(report.parties.len(), 2, "{report:#?}");
        for party in &report.parties {
            let resolved = party
                .resolved
                .as_ref()
                .unwrap_or_else(|| panic!("did:peer resolves offline: {party:#?}"));
            assert!(
                matches!(resolved.probes.as_slice(), [Probe::Blocked { .. }]),
                "{}: the inline internal endpoint must be blocked: {:?}",
                party.label,
                resolved.probes
            );
        }
        assert_eq!(
            report
                .notes
                .iter()
                .filter(|n| n.contains("not probed"))
                .count(),
            2,
            "each blocked endpoint is a finding: {:?}",
            report.notes
        );
        assert_never_dialled(&listener).await;
    }

    /// The literal half runs on the canonical URL, so the alternate spellings of
    /// an internal address are caught too. Every vector is refused before any
    /// I/O, so none of this touches the network.
    #[test]
    fn probe_urls_are_vetted_after_canonicalisation() {
        for url in [
            // Alternate IPv4 encodings of loopback.
            "https://2130706433/",
            "https://0x7f000001/",
            "https://017700000001/",
            "https://0177.0.0.1/",
            "https://0x7f.0.0.1/",
            "https://127.1/",
            "https://127.0.1/",
            "https://0/",
            "https://%31%32%37.0.0.1/",
            // Metadata, CGNAT, IPv6 forms.
            "https://169.254.169.254./",
            "https://100.100.100.200/",
            "https://[::ffff:127.0.0.1]/",
            "https://[0:0:0:0:0:ffff:7f00:1]/",
            "https://[::1]:8443/",
            "https://[fd00:ec2::254]/",
            // Names.
            "https://localhost/",
            "https://LOCALHOST./",
            "https://svc.localhost/",
            "https://printer.local/",
            "https://kube-dns.kube-system.svc.cluster.local/",
            // Userinfo, including the confusable forms.
            "https://example.com@127.0.0.1/",
            "https://127.0.0.1\\@example.com/",
            "https://user:pass@example.com/",
            // Invalid.
            "https://0x100000000/",
            "https://1.2.3.4.5/",
            "https://[fe80::1%25en0]/",
            "not a url",
            // Schemes.
            "http://example.com/",
            "ws://example.com/",
            "ftp://example.com/",
            "file:///etc/passwd",
            "gopher://example.com/",
            "data:text/plain,x",
            "javascript:alert(1)",
            "blob:https://x/y",
        ] {
            assert!(
                vet_probe_url(url, ProbePolicy::PublicOnly).is_err(),
                "{url} must not be probed"
            );
        }
        for url in [
            "https://example.com/",
            "https://example.com./",
            "https://localhost.example.com/",
            "https://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ] {
            assert!(
                vet_probe_url(url, ProbePolicy::PublicOnly).is_ok(),
                "{url} is a public HTTPS endpoint and must be probed"
            );
        }
    }

    /// The dev-stack escape hatch admits plaintext and private hosts, and
    /// nothing more: credentials and non-HTTP schemes are still refused.
    #[test]
    fn allow_private_admits_dev_endpoints_but_not_credentials() {
        for url in [
            "http://localhost:8000/",
            "http://127.0.0.1:9099/",
            "http://[::1]:7037/",
            "https://10.0.0.5/",
        ] {
            assert!(
                vet_probe_url(url, ProbePolicy::AllowPrivate).is_ok(),
                "{url} is a dev endpoint AllowPrivate exists for"
            );
        }
        for url in [
            "https://user:pass@10.0.0.5/",
            "ftp://127.0.0.1/",
            "not a url",
        ] {
            assert!(
                vet_probe_url(url, ProbePolicy::AllowPrivate).is_err(),
                "{url} must still be refused"
            );
        }
    }

    /// A blocked endpoint is stated, and is additive for `--json` consumers,
    /// but it does not make the chain unhealthy.
    #[test]
    fn a_blocked_probe_is_a_finding_but_not_a_fault() {
        let blocked = Probe::Blocked {
            url: "https://127.0.0.1/".into(),
            reason: "non-public host 127.0.0.1".into(),
        };
        assert_eq!(
            serde_json::to_value(&blocked).expect("serialises"),
            json!({
                "status": "blocked",
                "url": "https://127.0.0.1/",
                "reason": "non-public host 127.0.0.1",
            })
        );

        let mut party = resolved_party(
            Role::Vtc,
            "VTC",
            "did:peer:2.x",
            &json!({"service": [{
                "id": "#dc", "type": "DIDCommMessaging",
                "serviceEndpoint": "https://127.0.0.1/",
            }]}),
        );
        party.resolved.as_mut().expect("resolved").probes = vec![blocked];
        let parties = vec![party];
        let notes = collect_notes(&parties, &[]);
        assert!(
            notes
                .iter()
                .any(|n| n.contains("https://127.0.0.1/ not probed (non-public host 127.0.0.1)")),
            "{notes:?}"
        );
        assert!(
            HealthReport {
                parties,
                links: Vec::new(),
                notes,
            }
            .is_healthy()
        );
    }
}
