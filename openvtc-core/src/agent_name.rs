//! Agent names — human-memorable shortcuts that resolve to DIDs.
//!
//! An agent name is a URL whose path begins with `/@`
//! (`example.com/@alice`). It is **not** a DID method; it is a shortcut layer
//! in front of DID resolution. Resolution is three stages and the third is
//! mandatory:
//!
//! 1. the name URL redirects to a DID,
//! 2. the DID resolves to a document,
//! 3. **the document must claim the name back via `alsoKnownAs`.**
//!
//! Stage 1 is served by the name's own web server, so on its own it proves
//! nothing — anyone can publish a redirect at somebody else's DID. Stage 3 is
//! what makes the binding real: only the DID's controller can add an
//! `alsoKnownAs` entry. This module never surfaces a name that has not
//! completed all three, so a hostile DID cannot make the UI display it under a
//! name it does not actually own.
//!
//! All parsing, canonicalisation and `alsoKnownAs` matching delegates to the
//! [`agent_names`] crate. Canonicalisation is unspecified by the agent-name
//! spec, so two implementations that normalise differently disagree about
//! whether a name verifies — hand-rolling any of it is how the two sides drift.
//! This is the same rule the crate states for `didwebvh-rs`.

use affinidi_did_resolver_cache_sdk::{DIDCacheClient, errors::DIDCacheError};
use affinidi_tdk::did_common::Document;
use agent_names::AgentName;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// How many `alsoKnownAs` candidates we are willing to round-trip per document
/// before giving up. A document that claims a name makes us do one network
/// resolve per candidate; a hostile document could list hundreds, so we cap it.
/// The first candidate that verifies wins, so a well-formed document (one or a
/// few names) is unaffected.
const MAX_CANDIDATES: usize = 4;

/// How long a persisted **positive** lookup is trusted before the background
/// refresh re-verifies it. The resolver's own name cache is short (~5 min) and
/// handles churn; this persisted layer only exists so names show instantly at
/// launch without a network round-trip, so a day is ample.
pub const AGENT_NAME_TTL: Duration = Duration::hours(24);

/// How long a persisted **negative** lookup is trusted.
///
/// Deliberately far shorter than [`AGENT_NAME_TTL`]. A negative is not a fact
/// about the DID, it is the absence of evidence — and every transient cause
/// produces one: the naming host briefly down, no network at launch, a name
/// claimed on the VTA moments ago whose redirect is not yet live. Caching those
/// for a day blinds every display surface for a day, with the DID rendering
/// exactly as it would if it genuinely had no name, and nothing in the sweep to
/// re-check it (`agent_name_refresh_targets` skips entries that are not stale).
///
/// A few minutes is enough to stop a nameless DID being re-resolved on every
/// render, while letting a transient failure heal itself on the next sweep.
///
/// Set to the sweep interval rather than below it. Because staleness is
/// `now - checked_at >= TTL`, a negative written *during* a sweep is a shade
/// under one interval old at the next tick and is picked up by the one after,
/// so the effective retry is ~2 sweeps. That is deliberate: retrying a failing
/// name on *every* sweep would re-fetch up to `MAX_CANDIDATES` redirects per DID
/// indefinitely, which is the unbounded-polling shape VTI R1.4 warns about.
pub const AGENT_NAME_NEGATIVE_TTL: Duration = Duration::minutes(5);

/// A persisted DID → agent-name lookup. The value is deliberately an
/// `Option`: a resolved-and-verified name, **or** `None` recording that the DID
/// currently has no verifiable name — a negative result worth caching so the UI
/// does not re-resolve a nameless DID on every render.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachedAgentName {
    /// The verified name (scheme-less, `example.com/@alice`), or `None` if the
    /// DID has no verifiable name.
    pub name: Option<String>,
    /// When this was last verified, for staleness (`AGENT_NAME_TTL`).
    pub checked_at: DateTime<Utc>,
}

impl CachedAgentName {
    /// How long this entry is trusted: [`AGENT_NAME_TTL`] for a verified name,
    /// the much shorter [`AGENT_NAME_NEGATIVE_TTL`] for a negative.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        if self.name.is_some() {
            AGENT_NAME_TTL
        } else {
            AGENT_NAME_NEGATIVE_TTL
        }
    }

    /// Whether this entry has outlived its [`ttl`](Self::ttl) as of `now` and
    /// should be re-verified by the background refresh.
    #[must_use]
    pub fn is_stale(&self, now: DateTime<Utc>) -> bool {
        now - self.checked_at >= self.ttl()
    }
}

/// Cheap syntactic test — no network. A string containing the `/@` marker is
/// treated as an agent name; everything else is a DID (or nonsense) for the
/// resolver to judge.
#[must_use]
pub fn looks_like_agent_name(input: &str) -> bool {
    AgentName::looks_like_agent_name(input)
}

/// Resolve `did` to a **verified** agent name for display, or `None`.
///
/// Returns `Some(name)` only when a name the document claims round-trips: the
/// name resolves forward (via [`DIDCacheClient::resolve_any`], which performs
/// the mandatory `alsoKnownAs` check on the document *it* fetches) **and** that
/// forward resolution lands on the same `did` we are labelling. The returned
/// string is the scheme-less spelling (`example.com/@alice`).
///
/// Anything short of that — the name points at a different DID (a spoof), the
/// name no longer redirects, the host is unreachable — yields `None`, and the
/// caller falls back to showing the DID. A name is a mutable web redirect; the
/// verification is what stops the UI from becoming a phishing surface, so a
/// failure to verify is deliberately indistinguishable here from "no name".
pub async fn verified_agent_name(
    resolver: &DIDCacheClient,
    did: &str,
    doc: &Document,
) -> Option<String> {
    match name_outcome(resolver, did, doc).await {
        NameOutcome::Verified(name) => Some(name),
        NameOutcome::NoClaim | NameOutcome::NotVerified(_) => None,
    }
}

/// Why `did` does or does not have a displayable agent name.
///
/// Same verification as [`verified_agent_name`], but it keeps the reasons
/// instead of collapsing them to `None`. Display code should use
/// `verified_agent_name`; this exists so the background sweep and any operator
/// diagnostic can say *why* a DID is rendering as a raw DID — the distinction
/// between "this DID claims no name", "the naming host is unreachable" and
/// "the name points at somebody else's DID" is invisible otherwise, which is
/// what makes a silent no-name display so hard to debug (VTI R6.4).
pub async fn name_outcome(resolver: &DIDCacheClient, did: &str, doc: &Document) -> NameOutcome {
    let candidates = agent_names::extract_agent_names(doc);
    verify_candidates_detailed(did, candidates, |name| async move {
        // resolve_any performs the mandatory `alsoKnownAs` check on the document
        // it fetches; we additionally require its resolved DID to be the one we
        // are labelling, which ties the name's forward redirect back to `did`.
        resolver
            .resolve_any(&name)
            .await
            .map(|resp| resp.did)
            .map_err(|e| e.to_string())
    })
    .await
}

/// The outcome of looking for a displayable agent name for a DID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameOutcome {
    /// A name that completed the full round-trip and is safe to display.
    Verified(String),
    /// The document claims no agent names at all — this DID simply has none.
    NoClaim,
    /// Names were claimed but none verified; carries each rejection reason.
    NotVerified(Vec<CandidateFailure>),
}

impl NameOutcome {
    /// The verified name, if there is one.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            NameOutcome::Verified(n) => Some(n),
            _ => None,
        }
    }

    /// A short operator-facing summary for logs.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            NameOutcome::Verified(n) => format!("verified '{n}'"),
            NameOutcome::NoClaim => "no agent name claimed in the document".to_string(),
            NameOutcome::NotVerified(failures) => {
                let detail = failures
                    .iter()
                    .map(|f| format!("'{}' ({})", f.name, f.reason))
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("claimed but not verified: {detail}")
            }
        }
    }
}

/// One claimed name that failed verification, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateFailure {
    /// The claimed name, scheme-less.
    pub name: String,
    /// Why it was rejected — unreachable host, not a DID, or a spoof.
    pub reason: String,
}

/// Resolve `did` to a verified agent name, fetching its document first.
///
/// The batch refresh has only DIDs to work from, not documents, so this wraps
/// [`verified_agent_name`] with the leading `resolve(did)`. Both hops reuse the
/// resolver's document cache. `None` if the DID does not resolve or has no
/// verifiable name.
pub async fn resolve_verified_name(resolver: &DIDCacheClient, did: &str) -> Option<String> {
    match resolve_name_outcome(resolver, did).await {
        Ok(outcome) => outcome.name().map(str::to_owned),
        Err(_) => None,
    }
}

/// [`resolve_verified_name`] retaining the reason, for the background sweep and
/// operator diagnostics. `Err` carries the resolver's message when the DID
/// itself could not be resolved — distinct from resolving fine but having no
/// verifiable name.
pub async fn resolve_name_outcome(
    resolver: &DIDCacheClient,
    did: &str,
) -> Result<NameOutcome, String> {
    let resp = resolver.resolve(did).await.map_err(|e| e.to_string())?;
    Ok(name_outcome(resolver, did, &resp.doc).await)
}

/// The verification decision, factored out so the spoof guard is testable
/// without a live resolver: accept the first candidate whose forward resolution
/// lands on `did`; a candidate resolving to a *different* DID (a spoof) or not
/// resolving at all is skipped. Capped at [`MAX_CANDIDATES`].
///
/// `resolve` maps a name's canonical string to the DID it forward-resolves to
/// (`None` on any failure).
/// The verification decision, factored out so the spoof guard is testable
/// without a live resolver, and retaining the rejection reasons.
///
/// `resolve` maps a name's canonical string to the DID it forward-resolves to,
/// or an error describing why it could not be resolved.
async fn verify_candidates_detailed<F, Fut>(
    did: &str,
    candidates: Vec<AgentName>,
    resolve: F,
) -> NameOutcome
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, String>>,
{
    if candidates.is_empty() {
        return NameOutcome::NoClaim;
    }
    let mut failures = Vec::new();
    for name in candidates.into_iter().take(MAX_CANDIDATES) {
        match resolve(name.as_str().to_string()).await {
            Ok(got) if got == did => {
                return NameOutcome::Verified(name.without_scheme().to_string());
            }
            // The spoof case: the name is real but belongs to another DID.
            Ok(got) => failures.push(CandidateFailure {
                name: name.without_scheme().to_string(),
                reason: format!("forward-resolves to a different DID ({got})"),
            }),
            Err(reason) => failures.push(CandidateFailure {
                name: name.without_scheme().to_string(),
                reason,
            }),
        }
    }
    NameOutcome::NotVerified(failures)
}

/// Why an identifier the user typed could not be turned into a DID.
///
/// The variants exist so the operator can tell the failure modes apart, rather
/// than getting one fixed hint for every failure. `resolve_any` collapses the
/// underlying [`agent_names::AgentNameError`] into a string, so [`Self::AgentName`]
/// carries that already-descriptive message (e.g. "did not redirect (HTTP 404)"
/// vs "is not authorized by DID" vs "resolves to the non-public address")
/// rather than re-deriving a typed variant by string-matching.
#[derive(Debug, thiserror::Error)]
pub enum IdentifierError {
    /// An agent name failed to resolve or verify. The message distinguishes the
    /// cause (not-found / not-a-DID / not-claimed-back / blocked address).
    #[error("agent name '{input}' could not be resolved: {detail}")]
    AgentName {
        /// The input, as given.
        input: String,
        /// Why it did not resolve or verify, in words.
        detail: String,
    },

    /// The resolver could not reach the network (timeout or transport failure).
    #[error("could not reach the network resolving '{input}'")]
    Unreachable {
        /// The input, as given.
        input: String,
    },

    /// It was not an agent name, and it is not a resolvable DID either.
    #[error("'{input}' is not a resolvable DID")]
    InvalidDid {
        /// The input, as given.
        input: String,
    },
}

/// Resolve user input that may be a DID **or** an agent name to a DID string.
///
/// A DID is passed straight through the resolver; an agent name goes through
/// the full three-stage resolve-and-verify. On success the caller should
/// persist the returned **DID**, never the name — a name is a mutable web
/// redirect, and persisting one would let a redirect change silently repoint a
/// saved identity.
///
/// Bounded by [`IDENTIFIER_RESOLVE_TIMEOUT`] (R1.2): a name pointing at a slow
/// host comes back as [`IdentifierError::Unreachable`] rather than holding the
/// caller — often the state-handler loop — for as long as the resolver's own
/// per-step timeouts add up to.
pub async fn resolve_identifier(
    resolver: &DIDCacheClient,
    input: &str,
) -> Result<String, IdentifierError> {
    let input = input.trim();
    match tokio::time::timeout(IDENTIFIER_RESOLVE_TIMEOUT, resolver.resolve_any(input)).await {
        Ok(Ok(resp)) => Ok(resp.did),
        Ok(Err(e)) => Err(classify(input, e)),
        Err(_) => Err(IdentifierError::Unreachable {
            input: input.to_string(),
        }),
    }
}

/// The most [`resolve_identifier`] waits. A name costs a redirect fetch, a DID
/// resolve and the `alsoKnownAs` check; each is bounded by the resolver, and
/// this bounds the whole.
pub const IDENTIFIER_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Map a [`DIDCacheError`] onto the operator-facing [`IdentifierError`], using
/// whether the input looked like a name to disambiguate the parse/DID buckets.
fn classify(input: &str, err: DIDCacheError) -> IdentifierError {
    let input = input.to_string();
    match err {
        // `AgentNameError` is gated behind the cache-sdk's `agent-names`
        // feature, which this workspace always enables (see the root
        // `Cargo.toml`), so the variant is always present in our build.
        DIDCacheError::AgentNameError(detail) => IdentifierError::AgentName { input, detail },
        DIDCacheError::NetworkTimeout | DIDCacheError::TransportError(_) => {
            IdentifierError::Unreachable { input }
        }
        // A DID-parse / method / config failure. If the user typed a name, the
        // name-shaped failure is the useful framing; otherwise it is a bad DID.
        other => {
            if looks_like_agent_name(&input) {
                IdentifierError::AgentName {
                    input,
                    detail: other.to_string(),
                }
            } else {
                IdentifierError::InvalidDid { input }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;

    fn name(s: &str) -> AgentName {
        AgentName::parse(s).expect("valid agent name in test")
    }

    #[test]
    fn cache_entry_staleness_tracks_the_ttl() {
        let checked_at = Utc::now();
        let fresh = CachedAgentName {
            name: Some("example.com/@alice".into()),
            checked_at,
        };
        assert!(!fresh.is_stale(checked_at));
        assert!(!fresh.is_stale(checked_at + Duration::hours(23)));
        assert!(fresh.is_stale(checked_at + AGENT_NAME_TTL));
        assert!(fresh.is_stale(checked_at + Duration::hours(25)));
    }

    /// A negative expires on the short TTL, not the 24h one. Caching "no name"
    /// for a day is what made a transient resolve failure — host briefly down,
    /// offline at launch, a redirect not yet live — hide every name until the
    /// next day, indistinguishable from the DID genuinely having no name.
    #[test]
    fn negative_entries_expire_far_sooner_than_positive_ones() {
        let checked_at = Utc::now();
        let negative = CachedAgentName {
            name: None,
            checked_at,
        };
        assert_eq!(negative.ttl(), AGENT_NAME_NEGATIVE_TTL);
        assert!(!negative.is_stale(checked_at));
        assert!(negative.is_stale(checked_at + AGENT_NAME_NEGATIVE_TTL));

        // The point of the split: at a time when a negative is already stale, a
        // positive written at the same instant is still trusted.
        let positive = CachedAgentName {
            name: Some("example.com/@alice".into()),
            checked_at,
        };
        let after = checked_at + AGENT_NAME_NEGATIVE_TTL;
        assert!(negative.is_stale(after));
        assert!(!positive.is_stale(after));
    }

    /// The spoof case, and the single most important behaviour in this module:
    /// a document claims `example.com/@alice`, but that name forward-resolves to
    /// a *different* DID. It must NOT be displayed as our name, and the reason
    /// must name the DID it actually landed on so the report is actionable.
    #[tokio::test]
    async fn rejects_name_resolving_to_a_different_did() {
        let got = verify_candidates_detailed(
            "did:webvh:us:example.com",
            vec![name("example.com/@alice")],
            // The name points at somebody else's DID.
            |_| async { Ok("did:webvh:them:evil.example".to_string()) },
        )
        .await;
        assert_eq!(
            got.name(),
            None,
            "a name pointing at a different DID must be rejected"
        );
        match &got {
            NameOutcome::NotVerified(failures) => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].name, "example.com/@alice");
                assert!(
                    failures[0].reason.contains("did:webvh:them:evil.example"),
                    "reason was: {}",
                    failures[0].reason
                );
            }
            other => panic!("expected NotVerified, got {other:?}"),
        }
    }

    /// The happy path: the claimed name forward-resolves back to the DID we are
    /// labelling. Returned scheme-less.
    #[tokio::test]
    async fn accepts_name_that_round_trips() {
        let did = "did:webvh:us:example.com";
        let got = verify_candidates_detailed(did, vec![name("example.com/@alice")], |n| {
            let did = did.to_string();
            async move {
                assert_eq!(n, "https://example.com/@alice");
                Ok(did)
            }
        })
        .await;
        assert_eq!(got.name(), Some("example.com/@alice"));
    }

    /// A name that does not resolve at all (host down, no redirect) yields no
    /// name rather than an error — the caller falls back to the DID — but the
    /// transport reason is kept, so "host is down" stays distinguishable from
    /// "the name is not claimed".
    #[tokio::test]
    async fn skips_unresolvable_name() {
        let got = verify_candidates_detailed(
            "did:webvh:us:example.com",
            vec![name("example.com/@alice")],
            |_| async { Err("connection refused".to_string()) },
        )
        .await;
        assert_eq!(got.name(), None);
        assert!(got.summary().contains("connection refused"), "{got:?}");
    }

    /// A document that claims many names must not trigger an unbounded number of
    /// network resolves; verification stops at MAX_CANDIDATES.
    #[tokio::test]
    async fn caps_the_number_of_candidates_verified() {
        let calls = Cell::new(0usize);
        let candidates: Vec<AgentName> = (0..(MAX_CANDIDATES + 5))
            .map(|i| name(&format!("example.com/@name{i}")))
            .collect();
        let got = verify_candidates_detailed("did:webvh:us:example.com", candidates, |_| {
            calls.set(calls.get() + 1);
            // None of them match, so every attempt (up to the cap) is made.
            async { Ok("did:webvh:other:host".to_string()) }
        })
        .await;
        assert_eq!(got.name(), None);
        assert_eq!(calls.get(), MAX_CANDIDATES, "must not resolve past the cap");
    }

    /// The first verifying candidate wins; later ones are not resolved.
    #[tokio::test]
    async fn stops_at_first_verified_candidate() {
        let did = "did:webvh:us:example.com";
        let calls = Cell::new(0usize);
        let candidates = vec![name("example.com/@first"), name("example.com/@second")];
        let got = verify_candidates_detailed(did, candidates, |_| {
            calls.set(calls.get() + 1);
            let did = did.to_string();
            async move { Ok(did) }
        })
        .await;
        assert_eq!(got.name(), Some("example.com/@first"));
        assert_eq!(calls.get(), 1, "must short-circuit on the first match");
    }

    /// A document claiming nothing is reported as `NoClaim`, not as a failure —
    /// the operator needs "this DID has no name" to read differently from "the
    /// name would not verify".
    #[tokio::test]
    async fn no_claimed_names_reports_no_claim() {
        let got = verify_candidates_detailed("did:webvh:us:example.com", vec![], |_| async {
            panic!("must not resolve anything when there are no candidates")
        })
        .await;
        assert_eq!(got, NameOutcome::NoClaim);
        assert!(got.summary().contains("no agent name claimed"));
    }

    #[test]
    fn recognises_agent_names() {
        assert!(looks_like_agent_name("example.com/@alice"));
        assert!(looks_like_agent_name("https://connect.me/@bob"));
        assert!(looks_like_agent_name(
            "firstperson.network/@drummond/h2hsummit"
        ));
    }

    #[test]
    fn rejects_non_agent_names() {
        assert!(!looks_like_agent_name("did:webvh:QmScid:example.com"));
        assert!(!looks_like_agent_name("did:web:example.com"));
        // An email is not an agent name — the marker is `/@`, not `@`.
        assert!(!looks_like_agent_name("alice@example.com"));
        // A bare handle with no host is not resolvable and not an agent name.
        assert!(!looks_like_agent_name("@alice"));
        assert!(!looks_like_agent_name(""));
    }

    /// A non-name, non-DID string that the resolver rejects with a DID-parse
    /// error surfaces as `InvalidDid`, not as an agent-name failure.
    #[test]
    fn classify_non_name_did_error_is_invalid_did() {
        let err = classify("not-a-did", DIDCacheError::DIDError("bad".into()));
        assert!(matches!(err, IdentifierError::InvalidDid { .. }));
    }

    /// The same DID-parse error, when the input *looked* like a name, is framed
    /// as an agent-name failure so the operator gets the name-shaped hint.
    #[test]
    fn classify_name_shaped_parse_error_is_agent_name() {
        let err = classify("example.com/@alice", DIDCacheError::DIDError("bad".into()));
        assert!(matches!(err, IdentifierError::AgentName { .. }));
    }

    /// Network failures are their own bucket regardless of input shape, so the
    /// operator can tell "the host is down" from "the name isn't claimed".
    #[test]
    fn classify_network_errors_are_unreachable() {
        assert!(matches!(
            classify("example.com/@alice", DIDCacheError::NetworkTimeout),
            IdentifierError::Unreachable { .. }
        ));
        assert!(matches!(
            classify("did:web:x", DIDCacheError::TransportError("refused".into())),
            IdentifierError::Unreachable { .. }
        ));
    }

    /// The agent-name resolver's descriptive message is preserved verbatim, so
    /// distinct causes (not-found vs not-claimed vs blocked) reach the user.
    #[test]
    fn classify_agent_name_error_preserves_detail() {
        let err = classify(
            "example.com/@alice",
            DIDCacheError::AgentNameError(
                "Agent name 'example.com/@alice' did not redirect (HTTP 404)".into(),
            ),
        );
        match err {
            IdentifierError::AgentName { detail, .. } => {
                assert!(detail.contains("did not redirect"), "detail was: {detail}");
            }
            other => panic!("expected AgentName, got {other:?}"),
        }
    }
}
