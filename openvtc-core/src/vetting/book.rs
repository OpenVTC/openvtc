//! Everything vetting persists, in one place: `ProtectedConfig::vetting`.
//!
//! Protected rather than public because it names people. An application lists
//! who is vetting the applicant; the vetter desk lists who asked to be vetted
//! and, briefly, the card they showed. None of it belongs in plaintext config.
//!
//! V0 keeps this client-local. Moving tickets and the desk into VTA appstate is
//! V1, once `spec/vta/appstate/*` exists (design §11.2).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use vta_sdk::protocols::join_requests::JoinRequestManifestResponseBody;
use vta_sdk::protocols::vetting::{VettingRequirements, documentation};

use super::applicant::{Application, RequestState};
use super::tickets::{GuessThrottle, Ticket};
use super::vetter::{DeskEntry, DeskState, IssuedStatement};
use crate::config::account::PersonaId;

/// A vetter's own rules (design §11.2). Every number is the vetter's choice;
/// the community decides what counts, not what a vetter must accept.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VetterPolicy {
    /// Requests a persona holds open at once; more are refused with
    /// `capacity`.
    pub max_open_requests: usize,
    /// How long a session stays open for the applicant to answer.
    pub session_minutes: i64,
    /// `validUntil` of a statement, from issue. A community's
    /// `maxStatementAge` is applied by the community regardless.
    pub statement_validity_days: i64,
    /// Days a received card is kept after the statement is issued or the
    /// request declined; afterwards only its digest remains.
    pub card_retention_days: i64,
    /// The documentation this vetter accepts (D16), offered to applicants.
    pub accepts_documentation: Vec<String>,
}

impl Default for VetterPolicy {
    fn default() -> Self {
        Self {
            max_open_requests: 10,
            session_minutes: 15,
            statement_validity_days: 180,
            card_retention_days: 7,
            accepts_documentation: vec![
                documentation::PASSPORT.into(),
                documentation::NATIONAL_ID.into(),
                documentation::DRIVER_LICENCE.into(),
            ],
        }
    }
}

impl VetterPolicy {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// [`Self::session_minutes`] as a duration.
    #[must_use]
    pub fn session_length(&self) -> Duration {
        Duration::minutes(self.session_minutes.clamp(1, 60))
    }

    /// [`Self::statement_validity_days`] as a duration.
    #[must_use]
    pub fn statement_validity(&self) -> Duration {
        Duration::days(self.statement_validity_days.max(1))
    }
}

/// The claim types a session asks for when the community's requirements are
/// not known. Every vetter of one application must ask for the same set, or
/// the cards commit to different identities — so a vetter should fetch the
/// manifest rather than rely on this.
pub const FALLBACK_REQUIRED_CLAIMS: &[&str] = &["name.legal"];

/// A community's vetting criterion, as last read from its manifest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KnownCriterion {
    /// The community.
    pub community: String,
    /// The criterion id.
    pub criterion_id: String,
    /// Its `requirementsDigest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements_digest: Option<String>,
    /// What it requires.
    pub requirements: VettingRequirements,
    /// When it was read.
    pub fetched_at: DateTime<Utc>,
}

/// All vetting state, for both sides.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct VettingBook {
    /// Our applications, one per community and persona.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applications: Vec<Application>,
    /// Tickets we have issued as a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tickets: Vec<Ticket>,
    /// Requests people have made of us as a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub desk: Vec<DeskEntry>,
    /// Statements we have signed, kept so we can withdraw them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issued: Vec<IssuedStatement>,
    /// Recent wrong ticket codes.
    #[serde(default, skip_serializing_if = "GuessThrottle::is_empty")]
    pub throttle: GuessThrottle,
    /// Vetting criteria read from community manifests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub criteria: Vec<KnownCriterion>,
    /// Our rules as a vetter.
    #[serde(default, skip_serializing_if = "VetterPolicy::is_default")]
    pub policy: VetterPolicy,
    /// Fields written by a newer build, preserved verbatim (D19).
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl VettingBook {
    /// Nothing to persist — keeps a config without vetting byte-identical.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
            && self.tickets.is_empty()
            && self.desk.is_empty()
            && self.issued.is_empty()
            && self.throttle.is_empty()
            && self.criteria.is_empty()
            && self.policy.is_default()
            && self.extra.is_empty()
    }

    /// Remember `community`'s vetting criteria from its manifest, replacing
    /// what was known. Returns whether anything changed.
    pub fn learn_manifest(
        &mut self,
        community: &str,
        manifest: &JoinRequestManifestResponseBody,
        now: DateTime<Utc>,
    ) -> bool {
        let fresh: Vec<KnownCriterion> = manifest
            .criteria
            .iter()
            .filter_map(|c| {
                let requirements = c.vetting.clone()?;
                requirements.validate().ok()?;
                Some(KnownCriterion {
                    community: community.to_string(),
                    criterion_id: c.id.clone(),
                    requirements_digest: c.requirements_digest.clone(),
                    requirements,
                    fetched_at: now,
                })
            })
            .collect();
        let known: Vec<&KnownCriterion> = self
            .criteria
            .iter()
            .filter(|k| k.community == community)
            .collect();
        let unchanged = known.len() == fresh.len()
            && known.iter().zip(&fresh).all(|(a, b)| {
                a.criterion_id == b.criterion_id
                    && a.requirements_digest == b.requirements_digest
                    && a.requirements == b.requirements
            });
        self.criteria.retain(|k| k.community != community);
        self.criteria.extend(fresh);
        !unchanged
    }

    /// The claim types a session for `community` should require: those of the
    /// criterion with `digest` (what the applicant named), else the community's
    /// first vetting criterion, else [`FALLBACK_REQUIRED_CLAIMS`]. The second
    /// value says whether the community's requirements were known.
    #[must_use]
    pub fn required_claims_for(
        &self,
        community: &str,
        digest: Option<&str>,
    ) -> (Vec<String>, bool) {
        let mut ours = self.criteria.iter().filter(|k| k.community == community);
        let chosen = digest
            .and_then(|d| {
                self.criteria.iter().find(|k| {
                    k.community == community && k.requirements_digest.as_deref() == Some(d)
                })
            })
            .or_else(|| ours.next());
        match chosen {
            Some(k) if !k.requirements.required_claims.is_empty() => {
                (k.requirements.required_claims.clone(), true)
            }
            Some(_) => (Vec::new(), true),
            None => (
                FALLBACK_REQUIRED_CLAIMS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                false,
            ),
        }
    }

    /// How long `community` says it takes to decide a join (`decisionSla`),
    /// from our application as `persona` or else what we know of its criteria.
    /// `None` when it has not said, or said something unparseable.
    #[must_use]
    pub fn decision_sla(&self, community: &str, persona: PersonaId) -> Option<Duration> {
        let from_application = self
            .application(community, persona)
            .and_then(|a| a.requirements.as_ref())
            .and_then(|r| r.decision_sla.as_deref());
        let from_criteria = || {
            self.criteria
                .iter()
                .filter(|k| k.community == community)
                .find_map(|k| k.requirements.decision_sla.as_deref())
        };
        from_application
            .or_else(from_criteria)
            .and_then(vta_sdk::protocols::vetting::parse_iso8601_duration)
    }

    /// Our application to `community` as `persona`.
    #[must_use]
    pub fn application(&self, community: &str, persona: PersonaId) -> Option<&Application> {
        self.applications
            .iter()
            .find(|a| a.community == community && a.persona == persona)
    }

    /// Mutable [`Self::application`].
    pub fn application_mut(
        &mut self,
        community: &str,
        persona: PersonaId,
    ) -> Option<&mut Application> {
        self.applications
            .iter_mut()
            .find(|a| a.community == community && a.persona == persona)
    }

    /// The application with this id.
    pub fn application_by_id_mut(&mut self, id: &str) -> Option<&mut Application> {
        self.applications.iter_mut().find(|a| a.id == id)
    }

    /// The application `persona` is making to `community`, started if there is
    /// none yet. `join_did` is the persona's DID, and the design fixes it when
    /// the application starts (D13).
    ///
    /// # Errors
    ///
    /// Only if the platform has no randomness for the commitment salt.
    pub fn start_application(
        &mut self,
        community: &str,
        persona: PersonaId,
        join_did: &str,
        now: DateTime<Utc>,
    ) -> Result<&mut Application, vta_sdk::vetting::VettingError> {
        if let Some(i) = self
            .applications
            .iter()
            .position(|a| a.community == community && a.persona == persona)
        {
            return Ok(&mut self.applications[i]);
        }
        self.applications
            .push(Application::new(community, persona, join_did, now)?);
        Ok(self.applications.last_mut().expect("just pushed"))
    }

    /// The desk entry with our `request_id`.
    #[must_use]
    pub fn desk_entry(&self, request_id: &str) -> Option<&DeskEntry> {
        self.desk.iter().find(|e| e.request_id == request_id)
    }

    /// Mutable [`Self::desk_entry`].
    pub fn desk_entry_mut(&mut self, request_id: &str) -> Option<&mut DeskEntry> {
        self.desk.iter_mut().find(|e| e.request_id == request_id)
    }

    /// Requests `persona` has accepted and not yet finished.
    #[must_use]
    pub fn open_requests(&self, persona: PersonaId) -> usize {
        self.desk
            .iter()
            .filter(|e| e.persona == persona && e.state.is_open())
            .count()
    }

    /// Let time pass: close sessions nobody answered, forget cards past their
    /// retention, and drop tickets that can admit nothing. Returns whether
    /// anything changed.
    pub fn prune(&mut self, now: DateTime<Utc>) -> bool {
        let mut changed = false;

        let before = self.tickets.len();
        self.tickets
            .retain(|t| t.is_live(now) || now - t.expires_at.min(now) < Duration::days(1));
        changed |= self.tickets.len() != before;

        let retention = Duration::days(self.policy.card_retention_days.max(0));
        for entry in &mut self.desk {
            changed |= entry.expire_session(now);
            changed |= entry.forget_card_after(retention, now);
        }

        for application in &mut self.applications {
            for request in &mut application.requests {
                if let RequestState::Session {
                    request_id,
                    session,
                    ..
                } = &request.state
                    && session.expires_at <= now
                {
                    request.state = RequestState::Accepted {
                        request_id: request_id.clone(),
                        accepts_documentation: Vec::new(),
                        session_hint: None,
                    };
                    request.updated_at = now;
                    changed = true;
                }
            }
        }
        changed
    }
}

impl DeskState {
    /// Still needs the vetter.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(
            self,
            DeskState::Accepted | DeskState::Session { .. } | DeskState::CardReceived { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_book_is_not_written() {
        let book = VettingBook::default();
        assert!(book.is_empty());
        assert_eq!(serde_json::to_value(&book).unwrap(), serde_json::json!({}));
    }

    #[test]
    fn one_application_per_community_and_persona() {
        let mut book = VettingBook::default();
        let persona = PersonaId::new();
        let now = Utc::now();
        let first = book
            .start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        let again = book
            .start_application("did:web:vtc", persona, "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        assert_eq!(first, again);
        book.start_application("did:web:other", persona, "did:key:zA", now)
            .unwrap();
        assert_eq!(book.applications.len(), 2);
    }

    #[test]
    fn unknown_members_survive_a_round_trip() {
        let mut v = serde_json::to_value(VettingBook::default()).unwrap();
        v["vetterDirectory"] = serde_json::json!({ "listed": true });
        let book: VettingBook = serde_json::from_value(v).unwrap();
        assert!(!book.is_empty());
        assert_eq!(
            serde_json::to_value(&book).unwrap()["vetterDirectory"]["listed"],
            true
        );
    }
}
