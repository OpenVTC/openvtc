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
use vta_sdk::protocols::join_requests::{CommunityBranding, JoinRequestManifestResponseBody};
use vta_sdk::protocols::vetting::{VettingRequirements, documentation};

use super::applicant::{Application, RequestState};
use super::queries::CommunityQuery;
use super::registry::VetterProfileRecord;
use super::tickets::{GuessThrottle, Ticket};
use super::vetter::{DeskEntry, DeskState, IssuedStatement};
use crate::config::account::{Account, CommunityRecord, PersonaId};

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

/// A community naming one of our personas a vetter: the role credential it
/// issued through `vtc/vetting/vetters/grant` (design §10.3). Presented to
/// applicants with every acceptance, and needed to hand out tickets.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VetterGrant {
    /// The community that issued it.
    pub community: String,
    /// Our persona it names.
    pub persona: PersonaId,
    /// The credential's `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// Its `validUntil`. A grant without one is never treated as live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// When it arrived.
    pub received_at: DateTime<Utc>,
    /// The signed credential, exactly as delivered.
    pub credential: serde_json::Value,
}

impl VetterGrant {
    /// Unexpired at `now`. Revocation is the community's to apply: a revoked
    /// grant stops the vetter's statements counting there.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.valid_until.is_some_and(|until| until > now)
    }
}

/// How a community presents itself, from its manifest's `branding`.
///
/// Presentation only: nothing is trusted because of it. Kept as this crate's
/// own type rather than the SDK's, which refuses unknown members — a config
/// written by a newer build must still open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Branding {
    /// The name the community gives itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// `#rrggbb`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
}

impl Branding {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// What of `branding` this client keeps: nothing, if it breaks its schema.
    fn from_manifest(branding: &CommunityBranding) -> Self {
        if branding.check_shape().is_err() {
            return Self::default();
        }
        Self {
            display_name: branding.display_name.clone(),
            accent_color: branding.accent_color.clone(),
        }
    }

    /// The accent colour as RGB.
    #[must_use]
    pub fn accent_rgb(&self) -> Option<(u8, u8, u8)> {
        self.accent_color.as_deref().and_then(parse_accent)
    }
}

/// `#rrggbb` as RGB; `None` for anything else.
#[must_use]
pub fn parse_accent(color: &str) -> Option<(u8, u8, u8)> {
    let hex = color.strip_prefix('#')?;
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).ok();
    Some((channel(0)?, channel(2)?, channel(4)?))
}

/// A community whose manifest we have read — whether or not it vets.
///
/// The criteria alone cannot say "this community does not vet": a manifest
/// with no vetting criterion leaves none behind. This record is what tells
/// "does not vet" apart from "never asked".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownCommunity {
    /// The community.
    pub community: String,
    /// Its branding, if it publishes any.
    #[serde(default, skip_serializing_if = "Branding::is_default")]
    pub branding: Branding,
    /// When its manifest was last read.
    pub fetched_at: DateTime<Utc>,
}

/// What this book knows of whether a community vets its members.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Knowledge<'a> {
    /// Its manifest has not been read.
    Unknown,
    /// Its manifest names no vetting.
    NoVetting,
    /// It vets: its first vetting criterion.
    Vetting(&'a KnownCriterion),
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
    /// Communities that named one of our personas a vetter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vetter_grants: Vec<VetterGrant>,
    /// Communities whose manifests we have read, with their branding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<KnownCommunity>,
    /// The vetter profile we last sent each community, per persona.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vetter_profiles: Vec<VetterProfileRecord>,
    /// Questions put to communities and not yet answered. Memory only — see
    /// [`super::queries`].
    #[serde(skip)]
    pub queries: Vec<CommunityQuery>,
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
            && self.vetter_grants.is_empty()
            && self.communities.is_empty()
            && self.vetter_profiles.is_empty()
            && self.extra.is_empty()
    }

    /// Keep `grant`, replacing an earlier one from the same community for the
    /// same persona. Returns whether anything changed.
    pub fn keep_vetter_grant(&mut self, grant: VetterGrant) -> bool {
        let same = |g: &VetterGrant| g.community == grant.community && g.persona == grant.persona;
        if let Some(existing) = self.vetter_grants.iter_mut().find(|g| same(g)) {
            if existing.credential == grant.credential {
                return false;
            }
            *existing = grant;
        } else {
            self.vetter_grants.push(grant);
        }
        true
    }

    /// `persona`'s live vetter grant from `community`.
    #[must_use]
    pub fn vetter_grant(
        &self,
        community: &str,
        persona: PersonaId,
        now: DateTime<Utc>,
    ) -> Option<&VetterGrant> {
        self.vetter_grants
            .iter()
            .find(|g| g.community == community && g.persona == persona && g.is_live(now))
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

        let branding = manifest
            .branding
            .as_ref()
            .map(Branding::from_manifest)
            .unwrap_or_default();
        // A re-read refreshes `fetched_at` without counting as a change: the
        // same manifest again is not worth a save.
        let branding_changed = match self
            .communities
            .iter_mut()
            .find(|c| c.community == community)
        {
            Some(known) => {
                known.fetched_at = now;
                let changed = known.branding != branding;
                known.branding = branding;
                changed
            }
            None => {
                self.communities.push(KnownCommunity {
                    community: community.to_string(),
                    branding,
                    fetched_at: now,
                });
                true
            }
        };
        !unchanged || branding_changed
    }

    /// Whether `community` vets its members, as far as this book knows.
    ///
    /// Criteria recorded before communities were ([`KnownCommunity`]) still
    /// count as knowing that it vets.
    #[must_use]
    pub fn knowledge(&self, community: &str) -> Knowledge<'_> {
        if let Some(criterion) = self.criteria.iter().find(|k| k.community == community) {
            return Knowledge::Vetting(criterion);
        }
        if self.communities.iter().any(|c| c.community == community) {
            Knowledge::NoVetting
        } else {
            Knowledge::Unknown
        }
    }

    /// `community`'s branding, if it publishes any.
    #[must_use]
    pub fn branding(&self, community: &str) -> Option<&Branding> {
        self.communities
            .iter()
            .find(|c| c.community == community)
            .map(|c| &c.branding)
            .filter(|b| !b.is_default())
    }

    /// Give application `application_id` the requirements already known for
    /// its community — the criterion it chose, else the first — so a new
    /// application shows them before its own manifest request is answered.
    /// Returns whether anything changed.
    pub fn adopt_known_requirements(&mut self, application_id: &str) -> bool {
        let Some(app) = self.applications.iter().find(|a| a.id == application_id) else {
            return false;
        };
        let mut known = self
            .criteria
            .iter()
            .filter(|k| k.community == app.community);
        let chosen = app
            .criterion_id
            .as_deref()
            .and_then(|id| {
                self.criteria
                    .iter()
                    .find(|k| k.community == app.community && k.criterion_id == id)
            })
            .or_else(|| known.next())
            .cloned();
        let (Some(criterion), Some(app)) = (chosen, self.application_by_id_mut(application_id))
        else {
            return false;
        };
        let changed = app.requirements.as_ref() != Some(&criterion.requirements)
            || app.requirements_digest != criterion.requirements_digest
            || app.criterion_id.as_deref() != Some(criterion.criterion_id.as_str());
        app.criterion_id = Some(criterion.criterion_id);
        app.requirements = Some(criterion.requirements);
        app.requirements_digest = criterion.requirements_digest;
        changed
    }

    /// Active memberships holding no live vetter grant — where a member the
    /// community did name a vetter may simply never have received the
    /// credential, and can ask for it again.
    #[must_use]
    pub fn resend_candidates<'a>(
        &self,
        account: &'a Account,
        now: DateTime<Utc>,
    ) -> Vec<&'a CommunityRecord> {
        account
            .memberships()
            .filter(|m| m.status.is_active())
            .filter(|m| self.vetter_grant(&m.vtc_did, m.persona_ref, now).is_none())
            .collect()
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

    fn manifest(
        branding: Option<CommunityBranding>,
        vetting: bool,
    ) -> JoinRequestManifestResponseBody {
        let requirements: VettingRequirements = serde_json::from_value(serde_json::json!({
            "version": "0.1",
            "statementType": vta_sdk::protocols::vetting::IDENTITY_VETTING_ENDORSEMENT_TYPE,
            "minStatements": 1,
            "acceptedMethods": ["inPerson"],
            "requiredClaims": ["name.legal"],
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap();
        JoinRequestManifestResponseBody {
            community_did: "did:web:vtc".into(),
            criteria: vec![vta_sdk::protocols::join_requests::ManifestCriterion {
                id: "c1".into(),
                description: None,
                presentation_definition: serde_json::json!({}),
                vetting: vetting.then_some(requirements),
                requirements_digest: Some("zDigest".into()),
            }],
            branding,
        }
    }

    #[test]
    fn a_manifest_says_whether_a_community_vets_and_how_it_looks() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        assert_eq!(book.knowledge("did:web:vtc"), Knowledge::Unknown);

        let branding = CommunityBranding {
            display_name: Some("Kernel".into()),
            accent_color: Some("#1a2B3c".into()),
            ..CommunityBranding::default()
        };
        assert!(book.learn_manifest("did:web:vtc", &manifest(Some(branding.clone()), true), now));
        assert!(matches!(
            book.knowledge("did:web:vtc"),
            Knowledge::Vetting(_)
        ));
        let known = book.branding("did:web:vtc").unwrap();
        assert_eq!(known.display_name.as_deref(), Some("Kernel"));
        assert_eq!(known.accent_rgb(), Some((0x1a, 0x2b, 0x3c)));
        assert!(
            !book.learn_manifest("did:web:vtc", &manifest(Some(branding), true), now),
            "the same manifest again is not a change"
        );

        assert!(book.learn_manifest("did:web:open", &manifest(None, false), now));
        assert_eq!(book.knowledge("did:web:open"), Knowledge::NoVetting);
        assert!(book.branding("did:web:open").is_none());

        let broken = CommunityBranding {
            accent_color: Some("red".into()),
            ..CommunityBranding::default()
        };
        book.learn_manifest("did:web:broken", &manifest(Some(broken), false), now);
        assert!(
            book.branding("did:web:broken").is_none(),
            "a bad branding is dropped whole"
        );
    }

    #[test]
    fn only_rrggbb_is_an_accent() {
        assert_eq!(parse_accent("#ff0080"), Some((255, 0, 128)));
        for bad in ["ff0080", "#ff008", "#ff00800", "#gg0080", "#ff0 80"] {
            assert_eq!(parse_accent(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_new_application_takes_the_requirements_already_known() {
        let mut book = VettingBook::default();
        let now = Utc::now();
        book.learn_manifest("did:web:vtc", &manifest(None, true), now);
        let id = book
            .start_application("did:web:vtc", PersonaId::new(), "did:key:zA", now)
            .unwrap()
            .id
            .clone();
        assert!(book.adopt_known_requirements(&id));
        let app = book.application_by_id_mut(&id).unwrap();
        assert_eq!(app.criterion_id.as_deref(), Some("c1"));
        assert_eq!(app.requirements_digest.as_deref(), Some("zDigest"));
        assert!(
            !book.adopt_known_requirements(&id),
            "nothing new the second time"
        );
    }

    #[test]
    fn a_member_without_a_live_grant_can_ask_for_it_again() {
        let now = Utc::now();
        let mut account = Account::default();
        let persona = PersonaId::new();
        for (vtc, active) in [
            ("did:web:a", true),
            ("did:web:b", true),
            ("did:web:c", false),
        ] {
            let mut record = CommunityRecord::new_pending(
                vtc.to_string(),
                None,
                "openvtc/test".to_string(),
                persona,
                uuid::Uuid::new_v4(),
                now,
            );
            if active {
                record.activate(now);
            }
            account.add_membership(record);
        }
        let mut book = VettingBook::default();
        book.keep_vetter_grant(VetterGrant {
            community: "did:web:a".into(),
            persona,
            credential_id: None,
            valid_until: Some(now + Duration::days(30)),
            received_at: now,
            credential: serde_json::json!({}),
        });
        let candidates: Vec<&str> = book
            .resend_candidates(&account, now)
            .into_iter()
            .map(|m| m.vtc_did.as_str())
            .collect();
        assert_eq!(candidates, vec!["did:web:b"]);
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
