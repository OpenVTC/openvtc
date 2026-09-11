//! The vetter registry: a vetter's published profile, the directory applicants
//! search, and the forms both are typed into.
//!
//! A person types text; the community takes a `VetterProfileBody` or a
//! `VetterListBody` and refuses anything that breaks its schema. This module
//! sits between the two. It turns the text into the body, names the field a
//! person got wrong in their own terms, and leaves every schema bound to the
//! SDK's `check_shape`, so this client never disagrees with the community about
//! what is valid.
//!
//! The last profile we published is kept in the book, so it can be edited
//! rather than typed again. It is kept as the JSON we sent rather than as the
//! SDK type. That type refuses unknown members, and a profile written by a
//! newer build must not stop an older one from opening the config.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vta_sdk::protocols::vetting::{
    ShapeError, VetterEvent, VetterListBody, VetterLocation, VetterProfileBody,
    VetterProfileResponseBody, VettingMethod,
};

use super::book::{VetterPolicy, VettingBook};
use crate::config::account::PersonaId;

/// Why typed text is not yet a body the community would accept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// A date is not `YYYY-MM-DD`.
    #[error("{0} must be a date written YYYY-MM-DD, like 2026-10-05")]
    Date(&'static str),
    /// A region or city without a country.
    #[error("{0}: a region or city needs a country, as a two-letter code such as CZ")]
    LocationWithoutCountry(&'static str),
    /// No method ticked.
    #[error("choose at least one way you vet: in person, on video, or people you already know")]
    NoMethods,
    /// The community's schema refuses it.
    #[error("the community would refuse this: {0}")]
    Shape(ShapeError),
}

impl From<ShapeError> for DraftError {
    fn from(e: ShapeError) -> Self {
        DraftError::Shape(e)
    }
}

/// Split a typed list on commas and whitespace, dropping empties and repeats.
/// Repeats are dropped rather than refused: `en, en` is a slip, not a choice.
fn split_list(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in text.split(|c: char| c == ',' || c.is_whitespace()) {
        let item = item.trim();
        if !item.is_empty() && !out.iter().any(|o| o == item) {
            out.push(item.to_string());
        }
    }
    out
}

fn optional(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn date(field: &'static str, text: &str) -> Result<NaiveDate, DraftError> {
    NaiveDate::parse_from_str(text.trim(), "%Y-%m-%d").map_err(|_| DraftError::Date(field))
}

fn location(
    what: &'static str,
    country: &str,
    region: &str,
    city: &str,
) -> Result<Option<VetterLocation>, DraftError> {
    match optional(country) {
        Some(country) => Ok(Some(VetterLocation {
            country: country.to_uppercase(),
            region: optional(region),
            city: optional(city),
        })),
        None if optional(region).is_some() || optional(city).is_some() => {
            Err(DraftError::LocationWithoutCountry(what))
        }
        None => Ok(None),
    }
}

/// One event, as typed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventDraft {
    pub name: String,
    pub start_date: String,
    pub end_date: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub url: String,
}

impl EventDraft {
    /// The fields of `event`, for editing.
    #[must_use]
    pub fn from_event(event: &VetterEvent) -> Self {
        let place = event.location.as_ref();
        Self {
            name: event.name.clone(),
            start_date: event.start_date.format("%Y-%m-%d").to_string(),
            end_date: event.end_date.format("%Y-%m-%d").to_string(),
            country: place.map(|l| l.country.clone()).unwrap_or_default(),
            region: place.and_then(|l| l.region.clone()).unwrap_or_default(),
            city: place.and_then(|l| l.city.clone()).unwrap_or_default(),
            url: event.url.clone().unwrap_or_default(),
        }
    }

    /// The event, checked the way the community checks it.
    ///
    /// # Errors
    ///
    /// A date that does not parse, a place without a country, or anything
    /// `VetterEvent::check_shape` refuses — an end before the start, a span
    /// over 31 days, a URL that is not `https`.
    pub fn to_event(&self) -> Result<VetterEvent, DraftError> {
        let event = VetterEvent {
            name: self.name.trim().to_string(),
            start_date: date("the start date", &self.start_date)?,
            end_date: date("the end date", &self.end_date)?,
            location: location("the event", &self.country, &self.region, &self.city)?,
            url: optional(&self.url),
        };
        event.check_shape()?;
        Ok(event)
    }
}

/// A vetter profile, as typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileDraft {
    /// Shown in the directory.
    pub listed: bool,
    pub display_name: String,
    /// BCP 47 tags, separated by commas or spaces.
    pub languages: String,
    pub country: String,
    pub region: String,
    pub city: String,
    /// In [`VettingMethod`] order.
    pub methods: Vec<VettingMethod>,
    /// Documentation tokens, separated by commas or spaces.
    pub accepts_documentation: String,
    pub availability: String,
    pub contact_hint: String,
    pub events: Vec<EventDraft>,
}

/// The order methods are kept and shown in.
const METHOD_ORDER: [VettingMethod; 3] = [
    VettingMethod::InPerson,
    VettingMethod::Video,
    VettingMethod::PriorAcquaintance,
];

impl ProfileDraft {
    /// A first profile.
    ///
    /// Unlisted, because being listed is opt-in (design §7) and publishing is
    /// not the same as choosing to be found. The documentation starts as the
    /// vetter's own policy, because that is what their acceptances already
    /// tell applicants (D16).
    #[must_use]
    pub fn new(policy: &VetterPolicy) -> Self {
        Self {
            listed: false,
            display_name: String::new(),
            languages: String::new(),
            country: String::new(),
            region: String::new(),
            city: String::new(),
            methods: vec![VettingMethod::InPerson, VettingMethod::Video],
            accepts_documentation: policy.accepts_documentation.join(", "),
            availability: String::new(),
            contact_hint: String::new(),
            events: Vec::new(),
        }
    }

    /// The fields of a published profile, for editing.
    #[must_use]
    pub fn from_body(body: &VetterProfileBody) -> Self {
        let place = body.location.as_ref();
        Self {
            listed: body.listed,
            display_name: body.display_name.clone().unwrap_or_default(),
            languages: body.languages.join(", "),
            country: place.map(|l| l.country.clone()).unwrap_or_default(),
            region: place.and_then(|l| l.region.clone()).unwrap_or_default(),
            city: place.and_then(|l| l.city.clone()).unwrap_or_default(),
            methods: METHOD_ORDER
                .into_iter()
                .filter(|m| body.methods.contains(m))
                .collect(),
            accepts_documentation: body.accepts_documentation.join(", "),
            availability: body.availability.clone().unwrap_or_default(),
            contact_hint: body.contact_hint.clone().unwrap_or_default(),
            events: body.events.iter().map(EventDraft::from_event).collect(),
        }
    }

    /// Tick or untick `method`, keeping the order stable.
    pub fn toggle_method(&mut self, method: VettingMethod) {
        let mut on: Vec<VettingMethod> = self.methods.clone();
        if on.contains(&method) {
            on.retain(|m| *m != method);
        } else {
            on.push(method);
        }
        self.methods = METHOD_ORDER
            .into_iter()
            .filter(|m| on.contains(m))
            .collect();
    }

    /// The profile body, checked the way the community checks it.
    ///
    /// # Errors
    ///
    /// No method, a place without a country, a bad event, or anything
    /// `VetterProfileBody::check_shape` refuses.
    pub fn to_body(&self) -> Result<VetterProfileBody, DraftError> {
        if self.methods.is_empty() {
            return Err(DraftError::NoMethods);
        }
        let body = VetterProfileBody {
            listed: self.listed,
            display_name: optional(&self.display_name),
            languages: split_list(&self.languages),
            location: location("your location", &self.country, &self.region, &self.city)?,
            methods: self.methods.clone(),
            accepts_documentation: split_list(&self.accepts_documentation),
            availability: optional(&self.availability),
            contact_hint: optional(&self.contact_hint),
            events: self
                .events
                .iter()
                .map(EventDraft::to_event)
                .collect::<Result<_, _>>()?,
            ext: None,
        };
        body.check_shape()?;
        Ok(body)
    }
}

/// Directory filters, as typed. Empty means "any".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryFilter {
    pub language: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub method: Option<VettingMethod>,
    pub event_from: String,
    pub event_to: String,
    pub event_name: String,
}

impl DirectoryFilter {
    /// The list request for one page: `cursor` is the previous page's
    /// `nextCursor`, or `None` for the first.
    ///
    /// # Errors
    ///
    /// A date that does not parse, or anything `VetterListBody::check_shape`
    /// refuses — an end before the start, a country that is not two letters.
    pub fn to_body(&self, cursor: Option<String>) -> Result<VetterListBody, DraftError> {
        let body = VetterListBody {
            language: optional(&self.language),
            country: optional(&self.country).map(|c| c.to_uppercase()),
            region: optional(&self.region),
            city: optional(&self.city),
            method: self.method,
            event_from: optional(&self.event_from)
                .map(|d| date("the first event date", &d))
                .transpose()?,
            event_to: optional(&self.event_to)
                .map(|d| date("the last event date", &d))
                .transpose()?,
            event_name: optional(&self.event_name),
            limit: None,
            cursor,
            ext: None,
        };
        body.check_shape()?;
        Ok(body)
    }
}

/// Where a community stands on the profile we last sent it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ProfileState {
    /// Sent; no answer yet.
    Sent {
        /// When.
        sent_at: DateTime<Utc>,
    },
    /// Stored.
    Stored {
        /// Whether it lists us.
        listed: bool,
        /// When it stored the profile.
        updated_at: DateTime<Utc>,
    },
    /// Refused, e.g. `notEligible`.
    Refused {
        /// The error code.
        code: String,
        /// When the refusal arrived.
        at: DateTime<Utc>,
    },
}

/// The profile we last sent one community as one persona.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VetterProfileRecord {
    /// The community.
    pub community: String,
    /// Our member persona there.
    pub persona: PersonaId,
    /// The `VetterProfileBody` we sent, as JSON (see the module docs).
    pub profile: Value,
    /// Where it stands.
    pub state: ProfileState,
}

impl VetterProfileRecord {
    /// The profile, ready to edit. A record this build cannot read — written
    /// by a newer one — starts from a first profile rather than failing.
    #[must_use]
    pub fn draft(&self, policy: &VetterPolicy) -> ProfileDraft {
        serde_json::from_value::<VetterProfileBody>(self.profile.clone()).map_or_else(
            |_| ProfileDraft::new(policy),
            |b| ProfileDraft::from_body(&b),
        )
    }
}

impl VettingBook {
    /// The profile we last sent `community` as `persona`.
    #[must_use]
    pub fn vetter_profile(
        &self,
        community: &str,
        persona: PersonaId,
    ) -> Option<&VetterProfileRecord> {
        self.vetter_profiles
            .iter()
            .find(|r| r.community == community && r.persona == persona)
    }

    fn vetter_profile_mut(
        &mut self,
        community: &str,
        persona: PersonaId,
    ) -> Option<&mut VetterProfileRecord> {
        self.vetter_profiles
            .iter_mut()
            .find(|r| r.community == community && r.persona == persona)
    }

    /// Record `body` as sent. Returns the record it replaced, so a failed send
    /// can put it back ([`Self::restore_profile`]).
    pub fn record_profile_sent(
        &mut self,
        community: &str,
        persona: PersonaId,
        body: &VetterProfileBody,
        now: DateTime<Utc>,
    ) -> Option<VetterProfileRecord> {
        let record = VetterProfileRecord {
            community: community.to_string(),
            persona,
            profile: serde_json::to_value(body).unwrap_or(Value::Null),
            state: ProfileState::Sent { sent_at: now },
        };
        match self.vetter_profile_mut(community, persona) {
            Some(existing) => Some(std::mem::replace(existing, record)),
            None => {
                self.vetter_profiles.push(record);
                None
            }
        }
    }

    /// Undo [`Self::record_profile_sent`] after a send that never left.
    pub fn restore_profile(
        &mut self,
        community: &str,
        persona: PersonaId,
        previous: Option<VetterProfileRecord>,
    ) {
        self.vetter_profiles
            .retain(|r| !(r.community == community && r.persona == persona));
        self.vetter_profiles.extend(previous);
    }

    /// The community stored the profile. Returns whether a record changed.
    pub fn on_profile_stored(
        &mut self,
        community: &str,
        persona: PersonaId,
        response: &VetterProfileResponseBody,
    ) -> bool {
        match self.vetter_profile_mut(community, persona) {
            Some(record) => {
                record.state = ProfileState::Stored {
                    listed: response.listed,
                    updated_at: response.updated_at,
                };
                true
            }
            None => false,
        }
    }

    /// The community refused the profile. Returns whether a record changed.
    pub fn on_profile_refused(
        &mut self,
        community: &str,
        persona: PersonaId,
        code: &str,
        now: DateTime<Utc>,
    ) -> bool {
        match self.vetter_profile_mut(community, persona) {
            Some(record) => {
                record.state = ProfileState::Refused {
                    code: code.to_string(),
                    at: now,
                };
                true
            }
            None => false,
        }
    }
}

/// A place in a line: `Prague, Central Bohemia, CZ`.
#[must_use]
pub fn location_line(location: &VetterLocation) -> String {
    [
        location.city.as_deref(),
        location.region.as_deref(),
        Some(location.country.as_str()),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(", ")
}

/// An event in a line: `LPC — 2026-10-05 to 2026-10-07, Prague, CZ`.
#[must_use]
pub fn event_line(event: &VetterEvent) -> String {
    let dates = if event.start_date == event.end_date {
        event.start_date.format("%Y-%m-%d").to_string()
    } else {
        format!(
            "{} to {}",
            event.start_date.format("%Y-%m-%d"),
            event.end_date.format("%Y-%m-%d")
        )
    };
    match &event.location {
        Some(place) => format!("{} — {dates}, {}", event.name, location_line(place)),
        None => format!("{} — {dates}", event.name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> EventDraft {
        EventDraft {
            name: "Linux Plumbers".into(),
            start_date: "2026-10-05".into(),
            end_date: "2026-10-07".into(),
            country: "cz".into(),
            region: String::new(),
            city: "Prague".into(),
            url: "https://lpc.events".into(),
        }
    }

    #[test]
    fn a_first_profile_is_unlisted_and_accepts_what_the_vetter_already_accepts() {
        let policy = VetterPolicy::default();
        let draft = ProfileDraft::new(&policy);
        assert!(!draft.listed, "being listed is opt-in");
        let body = draft.to_body().unwrap();
        assert_eq!(body.accepts_documentation, policy.accepts_documentation);
        assert!(body.location.is_none());
    }

    #[test]
    fn typed_lists_and_places_become_the_body() {
        let mut draft = ProfileDraft::new(&VetterPolicy::default());
        draft.listed = true;
        draft.display_name = " Carol ".into();
        draft.languages = "en, de-AT en".into();
        draft.country = "de".into();
        draft.city = "Berlin".into();
        draft.events = vec![event()];
        let body = draft.to_body().unwrap();
        assert_eq!(body.display_name.as_deref(), Some("Carol"));
        assert_eq!(body.languages, vec!["en", "de-AT"]);
        assert_eq!(body.location.as_ref().unwrap().country, "DE");
        assert_eq!(body.events[0].location.as_ref().unwrap().country, "CZ");
        assert_eq!(ProfileDraft::from_body(&body).to_body().unwrap(), body);
    }

    #[test]
    fn event_dates_are_checked_before_anything_is_sent() {
        let mut bad = event();
        bad.start_date = "5 Oct".into();
        assert_eq!(bad.to_event(), Err(DraftError::Date("the start date")));

        let mut backwards = event();
        backwards.end_date = "2026-10-01".into();
        assert!(matches!(backwards.to_event(), Err(DraftError::Shape(_))));

        let mut too_long = event();
        too_long.end_date = "2026-11-30".into();
        assert!(matches!(too_long.to_event(), Err(DraftError::Shape(_))));

        let mut http = event();
        http.url = "http://lpc.events".into();
        assert!(matches!(http.to_event(), Err(DraftError::Shape(_))));
    }

    #[test]
    fn a_place_needs_a_country_and_a_method_is_required() {
        let mut draft = ProfileDraft::new(&VetterPolicy::default());
        draft.city = "Berlin".into();
        assert_eq!(
            draft.to_body(),
            Err(DraftError::LocationWithoutCountry("your location"))
        );
        let mut draft = ProfileDraft::new(&VetterPolicy::default());
        draft.toggle_method(VettingMethod::InPerson);
        draft.toggle_method(VettingMethod::Video);
        assert_eq!(draft.to_body(), Err(DraftError::NoMethods));
        draft.toggle_method(VettingMethod::PriorAcquaintance);
        draft.toggle_method(VettingMethod::InPerson);
        assert_eq!(
            draft.methods,
            vec![VettingMethod::InPerson, VettingMethod::PriorAcquaintance],
            "ticks keep a stable order"
        );
    }

    #[test]
    fn directory_filters_are_optional_and_checked() {
        assert_eq!(
            DirectoryFilter::default().to_body(None).unwrap(),
            VetterListBody::default()
        );
        let filter = DirectoryFilter {
            country: "cz".into(),
            event_from: "2026-10-01".into(),
            event_to: "2026-10-10".into(),
            ..DirectoryFilter::default()
        };
        let body = filter.to_body(Some("next".into())).unwrap();
        assert_eq!(body.country.as_deref(), Some("CZ"));
        assert!(body.has_event_filter());
        assert_eq!(body.cursor.as_deref(), Some("next"));

        let backwards = DirectoryFilter {
            event_from: "2026-10-10".into(),
            event_to: "2026-10-01".into(),
            ..DirectoryFilter::default()
        };
        assert!(matches!(backwards.to_body(None), Err(DraftError::Shape(_))));
        let bad_date = DirectoryFilter {
            event_to: "soon".into(),
            ..DirectoryFilter::default()
        };
        assert_eq!(
            bad_date.to_body(None),
            Err(DraftError::Date("the last event date"))
        );
    }

    #[test]
    fn the_last_profile_sent_is_kept_and_follows_the_communitys_answer() {
        let mut book = VettingBook::default();
        let persona = PersonaId::new();
        let now = Utc::now();
        let policy = VetterPolicy::default();
        let mut draft = ProfileDraft::new(&policy);
        draft.display_name = "Carol".into();
        let body = draft.to_body().unwrap();

        assert!(
            book.record_profile_sent("did:web:a", persona, &body, now)
                .is_none()
        );
        let record = book.vetter_profile("did:web:a", persona).unwrap();
        assert_eq!(
            record.draft(&policy),
            draft,
            "edited later from what was sent"
        );

        assert!(book.on_profile_stored(
            "did:web:a",
            persona,
            &VetterProfileResponseBody {
                listed: false,
                updated_at: now,
            }
        ));
        assert!(matches!(
            book.vetter_profile("did:web:a", persona).unwrap().state,
            ProfileState::Stored { listed: false, .. }
        ));

        // A second send that never left puts the stored one back.
        let previous = book.record_profile_sent("did:web:a", persona, &body, now);
        book.restore_profile("did:web:a", persona, previous);
        assert!(matches!(
            book.vetter_profile("did:web:a", persona).unwrap().state,
            ProfileState::Stored { .. }
        ));

        assert!(book.on_profile_refused("did:web:a", persona, "x:notEligible", now));
        assert!(!book.on_profile_refused("did:web:b", persona, "x:notEligible", now));

        let unreadable = VetterProfileRecord {
            community: "did:web:c".into(),
            persona,
            profile: serde_json::json!({ "listed": true, "fromTheFuture": 1 }),
            state: ProfileState::Sent { sent_at: now },
        };
        assert_eq!(unreadable.draft(&policy), ProfileDraft::new(&policy));
    }

    #[test]
    fn places_and_events_read_as_one_line() {
        let e = event().to_event().unwrap();
        assert_eq!(
            event_line(&e),
            "Linux Plumbers — 2026-10-05 to 2026-10-07, Prague, CZ"
        );
    }
}
