//! The vetter registry: a vetter's published profile, the directory applicants
//! search, and the forms both are typed into.
//!
//! A person types text; the community takes a `vetters/profile/0.1` payload or
//! a `vetters/list/0.1` one and refuses anything that breaks its schema. This module
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
use vta_sdk::protocols::vetting::vetters::list::v0_1 as list;
use vta_sdk::protocols::vetting::vetters::profile::v0_1::{
    self as profile, CalendarDate, CountryCode, LanguageTag, PlaceName, VetterAcceptsDocumentation,
    VetterEvent, VetterLocation, VetterMethods, VettingDocumentation,
};
use vta_sdk::protocols::vetting::{CheckShape, ShapeError, VettingMethod};

use super::book::{VetterPolicy, VettingBook};
use crate::config::account::PersonaId;

/// Why typed text is not yet a body the community would accept.
///
/// Every variant that can name the row it came from does, in the form's own
/// label for it, and [`row`](DraftError::row) hands that label back so the form
/// can put the cursor there. The labels are the strings in
/// `content::PROFILE_LABELS` and its two siblings; a label that matches no row
/// simply leaves the cursor where it was, so a mismatch reads as a message
/// without a jump rather than as a jump to the wrong row.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// A date is not `YYYY-MM-DD`. Carries the row's label.
    #[error("{0} must be a date written YYYY-MM-DD, like 2026-10-05")]
    Date(&'static str),
    /// A region or city without a country. Reported against the country row,
    /// because that is the row with something missing from it.
    #[error("Country: a region or city needs a country too — a two-letter code such as CZ")]
    LocationWithoutCountry,
    /// No method ticked.
    #[error("I vet: choose at least one way — in person, on video, or people you already know")]
    NoMethods,
    /// A country written as anything but a two-letter code.
    ///
    /// Its own variant rather than a [`Field`](DraftError::Field) carrying the
    /// schema's wording, because the schema's wording for this one is
    /// `doesn't match pattern "^[A-Z]{2}$"` — true, and no help at all to
    /// someone who wrote "USA" and has to work out that the rule wants "US".
    #[error("Country: write it as a two-letter code, like US or CZ — not the country's name")]
    Country,
    /// The community's schema refuses one field's value.
    #[error("{field}: the community would refuse this: {problem}")]
    Field {
        /// The row it came from, labelled as the form labels it.
        field: &'static str,
        /// What the published type or schema said about the value.
        problem: ShapeError,
    },
    /// One of the profile's events is not yet a body, wrapping the event
    /// form's own refusal.
    ///
    /// Kept apart from the refusal it carries because the two forms share row
    /// labels: an event's "Country" and the profile's "Country" are different
    /// rows, and a profile that resolved the inner label against its own rows
    /// would move the cursor to the wrong one. The profile knows which of its
    /// event rows this is — see [`event`](DraftError::event) — and the event's
    /// own rows are the event form's business.
    #[error("event {}: {source}", .index + 1)]
    Event {
        /// Which event, counted from zero as the profile holds them.
        index: usize,
        /// Why that event was refused.
        source: Box<DraftError>,
    },
    /// The community's schema refuses the payload as a whole — a rule about
    /// more than one field, so there is no single row to point at.
    #[error("the community would refuse this: {0}")]
    Shape(ShapeError),
}

impl DraftError {
    /// The label of the row this is about, for a form that wants to put the
    /// cursor on it. `None` when no single row is at fault — a rule spanning
    /// fields, or a value the client built rather than one that was typed.
    ///
    /// Naming the row in the message and moving the cursor to it are the same
    /// answer given twice, so they come from the same place: a message that
    /// says "Country:" cannot send the cursor somewhere else.
    #[must_use]
    pub fn row(&self) -> Option<&'static str> {
        match self {
            DraftError::Date(field) | DraftError::Field { field, .. } => Some(field),
            DraftError::LocationWithoutCountry | DraftError::Country => Some("Country"),
            DraftError::NoMethods => Some("I vet"),
            // An event's rows belong to the event form, not to the form
            // holding this error.
            DraftError::Event { .. } | DraftError::Shape(_) => None,
        }
    }

    /// Which of the profile's events this is about, for a form that lists them
    /// as rows of its own. `None` when it is not about an event.
    #[must_use]
    pub fn event(&self) -> Option<usize> {
        match self {
            DraftError::Event { index, .. } => Some(*index),
            _ => None,
        }
    }
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

/// A value the published type refuses outright — a place name past its bound, a
/// documentation token that is not lowerCamelCase, a display name too long. The
/// community refuses the same value, so it reads as a schema failure here too.
///
/// It is reported against `field`, the form's own label for the row it was
/// typed into. The schema's wording says what is wrong with the value but
/// never which value it was: a profile is thirteen rows and four of them are
/// free text, so "breaks its published schema" on its own leaves the person
/// re-reading all of them. The label is the only part of the sentence they can
/// act on.
fn refused<E: std::fmt::Display>(field: &'static str) -> impl Fn(E) -> DraftError {
    move |e| DraftError::Field {
        field,
        problem: ShapeError::Schema(e.to_string()),
    }
}

/// The payload as a whole was refused — a rule spanning fields, or a value this
/// client built rather than one that was typed. No row to name.
fn refused_payload(e: impl std::fmt::Display) -> DraftError {
    DraftError::Shape(ShapeError::Schema(e.to_string()))
}

fn place(field: &'static str, text: &str) -> Result<Option<PlaceName>, DraftError> {
    optional(text)
        .map(|t| PlaceName::try_from(t).map_err(refused(field)))
        .transpose()
}

/// The three location rows as one value. Both forms that have them label them
/// "Country" / "Region" / "City", so a refusal names the same row in either.
fn location(country: &str, region: &str, city: &str) -> Result<Option<VetterLocation>, DraftError> {
    match optional(country) {
        Some(country) => {
            let country =
                CountryCode::try_from(country.to_uppercase()).map_err(|_| DraftError::Country)?;
            let built = VetterLocation::try_from(
                VetterLocation::builder()
                    .country(country)
                    .region(place("Region", region)?)
                    .city(place("City", city)?),
            )
            .map_err(refused_payload)?;
            Ok(Some(built))
        }
        None if optional(region).is_some() || optional(city).is_some() => {
            Err(DraftError::LocationWithoutCountry)
        }
        None => Ok(None),
    }
}

/// Check one event the way the community checks it.
///
/// The published `VetterEvent` carries no check of its own: the rules no schema
/// can state — `endDate` on or after `startDate`, a span of at most 31 days —
/// and its `url` as an absolute https URI are checked over the whole profile.
/// The event form runs one event through a profile that carries only it, so a
/// bad date is still named while the form is open rather than at publish.
fn check_event(event: &VetterEvent) -> Result<(), DraftError> {
    let passport =
        VettingDocumentation::try_from(vta_sdk::protocols::vetting::documentation::PASSPORT)
            .map_err(refused_payload)?;
    let probe = profile::Payload::try_from(
        profile::Payload::builder()
            .listed(false)
            .languages(Vec::new())
            .methods(VetterMethods(vec![profile::VettingMethod::InPerson]))
            .accepts_documentation(VetterAcceptsDocumentation(vec![passport]))
            .events(vec![event.clone()]),
    )
    .map_err(refused_payload)?;
    probe.check_shape().map_err(DraftError::Shape)
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
            name: event.name.as_str().to_string(),
            start_date: event.start_date.0.format("%Y-%m-%d").to_string(),
            end_date: event.end_date.0.format("%Y-%m-%d").to_string(),
            country: place
                .map(|l| l.country.as_str().to_string())
                .unwrap_or_default(),
            region: place
                .and_then(|l| l.region.as_ref())
                .map(|r| r.as_str().to_string())
                .unwrap_or_default(),
            city: place
                .and_then(|l| l.city.as_ref())
                .map(|c| c.as_str().to_string())
                .unwrap_or_default(),
            url: event.url.clone().unwrap_or_default(),
        }
    }

    /// The event, checked the way the community checks it.
    ///
    /// # Errors
    ///
    /// A date that does not parse, a place without a country, or anything the
    /// event check refuses — an end before the start, a span over 31 days, a
    /// URL that is not an absolute `https` one.
    pub fn to_event(&self) -> Result<VetterEvent, DraftError> {
        let name = profile::VetterEventName::try_from(self.name.trim()).map_err(refused("Name"))?;
        let event = VetterEvent::try_from(
            VetterEvent::builder()
                .name(name)
                .start_date(CalendarDate(date("First day", &self.start_date)?))
                .end_date(CalendarDate(date("Last day", &self.end_date)?))
                .location(location(&self.country, &self.region, &self.city)?)
                .url(optional(&self.url)),
        )
        .map_err(refused_payload)?;
        check_event(&event)?;
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
    pub fn from_body(body: &profile::Payload) -> Self {
        let place = body.location.as_ref();
        let join = |items: Vec<String>| items.join(", ");
        Self {
            listed: body.listed,
            display_name: body
                .display_name
                .as_ref()
                .map(|n| n.as_str().to_string())
                .unwrap_or_default(),
            languages: join(
                body.languages
                    .iter()
                    .map(|l| l.as_str().to_string())
                    .collect(),
            ),
            country: place
                .map(|l| l.country.as_str().to_string())
                .unwrap_or_default(),
            region: place
                .and_then(|l| l.region.as_ref())
                .map(|r| r.as_str().to_string())
                .unwrap_or_default(),
            city: place
                .and_then(|l| l.city.as_ref())
                .map(|c| c.as_str().to_string())
                .unwrap_or_default(),
            methods: METHOD_ORDER
                .into_iter()
                .filter(|m| {
                    body.methods
                        .0
                        .iter()
                        .any(|published| published.to_string() == m.to_string())
                })
                .collect(),
            accepts_documentation: join(
                body.accepts_documentation
                    .0
                    .iter()
                    .map(|d| d.as_str().to_string())
                    .collect(),
            ),
            availability: body
                .availability
                .as_ref()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default(),
            contact_hint: body
                .contact_hint
                .as_ref()
                .map(|c| c.as_str().to_string())
                .unwrap_or_default(),
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
    /// No method, a place without a country, a bad event, or anything the
    /// published profile's `check_shape` refuses.
    pub fn to_body(&self) -> Result<profile::Payload, DraftError> {
        if self.methods.is_empty() {
            return Err(DraftError::NoMethods);
        }
        let languages = split_list(&self.languages)
            .into_iter()
            .map(|l| LanguageTag::try_from(l).map_err(refused("Languages")))
            .collect::<Result<Vec<_>, _>>()?;
        let documentation = split_list(&self.accepts_documentation)
            .into_iter()
            .map(|d| VettingDocumentation::try_from(d).map_err(refused("Documents I accept")))
            .collect::<Result<Vec<_>, _>>()?;
        // The profile task has its own copy of the method vocabulary (see
        // `super::same_token`), so the ticked methods are carried across by the
        // token they both spell.
        let methods = self
            .methods
            .iter()
            .map(|m| super::same_token::<_, profile::VettingMethod>(m).map_err(refused("I vet")))
            .collect::<Result<Vec<_>, _>>()?;
        let display_name = optional(&self.display_name)
            .map(|n| profile::VetterDisplayName::try_from(n).map_err(refused("Display name")))
            .transpose()?;
        let availability = optional(&self.availability)
            .map(|a| profile::VetterAvailability::try_from(a).map_err(refused("Availability")))
            .transpose()?;
        let contact_hint = optional(&self.contact_hint)
            .map(|c| {
                profile::VetterContactHint::try_from(c).map_err(refused("How to get a ticket"))
            })
            .transpose()?;
        let body = profile::Payload::try_from(
            profile::Payload::builder()
                .listed(self.listed)
                .display_name(display_name)
                .languages(languages)
                .location(location(&self.country, &self.region, &self.city)?)
                .methods(VetterMethods(methods))
                .accepts_documentation(VetterAcceptsDocumentation(documentation))
                .availability(availability)
                .contact_hint(contact_hint)
                .events(
                    self.events
                        .iter()
                        .enumerate()
                        .map(|(index, event)| {
                            event.to_event().map_err(|source| DraftError::Event {
                                index,
                                source: Box::new(source),
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
        )
        .map_err(refused_payload)?;
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
    /// A date that does not parse, or anything the published list request's
    /// `check_shape` refuses — an end before the start, a country that is not
    /// two letters.
    pub fn to_body(&self, cursor: Option<String>) -> Result<list::Payload, DraftError> {
        // The listing task carries its own copy of every constrained string —
        // `LanguageTag`, `CountryCode`, `PlaceName`, `CalendarDate` are all
        // generated per specification (see `super::same_token`) — so these are
        // the listing's, not the profile's.
        let list_place =
            |field: &'static str, text: &str| -> Result<Option<list::PlaceName>, DraftError> {
                optional(text)
                    .map(|t| list::PlaceName::try_from(t).map_err(refused(field)))
                    .transpose()
            };
        let language = optional(&self.language)
            .map(|l| list::LanguageTag::try_from(l).map_err(refused("Language")))
            .transpose()?;
        let country = optional(&self.country)
            .map(|c| list::CountryCode::try_from(c.to_uppercase()))
            .transpose()
            .map_err(|_| DraftError::Country)?;
        let event_name = optional(&self.event_name)
            .map(|n| list::PayloadEventName::try_from(n).map_err(refused("Event name")))
            .transpose()?;
        // Not a field on any form: the cursor is the previous page's, handed
        // straight back to the community.
        let cursor = cursor
            .map(|c| list::PayloadCursor::try_from(c).map_err(refused_payload))
            .transpose()?;
        // The listing task has its own copy of the method vocabulary.
        let method = self
            .method
            .map(|m| super::same_token::<_, list::VettingMethod>(&m).map_err(refused("Method")))
            .transpose()?;
        let day =
            |what: &'static str, text: &str| -> Result<Option<list::CalendarDate>, DraftError> {
                optional(text)
                    .map(|d| date(what, &d).map(list::CalendarDate))
                    .transpose()
            };
        let body = list::Payload::try_from(
            list::Payload::builder()
                .language(language)
                .country(country)
                .region(list_place("Region", &self.region)?)
                .city(list_place("City", &self.city)?)
                .method(method)
                .event_from(day("Events from", &self.event_from)?)
                .event_to(day("Events until", &self.event_to)?)
                .event_name(event_name)
                .cursor(cursor),
        )
        .map_err(refused_payload)?;
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
    /// The `vtc/vetting/vetters/profile/0.1` payload we sent, as JSON (see the
    /// module docs).
    pub profile: Value,
    /// Where it stands.
    pub state: ProfileState,
}

impl VetterProfileRecord {
    /// The profile, ready to edit. A record this build cannot read — written
    /// by a newer one — starts from a first profile rather than failing.
    #[must_use]
    pub fn draft(&self, policy: &VetterPolicy) -> ProfileDraft {
        serde_json::from_value::<profile::Payload>(self.profile.clone()).map_or_else(
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
        body: &profile::Payload,
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
        response: &profile::Response,
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
    place_line(
        location.city.as_ref().map(|c| c.as_str()),
        location.region.as_ref().map(|r| r.as_str()),
        location.country.as_str(),
    )
}

/// [`location_line`] for a place as the **listing** publishes it.
///
/// The listing specification generates its own `VetterLocation`, distinct from
/// the profile's (see `super::same_token`), so the same line is written from
/// both rather than one being converted into the other to be displayed.
#[must_use]
pub fn listed_location_line(location: &list::VetterLocation) -> String {
    place_line(
        location.city.as_ref().map(|c| c.as_str()),
        location.region.as_ref().map(|r| r.as_str()),
        location.country.as_str(),
    )
}

fn place_line(city: Option<&str>, region: Option<&str>, country: &str) -> String {
    [city, region, Some(country)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ")
}

/// An event in a line: `LPC — 2026-10-05 to 2026-10-07, Prague, CZ`.
#[must_use]
pub fn event_line(event: &VetterEvent) -> String {
    event_line_parts(
        event.name.as_str(),
        event.start_date.0,
        event.end_date.0,
        event.location.as_ref().map(location_line),
    )
}

/// [`event_line`] for an event as the **listing** publishes it, which generates
/// its own `VetterEvent`.
#[must_use]
pub fn listed_event_line(event: &list::VetterEvent) -> String {
    event_line_parts(
        event.name.as_str(),
        event.start_date.0,
        event.end_date.0,
        event.location.as_ref().map(listed_location_line),
    )
}

fn event_line_parts(name: &str, start: NaiveDate, end: NaiveDate, place: Option<String>) -> String {
    let dates = if start == end {
        start.format("%Y-%m-%d").to_string()
    } else {
        format!("{} to {}", start.format("%Y-%m-%d"), end.format("%Y-%m-%d"))
    };
    match place {
        Some(place) => format!("{name} — {dates}, {place}"),
        None => format!("{name} — {dates}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Whether a listing request filters on events at all is a free function on
    // this line rather than a method on the request.
    use vta_sdk::protocols::vetting::has_event_filter;

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
        let accepted: Vec<String> = body
            .accepts_documentation
            .0
            .iter()
            .map(|d| d.as_str().to_string())
            .collect();
        assert_eq!(accepted, policy.accepts_documentation);
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
        assert_eq!(
            body.display_name.as_ref().map(|n| n.as_str()),
            Some("Carol")
        );
        assert_eq!(
            body.languages
                .iter()
                .map(|l| l.as_str())
                .collect::<Vec<_>>(),
            vec!["en", "de-AT"]
        );
        assert_eq!(body.location.as_ref().unwrap().country.as_str(), "DE");
        assert_eq!(
            body.events[0].location.as_ref().unwrap().country.as_str(),
            "CZ"
        );
        // The generated payload has no `PartialEq`; a round trip is compared as
        // what it puts on the wire.
        assert_eq!(
            serde_json::to_value(ProfileDraft::from_body(&body).to_body().unwrap()).unwrap(),
            serde_json::to_value(&body).unwrap()
        );
    }

    #[test]
    fn event_dates_are_checked_before_anything_is_sent() {
        let mut bad = event();
        bad.start_date = "5 Oct".into();
        // The published event has no `PartialEq`, so the error is matched.
        assert!(matches!(bad.to_event(), Err(DraftError::Date("First day"))));

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

    /// Every refusal of a typed value names the row it came from, labelled the
    /// way the form labels it.
    ///
    /// The profile is thirteen rows, four of them free text, and the schema's
    /// own wording describes the value without ever identifying it: a country
    /// written "USA" was refused as `doesn't match pattern "^[A-Z]{2}$"`
    /// under a cursor sitting on "How to get a ticket", with nothing tying the
    /// two together. The label is the part of the sentence a person can act on.
    #[test]
    fn a_refusal_names_the_row_it_came_from() {
        let profile = |edit: fn(&mut ProfileDraft)| {
            let mut draft = ProfileDraft::new(&VetterPolicy::default());
            draft.toggle_method(VettingMethod::InPerson);
            edit(&mut draft);
            draft.to_body().unwrap_err().to_string()
        };

        // The one in hand: a country's name where a code belongs. It says the
        // rule, not the pattern the schema spells the rule with.
        let err = profile(|d| d.country = "USA".into());
        assert_eq!(
            err,
            "Country: write it as a two-letter code, like US or CZ — not the country's name"
        );
        assert_eq!(
            DraftError::Country.row(),
            Some("Country"),
            "the row the message names is the row the cursor is sent to"
        );

        for (row, edit) in [
            (
                "Languages",
                (|d: &mut ProfileDraft| d.languages = "english".into()) as fn(&mut ProfileDraft),
            ),
            ("Documents I accept", |d: &mut ProfileDraft| {
                d.accepts_documentation = "Passport!".into()
            }),
            ("Display name", |d: &mut ProfileDraft| {
                d.display_name = "x".repeat(500)
            }),
            ("City", |d: &mut ProfileDraft| {
                d.country = "de".into();
                d.city = "x".repeat(500);
            }),
        ] {
            let err = profile(edit);
            assert!(
                err.starts_with(&format!("{row}:")),
                "a refusal must name its row: {err}"
            );
        }

        // Nothing ticked names the row the ticks are on, so the cursor lands
        // where the fix is made rather than wherever it happened to be.
        assert_eq!(DraftError::NoMethods.row(), Some("I vet"));
        assert!(DraftError::NoMethods.to_string().starts_with("I vet:"));
        assert_eq!(DraftError::LocationWithoutCountry.row(), Some("Country"));

        // An event is its own form, with its own rows.
        let mut bad_name = event();
        bad_name.name = String::new();
        let err = bad_name.to_event().unwrap_err().to_string();
        assert!(err.starts_with("Name:"), "got: {err}");

        // And so is the directory filter.
        let err = DirectoryFilter {
            country: "Czechia".into(),
            ..DirectoryFilter::default()
        }
        .to_body(None)
        .unwrap_err();
        assert_eq!(err, DraftError::Country);
    }

    #[test]
    fn a_place_needs_a_country_and_a_method_is_required() {
        let mut draft = ProfileDraft::new(&VetterPolicy::default());
        draft.city = "Berlin".into();
        assert!(matches!(
            draft.to_body(),
            Err(DraftError::LocationWithoutCountry)
        ));
        let mut draft = ProfileDraft::new(&VetterPolicy::default());
        draft.toggle_method(VettingMethod::InPerson);
        draft.toggle_method(VettingMethod::Video);
        assert!(matches!(draft.to_body(), Err(DraftError::NoMethods)));
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
        // Every filter empty is every member absent, which is the whole of an
        // unfiltered listing request.
        assert_eq!(
            serde_json::to_value(DirectoryFilter::default().to_body(None).unwrap()).unwrap(),
            serde_json::json!({})
        );
        let filter = DirectoryFilter {
            country: "cz".into(),
            event_from: "2026-10-01".into(),
            event_to: "2026-10-10".into(),
            ..DirectoryFilter::default()
        };
        let body = filter.to_body(Some("next".into())).unwrap();
        assert_eq!(body.country.as_ref().map(|c| c.as_str()), Some("CZ"));
        assert!(has_event_filter(&body));
        assert_eq!(body.cursor.as_ref().map(|c| c.as_str()), Some("next"));

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
        assert!(matches!(
            bad_date.to_body(None),
            Err(DraftError::Date("Events until"))
        ));
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

        let stored =
            profile::Response::try_from(profile::Response::builder().listed(false).updated_at(now))
                .unwrap();
        assert!(book.on_profile_stored("did:web:a", persona, &stored));
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
