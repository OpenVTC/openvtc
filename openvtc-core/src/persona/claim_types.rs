//! What a claim type says about showing its own value — **read from the agent**,
//! with a compiled copy kept only for an agent too old to serve one.
//!
//! Source of truth on the wire: `persona/claim-types/list/1.0`, served since
//! VTI #1315. The reasoning behind the table itself lives beside it in
//! `dtgwg-trust-tasks-tf/specs/persona/_shared/0.1/CLAIM-TYPES.md`.
//!
//! # Why this stopped being vendored
//!
//! This module used to carry a copy of the registry, and the copy was
//! *correct*. That was never the problem. The problem is that a copy of a table
//! two other repositories own costs a re-sync against each of them on every
//! change — which is the argument for the registry existing at all, applied one
//! layer down — and, since VTI #1327, that a **deployment may declare its own
//! claim types**. An agent serving an extension token is invisible to a client
//! that ships its own table, and the divergence is silent: the token resolves
//! from the compiled copy exactly as it would have with no configuration at
//! all, so the operator's intended tightening is quietly not in force and the
//! screen looks completely normal.
//!
//! That is the shape of the `employer` / `profile.*` masking divergence this
//! module was carrying: our copy matched spec 0.1 exactly, and 0.1 simply has
//! no entry for either.
//!
//! # The compiled copy that remains
//!
//! [`Registry::vendored`] is spec 0.1, and it is reached in exactly one case:
//! the agent answered `persona/claim-types/list` with
//! `VtaError::UnsupportedTaskType`, meaning it is older than this client. Every
//! other failure — the network, the ACL, a malformed body — is returned as an
//! error, because a fallback that also covers "we could not ask" is a fallback
//! that hides an outage behind a plausible screen. [`Registry::is_fallback`]
//! says which one the caller got, and the pane says so too: a masking decision
//! taken from a table the holder's own agent did not supply is worth one line
//! of screen.
//!
//! # This is not a security control, and it must not be described as one
//!
//! Masking here happens *after* the value has been fetched, decrypted by the
//! agent, sent over DIDComm and parked in this process's memory. Everything
//! that could read it before still can. What it defends against is a person
//! reading the terminal over a shoulder, and a screenshot or a screen share
//! carrying a card number to an audience that was never asked.
//!
//! # Masking is the half of the registry this client can honour
//!
//! §3.3 makes `mask` and `sensitivity` two decisions, not one, and they land in
//! two different places:
//!
//! - **`mask`** is a rendering. Any type whose style is not `none` is shown
//!   reduced, whatever its sensitivity — which is why `email.work` is masked
//!   despite being `normal`. An address is worth hiding from the person behind
//!   you without being worth withholding from every listing.
//! - **`sensitivity: high`** means the value is *withheld from a listing that
//!   did not explicitly ask for sensitive values* — a read-path control, not a
//!   cosmetic one. It exists on the wire (`persona_attribute_list`'s
//!   `include_sensitive`), and this pane still has one escalation where the
//!   control needs two. See `pool::list`.
//!
//! `release` is carried but not acted on: nothing in this client releases
//! anything. It is read so that a caller can *say* what a type would require,
//! which is the half a holder can act on.

use std::collections::BTreeSet;

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::trust_tasks;

use crate::errors::OpenVTCError;

/// Round-trip budget for the registry read, in seconds.
///
/// The same 30s every other persona task gets (VTI R1.2 — an outbound call
/// without a finite timeout turns a hung service into a hung command). This one
/// is a pure local-store read at the agent, so the budget is generous rather
/// than tuned.
const REGISTRY_TIMEOUT: u64 = 30;

/// The namespace the registry leaves open, and never resolves through a family.
const EXTENSION_PREFIX: &str = "x:";

/// The reverse-DNS `ext` key the agent reports its own configuration under.
/// Kept in lockstep with `vta-service`'s `handle_claim_types_list` and with the
/// console's `EXT_KEY_CLAIM_TYPES`.
const EXT_KEY_CLAIM_TYPES: &str = "org.openvtc.claim-types";

/// How carefully a value is shown **to its own holder**.
///
/// Not linkability, and not what it takes to release the value — §3 keeps those
/// three apart because a mechanism that reads one as a proxy for another hides
/// the wrong things and warns about the wrong things. A payment card is highly
/// sensitive and barely linkable; a nickname can be the reverse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sensitivity {
    /// Nothing beyond whatever [`MaskStyle`] the type carries.
    #[default]
    Normal,
    /// Additionally withheld from a listing that did not ask for sensitive
    /// values. See the module header.
    High,
}

impl Sensitivity {
    /// Read a served token. An unrecognised one is treated as
    /// [`High`](Sensitivity::High), the protective answer: a client that reads
    /// an unknown sensitivity as `normal` has quietly widened a listing the
    /// maintainer narrowed.
    fn from_wire(token: &str) -> Self {
        match token {
            "normal" => Self::Normal,
            _ => Self::High,
        }
    }
}

/// How a value is reduced when it is shown masked. The styles, and their
/// wording, are `claim-types.json`'s `maskStyles`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MaskStyle {
    /// Shown in full. The value is not one a shoulder can steal.
    #[default]
    None,
    /// Final two characters shown; everything before them replaced.
    Last2,
    /// Final four characters shown; everything before them replaced.
    Last4,
    /// First character of the local part, then the domain in full.
    EmailLocal,
    /// No characters shown.
    Full,
}

/// The bullet a replaced character is drawn as. `*` reads as a footnote and `x`
/// as data; `•` is neither, and is what every other masked field in the
/// ecosystem uses.
const BULLET: char = '•';

/// Width of a fully masked value.
///
/// Fixed, rather than one bullet per character held: the length of a passport
/// number or a date of birth is itself a hint, and a mask that leaks it has
/// given away the one thing the style exists to withhold. It also keeps a
/// column stable while the holder pages down a list.
const FULL_MASK_WIDTH: usize = 8;

impl MaskStyle {
    /// Read a served token.
    ///
    /// An unrecognised style becomes [`Full`](MaskStyle::Full), which the
    /// schema states as a MUST: a maintainer may serve a style this build has
    /// never heard of, and the only safe reading of "I do not know how to
    /// reduce this" is "do not show it". Reading it as `none` would show in the
    /// clear precisely the values a maintainer had just decided to reduce.
    ///
    /// Note that this collapses *rendering* only. Strictness comparison uses
    /// the served ordering and the token as written, so an unknown style the
    /// agent ranks as looser than `full` still compares at its true position —
    /// see [`Registry::resolve`].
    fn from_wire(token: &str) -> Self {
        match token {
            "none" => Self::None,
            "last2" => Self::Last2,
            "last4" => Self::Last4,
            "emailLocal" => Self::EmailLocal,
            _ => Self::Full,
        }
    }

    /// Reduce `text` to the form this style shows.
    ///
    /// Every style falls back to [`Full`](MaskStyle::Full) rather than to the
    /// clear text when the value does not have the shape the style assumes —
    /// a `last4` over three characters, an `emailLocal` over something with no
    /// `@`. The alternative is a mask that silently stops masking on exactly
    /// the values it was misapplied to.
    #[must_use]
    pub fn apply(self, text: &str) -> String {
        let full = || BULLET.to_string().repeat(FULL_MASK_WIDTH);
        match self {
            Self::None => text.to_string(),
            Self::Full => full(),
            Self::Last2 | Self::Last4 => {
                let keep = if self == Self::Last2 { 2 } else { 4 };
                let chars: Vec<char> = text.chars().collect();
                // Strictly longer, not "at least": a four-character value under
                // `last4` would be shown whole by a rule that says it is masked.
                if chars.len() <= keep {
                    return full();
                }
                let tail: String = chars[chars.len() - keep..].iter().collect();
                format!("{}{tail}", BULLET.to_string().repeat(chars.len() - keep))
            }
            Self::EmailLocal => match text.split_once('@') {
                // The domain is what makes an address recognisable to its
                // owner; the local part is what makes it usable to anyone else.
                Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
                    let first = local.chars().next().unwrap_or(BULLET);
                    format!("{first}{}@{domain}", BULLET.to_string().repeat(3))
                }
                _ => full(),
            },
        }
    }

    /// Whether showing a value through this style actually withholds anything.
    #[must_use]
    pub fn hides_anything(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// What it takes to let a value leave — `release` in the registry's words.
///
/// Carried, not enforced: nothing in this client releases anything. It is here
/// so a pane can *say* which attributes the holder's agent will stop and ask
/// about, which is a fact about the holder's own arrangement and one they can
/// act on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Release {
    /// Approved once, before it goes.
    #[default]
    Consent,
    /// Asked again, on the holder's own device, every single time.
    StepUp,
}

impl Release {
    /// Read a served token, defaulting to the protective answer for the same
    /// reason [`Sensitivity::from_wire`] does.
    fn from_wire(token: &str) -> Self {
        match token {
            "consent" => Self::Consent,
            _ => Self::StepUp,
        }
    }

    /// The words this requirement wears on screen
    /// (`design-docs/persona-vocabulary.md`, *letting it leave*).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Consent => "you approve it once, before it goes",
            Self::StepUp => "your agent asks you again, every single time",
        }
    }
}

/// What one claim type says about showing and releasing its value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClaimTypeDefaults {
    pub sensitivity: Sensitivity,
    pub mask: MaskStyle,
    pub release: Release,
}

impl ClaimTypeDefaults {
    /// Whether a value of this type is shown masked by default.
    ///
    /// The style alone decides, per §3.3 — a `high` type reaches this through
    /// its style like any other. Reading `sensitivity` as the trigger is the
    /// tangle the registry's first draft had and its second draft names: it
    /// left `email.*` carrying an `emailLocal` style that no rule could ever
    /// apply, while §1 used `a•••@example.com` to motivate the registry.
    #[must_use]
    pub fn masks_by_default(self) -> bool {
        self.mask.hides_anything()
    }

    /// The value as this type shows it — masked when the type asks for it.
    #[must_use]
    pub fn render(self, text: &str) -> String {
        if self.masks_by_default() {
            self.mask.apply(text)
        } else {
            text.to_string()
        }
    }
}

/// One row of the served table, as written.
///
/// The wire tokens are kept rather than parsed straight to enums, because
/// strictness comparison happens against the agent's own ordering and a token
/// this build does not recognise still has a true position in it.
#[derive(Clone, Debug)]
struct Entry {
    claim_type: String,
    sensitivity: String,
    mask: String,
    release: String,
}

/// One axis's ordering, most protective first.
#[derive(Clone, Debug, Default)]
struct Axis(Vec<String>);

impl Axis {
    /// Position of a token in this ordering, if it places it at all.
    fn rank(&self, token: &str) -> Option<usize> {
        self.0.iter().position(|t| t == token)
    }

    /// The more protective of a registered prefix's answer and the floor's.
    ///
    /// Asymmetric on purpose — the two arguments are not interchangeable, and
    /// naming them is what keeps the fallback honest. When the ordering does
    /// not place **both** tokens it cannot say which is more protective, and
    /// the answer is the floor: it is the one that shows less, and a tie-break
    /// that reached for the prefix instead would let a family *loosen* the
    /// floor on an ordering the agent never sent. That is precisely the
    /// direction §4 says must never happen, and it is the direction that fails
    /// quietly — an unregistered `name.somethingNew` inheriting `name`'s `none`
    /// is a value shown in the clear that no table said to show.
    fn stricter<'a>(&self, prefix: &'a str, floor: &'a str) -> &'a str {
        match (self.rank(prefix), self.rank(floor)) {
            (Some(p), Some(f)) if p <= f => prefix,
            _ => floor,
        }
    }
}

/// One claim type this deployment declared and its agent would not apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnappliedClaimType {
    /// The token as the operator's file spelled it.
    pub claim_type: String,
    /// The agent's reason, in its words.
    pub reason: String,
}

/// What the agent could not apply from its own claim-type configuration.
///
/// **Why a client reads this at all.** A refused row is otherwise invisible:
/// the token resolves from the core table exactly as it would with no file, so
/// an operator's intended tightening is quietly not in force and the screen
/// looks completely normal. The agent reports its refusals precisely so
/// somebody can be told, and this is the half that tells them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnappliedReport {
    pub rejected: Vec<UnappliedClaimType>,
    /// Set when the extension file itself could not be read — a different
    /// sentence from a rejected row, because then *nothing* the deployment
    /// declared is in force.
    pub file_error: Option<String>,
}

impl UnappliedReport {
    /// Whether there is anything here worth saying on screen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rejected.is_empty() && self.file_error.is_none()
    }
}

/// The claim-type registry this agent resolves against.
///
/// Held for the life of a session and keyed on
/// [`registry_version`](Registry::registry_version); it is a constant for a
/// given agent. It **must not** be carried across agents: two agents may
/// declare different extension types, and a table from one applied to the other
/// resolves tokens it has never heard of.
#[derive(Clone, Debug)]
pub struct Registry {
    /// Version of the core registry the agent implements — the version of
    /// `claim-types.json`, not of the task.
    pub registry_version: String,
    /// True when this is [`Registry::vendored`] rather than the agent's answer.
    pub is_fallback: bool,
    /// What the deployment declared and the agent refused.
    pub unapplied: UnappliedReport,
    entries: Vec<Entry>,
    unregistered: Entry,
    sensitivity_order: Axis,
    mask_order: Axis,
    release_order: Axis,
}

impl Default for Registry {
    /// The compiled copy. A [`Registry`] is only ever *default* before the
    /// first read has come back, and drawing from spec 0.1 in that window is
    /// the same answer this client gave for its whole life until now.
    fn default() -> Self {
        Self::vendored()
    }
}

impl Registry {
    /// Read the agent's claim-type registry.
    ///
    /// Returns [`vendored`](Registry::vendored) — flagged
    /// [`is_fallback`](Registry::is_fallback) — only when the agent says it
    /// does not serve the task, which means it predates VTI #1315. Every other
    /// failure is an error: a fallback that also covered "we could not ask"
    /// would draw a plausible screen over an outage, and the holder would have
    /// no way to tell a masking decision their agent made from one this binary
    /// invented (VTI R6.4).
    pub async fn fetch(client: &VtaClient) -> Result<Self, OpenVTCError> {
        // The payload is empty by schema, and the agent gates the task as
        // reachable by any authenticated caller precisely so the holder's own
        // tooling — which has no trust context to name — can read it.
        match client
            .dispatch_trust_task(
                trust_tasks::TASK_PERSONA_CLAIM_TYPES_LIST_1_0,
                serde_json::json!({}),
                REGISTRY_TIMEOUT,
            )
            .await
        {
            Ok(value) => Ok(Self::from_wire(&value)),
            Err(VtaError::UnsupportedTaskType { .. }) => Ok(Self::vendored()),
            Err(e) => Err(OpenVTCError::Vta(format!(
                "persona claim-types list failed: {e}"
            ))),
        }
    }

    /// Parse a served response.
    ///
    /// Read member by member and defensively: a missing ordering leaves the
    /// axis unable to place either token, which [`Axis::stricter`] resolves to
    /// the floor — degraded, but degraded towards showing less.
    ///
    /// `pub(crate)` for [`family`](crate::persona::family)'s tests, which need
    /// a table declaring a root this build has no words for and cannot get one
    /// from the compiled copy by construction.
    pub(crate) fn from_wire(value: &Value) -> Self {
        let entries = value
            .get("entries")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().filter_map(Entry::from_wire).collect())
            .unwrap_or_default();

        let unregistered = value
            .get("unregistered")
            .map_or_else(Entry::conservative_floor, Entry::floor_from_wire);

        let axis = |name: &str| {
            Axis(
                value
                    .get("strictness")
                    .and_then(|s| s.get(name))
                    .and_then(Value::as_array)
                    .map(|xs| {
                        xs.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
            )
        };

        Self {
            registry_version: value
                .get("registryVersion")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            is_fallback: false,
            unapplied: unapplied_from_ext(value),
            entries,
            unregistered,
            sensitivity_order: axis("sensitivity"),
            mask_order: axis("mask"),
            release_order: axis("release"),
        }
    }

    /// Resolve a claim type to how its value is shown — §4, minus the rule this
    /// client cannot reach.
    ///
    /// 1. Rule 1 — a holder's explicit override — is **not implemented, because
    ///    there is nowhere to store one.** `persona/attribute/put` has no
    ///    `sensitivity` or `mask` member, so the choice the rule resolves first
    ///    cannot currently be made. When it can, it belongs above everything
    ///    here.
    /// 2. Rule 4 is taken first among the rest: `x:` is unregistered *by
    ///    construction*, so it borrows neither an entry nor a family however
    ///    much of a registered token it happens to spell.
    /// 3. An exact entry is used **as written**, and is not compared against
    ///    anything: it is a decision someone made about that token.
    /// 4. Otherwise the longest registered *proper* prefix, on dot boundaries,
    ///    is taken together with the floor and the more protective of the two
    ///    wins on each axis. A family entry can therefore only ever tighten —
    ///    `name` as a prefix does not make an unregistered `name.somethingNew`
    ///    visible, while `payment.giftCard` still inherits `payment`'s gating.
    /// 5. Otherwise the floor.
    ///
    /// Rule 4's tightening direction is the one that fails quietly. Without it
    /// `payment.giftCard` resolves to a floor whose `release` is weaker than
    /// every registered member of the family it plainly belongs to, and a gated
    /// family becomes leavable by inventing a token.
    #[must_use]
    pub fn resolve(&self, claim_type: &str) -> ClaimTypeDefaults {
        let floor = &self.unregistered;

        if claim_type.starts_with(EXTENSION_PREFIX) {
            return floor.defaults();
        }

        if let Some(exact) = self.exact(claim_type) {
            return exact.defaults();
        }

        let Some(prefix) = self.longest_registered_prefix(claim_type) else {
            return floor.defaults();
        };

        ClaimTypeDefaults {
            sensitivity: Sensitivity::from_wire(
                self.sensitivity_order
                    .stricter(&prefix.sensitivity, &floor.sensitivity),
            ),
            mask: MaskStyle::from_wire(self.mask_order.stricter(&prefix.mask, &floor.mask)),
            release: Release::from_wire(
                self.release_order.stricter(&prefix.release, &floor.release),
            ),
        }
    }

    /// Whether the registry **declares** this token, or a family it belongs to.
    ///
    /// The same walk [`resolve`](Registry::resolve) performs, asked as a
    /// question: the floor and a declared entry are different kinds of answer,
    /// and a pane that groups by family needs to tell them apart. An `x:` token
    /// is never registered, per §4's last rule.
    #[must_use]
    pub fn is_registered(&self, claim_type: &str) -> bool {
        !claim_type.starts_with(EXTENSION_PREFIX)
            && (self.exact(claim_type).is_some()
                || self.longest_registered_prefix(claim_type).is_some())
    }

    /// The first segment of every registered token — the roots a pane may group
    /// by.
    ///
    /// Read from the table rather than from a compiled list, so a family the
    /// agent knows and this build does not still groups.
    #[must_use]
    pub fn registered_roots(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter_map(|e| e.claim_type.split('.').next())
            .map(str::to_string)
            .collect()
    }

    fn exact(&self, claim_type: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.claim_type == claim_type)
    }

    /// The longest registered ancestor of a token, on `.` boundaries.
    ///
    /// Boundaries matter, and it is a *proper* prefix: `paymentx.foo` is not in
    /// the `payment` family, and a plain `starts_with` would put it there.
    fn longest_registered_prefix(&self, claim_type: &str) -> Option<&Entry> {
        let mut cut = claim_type.len();
        while let Some(dot) = claim_type[..cut].rfind('.') {
            if let Some(entry) = self.exact(&claim_type[..dot]) {
                return Some(entry);
            }
            cut = dot;
        }
        None
    }

    /// Spec 0.1, compiled in — the answer for an agent that predates
    /// `persona/claim-types/list`, and nothing else. See the module header.
    #[must_use]
    pub fn vendored() -> Self {
        // `claim-types.json`'s order, so the two diff against each other by eye.
        const TABLE: &[(&str, &str, &str, &str)] = &[
            // Family entries, matched as prefixes. Without them
            // `payment.somethingNew` resolves to the floor, and a gated family
            // becomes leavable by inventing a token. `name` is also an exact
            // token: a pool that keeps one undifferentiated name is using it.
            ("payment", "high", "full", "stepUp"),
            ("gov", "high", "full", "stepUp"),
            ("name", "normal", "none", "consent"),
            ("name.legal", "normal", "none", "consent"),
            ("name.given", "normal", "none", "consent"),
            ("name.family", "normal", "none", "consent"),
            ("name.display", "normal", "none", "consent"),
            // A former name is the one a holder most often keeps in order to
            // answer a question once and never show again.
            ("name.previous", "high", "full", "consent"),
            ("person.birthDate", "high", "full", "consent"),
            ("person.pronouns", "normal", "none", "consent"),
            ("person.locale", "normal", "none", "consent"),
            ("email.personal", "normal", "emailLocal", "consent"),
            ("email.work", "normal", "emailLocal", "consent"),
            // High because a mobile number is both a strong join key and an
            // authentication factor: its harm is account takeover, not
            // embarrassment.
            ("phone.mobile", "high", "last2", "consent"),
            ("phone.landline", "high", "last2", "consent"),
            ("address.postal", "high", "full", "consent"),
            ("address.country", "normal", "none", "consent"),
            ("gov.id.passport", "high", "last4", "stepUp"),
            ("gov.id.driverLicence", "high", "last4", "stepUp"),
            ("gov.id.national", "high", "last4", "stepUp"),
            ("gov.taxId", "high", "last4", "stepUp"),
            ("payment.card", "high", "last4", "stepUp"),
            ("payment.cardExpiry", "high", "full", "stepUp"),
            ("payment.iban", "high", "last4", "stepUp"),
            ("payment.accountNumber", "high", "last4", "stepUp"),
            ("account.handle", "normal", "none", "consent"),
            ("url.homepage", "normal", "none", "consent"),
            ("org.name", "normal", "none", "consent"),
            ("org.role", "normal", "none", "consent"),
        ];

        let order = |xs: &[&str]| Axis(xs.iter().map(|s| (*s).to_string()).collect());

        Self {
            registry_version: "0.1".to_string(),
            is_fallback: true,
            unapplied: UnappliedReport::default(),
            entries: TABLE
                .iter()
                .map(|(claim_type, sensitivity, mask, release)| Entry {
                    claim_type: (*claim_type).to_string(),
                    sensitivity: (*sensitivity).to_string(),
                    mask: (*mask).to_string(),
                    release: (*release).to_string(),
                })
                .collect(),
            unregistered: Entry::conservative_floor(),
            sensitivity_order: order(&["high", "normal"]),
            mask_order: order(&["full", "last2", "last4", "emailLocal", "none"]),
            release_order: order(&["stepUp", "consent"]),
        }
    }
}

impl Entry {
    fn from_wire(value: &Value) -> Option<Self> {
        Some(Self {
            claim_type: value.get("type").and_then(Value::as_str)?.to_string(),
            sensitivity: read_token(value, "sensitivity", "high"),
            mask: read_token(value, "mask", "full"),
            release: read_token(value, "release", "stepUp"),
        })
    }

    /// The served floor, which carries no `type` of its own.
    fn floor_from_wire(value: &Value) -> Self {
        Self {
            claim_type: String::new(),
            sensitivity: read_token(value, "sensitivity", "high"),
            mask: read_token(value, "mask", "full"),
            release: read_token(value, "release", "stepUp"),
        }
    }

    /// The floor when the agent supplied none: the conservative answer, and
    /// §4's rule 4. A vocabulary nobody has reasoned about is exactly the one
    /// nothing is known about, and an unknown value rendered in the clear is a
    /// decision nobody made.
    fn conservative_floor() -> Self {
        Self {
            claim_type: String::new(),
            sensitivity: "high".to_string(),
            mask: "full".to_string(),
            release: "consent".to_string(),
        }
    }

    fn defaults(&self) -> ClaimTypeDefaults {
        ClaimTypeDefaults {
            sensitivity: Sensitivity::from_wire(&self.sensitivity),
            mask: MaskStyle::from_wire(&self.mask),
            release: Release::from_wire(&self.release),
        }
    }
}

/// One axis token off a served object, defaulting to the protective answer when
/// the member is missing or is not a string.
fn read_token(value: &Value, member: &str, fallback: &str) -> String {
    value
        .get(member)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

/// Read the agent's own refusals out of the response's `ext`.
///
/// Member by member and defensively, because `ext` is a vendor-namespaced
/// object the schema does not constrain, so nothing upstream has checked its
/// shape. A malformed report is dropped rather than rendered: a banner built
/// from a missing field is a second fault reported as the first.
fn unapplied_from_ext(value: &Value) -> UnappliedReport {
    let Some(report) = value.get("ext").and_then(|e| e.get(EXT_KEY_CLAIM_TYPES)) else {
        return UnappliedReport::default();
    };

    UnappliedReport {
        rejected: report
            .get("rejected")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(UnappliedClaimType {
                            claim_type: row.get("type").and_then(Value::as_str)?.to_string(),
                            reason: row
                                .get("reason")
                                .and_then(Value::as_str)
                                .unwrap_or("no reason given")
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        file_error: report
            .get("fileError")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every resolution test below runs against the compiled copy, which is
    /// spec 0.1 — the same table this module used to *be*. Keeping the
    /// assertions is what says the fallback did not quietly change meaning when
    /// it stopped being the only answer.
    fn spec_0_1() -> Registry {
        Registry::vendored()
    }

    /// The floor, asked for by resolving something nothing declares. Written as
    /// a question rather than as a constant so the served and compiled tables
    /// can both be checked against their own floor.
    fn floor(registry: &Registry) -> ClaimTypeDefaults {
        registry.resolve("nothing.registered.here")
    }

    /// The registered types resolve to what the table says, including the two
    /// that are `high` without being `full` — the styles exist so a holder can
    /// still recognise their own card and their own number.
    #[test]
    fn registered_types_resolve_to_their_entry() {
        let r = spec_0_1();
        assert_eq!(r.resolve("name.legal").sensitivity, Sensitivity::Normal);
        assert_eq!(r.resolve("phone.mobile").mask, MaskStyle::Last2);
        assert!(r.resolve("gov.id.passport").masks_by_default());
        assert!(!r.resolve("org.role").masks_by_default());
        // An exact entry is used as written and is not compared against its
        // family: `payment.card` shows its last four even though the `payment`
        // family entry is `full`. Someone decided that about that token.
        assert_eq!(r.resolve("payment.card").mask, MaskStyle::Last4);
    }

    /// An unregistered token with no registered family gets the conservative
    /// answer.
    ///
    /// This is the case the floor exists for: a build that has never heard of a
    /// vocabulary knows nothing about what it holds, and showing it in the
    /// clear would be a decision nobody made.
    #[test]
    fn an_unknown_type_masks_fully() {
        let r = spec_0_1();
        for token in ["medical.condition", "", "somethingElse"] {
            let resolved = r.resolve(token);
            assert_eq!(resolved.sensitivity, Sensitivity::High, "{token}");
            assert_eq!(resolved.mask, MaskStyle::Full, "{token}");
        }
    }

    /// A new token in a gated family inherits the family, not the floor.
    ///
    /// Without this a gated family is leavable by inventing a token:
    /// `payment.giftCard` would resolve to the unregistered default, whose
    /// `release` is weaker than every registered member of the family it
    /// plainly belongs to.
    #[test]
    fn a_new_token_inherits_its_registered_family() {
        let r = spec_0_1();
        assert_eq!(r.resolve("payment.giftCard"), r.resolve("payment"));
        assert_eq!(r.resolve("gov.id.somethingNew").mask, MaskStyle::Full);
        assert_eq!(r.resolve("payment.giftCard").release, Release::StepUp);
    }

    /// A family can only tighten. `name` is `normal`/`none`, and an unknown
    /// `name.*` still lands on the floor rather than being shown in the clear
    /// on the strength of its prefix.
    #[test]
    fn a_family_never_loosens_the_floor() {
        let r = spec_0_1();
        assert_eq!(r.resolve("name.somethingNew"), floor(&r));
        // …while the family token itself, being an exact entry, is used as
        // written.
        assert_eq!(r.resolve("name").mask, MaskStyle::None);
    }

    /// A prefix is a prefix on `.` boundaries. `paymentx` is not in the
    /// `payment` family, and a plain `starts_with` would put it there.
    #[test]
    fn a_family_matches_on_segment_boundaries() {
        let r = spec_0_1();
        assert_eq!(r.resolve("paymentx.token"), floor(&r));
        assert_eq!(r.resolve("governance.role"), floor(&r));
        assert!(!r.is_registered("paymentx.token"));
    }

    /// The open namespace never inherits a family: `x:payment.card` is a token
    /// this registry has never seen that happens to read like one it has.
    #[test]
    fn an_extension_token_never_inherits() {
        let r = spec_0_1();
        for token in ["x:employer.badge", "x:payment.card", "x:name.given"] {
            assert_eq!(r.resolve(token), floor(&r), "{token}");
            assert!(!r.is_registered(token), "{token}");
        }
    }

    /// The style masks whatever the sensitivity says. `email.work` is `normal`
    /// and masked, which is §3.3's whole point: an address is worth hiding from
    /// the person behind you without being worth withholding from a listing.
    #[test]
    fn a_normal_type_is_masked_by_its_style() {
        let email = spec_0_1().resolve("email.work");
        assert_eq!(email.sensitivity, Sensitivity::Normal);
        assert!(email.masks_by_default());
        assert_eq!(email.render("alice@example.com"), "a•••@example.com");
    }

    /// …and a `normal` type with no style is shown as it is held. Masking
    /// everything would teach the reveal as a reflex, and a reveal pressed by
    /// reflex protects nothing.
    #[test]
    fn a_type_with_no_style_is_shown_whole() {
        let name = spec_0_1().resolve("name.given");
        assert!(!name.masks_by_default());
        assert_eq!(name.render("Alice"), "Alice");
    }

    /// Each style keeps exactly the characters it says it keeps.
    #[test]
    fn each_style_keeps_what_it_says_it_keeps() {
        assert_eq!(MaskStyle::None.apply("Alice"), "Alice");
        assert_eq!(
            MaskStyle::Last4.apply("4242424242424242"),
            "••••••••••••4242"
        );
        assert_eq!(MaskStyle::Last2.apply("+61400123456"), "••••••••••56");
        assert_eq!(
            MaskStyle::EmailLocal.apply("alice@example.com"),
            "a•••@example.com"
        );
        assert_eq!(MaskStyle::Full.apply("1990-01-01"), "••••••••");
    }

    /// A fully masked value is a fixed width, so the mask does not report the
    /// length of what it is hiding.
    #[test]
    fn a_full_mask_does_not_leak_the_length() {
        assert_eq!(
            MaskStyle::Full.apply("1990-01-01"),
            MaskStyle::Full.apply("a much longer secret value"),
        );
    }

    /// A value too short for its style is masked entirely rather than shown.
    ///
    /// The failure this refuses is a mask that stops masking on the values it
    /// was misapplied to: `last4` over a four-character card number is the
    /// whole number, printed by code that believes it is redacting.
    #[test]
    fn a_value_too_short_for_its_style_is_masked_whole() {
        assert_eq!(MaskStyle::Last4.apply("4242"), "••••••••");
        assert_eq!(MaskStyle::Last2.apply("7"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("not-an-address"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("@example.com"), "••••••••");
        assert_eq!(MaskStyle::EmailLocal.apply("alice@"), "••••••••");
    }

    /// Masking counts characters, not bytes: a multi-byte value must not panic
    /// on a slice boundary, and must keep the count the style promises.
    #[test]
    fn masking_counts_characters_not_bytes() {
        assert_eq!(MaskStyle::Last2.apply("naïve café"), "••••••••fé");
    }

    // ── the served table ────────────────────────────────────────────────

    /// A minimal served response, with room for a caller to add rows.
    fn served(entries: Value, extra: Option<(&str, Value)>) -> Registry {
        let mut body = serde_json::json!({
            "registryVersion": "0.2",
            "entries": entries,
            "unregistered": { "sensitivity": "high", "release": "consent", "mask": "full" },
            "strictness": {
                "sensitivity": ["high", "normal"],
                "release": ["stepUp", "consent"],
                "mask": ["full", "last2", "last4", "emailLocal", "none"]
            }
        });
        if let Some((key, value)) = extra {
            body[key] = value;
        }
        Registry::from_wire(&body)
    }

    /// A token the compiled copy has never heard of resolves from the agent's
    /// table — which is the whole reason this stopped being vendored.
    ///
    /// `employer` and `profile.*` are the two that were actually diverging:
    /// spec 0.1 declares neither, so a deployment that declared them got the
    /// floor's full mask from a client that could not be told otherwise.
    #[test]
    fn a_deployment_type_resolves_from_the_served_table() {
        let r = served(
            serde_json::json!([
                { "type": "employer", "sensitivity": "normal", "release": "consent", "mask": "none" },
                { "type": "profile", "sensitivity": "normal", "release": "consent", "mask": "none" },
            ]),
            None,
        );

        assert!(!r.is_fallback);
        assert_eq!(r.registry_version, "0.2");
        assert!(!r.resolve("employer").masks_by_default());
        assert!(r.is_registered("profile.github"));
        // …and the compiled copy still gives the old, wrong-for-this-deployment
        // answer, which is what the fallback flag exists to disclose.
        assert!(spec_0_1().resolve("employer").masks_by_default());
    }

    /// Strictness comes from the agent, not from a constant here.
    ///
    /// A maintainer that serves a style this build has never heard of, and
    /// ranks it looser than `full`, gets that ranking honoured in the
    /// comparison — while the *rendering* still collapses to `full`, because
    /// this build does not know how to reduce a value that way. Those are two
    /// separate decisions and reading either off the other loses one of them.
    #[test]
    fn an_unknown_mask_style_ranks_where_the_agent_puts_it() {
        let r = served(
            serde_json::json!([
                { "type": "vessel", "sensitivity": "normal", "release": "consent", "mask": "first3" },
            ]),
            Some((
                "strictness",
                serde_json::json!({
                    "sensitivity": ["high", "normal"],
                    "release": ["stepUp", "consent"],
                    "mask": ["full", "first3", "none"]
                }),
            )),
        );

        // `first3` is looser than the floor's `full`, so the floor wins the
        // comparison for an unregistered member of the family…
        assert_eq!(r.resolve("vessel.somethingNew").mask, MaskStyle::Full);
        // …while the exact entry is used as written, and an unrenderable style
        // is drawn as `full` rather than shown in the clear.
        assert_eq!(r.resolve("vessel").mask, MaskStyle::Full);
    }

    /// A response missing its orderings still resolves, and resolves towards
    /// showing less: an axis nobody ordered ranks everything most protective.
    #[test]
    fn a_response_with_no_strictness_degrades_protectively() {
        let r = Registry::from_wire(&serde_json::json!({
            "registryVersion": "0.1",
            "entries": [
                { "type": "name", "sensitivity": "normal", "release": "consent", "mask": "none" }
            ],
            "unregistered": { "sensitivity": "high", "release": "consent", "mask": "full" }
        }));

        // The exact entry is used as written, and needs no ordering to be.
        assert_eq!(r.resolve("name").mask, MaskStyle::None);
        // …while the family cannot loosen the floor on an ordering that was
        // never sent, so an unregistered member of it stays masked.
        assert_eq!(r.resolve("name.somethingNew").mask, MaskStyle::Full);
        assert_eq!(
            r.resolve("name.somethingNew").sensitivity,
            Sensitivity::High
        );
    }

    /// The roots a pane groups by come from the served table, so a family the
    /// agent knows and this build does not still groups.
    #[test]
    fn the_grouping_roots_come_from_the_table() {
        let r = served(
            serde_json::json!([
                { "type": "name.given", "sensitivity": "normal", "release": "consent", "mask": "none" },
                { "type": "vessel.hull", "sensitivity": "normal", "release": "consent", "mask": "none" },
            ]),
            None,
        );
        let roots = r.registered_roots();
        assert!(roots.contains("name"));
        assert!(roots.contains("vessel"));
        assert_eq!(roots.len(), 2);
    }

    /// A refused row from the deployment's own file is read back, because it is
    /// otherwise invisible: the token resolves exactly as it would with no file
    /// at all, so the operator's intended tightening is silently not in force.
    #[test]
    fn the_agents_own_refusals_are_read_back() {
        let r = served(
            serde_json::json!([]),
            Some((
                "ext",
                serde_json::json!({
                    "org.openvtc.claim-types": {
                        "rejected": [{ "type": "Employer", "reason": "type is not lowercase" }],
                        "fileError": "claim-types.json: permission denied"
                    }
                }),
            )),
        );

        assert!(!r.unapplied.is_empty());
        assert_eq!(r.unapplied.rejected[0].claim_type, "Employer");
        assert_eq!(r.unapplied.rejected[0].reason, "type is not lowercase");
        assert_eq!(
            r.unapplied.file_error.as_deref(),
            Some("claim-types.json: permission denied")
        );
    }

    /// A malformed `ext` is dropped rather than rendered: nothing upstream has
    /// checked its shape, and a banner built from a missing field is a second
    /// fault reported as the first.
    #[test]
    fn a_malformed_refusal_report_is_dropped() {
        let r = served(
            serde_json::json!([]),
            Some((
                "ext",
                serde_json::json!({
                    "org.openvtc.claim-types": { "rejected": [{ "reason": "no type member" }] }
                }),
            )),
        );
        assert!(r.unapplied.is_empty());
    }

    /// The compiled copy says so about itself. The pane reads this to disclose
    /// that a masking decision came from a table the holder's agent did not
    /// supply.
    #[test]
    fn the_compiled_copy_declares_itself() {
        assert!(Registry::vendored().is_fallback);
        assert!(Registry::default().is_fallback);
        assert_eq!(Registry::vendored().registry_version, "0.1");
    }
}
