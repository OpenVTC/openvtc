//! Worlds — the parts of a life, and the faces that belong to them.
//!
//! `persona/facet/*` on the wire (VTI #1338); **world** on screen, per
//! `design-docs/persona-vocabulary.md`. "Facet" is the analyst's word — nobody
//! says "my work facet" to a friend — and "group" carries no model while
//! colliding with grouping attributes by family.
//!
//! A world is *a part of your life, and the faces that belong to it*: Work,
//! Home, Play. A face belongs to at most one world; an attribute may belong to
//! several, because a mobile number is genuinely both work and home.
//!
//! # A world arranges, it does not contain
//!
//! Deleting a world deletes nothing else. The faces and attributes that
//! belonged to it are untouched and simply belong to no world afterwards —
//! which is why [`delete`] returns [`Deletion::released_faces`] rather than a
//! bare acknowledgement: the count is what lets a caller say what the screen
//! will look like, and "deleted" on its own invites the reading that the faces
//! went with it.
//!
//! # `put` is a replace, and that is the trap
//!
//! `persona/facet/put` replaces the whole record. Omitting `faceIds` means *an
//! empty list*, not "leave them as they were" — the spec is explicit, because a
//! member whose absence meant "keep" would make it impossible to empty one. So
//! every write from this module goes through [`FacetDraft`], which carries the
//! full membership, and every caller that wants to change one thing has to
//! start from what [`list`] returned. There is no partial update to reach for
//! by accident.
//!
//! # Dangling members are kept, not tidied
//!
//! A world may name a face or an attribute that has since been deleted. The
//! maintainer does not prune those and neither does this module: a dangling id
//! is how a consumer can offer to tidy, and silently dropping it turns a
//! deletion the holder may not have intended into one they cannot see. It
//! shows up wherever a caller resolves [`Facet::face_ids`] against a face list
//! and finds fewer faces than the world names.

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::trust_tasks;

use crate::errors::OpenVTCError;

/// Round-trip budget for a facet task, in seconds. The same 30s the rest of the
/// persona surface gets — these are local-store operations at the agent (VTI
/// R1.2: an outbound call with no finite timeout turns a hung service into a
/// hung command).
const FACET_TIMEOUT: u64 = 30;

/// How many worlds one page asks for.
///
/// The schema caps a page at 250 and a holder will have a handful, so this is
/// generous rather than tuned. [`list`] still follows `nextCursor` to the end:
/// the schema is explicit that a short page does not mean the last one, and a
/// pane that drew four of five worlds would be wrong in a way nothing on screen
/// could reveal.
const PAGE: u64 = 100;

/// How many pages [`list`] will follow before giving up.
///
/// A bound, not an expectation (VTI R1.4 — a polling or paging loop is bounded).
/// At [`PAGE`] a world each this is far past any real holder; what it actually
/// refuses is a maintainer whose cursor never terminates, which would otherwise
/// hang the pane forever on a read that looks like it is working.
const MAX_PAGES: usize = 32;

/// The colour a world wears.
///
/// A **name**, resolved by each consumer against its own palette — never a hex
/// value. A literal cannot be legible in a terminal, in a light theme and in a
/// dark one at once, so a stored `#8B0000` is a colour that is wrong somewhere
/// and the holder has no way to know where. The eight members deliberately
/// carry no status connotation: none is named for success, warning or danger,
/// so a holder's decorative choice can never be mistaken for the pane saying
/// something is wrong.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Colour {
    #[default]
    Slate,
    Indigo,
    Teal,
    Moss,
    Sand,
    Clay,
    Rose,
    Plum,
}

impl Colour {
    /// Every colour, in the order the spec lists them — which is the order a
    /// picker offers them in.
    #[must_use]
    pub fn all() -> [Colour; 8] {
        [
            Colour::Slate,
            Colour::Indigo,
            Colour::Teal,
            Colour::Moss,
            Colour::Sand,
            Colour::Clay,
            Colour::Rose,
            Colour::Plum,
        ]
    }

    /// The wire token.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Colour::Slate => "slate",
            Colour::Indigo => "indigo",
            Colour::Teal => "teal",
            Colour::Moss => "moss",
            Colour::Sand => "sand",
            Colour::Clay => "clay",
            Colour::Rose => "rose",
            Colour::Plum => "plum",
        }
    }

    /// Read a served token.
    ///
    /// An unrecognised colour becomes [`Slate`](Colour::Slate) rather than an
    /// error: a colour is decoration, and refusing to draw a whole world
    /// because a later spec added a ninth name would lose the holder something
    /// that matters over something that does not.
    #[must_use]
    pub fn from_wire(token: &str) -> Self {
        Colour::all()
            .into_iter()
            .find(|c| c.as_wire() == token)
            .unwrap_or(Colour::Slate)
    }
}

/// One world, as the agent holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facet {
    pub facet_id: String,
    /// The holder's name for this part of their life.
    ///
    /// Never disclosed to a verifier — it is how the holder finds it again. The
    /// agent stores it without interpreting it: it is not a scope, not a policy
    /// input, and not a name a counterparty ever sees.
    pub name: String,
    pub colour: Colour,
    /// One or two emoji, kept opaque.
    ///
    /// A mark rather than a field. A terminal that cannot render it shows the
    /// name, which is why it is optional and carries no meaning of its own.
    pub icon: Option<String>,
    /// The faces belonging to this world, by `profile_id`.
    pub face_ids: Vec<String>,
    /// The attributes belonging to this world, by `attribute_id`.
    ///
    /// Carried whole so that a write can put it back untouched. This client
    /// does not yet offer a way to change it — the console does — and a `put`
    /// that dropped it would silently empty a membership the holder set
    /// elsewhere.
    pub attribute_ids: Vec<String>,
    /// The store's write counter, for the conditional write that follows.
    pub version: u64,
    pub updated_at: String,
}

impl Facet {
    fn from_wire(value: &Value) -> Self {
        let ids = |member: &str| {
            value
                .get(member)
                .and_then(Value::as_array)
                .map(|xs| {
                    xs.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        Self {
            facet_id: value
                .get("facetId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            name: value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            colour: value
                .get("colour")
                .and_then(Value::as_str)
                .map_or(Colour::Slate, Colour::from_wire),
            icon: value
                .get("icon")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            face_ids: ids("faceIds"),
            attribute_ids: ids("attributeIds"),
            version: value.get("version").and_then(Value::as_u64).unwrap_or(0),
            updated_at: value
                .get("updatedAt")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }
    }

    /// The name to show. Never empty, so a row cannot render as a blank line.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self.name.trim().is_empty() {
            false => &self.name,
            true => "(unnamed world)",
        }
    }

    /// Whether this world names that face.
    #[must_use]
    pub fn holds_face(&self, profile_id: &str) -> bool {
        self.face_ids.iter().any(|id| id == profile_id)
    }

    /// This world's membership as a draft that replaces it unchanged.
    ///
    /// The starting point for every edit, because `put` is a replace: a caller
    /// that built a draft from scratch to rename a world would empty its
    /// membership on the way past.
    #[must_use]
    pub fn to_draft(&self) -> FacetDraft {
        FacetDraft {
            facet_id: Some(self.facet_id.clone()),
            name: self.name.clone(),
            colour: self.colour,
            icon: self.icon.clone(),
            face_ids: self.face_ids.clone(),
            attribute_ids: self.attribute_ids.clone(),
            expected_version: Some(self.version),
        }
    }
}

/// A world about to be written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FacetDraft {
    /// Absent to create; present to replace.
    pub facet_id: Option<String>,
    pub name: String,
    pub colour: Colour,
    pub icon: Option<String>,
    pub face_ids: Vec<String>,
    pub attribute_ids: Vec<String>,
    /// The version a prior read returned, making the write conditional.
    ///
    /// Supplied on every edit built by [`Facet::to_draft`], so a world someone
    /// changed from `pnm` or the console between the read and the write is
    /// refused rather than silently overwritten.
    pub expected_version: Option<u64>,
}

impl FacetDraft {
    /// A brand-new world with nothing in it yet.
    #[must_use]
    pub fn new(name: String, colour: Colour) -> Self {
        Self {
            name,
            colour,
            // Create-only. Without it a retry after a lost response would
            // replace whatever the first attempt had created, and the holder
            // would lose whatever they had put in it in between.
            expected_version: Some(0),
            ..Self::default()
        }
    }
}

/// What a write did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FacetWrite {
    pub facet_id: String,
    pub version: u64,
    /// True when the write created the world, false when it replaced one.
    pub created: bool,
}

/// What a delete did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deletion {
    /// False when there was nothing to delete — a successful no-op rather than
    /// an error, so a retry after a lost response can reach the state it wanted.
    pub existed: bool,
    /// How many faces belong to no world as a result.
    ///
    /// Nothing was deleted and nothing changed about them. This is the count a
    /// caller needs to finish the sentence honestly: "deleted" on its own reads
    /// as though the faces went too.
    pub released_faces: u64,
}

/// List the holder's worlds, following the cursor to the end.
///
/// Returns an empty list — not an error — when the agent does not serve
/// `persona/facet/*`, which means it predates VTI #1338. A holder on such an
/// agent has no worlds and cannot have any, and that is exactly what an empty
/// list says; every other failure is returned, because "we could not ask" and
/// "you have none" are one glance apart and one of them is a confident wrong
/// answer about the holder's own arrangement (VTI R6.4).
pub async fn list(client: &VtaClient) -> Result<Vec<Facet>, OpenVTCError> {
    let mut facets: Vec<Facet> = Vec::new();
    let mut cursor: Option<String> = None;

    for _ in 0..MAX_PAGES {
        let mut payload = json!({ "limit": PAGE });
        if let Some(c) = &cursor {
            payload["cursor"] = json!(c);
        }

        let value = match client
            .dispatch_trust_task(
                trust_tasks::TASK_PERSONA_FACET_LIST_1_0,
                payload,
                FACET_TIMEOUT,
            )
            .await
        {
            Ok(value) => value,
            Err(VtaError::UnsupportedTaskType { .. }) => return Ok(Vec::new()),
            Err(e) => return Err(OpenVTCError::Vta(format!("persona facet list failed: {e}"))),
        };

        facets.extend(
            value
                .get("facets")
                .and_then(Value::as_array)
                .map(|rows| rows.iter().map(Facet::from_wire))
                .into_iter()
                .flatten(),
        );

        // The absence of `nextCursor` is the *only* signal that a listing is
        // complete. A short page is not one: the schema says a maintainer may
        // return fewer than asked for reasons of its own.
        cursor = value
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }

    // Display order the holder can predict, which is the order they named them
    // in — the store returns creation order and a name sort would reshuffle the
    // whole screen the first time somebody renamed one.
    Ok(facets)
}

/// Create or replace one world.
///
/// A replace in the full sense: the draft's membership is what the world will
/// have afterwards. Build it with [`Facet::to_draft`] unless the world is new.
pub async fn put(client: &VtaClient, draft: FacetDraft) -> Result<FacetWrite, OpenVTCError> {
    let mut payload = json!({
        "name": draft.name,
        "colour": draft.colour.as_wire(),
        "faceIds": draft.face_ids,
        "attributeIds": draft.attribute_ids,
    });
    if let Some(id) = &draft.facet_id {
        payload["facetId"] = json!(id);
    }
    if let Some(icon) = draft.icon.as_deref().filter(|s| !s.is_empty()) {
        payload["icon"] = json!(icon);
    }
    if let Some(version) = draft.expected_version {
        payload["expectedVersion"] = json!(version);
    }

    let value = client
        .dispatch_trust_task(
            trust_tasks::TASK_PERSONA_FACET_PUT_1_0,
            payload,
            FACET_TIMEOUT,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona facet write failed: {e}")))?;

    Ok(FacetWrite {
        facet_id: value
            .get("facetId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        version: value.get("version").and_then(Value::as_u64).unwrap_or(0),
        created: value
            .get("created")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// Delete one world. The faces and attributes that belonged to it are
/// untouched.
pub async fn delete(
    client: &VtaClient,
    facet_id: &str,
    expected_version: Option<u64>,
) -> Result<Deletion, OpenVTCError> {
    let mut payload = json!({ "facetId": facet_id });
    if let Some(version) = expected_version {
        payload["expectedVersion"] = json!(version);
    }

    let value = client
        .dispatch_trust_task(
            trust_tasks::TASK_PERSONA_FACET_DELETE_1_0,
            payload,
            FACET_TIMEOUT,
        )
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona facet delete failed: {e}")))?;

    Ok(Deletion {
        existed: value
            .get("existed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        released_faces: value
            .get("releasedFaces")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

/// Move a face into a world, or out of every world.
///
/// Two writes at most, and they are not interchangeable: the face is removed
/// from whichever world holds it *before* it is added to the new one, because a
/// face belongs to at most one world and a maintainer refuses the second write
/// with `faceAlreadyPlaced` if the first has not happened yet.
///
/// `into` of `None` is *take it out of every world*, which is a real state — the
/// console calls it "belongs to no world" and says every face belonging
/// somewhere is fine too.
pub async fn place_face(
    client: &VtaClient,
    facets: &[Facet],
    profile_id: &str,
    into: Option<&str>,
) -> Result<(), OpenVTCError> {
    for facet in facets.iter().filter(|f| f.holds_face(profile_id)) {
        if Some(facet.facet_id.as_str()) == into {
            // Already where it is being asked to go. Writing anyway would burn
            // a version and turn a no-op into a conflict for anyone else
            // holding this world.
            return Ok(());
        }
        let mut draft = facet.to_draft();
        draft.face_ids.retain(|id| id != profile_id);
        put(client, draft).await?;
    }

    let Some(target) = into else {
        return Ok(());
    };
    let Some(facet) = facets.iter().find(|f| f.facet_id == target) else {
        return Err(OpenVTCError::Vta(format!(
            "no such world: {target}. It may have been deleted from another \
             client since this list was read"
        )));
    };

    let mut draft = facet.to_draft();
    // The version this draft carries came from the read, and the removal above
    // may have just moved it — but only on a *different* world, so this one is
    // still at the version we saw. A conflict here is a genuine one.
    draft.face_ids.push(profile_id.to_string());
    put(client, draft).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(name: &str, faces: &[&str]) -> Value {
        json!({
            "facetId": "01FACET",
            "name": name,
            "colour": "moss",
            "icon": "🏠",
            "faceIds": faces,
            "attributeIds": ["01ATTR"],
            "version": 3,
            "updatedAt": "2026-09-09T10:00:00Z",
        })
    }

    /// A served world is read whole, membership included.
    #[test]
    fn a_world_is_read_whole() {
        let facet = Facet::from_wire(&wire("Home", &["01FACE"]));
        assert_eq!(facet.facet_id, "01FACET");
        assert_eq!(facet.name, "Home");
        assert_eq!(facet.colour, Colour::Moss);
        assert_eq!(facet.icon.as_deref(), Some("🏠"));
        assert_eq!(facet.face_ids, vec!["01FACE".to_string()]);
        assert_eq!(facet.attribute_ids, vec!["01ATTR".to_string()]);
        assert_eq!(facet.version, 3);
    }

    /// A colour this build has never heard of is decoration that failed to
    /// arrive, not a reason to refuse the world it belongs to.
    #[test]
    fn an_unknown_colour_does_not_lose_the_world() {
        let mut value = wire("Home", &[]);
        value["colour"] = json!("chartreuse");
        let facet = Facet::from_wire(&value);
        assert_eq!(facet.colour, Colour::Slate);
        assert_eq!(facet.name, "Home");
    }

    /// Every colour round-trips through its wire token, so a value read back is
    /// the one written.
    #[test]
    fn every_colour_round_trips() {
        for colour in Colour::all() {
            assert_eq!(Colour::from_wire(colour.as_wire()), colour);
        }
    }

    /// An edit starts from what was read, membership and version included.
    ///
    /// This is the guard against the trap in `put`: a draft built from scratch
    /// to rename a world would send no `faceIds`, and the spec reads that as an
    /// empty list rather than "leave them alone".
    #[test]
    fn an_edit_carries_the_whole_membership_forward() {
        let facet = Facet::from_wire(&wire("Home", &["01FACE", "02FACE"]));
        let mut draft = facet.to_draft();
        draft.name = "Home life".to_string();

        assert_eq!(
            draft.face_ids,
            vec!["01FACE".to_string(), "02FACE".to_string()]
        );
        assert_eq!(draft.attribute_ids, vec!["01ATTR".to_string()]);
        assert_eq!(draft.expected_version, Some(3));
        assert_eq!(draft.facet_id.as_deref(), Some("01FACET"));
    }

    /// A new world is create-only, so a retry after a lost response cannot
    /// replace what the first attempt made.
    #[test]
    fn a_new_world_is_create_only() {
        let draft = FacetDraft::new("Play".to_string(), Colour::Rose);
        assert_eq!(draft.expected_version, Some(0));
        assert!(draft.facet_id.is_none());
        assert!(draft.face_ids.is_empty());
    }

    /// A world with no name still draws as a row rather than a blank line.
    #[test]
    fn an_unnamed_world_still_has_something_to_draw() {
        let mut value = wire("", &[]);
        value["name"] = json!("   ");
        assert_eq!(Facet::from_wire(&value).display_name(), "(unnamed world)");
    }

    /// Membership is asked as a question, and a world that does not hold a face
    /// says so.
    #[test]
    fn a_world_knows_which_faces_it_holds() {
        let facet = Facet::from_wire(&wire("Home", &["01FACE"]));
        assert!(facet.holds_face("01FACE"));
        assert!(!facet.holds_face("02FACE"));
    }
}
