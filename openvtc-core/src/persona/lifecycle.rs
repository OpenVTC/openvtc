//! A face's life, from the holder's side: made where it is asked for, retired
//! and reinstated, and read back — where it is worn and what it has done.
//!
//! `persona/profile/{compose,retire,reinstate,usage,timeline}`
//! (verifiable-trust-infrastructure design note `persona-context-first.md`
//! §5.3, §5.4, §9.4, §9.6).
//!
//! # Local by default
//!
//! [`compose`] makes a face for one community's context. A value typed there
//! stays in that face unless the holder says it may be used elsewhere
//! ([`ComposeValue::share`]); where the face lives follows from what it
//! carries, so there is no scope to pass and get wrong.
//!
//! # A history with no values in it
//!
//! [`history`] returns types, parties, contexts and versions only — the
//! timeline the agent serves has nowhere to put a value or a private label, and
//! nothing here reaches for one.

use serde_json::{Value, json};
use vta_sdk::client::VtaClient;

use crate::errors::OpenVTCError;
use crate::persona::profile::ProfileSummary;

/// One value typed while composing a face.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposeValue {
    pub claim_type: String,
    pub value: String,
    /// Make it reusable across the holder's faces. Off, it stays in this face.
    pub share: bool,
}

/// What a compose made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Composed {
    pub profile_id: String,
    /// True when the face lives in the community's context alone.
    pub local: bool,
    /// Shared values that were already kept, so the face now draws on the same
    /// fact as whatever else shows it.
    pub reused: usize,
}

/// Make a face for one context and wear it there as `persona_did`.
pub async fn compose(
    client: &VtaClient,
    context_id: &str,
    name: &str,
    persona_did: &str,
    values: &[ComposeValue],
) -> Result<Composed, OpenVTCError> {
    let claims: Vec<Value> = values
        .iter()
        .map(|v| {
            let mut claim = json!({
                "type": v.claim_type, "valueType": "string", "value": v.value,
            });
            if v.share {
                claim["share"] = "pool".into();
            }
            claim
        })
        .collect();
    let payload: trust_tasks_rs::specs::persona::profile::compose::v1_0::Payload =
        serde_json::from_value(json!({
            "contextId": context_id,
            "name": name,
            "claims": claims,
            "personaDid": persona_did,
        }))
        .map_err(|e| OpenVTCError::Vta(format!("not a face this build can make: {e}")))?;
    let out = client
        .persona_profile_compose(&payload)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not make the face: {e}")))?;
    Ok(Composed {
        profile_id: out.profile_id.to_string(),
        local: out.scope.to_string() == "local",
        reused: out.pooled.iter().filter(|p| !p.created).count(),
    })
}

/// Stop wearing a face anywhere, and keep it. Returns how many places it was
/// taken off.
pub async fn retire(client: &VtaClient, profile_id: &str) -> Result<usize, OpenVTCError> {
    client
        .persona_profile_retire(profile_id, None, None)
        .await
        .map(|r| r.unbound.len())
        .map_err(|e| OpenVTCError::Vta(format!("could not retire the face: {e}")))
}

/// Make a retired face wearable again. It is worn nowhere afterwards.
pub async fn reinstate(client: &VtaClient, profile_id: &str) -> Result<(), OpenVTCError> {
    client
        .persona_profile_reinstate(profile_id, None, None)
        .await
        .map(|_| ())
        .map_err(|e| OpenVTCError::Vta(format!("could not reinstate the face: {e}")))
}

/// The holder's retired faces — out of every picker, and listed here so one
/// can be brought back.
pub async fn list_retired(client: &VtaClient) -> Result<Vec<ProfileSummary>, OpenVTCError> {
    let value = client
        .persona_profile_list(None, None, true)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona profile list failed: {e}")))?;
    let mut faces: Vec<ProfileSummary> = value
        .get("profiles")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(ProfileSummary::from_wire_pub)
                .filter(|f| f.retired)
                .collect()
        })
        .unwrap_or_default();
    faces.sort_by(|a, b| a.display_name().cmp(b.display_name()));
    Ok(faces)
}

/// One place a face is worn now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceUsage {
    pub context_id: String,
    pub persona_did: String,
    pub until: Option<String>,
}

/// One thing that happened to a face. No value, no private label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceEvent {
    pub at: String,
    pub kind: String,
    pub context_id: Option<String>,
    pub verifier_did: Option<String>,
    pub claim_types: Vec<String>,
    pub version: Option<u64>,
}

impl FaceEvent {
    /// The event as a line, with contexts named by `context_name`.
    #[must_use]
    pub fn words(&self, context_name: impl Fn(&str) -> String) -> String {
        let place = self
            .context_id
            .as_deref()
            .map(|c| format!(" in {}", context_name(c)))
            .unwrap_or_default();
        let types = self.claim_types.join(", ");
        match self.kind.as_str() {
            "composed" => format!("made{place}"),
            "worn" => format!("worn{place}"),
            "unworn" => format!("taken off{place}"),
            "expired" => format!("came off by itself{place}"),
            "disclosed" => format!(
                "told {}{}{place}",
                self.verifier_did.as_deref().unwrap_or("a party"),
                if types.is_empty() {
                    String::new()
                } else {
                    format!(" {types}")
                }
            ),
            "valueChanged" => format!(
                "{} changed{}",
                if types.is_empty() {
                    "a value it shows"
                } else {
                    types.as_str()
                },
                self.version
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default()
            ),
            "promoted" => format!("made reusable across your faces{place}"),
            "retired" => "retired".to_string(),
            "reinstated" => "reinstated".to_string(),
            other => other.to_string(),
        }
    }
}

/// Where a face is worn and what it has done.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaceHistory {
    pub usage: Vec<FaceUsage>,
    pub events: Vec<FaceEvent>,
}

/// Read a face's history — to the end of the timeline, following its cursor.
pub async fn history(client: &VtaClient, profile_id: &str) -> Result<FaceHistory, OpenVTCError> {
    let usage = client
        .persona_profile_usage(profile_id, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not read where the face is worn: {e}")))?;
    let mut events = Vec::new();
    let mut cursor: Option<String> = None;
    // Bounded, so a far side that never ends a listing cannot hang the pane.
    for _ in 0..50 {
        let page = client
            .persona_profile_timeline(profile_id, None, None, cursor.as_deref(), Some(500))
            .await
            .map_err(|e| OpenVTCError::Vta(format!("could not read the face's history: {e}")))?;
        let page = serde_json::to_value(&page).unwrap_or(Value::Null);
        for e in page
            .get("events")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            events.push(FaceEvent {
                at: e
                    .get("at")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                kind: e
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                context_id: e
                    .get("contextId")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                verifier_did: e
                    .get("verifierDid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                claim_types: e
                    .get("claimTypes")
                    .and_then(Value::as_array)
                    .map(|t| {
                        t.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                version: e.get("version").and_then(Value::as_u64),
            });
        }
        cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
        if cursor.is_none() {
            break;
        }
    }
    Ok(FaceHistory {
        usage: usage
            .usage
            .iter()
            .map(|u| FaceUsage {
                context_id: u.context_id.to_string(),
                persona_did: u.persona_did.to_string(),
                until: u.until.map(|t| t.to_rfc3339()),
            })
            .collect(),
        events,
    })
}

/// One value a face made inside a community carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalEntry {
    /// Its position in the face — what promotion addresses.
    pub position: u64,
    pub claim_type: String,
}

/// A face made inside one community: its values live there alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalFace {
    pub profile_id: String,
    pub name: String,
    /// The version read — promotion is addressed against it.
    pub version: u64,
    pub entries: Vec<LocalEntry>,
}

/// The faces made inside `context_id`, each read whole: the listing carries
/// names and counts, and promotion addresses entries by position against a
/// version.
pub async fn local_faces(
    client: &VtaClient,
    context_id: &str,
) -> Result<Vec<LocalFace>, OpenVTCError> {
    let listing = client
        .persona_local_profile_list(context_id, std::num::NonZeroU64::new(500), None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not list the faces made here: {e}")))?;
    let mut faces = Vec::new();
    for summary in listing
        .get("profiles")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(id) = summary.get("profileId").and_then(Value::as_str) else {
            continue;
        };
        let read = client
            .persona_local_profile_get(context_id, id)
            .await
            .map_err(|e| OpenVTCError::Vta(format!("could not read a face made here: {e}")))?;
        let profile = read.get("profile").unwrap_or(&Value::Null);
        faces.push(LocalFace {
            profile_id: id.to_string(),
            name: profile
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed face")
                .to_string(),
            version: profile.get("version").and_then(Value::as_u64).unwrap_or(0),
            entries: profile
                .get("entries")
                .and_then(Value::as_array)
                .map(|es| {
                    es.iter()
                        .enumerate()
                        .filter_map(|(i, e)| {
                            let t = e.get("inline")?.get("type")?.as_str()?;
                            Some(LocalEntry {
                                position: i as u64,
                                claim_type: t.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
        });
    }
    faces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(faces)
}

/// What a promotion did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Promoted {
    /// Values that were already kept, so the face now shares them.
    pub reused: usize,
    /// Personas that wore the face and still do, from the pool now.
    pub rebound: usize,
}

/// Make `positions` of a face made in `context_id` reusable across the
/// holder's faces. **One-way**: the face moves into the pool with its id and
/// everyone wearing it; there is no undo to offer.
pub async fn promote(
    client: &VtaClient,
    context_id: &str,
    profile_id: &str,
    positions: &[u64],
    expected_version: u64,
) -> Result<Promoted, OpenVTCError> {
    let out = client
        .persona_attribute_promote(context_id, profile_id, positions, expected_version)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("could not make the values reusable: {e}")))?;
    Ok(Promoted {
        reused: out.promoted.iter().filter(|p| !p.created).count(),
        rebound: out.rebound_persona_dids.len(),
    })
}

/// "disclosed to N parties across M contexts — deleting does not un-tell
/// them", or `None` when the face told no one.
#[must_use]
pub fn untell_words(disclosed_to: Option<(u64, u64)>) -> Option<String> {
    let (parties, contexts) = disclosed_to?;
    (parties > 0).then(|| {
        format!(
            "It has disclosed to {parties} part{} across {contexts} communit{} — deleting it \
             does not un-tell them.",
            if parties == 1 { "y" } else { "ies" },
            if contexts == 1 { "y" } else { "ies" },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_face_that_told_no_one_gets_no_warning() {
        assert_eq!(untell_words(None), None);
        assert_eq!(untell_words(Some((0, 0))), None);
        let w = untell_words(Some((3, 1))).unwrap();
        assert!(w.contains("3 parties across 1 community"), "{w}");
        assert!(w.contains("does not un-tell"), "{w}");
    }

    #[test]
    fn a_history_line_names_types_and_parties_never_a_value() {
        let told = FaceEvent {
            at: "2026-01-01T00:00:00Z".into(),
            kind: "disclosed".into(),
            context_id: Some("ctx".into()),
            verifier_did: Some("did:web:v".into()),
            claim_types: vec!["name.display".into()],
            version: None,
        };
        assert_eq!(
            told.words(|c| if c == "ctx" { "Co-op".into() } else { c.into() }),
            "told did:web:v name.display in Co-op"
        );
        let changed = FaceEvent {
            kind: "valueChanged".into(),
            context_id: None,
            verifier_did: None,
            version: Some(7),
            ..told
        };
        assert_eq!(
            changed.words(|c| c.into()),
            "name.display changed (version 7)"
        );
    }
}
