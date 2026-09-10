//! Profiles — named projections over the pool, and the unit a persona is bound
//! to. **Holder-scoped**, like the pool they draw from.
//!
//! A profile is a whitelist: omission is exclusion. There is no removal marker,
//! because a blacklist over a growing pool leaks by default the first time an
//! attribute is added.
//!
//! # This build authors live references, and preserves everything else
//!
//! The Trust Task's profile entry has four forms — a live `ref` to a pool
//! attribute, a `pinVersion` pin of one, an `override` of its value, and an
//! `inline` value that never enters the pool. [`put`] from here writes the
//! first, and a picker over the pool is exactly what that form is: tick the
//! attributes this persona shows. It keeps "edit once, everywhere" true, which is the
//! property a holder is relying on when they correct their address in one
//! place.
//!
//! The other three are divergences — a value this profile shows that the pool
//! does not — and each is a decision worth naming out loud rather than
//! producing as a side effect of a checkbox. They are made through `pnm`.
//!
//! **But they are never silently discarded.** [`get`] parses every entry it
//! reads and hands the non-`ref` ones back in
//! [`ProfileDetail::other_entries`]; [`put`] takes them and writes them
//! through unchanged. Rebuilding a profile from only the ticked boxes would
//! delete a holder's pinned or overridden values the first time they renamed
//! it, and the deletion would be invisible — the profile would still resolve,
//! just to less than it did.
//!
//! An entry this build cannot parse at all (a form a newer VTA introduced) is
//! counted in [`ProfileDetail::unreadable_entries`] and makes the profile
//! **read-only here**: a save that cannot round-trip an entry cannot preserve
//! it, and dropping it is precisely the silent loss above.

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::persona::ProfileEntry;

use crate::errors::OpenVTCError;
use crate::persona::claim_types::Registry;
use crate::persona::pool::ProvenanceKind;

/// A profile as a list row.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfileSummary {
    pub profile_id: String,
    /// The holder's name for it — "Work", "Gaming". Never disclosed.
    pub name: String,
    /// How many entries it carries, all forms counted.
    pub entry_count: usize,
    /// The pool attributes this profile draws on, in any entry form.
    ///
    /// Carried on the summary because the listing already contains it and one
    /// question depends on it: deleting an attribute a profile references is
    /// refused unless the caller cascades, and a caller that has to *discover*
    /// that from a rejection asks the holder the wrong question first. With
    /// this, the one question put is the right one.
    pub referenced: Vec<String>,
    /// Credentials listed as this profile's inventory — what the persona can
    /// prove, as distinct from the evidence behind a credential-backed value.
    pub credential_ref_count: usize,
    pub version: u64,
    pub updated_at: String,
}

impl ProfileSummary {
    fn from_wire(value: &Value) -> Self {
        Self {
            profile_id: string_at(value, "profileId"),
            name: string_at(value, "name"),
            entry_count: value
                .get("entries")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            referenced: value
                .get("entries")
                .and_then(Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|e| e.get("ref").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            credential_ref_count: value
                .get("credentialRefs")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            version: value.get("version").and_then(Value::as_u64).unwrap_or(0),
            updated_at: string_at(value, "updatedAt"),
        }
    }

    /// The name to show. Never empty: an unnamed face still has to be
    /// selectable in a list.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.trim().is_empty() {
            "unnamed face"
        } else {
            &self.name
        }
    }
}

/// One claim a profile would present, as [`get`] with `resolve` returns it.
///
/// A *distinct type* from a pool attribute, and deliberately so at the source:
/// a resolved claim has nowhere to put a pool identifier when it does not have
/// one, which is what makes an inline value describable rather than a lie about
/// where it lives.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ResolvedClaim {
    pub claim_type: String,
    pub value: Option<Value>,
    pub value_type: String,
    pub provenance: ProvenanceKind,
    /// A credential-backed value that could not be re-derived.
    pub stale: bool,
    /// The pool attribute behind this claim. Absent for a value that lives only
    /// in this profile.
    pub attribute_id: Option<String>,
}

impl ResolvedClaim {
    fn from_wire(value: &Value) -> Self {
        Self {
            claim_type: string_at(value, "type"),
            value: value.get("value").cloned().filter(|v| !v.is_null()),
            value_type: string_at(value, "valueType"),
            provenance: ProvenanceKind::parse_wire(value.get("provenance")),
            stale: value.get("stale").and_then(Value::as_bool).unwrap_or(false),
            attribute_id: value
                .get("attributeId")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }

    /// The value as one line, masked when its claim type asks for that. Mirrors
    /// [`PoolAttribute::display_value`](crate::persona::pool::PoolAttribute::display_value),
    /// minus the "hidden" case: a resolve was asked for, so an absent value is
    /// an answer rather than a question that was never put.
    ///
    /// See [`revealed_value`](Self::revealed_value) for lifting the mask on one
    /// claim.
    #[must_use]
    pub fn display_value(&self, registry: &Registry) -> String {
        self.value_line(registry, false)
    }

    /// The same line with the mask lifted, for a holder who asked for this one
    /// claim.
    ///
    /// This used to be deliberately absent, on the argument that a resolved
    /// claim has no identity of its own to reveal *one* of — a face was read as
    /// a whole, so the only reveal the type could offer was the blanket one the
    /// mask exists to avoid. That argument was about the **pane**, not the
    /// type: it held only for as long as the face view had no cursor over its
    /// claims. It has one now, so "the selected claim" is a thing a holder can
    /// name, and the one-at-a-time reveal that the attributes tab has always
    /// offered works here on the same terms.
    ///
    /// Still a separate method rather than a `reveal: bool` on
    /// [`display_value`](Self::display_value), for the reason
    /// [`PoolAttribute::revealed_value`](crate::persona::pool::PoolAttribute::revealed_value)
    /// gives: reading a masked value in the clear should be something a call
    /// site had to *name*. A boolean gets passed through, and the caller that
    /// ends up passing `true` is rarely the one that meant to.
    #[must_use]
    pub fn revealed_value(&self, registry: &Registry) -> String {
        self.value_line(registry, true)
    }

    fn value_line(&self, registry: &Registry, reveal: bool) -> String {
        if self.stale {
            return "stale — can no longer be proven".to_string();
        }
        let shown = |text: String| {
            if reveal {
                text
            } else {
                registry.resolve(&self.claim_type).render(&text)
            }
        };
        match &self.value {
            Some(Value::String(s)) => shown(s.clone()),
            Some(other) => shown(other.to_string()),
            None => "(no value)".to_string(),
        }
    }

    /// Whether [`display_value`](Self::display_value) is reducing a value we
    /// hold, so a face can say *masked* rather than let the row read as empty.
    #[must_use]
    pub fn is_masked(&self, registry: &Registry) -> bool {
        !self.stale && self.value.is_some() && registry.resolve(&self.claim_type).masks_by_default()
    }
}

/// One profile, read in full.
#[derive(Clone, Debug, Default)]
pub struct ProfileDetail {
    pub summary: ProfileSummary,
    /// Pool attributes referenced live — the set this build's editor owns.
    pub live_refs: Vec<String>,
    /// Pinned, overridden and inline entries, kept exactly as read so a save
    /// writes them back untouched.
    pub other_entries: Vec<ProfileEntry>,
    /// Entries this build could not parse. Non-zero makes the profile
    /// read-only here — see the module header.
    pub unreadable_entries: usize,
    /// What the profile would present, when the read asked for it.
    pub resolved: Vec<ResolvedClaim>,
}

impl ProfileDetail {
    /// Whether this build may write the profile back.
    ///
    /// False only when an entry could not be parsed, because a save then cannot
    /// preserve it. The refusal is the point: a profile that quietly lost an
    /// entry still resolves, just to less than the holder believes it shows.
    #[must_use]
    pub fn is_editable_here(&self) -> bool {
        self.unreadable_entries == 0
    }

    /// The sentence to show when it is not.
    #[must_use]
    pub fn refusal(&self) -> String {
        format!(
            "This face has {} entr{} this version of OpenVTC cannot read, so saving would drop \
             {}. Edit it with `pnm persona profile`, or upgrade.",
            self.unreadable_entries,
            if self.unreadable_entries == 1 {
                "y"
            } else {
                "ies"
            },
            if self.unreadable_entries == 1 {
                "it"
            } else {
                "them"
            },
        )
    }
}

/// Enumerate the holder's profiles.
///
/// Metadata only, and there is no option to change that: resolving every
/// profile at once would decrypt the entire pool to answer a question about
/// names. [`get`] resolves the one the holder opened.
pub async fn list(client: &VtaClient) -> Result<Vec<ProfileSummary>, OpenVTCError> {
    let value = client
        .persona_profile_list(None, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona profile list failed: {e}")))?;

    let mut profiles: Vec<ProfileSummary> = value
        .get("profiles")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().map(ProfileSummary::from_wire).collect())
        .unwrap_or_default();
    profiles.sort_by(|a, b| a.display_name().cmp(b.display_name()));
    Ok(profiles)
}

/// Read one profile, optionally resolving what it would present.
///
/// `resolve` is opt-in for the same reason `include_values` is on the pool: it
/// decrypts values and re-derives credential-backed ones. A holder opening a
/// profile to see what it shows has asked; a list rebuilding itself has not.
pub async fn get(
    client: &VtaClient,
    profile_id: &str,
    resolve: bool,
) -> Result<ProfileDetail, OpenVTCError> {
    let value = client
        .persona_profile_get(profile_id, resolve)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona profile read failed: {e}")))?;

    let profile = value.get("profile").unwrap_or(&Value::Null).clone();
    let mut detail = ProfileDetail {
        summary: ProfileSummary::from_wire(&profile),
        resolved: value
            .get("resolved")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().map(ResolvedClaim::from_wire).collect())
            .unwrap_or_default(),
        ..ProfileDetail::default()
    };

    for entry in profile
        .get("entries")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        match serde_json::from_value::<ProfileEntry>(entry.clone()) {
            Ok(ProfileEntry::Ref { attribute_id }) => detail.live_refs.push(attribute_id),
            Ok(other) => detail.other_entries.push(other),
            // Counted, never dropped-and-forgotten: this is what makes the
            // profile read-only rather than silently rewritable.
            Err(_) => detail.unreadable_entries += 1,
        }
    }
    Ok(detail)
}

/// Create or update a profile.
///
/// `live_refs` are the pool attributes the holder ticked; `other_entries` are
/// the pinned/overridden/inline entries [`get`] read, passed straight back. A
/// caller that drops them deletes them.
///
/// The ticked entries are written first and in the order given, so the profile
/// resolves in the order the holder saw — entry order is display order.
pub async fn put(
    client: &VtaClient,
    profile_id: Option<&str>,
    name: &str,
    live_refs: &[String],
    other_entries: &[ProfileEntry],
    expected_version: Option<u64>,
) -> Result<String, OpenVTCError> {
    let entries: Vec<ProfileEntry> = live_refs
        .iter()
        .map(|id| ProfileEntry::Ref {
            attribute_id: id.clone(),
        })
        .chain(other_entries.iter().cloned())
        .collect();

    let response = client
        .persona_profile_put(name, entries, Vec::new(), profile_id, expected_version)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona profile write failed: {e}")))?;

    Ok(response
        .get("profileId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| profile_id.map(str::to_string))
        .unwrap_or_default())
}

/// Remove a profile.
///
/// Without `unbind` the VTA refuses while a persona still presents under it. A
/// context losing its identity mid-relationship is not something to do by
/// omission, so the refusal is surfaced and the holder is asked — the caller
/// must not retry with `unbind` on their behalf.
pub async fn delete(
    client: &VtaClient,
    profile_id: &str,
    unbind: bool,
) -> Result<(), OpenVTCError> {
    client
        .persona_profile_delete(profile_id, unbind, None)
        .await
        .map_err(|e| OpenVTCError::Vta(format!("persona profile delete failed: {e}")))?;
    Ok(())
}

/// Read a string member, defaulting to empty rather than failing the whole
/// parse: one missing label must not cost the holder the entire listing.
fn string_at(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::persona::claim_types::Registry;

    /// The compiled copy — spec 0.1 — as the table these tests resolve
    /// against. A unit test must not depend on what a live agent happens to
    /// serve, and every assertion below is about a token 0.1 declares.
    fn reg() -> Registry {
        Registry::vendored()
    }

    use super::*;

    fn profile_wire(entries: Value) -> Value {
        serde_json::json!({
            "profile": {
                "profileId": "01J9",
                "name": "Work",
                "entries": entries,
                "version": 2,
                "updatedAt": "2026-09-06T00:00:00Z",
            }
        })
    }

    /// The four entry forms split into the two buckets a save has to keep
    /// apart: what the editor owns, and what it must carry through untouched.
    #[test]
    fn entries_split_into_editable_refs_and_preserved_forms() {
        let wire = profile_wire(serde_json::json!([
            { "ref": "01A" },
            { "ref": "01B", "pinVersion": 3 },
            { "ref": "01C", "override": { "value": "other" } },
            { "inline": {
                "type": "nickname",
                "valueType": "string",
                "value": "Ace",
                "provenance": { "kind": "selfAsserted" }
            }},
        ]));
        let profile = wire.get("profile").unwrap().clone();
        let mut detail = ProfileDetail {
            summary: ProfileSummary::from_wire(&profile),
            ..ProfileDetail::default()
        };
        for entry in profile.get("entries").unwrap().as_array().unwrap() {
            match serde_json::from_value::<ProfileEntry>(entry.clone()) {
                Ok(ProfileEntry::Ref { attribute_id }) => detail.live_refs.push(attribute_id),
                Ok(other) => detail.other_entries.push(other),
                Err(_) => detail.unreadable_entries += 1,
            }
        }

        assert_eq!(detail.live_refs, vec!["01A".to_string()]);
        assert_eq!(
            detail.other_entries.len(),
            3,
            "a pin, an override and an inline value are not the editor's to rewrite"
        );
        assert!(detail.is_editable_here());
        assert_eq!(detail.summary.entry_count, 4);
    }

    /// An entry form this build has never seen makes the profile read-only.
    ///
    /// The alternative is the silent loss the module header describes: the save
    /// succeeds, the profile still resolves, and it presents less than the
    /// holder thinks it does.
    #[test]
    fn an_unreadable_entry_makes_the_profile_read_only() {
        let detail = ProfileDetail {
            unreadable_entries: 2,
            ..ProfileDetail::default()
        };
        assert!(!detail.is_editable_here());
        assert!(detail.refusal().contains("2 entries"));
        assert!(detail.refusal().contains("pnm"));
    }

    /// A resolved claim with no `attributeId` is an inline value, and saying so
    /// is the whole reason it is a distinct type from a pool attribute.
    ///
    /// The type is a registered `normal` one so the assertion is about the
    /// inline value and not about the mask: `nickname` is not in the claim-type
    /// registry, and an unregistered token resolves to masked.
    #[test]
    fn a_resolved_claim_without_an_attribute_id_is_inline() {
        let claim = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "name.display",
            "value": "Ace",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
            "stale": false,
        }));
        assert!(claim.attribute_id.is_none());
        assert_eq!(claim.display_value(&reg()), "Ace");
    }

    /// A resolved read that came back without a value says so, rather than
    /// reading as "hidden" — nothing was withheld; the resolve was asked for.
    #[test]
    fn a_resolved_claim_with_no_value_says_so() {
        let claim = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "email.work",
            "value": Value::Null,
            "stale": true,
        }));
        assert!(
            claim
                .display_value(&reg())
                .contains("can no longer be proven")
        );
    }

    /// A masked claim reads back whole when a caller asks for that one claim.
    ///
    /// The pairing is the point, and it is the same one the pool makes: the
    /// mask has to be liftable, or a holder cannot check what a community
    /// actually sees; and lifting it has to be a different call, or it is not a
    /// decision anyone made.
    #[test]
    fn a_masked_claim_is_only_whole_when_it_is_asked_for() {
        let claim = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "phone.mobile",
            "value": "+61400123456",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }));
        assert_eq!(claim.display_value(&reg()), "••••••••••56");
        assert_eq!(claim.revealed_value(&reg()), "+61400123456");
    }

    /// A stale claim says it is stale under a reveal too.
    ///
    /// The reason it cannot be shown is not that it is masked, and a reveal
    /// that turned the explanation into a blank would hide the one thing the
    /// holder needs to act on.
    #[test]
    fn a_stale_claim_still_says_it_is_stale_when_revealed() {
        let claim = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "phone.mobile",
            "value": "+61400123456",
            "stale": true,
        }));
        assert!(
            claim
                .revealed_value(&reg())
                .contains("can no longer be proven")
        );
    }

    /// A face masks what its type says to mask, and says that it did.
    ///
    /// The face detail view is a screen a holder opens to check what a
    /// community sees, which is exactly the screen someone else is most likely
    /// to be looking at over their shoulder.
    #[test]
    fn a_masked_claim_is_masked_on_a_face_too() {
        let claim = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "phone.mobile",
            "value": "+61400123456",
            "valueType": "string",
            "provenance": { "kind": "selfAsserted" },
        }));
        assert!(claim.is_masked(&reg()));
        assert_eq!(claim.display_value(&reg()), "••••••••••56");

        let normal = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "name.given",
            "value": "Alice",
            "valueType": "string",
        }));
        assert!(!normal.is_masked(&reg()));
        assert_eq!(normal.display_value(&reg()), "Alice");
    }

    /// Masked and absent stay distinguishable here too — a face that shows
    /// nothing and a face whose value is merely not painted are different
    /// answers to "what does this community see".
    #[test]
    fn a_masked_claim_is_not_an_absent_one() {
        let absent = ResolvedClaim::from_wire(&serde_json::json!({
            "type": "phone.mobile",
            "value": Value::Null,
        }));
        assert!(!absent.is_masked(&reg()));
        assert_eq!(absent.display_value(&reg()), "(no value)");
    }

    /// The put ordering: ticked entries first, preserved forms after, so the
    /// profile resolves in the order the holder saw in the picker.
    #[test]
    fn a_saved_profile_puts_the_ticked_entries_first() {
        let refs = ["01A".to_string(), "01B".to_string()];
        let other = [ProfileEntry::Inline {
            inline: serde_json::from_value(serde_json::json!({
                "type": "nickname",
                "valueType": "string",
                "value": "Ace",
                "provenance": { "kind": "selfAsserted" }
            }))
            .unwrap(),
        }];
        let entries: Vec<ProfileEntry> = refs
            .iter()
            .map(|id| ProfileEntry::Ref {
                attribute_id: id.clone(),
            })
            .chain(other.iter().cloned())
            .collect();
        assert_eq!(entries.len(), 3);
        assert!(matches!(&entries[0], ProfileEntry::Ref { attribute_id } if attribute_id == "01A"));
        assert!(matches!(entries[2], ProfileEntry::Inline { .. }));
    }
}
