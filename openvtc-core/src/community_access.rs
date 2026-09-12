//! A device or agent's access to one community's context.
//!
//! A holder can let another device — a laptop, a phone, an agent acting for
//! them — use their VTA inside one community's context and nowhere else. The
//! device is named by a `did:key` it holds the private key for; the holder
//! pastes that DID here and the VTA gets an ACL entry scoped to the community's
//! sub-context, with an expiry.
//!
//! # Built on the VTA's own ACL, not a new mechanism
//!
//! There is no pairing flow in OpenVTC to extend: [`crate::devices`] only
//! registers *this* install's binding. The VTA's device slice, on the other
//! hand, is explicitly "the device-facing half of an `AclEntry`" —
//! `device/register/0.1` refuses a DID that is not already in the ACL. So the
//! grant is an ordinary `acl/grant/0.1` entry, after which the device can
//! authenticate and register its own binding exactly as any enrolled device
//! does. Listing is `acl/list/0.1` read in the **subtree** direction, and
//! revocation is `acl/revoke/0.1` (or `acl/update/0.1` to narrow an entry that
//! also names contexts outside the community).
//!
//! # The role: `application`
//!
//! [`DEVICE_ROLE`] is the least-privileged VTA role that lets a device *act* in
//! a context rather than only look at it:
//!
//! - `monitor` derives no capabilities at all, and `reader` only reads the
//!   credential vault and agent memory. Neither can sign, so neither can
//!   present the persona's faces or answer a community as the holder.
//! - `application` adds signing (`sign`, `signTrustTask`) and presentation
//!   (`roomPresent`, `proxyLogin`) — what acting for the holder takes — and is
//!   the role the VTA's own device enrolment grants.
//! - `initiator` would add minting keys, writing the vault, and administering
//!   devices, and `admin` would let the device manage the context's ACL and
//!   grant itself more. A device acting in a community needs none of that.
//!
//! The scope is the community's context, which covers the sub-contexts beneath
//! it and nothing beside it, so a device granted for one community cannot act
//! in another.
//!
//! # One entry per DID
//!
//! The VTA holds at most one ACL entry per DID. A device already granted
//! somewhere is **not** silently widened into a second community: that would
//! share one expiry between two grants and could quietly extend an entry the
//! holder made for a different purpose (or with a different role). The grant is
//! refused with what the DID already holds, and a device that serves two
//! communities uses a key per community.

use chrono::{DateTime, Duration, TimeZone, Utc};
use vta_sdk::acl::{ActScope, ContextDirection};
use vta_sdk::client::{AclEntryResponse, CreateAclRequest, UpdateAclRequest, VtaClient};
use vta_sdk::context_path::is_ancestor_or_self;
use vta_sdk::error::VtaError;

use crate::config::community_context::{ensure_context, is_sub_context, vta_failure};
use crate::config::context_path::parse_sub_context_id;
use crate::errors::OpenVTCError;

/// The VTA role a device is granted in a community's context. See the module
/// documentation for why `application` and not a narrower or wider role.
pub const DEVICE_ROLE: &str = "application";

/// Longest label sent with a grant. The label is for the holder reading their
/// own ACL; a long community name should not make the grant fail.
const MAX_LABEL_LEN: usize = 120;

/// An expiry a grant can be given. Every grant expires: a device that is lost or
/// forgotten stops authenticating without anyone remembering to revoke it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiryChoice {
    /// How the choice reads on screen.
    pub label: &'static str,
    /// How long the grant lasts.
    pub days: i64,
}

/// The expiries offered, shortest first.
pub const EXPIRY_CHOICES: [ExpiryChoice; 4] = [
    ExpiryChoice {
        label: "1 day",
        days: 1,
    },
    ExpiryChoice {
        label: "7 days",
        days: 7,
    },
    ExpiryChoice {
        label: "30 days",
        days: 30,
    },
    ExpiryChoice {
        label: "90 days",
        days: 90,
    },
];

/// The expiry a new grant starts on: a week, short enough that a forgotten
/// device lapses, long enough not to be renewed daily.
pub const DEFAULT_EXPIRY: usize = 1;

/// When a grant made at `now` with expiry choice `index` ends. An index past
/// the end takes the longest choice rather than panicking.
#[must_use]
pub fn expires_at(now: DateTime<Utc>, index: usize) -> DateTime<Utc> {
    let choice = EXPIRY_CHOICES
        .get(index)
        .unwrap_or(&EXPIRY_CHOICES[EXPIRY_CHOICES.len() - 1]);
    now + Duration::days(choice.days)
}

/// Multicodec prefixes for the public keys a `did:key` can carry, with each
/// key's length. Only what a device key plausibly is: Ed25519, P-256
/// (secure-enclave keys), and secp256k1.
const DID_KEY_CODECS: [(&[u8], usize, &str); 3] = [
    (&[0xed, 0x01], 32, "Ed25519"),
    (&[0x80, 0x24], 33, "P-256"),
    (&[0xe7, 0x01], 33, "secp256k1"),
];

/// Read the `did:key` a holder pasted for a device.
///
/// Surrounding whitespace is dropped. What remains must be a bare `did:key`
/// (no fragment, query or path) whose multibase decodes to a known public key.
/// The VTA decides whether the device can authenticate; this catches a
/// truncated paste, a DID URL copied from a key reference, or a `did:webvh`
/// pasted where a device key belongs — before it becomes an ACL entry naming
/// nobody.
///
/// `own_did` is the DID OpenVTC authenticates to the VTA as. Granting it would
/// try to replace this install's own administrator entry.
///
/// # Errors
///
/// [`OpenVTCError::Config`] saying what is wrong with the input.
pub fn parse_device_did(input: &str, own_did: Option<&str>) -> Result<String, OpenVTCError> {
    let did = input.trim();
    let bad = |why: &str| Err(OpenVTCError::Config(why.to_string()));
    if did.is_empty() {
        return bad("Paste the device's did:key.");
    }
    let Some(encoded) = did.strip_prefix("did:key:") else {
        return bad("A device is identified by a did:key (it starts with did:key:z).");
    };
    if encoded.contains(['#', '?', '/']) || encoded.chars().any(char::is_whitespace) {
        return bad("Paste the did:key itself, not a key reference inside it.");
    }
    if !encoded.starts_with('z') {
        return bad("That did:key is not base58btc-encoded (it should start with did:key:z).");
    }
    let bytes = match multibase::decode(encoded) {
        Ok((_, bytes)) => bytes,
        Err(_) => return bad("That did:key does not decode — was it copied in full?"),
    };
    let known = DID_KEY_CODECS.iter().any(|(prefix, len, _)| {
        bytes
            .strip_prefix(*prefix)
            .is_some_and(|key| key.len() == *len)
    });
    if !known {
        return bad(
            "That did:key does not carry an Ed25519, P-256 or secp256k1 key — was it copied in full?",
        );
    }
    if own_did == Some(did) {
        return bad(
            "That is the DID OpenVTC itself uses at your VTA; paste the device's own did:key.",
        );
    }
    Ok(did.to_string())
}

/// The label a grant carries: the device's name and the community it is for.
#[must_use]
pub fn grant_label(device_name: &str, community: &str) -> String {
    let name = match device_name.trim() {
        "" => "device",
        name => name,
    };
    let label = format!("{name} — {community} (OpenVTC)");
    match label.char_indices().nth(MAX_LABEL_LEN) {
        Some((cut, _)) => label[..cut].to_string(),
        None => label,
    }
}

/// The `acl/grant/0.1` request giving `did` [`DEVICE_ROLE`] in `context_id`
/// until `expires`.
pub fn grant_request(
    did: &str,
    context_id: &str,
    label: &str,
    expires: DateTime<Utc>,
) -> CreateAclRequest {
    CreateAclRequest::new(did, DEVICE_ROLE)
        .contexts(vec![context_id.to_string()])
        .label(label)
        .expires_at(u64::try_from(expires.timestamp()).unwrap_or(0))
}

/// Where an ACL entry may act.
///
/// The VTA stores the act axis as `(role, allowed_contexts)` and decodes it
/// server-side (`vti_common::acl::act_scope_for`), which the SDK does not
/// expose for a listed entry. This is that decode, and the only place in
/// OpenVTC that reads the two fields together: an empty context list means
/// *everywhere* for an admin and *nowhere* for every other role, so neither
/// field means anything alone.
#[must_use]
pub fn act_scope(entry: &AclEntryResponse) -> ActScope {
    match (entry.role.as_str(), entry.allowed_contexts.as_slice()) {
        ("admin", []) => ActScope::All,
        (_, []) => ActScope::None,
        (_, contexts) => ActScope::Contexts(contexts.to_vec()),
    }
}

/// A grant of access inside one community's context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGrant {
    /// The device's DID.
    pub did: String,
    /// The VTA role the entry holds.
    pub role: String,
    /// The label the entry was given, if any.
    pub label: Option<String>,
    /// The contexts it names at or beneath the community's context.
    pub contexts: Vec<String>,
    /// The contexts it names outside the community. Revoking the grant for
    /// this community leaves these in place.
    pub elsewhere: Vec<String>,
    /// When the entry stops authenticating; `None` for an entry without one.
    pub expires_at: Option<DateTime<Utc>>,
}

impl DeviceGrant {
    /// Whether the entry has expired at `now`.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|at| at <= now)
    }

    /// One line for the panel: role, label, expiry, and any wider reach.
    #[must_use]
    pub fn describe(&self, now: DateTime<Utc>) -> String {
        let mut line = self.role.clone();
        if let Some(label) = self.label.as_deref().filter(|l| !l.is_empty()) {
            line.push_str(&format!(" · {label}"));
        }
        line.push_str(&match self.expires_at {
            Some(at) if at <= now => format!(" · expired {}", at.format("%Y-%m-%d")),
            Some(at) => format!(" · expires {}", at.format("%Y-%m-%d %H:%M UTC")),
            None => " · no expiry".to_string(),
        });
        match self.elsewhere.len() {
            0 => {}
            1 => line.push_str(" · also 1 other context"),
            n => line.push_str(&format!(" · also {n} other contexts")),
        }
        line
    }

    /// How revoking this grant for its community is done.
    #[must_use]
    pub fn revocation(&self) -> Revocation {
        if self.elsewhere.is_empty() {
            Revocation::Delete
        } else {
            Revocation::Narrow(self.elsewhere.clone())
        }
    }
}

/// How a grant is taken away from one community.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revocation {
    /// The entry names only this community: remove it.
    Delete,
    /// The entry also names other contexts: keep it, scoped to these.
    Narrow(Vec<String>),
}

/// What a revocation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Revoked {
    /// The entry was removed.
    Deleted,
    /// The entry was kept, scoped to the contexts outside the community.
    Narrowed(Vec<String>),
    /// The VTA holds no entry for the DID (already revoked, or expired and
    /// swept).
    AlreadyGone,
}

/// The grant `entry` holds inside `context_id`'s subtree, if it holds one.
///
/// An entry that acts everywhere or nowhere holds no grant *of* the branch —
/// the same edge the VTA's subtree listing draws — and neither does one
/// scoped only to an ancestor (such as OpenVTC's own entry on the top
/// context), which a VTA too old to honour the listing's direction would
/// return.
#[must_use]
pub fn grant_in(entry: &AclEntryResponse, context_id: &str) -> Option<DeviceGrant> {
    let scope = act_scope(entry);
    if !scope.acts_within(context_id) {
        return None;
    }
    let (contexts, elsewhere): (Vec<String>, Vec<String>) = scope
        .named_contexts()
        .iter()
        .cloned()
        .partition(|c| is_ancestor_or_self(context_id, c));
    Some(DeviceGrant {
        did: entry.did.clone(),
        role: entry.role.clone(),
        label: entry.label.clone(),
        contexts,
        elsewhere,
        expires_at: entry
            .expires_at
            .and_then(|secs| i64::try_from(secs).ok())
            .and_then(|secs| Utc.timestamp_opt(secs, 0).single()),
    })
}

/// The grants inside `context_id` among `entries`, by DID. `own_did` — the DID
/// OpenVTC authenticates as — is never listed, so it can never be revoked from
/// here.
#[must_use]
pub fn grants_in(
    entries: &[AclEntryResponse],
    context_id: &str,
    own_did: Option<&str>,
) -> Vec<DeviceGrant> {
    let mut grants: Vec<DeviceGrant> = entries
        .iter()
        .filter(|e| own_did != Some(e.did.as_str()))
        .filter_map(|e| grant_in(e, context_id))
        .collect();
    grants.sort_by(|a, b| a.did.cmp(&b.did));
    grants
}

/// Refuse anything but one of the account's own sub-contexts. A grant scoped
/// to the top context would reach every community.
fn require_community_context(top_context_id: &str, context_id: &str) -> Result<(), OpenVTCError> {
    if is_sub_context(context_id, top_context_id) {
        Ok(())
    } else {
        Err(OpenVTCError::Config(format!(
            "{context_id} is not a community context of its own, so access there would reach \
             every community"
        )))
    }
}

/// Give `did` [`DEVICE_ROLE`] in `context_id` until `expires`, and return the
/// grant as the VTA recorded it.
///
/// The context is made to exist first (the VTA refuses a grant naming one it
/// does not hold).
///
/// # Errors
///
/// A context that is not one of the account's sub-contexts; a DID that already
/// holds an ACL entry (described, and never widened — see the module
/// documentation); the VTA unreachable, refusing, or recording a different
/// scope than asked for.
pub async fn grant_device(
    client: &VtaClient,
    top_context_id: &str,
    context_id: &str,
    did: &str,
    label: &str,
    expires: DateTime<Utc>,
) -> Result<DeviceGrant, OpenVTCError> {
    require_community_context(top_context_id, context_id)?;
    let slug = parse_sub_context_id(context_id).map_or(context_id, |(_, slug)| slug);
    ensure_context(client, top_context_id, context_id, slug).await?;
    match client
        .create_acl(grant_request(did, context_id, label, expires))
        .await
    {
        Ok(entry) => grant_in(&entry, context_id).ok_or_else(|| {
            OpenVTCError::Vta(format!(
                "the VTA recorded {did} as {} in {:?}, not {DEVICE_ROLE} in {context_id} — \
                 check the entry before relying on it",
                entry.role, entry.allowed_contexts
            ))
        }),
        Err(VtaError::Conflict(_)) => {
            let held = match client.get_acl(did).await {
                Ok(entry) => match act_scope(&entry) {
                    ActScope::All => format!("{} everywhere", entry.role),
                    ActScope::None => format!("{} in no context", entry.role),
                    ActScope::Contexts(cs) => format!("{} in {}", entry.role, cs.join(", ")),
                },
                Err(_) => "an existing entry".to_string(),
            };
            Err(OpenVTCError::Config(format!(
                "{did} already has access at your VTA ({held}). A DID holds one entry, so \
                 revoke that first or give this community a key of its own."
            )))
        }
        Err(e) => Err(vta_failure("grant device access", e)),
    }
}

/// The grants inside `context_id`, read in the VTA's subtree direction.
///
/// # Errors
///
/// The VTA unreachable or refusing the listing.
pub async fn list_device_grants(
    client: &VtaClient,
    context_id: &str,
) -> Result<Vec<DeviceGrant>, OpenVTCError> {
    let listing = client
        .list_acl_in_direction(Some(context_id), ContextDirection::Subtree)
        .await
        .map_err(|e| vta_failure("list device access", e))?;
    Ok(grants_in(&listing.entries, context_id, client.caller_did()))
}

/// Take `did`'s access away from `context_id`.
///
/// The entry is read afresh rather than trusted from an earlier listing, so a
/// grant widened or narrowed since is revoked as it now stands: removed when it
/// names only this community, otherwise narrowed to what it holds elsewhere.
///
/// # Errors
///
/// The DID is OpenVTC's own; the entry no longer holds access inside the
/// context; the VTA unreachable or refusing.
pub async fn revoke_device_grant(
    client: &VtaClient,
    context_id: &str,
    did: &str,
) -> Result<Revoked, OpenVTCError> {
    if client.caller_did() == Some(did) {
        return Err(OpenVTCError::Config(
            "that is the DID OpenVTC itself uses at your VTA".to_string(),
        ));
    }
    let entry = match client.get_acl(did).await {
        Ok(entry) => entry,
        Err(VtaError::NotFound(_)) => return Ok(Revoked::AlreadyGone),
        Err(e) => return Err(vta_failure("read the device's access", e)),
    };
    let grant = grant_in(&entry, context_id).ok_or_else(|| {
        OpenVTCError::Config(format!("{did} no longer holds access in {context_id}"))
    })?;
    match grant.revocation() {
        Revocation::Delete => match client.delete_acl(did).await {
            Ok(()) | Err(VtaError::NotFound(_)) => Ok(Revoked::Deleted),
            Err(e) => Err(vta_failure("revoke device access", e)),
        },
        Revocation::Narrow(rest) => client
            .update_acl(
                did,
                UpdateAclRequest {
                    label: None,
                    allowed_contexts: Some(rest.clone()),
                    step_up_approver: None,
                    step_up_require: None,
                    approve_scope: None,
                    allowed_keys: None,
                    capabilities: None,
                },
            )
            .await
            .map(|_| Revoked::Narrowed(rest))
            .map_err(|e| vta_failure("narrow device access", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &str = "openvtc/kernel";

    /// A real Ed25519 did:key.
    const DEVICE: &str = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";

    /// An entry as the canonical `acl/*` wire carries it: timestamps in
    /// RFC 3339, which the SDK turns into epoch seconds.
    fn entry(did: &str, role: &str, contexts: &[&str], expires: Option<u64>) -> AclEntryResponse {
        let rfc3339 = |secs: u64| {
            Utc.timestamp_opt(secs as i64, 0)
                .single()
                .expect("a valid instant")
                .to_rfc3339()
        };
        serde_json::from_value(serde_json::json!({
            "subject": did,
            "role": role,
            "label": "laptop",
            "scopes": contexts,
            "createdAt": rfc3339(1_700_000_000),
            "createdBy": "did:key:zAdmin",
            "expiresAt": expires.map(rfc3339),
        }))
        .expect("an ACL entry")
    }

    #[test]
    fn a_pasted_device_did_is_checked_before_it_becomes_a_grant() {
        assert_eq!(
            parse_device_did(&format!("  {DEVICE}\n"), None).unwrap(),
            DEVICE
        );
        for bad in [
            "",
            "did:webvh:scid:example.com",
            "did:key:6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
            &format!("{DEVICE}#key-1"),
            "did:key:z6MkjchhfUsD6mmvni8m",
            "did:key:zzzzzz",
        ] {
            assert!(
                parse_device_did(bad, None).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(
            parse_device_did(DEVICE, Some(DEVICE)).is_err(),
            "OpenVTC's own DID is never granted"
        );
    }

    /// The wire request carries the role, the one context and the expiry —
    /// the three things that bound what the device can do.
    #[test]
    fn a_grant_is_application_in_one_context_with_an_expiry() {
        let expires = Utc.with_ymd_and_hms(2026, 9, 18, 12, 0, 0).unwrap();
        let req = grant_request(DEVICE, CTX, "laptop — Kernel (OpenVTC)", expires);
        let wire = serde_json::to_value(&req).unwrap();
        let entry = &wire["entry"];
        assert_eq!(entry["subject"], DEVICE);
        assert_eq!(entry["role"], "application");
        assert_eq!(entry["scopes"], serde_json::json!([CTX]));
        assert_eq!(req.expires_at, Some(expires.timestamp() as u64));
    }

    #[test]
    fn every_expiry_is_in_the_future_and_the_default_is_a_week() {
        let now = Utc::now();
        assert_eq!(expires_at(now, DEFAULT_EXPIRY), now + Duration::days(7));
        assert_eq!(expires_at(now, 99), now + Duration::days(90));
        assert!(EXPIRY_CHOICES.iter().all(|c| c.days > 0));
    }

    #[test]
    fn labels_name_the_device_and_the_community_within_bounds() {
        assert_eq!(grant_label("", "Kernel"), "device — Kernel (OpenVTC)");
        assert!(grant_label("phone", &"x".repeat(500)).chars().count() <= MAX_LABEL_LEN);
    }

    /// The decode pairs the role with the list: an empty list is everywhere
    /// for an admin and nowhere for anyone else.
    #[test]
    fn scope_is_decoded_from_the_role_and_the_list_together() {
        assert_eq!(act_scope(&entry(DEVICE, "admin", &[], None)), ActScope::All);
        assert_eq!(
            act_scope(&entry(DEVICE, "application", &[], None)),
            ActScope::None
        );
        assert_eq!(
            act_scope(&entry(DEVICE, "reader", &[CTX], None)),
            ActScope::Contexts(vec![CTX.to_string()])
        );
    }

    #[test]
    fn only_grants_inside_the_community_are_listed() {
        let entries = [
            entry(
                "did:key:zInside",
                "application",
                &[CTX],
                Some(1_900_000_000),
            ),
            entry(
                "did:key:zDeeper",
                "application",
                &["openvtc/kernel/ci"],
                None,
            ),
            entry("did:key:zTop", "admin", &["openvtc"], None),
            entry("did:key:zSuper", "admin", &[], None),
            entry("did:key:zNowhere", "reader", &[], None),
            entry(
                "did:key:zSibling",
                "application",
                &["openvtc/kernel-evil"],
                None,
            ),
            entry("did:key:zOwn", "application", &[CTX], None),
        ];
        let grants = grants_in(&entries, CTX, Some("did:key:zOwn"));
        let dids: Vec<&str> = grants.iter().map(|g| g.did.as_str()).collect();
        assert_eq!(dids, ["did:key:zDeeper", "did:key:zInside"]);
        assert_eq!(
            grants[1].expires_at.map(|t| t.timestamp()),
            Some(1_900_000_000)
        );
    }

    /// An entry naming contexts on both sides is listed, and revoking it for
    /// this community keeps its other contexts.
    #[test]
    fn revoking_a_wider_entry_narrows_it_and_a_scoped_one_is_deleted() {
        let wide = grant_in(
            &entry(DEVICE, "application", &[CTX, "openvtc/work"], None),
            CTX,
        )
        .unwrap();
        assert_eq!(wide.contexts, [CTX]);
        assert_eq!(
            wide.revocation(),
            Revocation::Narrow(vec!["openvtc/work".to_string()])
        );
        let scoped = grant_in(&entry(DEVICE, "application", &[CTX], None), CTX).unwrap();
        assert_eq!(scoped.revocation(), Revocation::Delete);
    }

    #[test]
    fn a_grant_says_when_it_ends() {
        let now = Utc.with_ymd_and_hms(2026, 9, 11, 0, 0, 0).unwrap();
        let live = grant_in(
            &entry(
                DEVICE,
                "application",
                &[CTX],
                Some(now.timestamp() as u64 + 86_400),
            ),
            CTX,
        )
        .unwrap();
        assert!(!live.is_expired(now));
        assert!(live.describe(now).contains("expires 2026-09-12"));
        let lapsed = grant_in(
            &entry(
                DEVICE,
                "application",
                &[CTX],
                Some(now.timestamp() as u64 - 1),
            ),
            CTX,
        )
        .unwrap();
        assert!(lapsed.is_expired(now));
        assert!(lapsed.describe(now).contains("expired"));
    }

    #[test]
    fn the_top_context_is_never_a_community_context() {
        assert!(require_community_context("openvtc", "openvtc").is_err());
        assert!(require_community_context("openvtc", CTX).is_ok());
    }
}
