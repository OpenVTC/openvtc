//! Which VTA context a community lives in.
//!
//! Every community a person joins can get its own sub-context under the
//! account's top context (`<top>/<slug>`). A sub-context has its own branch of
//! the key hierarchy and its own ACL scope, and the persona's faces for that
//! community are worn in it, so nothing a community is shown, and no key its
//! persona signs with, is shared with another community unless the person
//! chooses to share it.
//!
//! The choice is the person's, made when they join (or start a vetting
//! application): a new sub-context, a context they already use, or the top
//! context. One constraint shapes the options: a persona's keys and DID live in
//! exactly one context, the one it was minted in. A persona minted into a
//! sub-context can only be presented from that context; picking it means
//! sharing that context. A persona minted before per-community contexts has its
//! keys in the top context, so any context can hold its faces, but none of them
//! isolates its keys.
//!
//! OpenVTC holds admin of the top context, which covers every sub-context
//! beneath it. Isolation is therefore between communities, not from OpenVTC
//! itself.

use vta_sdk::client::{CreateContextRequest, VtaClient};
use vta_sdk::error::VtaError;
use vta_sdk::protocols::context_management::delete::DeleteContextPreviewResultBody;

use super::account::{Account, CommunityRecord, PersonaId, PersonaRecord};
use super::context_path::{
    SEPARATOR, build_sub_context_id, child_path, parse_sub_context_id, slugify,
    validate_context_path,
};
use crate::errors::OpenVTCError;
use crate::vetting::applicant::Application;

/// The context `persona`'s keys and DID live in. Personas minted before
/// per-community contexts record none, and theirs are in the top context.
#[must_use]
pub fn persona_context<'a>(persona: &'a PersonaRecord, top_context_id: &'a str) -> &'a str {
    if persona.origin_context_id.is_empty() {
        top_context_id
    } else {
        &persona.origin_context_id
    }
}

/// Whether `context_id` is a sub-context of `top_context_id` (strictly below it).
#[must_use]
pub fn is_sub_context(context_id: &str, top_context_id: &str) -> bool {
    context_id
        .strip_prefix(top_context_id)
        .is_some_and(|rest| rest.starts_with(SEPARATOR) && rest.len() > 1)
}

/// What kind of context an option is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKind {
    /// A new sub-context, for this community alone.
    New,
    /// A context the account already uses.
    Existing,
    /// The account's top context.
    Top,
}

/// One context a join or an application can use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextOption {
    /// The full context path.
    pub context_id: String,
    pub kind: ContextKind,
    /// The communities already in it, by VTC DID.
    pub communities: Vec<String>,
    /// The persona being presented has its keys here, so this is the only
    /// context it can be presented from.
    pub holds_persona_keys: bool,
}

impl ContextOption {
    /// The option in one line: its path and what choosing it means.
    #[must_use]
    pub fn summary(&self) -> String {
        let id = &self.context_id;
        match self.kind {
            ContextKind::New => format!("{id}  (a context of its own)"),
            ContextKind::Existing if self.holds_persona_keys => {
                format!("{id}  (this persona's context)")
            }
            ContextKind::Existing => match self.communities.len() {
                0 => format!("{id}  (in use)"),
                1 => format!("{id}  (shared with 1 community)"),
                n => format!("{id}  (shared with {n} communities)"),
            },
            ContextKind::Top => format!("{id}  (top context — nothing kept apart)"),
        }
    }
}

/// The contexts available for presenting `persona` — `None` for a persona not
/// yet minted — to a community, with `suggested_new` as the new sub-context.
///
/// A persona whose keys live in a sub-context has one option: that context.
/// Everyone else may choose a new sub-context (first, the default), any
/// sub-context the account already uses, or the top context.
#[must_use]
pub fn context_options(
    account: &Account,
    persona: Option<&PersonaRecord>,
    suggested_new: &str,
) -> Vec<ContextOption> {
    let top = account.top_context_id.as_str();
    let in_context = |context_id: &str| -> Vec<String> {
        let mut communities: Vec<String> = account
            .memberships()
            .filter(|m| m.sub_context_id == context_id)
            .map(|m| m.vtc_did.clone())
            .collect();
        communities.sort();
        communities.dedup();
        communities
    };

    if let Some(persona) = persona {
        let home = persona_context(persona, top);
        if is_sub_context(home, top) {
            return vec![ContextOption {
                context_id: home.to_string(),
                kind: ContextKind::Existing,
                communities: in_context(home),
                holds_persona_keys: true,
            }];
        }
    }

    let mut existing: Vec<String> = account
        .memberships()
        .map(|m| m.sub_context_id.clone())
        .chain(
            account
                .personas
                .values()
                .map(|p| p.origin_context_id.clone()),
        )
        .filter(|c| is_sub_context(c, top) && c != suggested_new)
        .collect();
    existing.sort();
    existing.dedup();

    let mut options = vec![ContextOption {
        context_id: suggested_new.to_string(),
        kind: ContextKind::New,
        communities: Vec::new(),
        holds_persona_keys: false,
    }];
    options.extend(existing.into_iter().map(|context_id| ContextOption {
        communities: in_context(&context_id),
        context_id,
        kind: ContextKind::Existing,
        holds_persona_keys: false,
    }));
    options.push(ContextOption {
        context_id: top.to_string(),
        kind: ContextKind::Top,
        communities: in_context(top),
        holds_persona_keys: persona.is_some(),
    });
    options
}

/// Whether `context_id` is already used by the account — by a membership or a
/// persona's keys.
#[must_use]
pub fn context_in_use(account: &Account, context_id: &str) -> bool {
    account
        .memberships()
        .any(|m| m.sub_context_id == context_id)
        || account
            .personas
            .values()
            .any(|p| p.origin_context_id == context_id)
}

/// The new sub-context `<top>/<slug>` for a slug the person typed.
///
/// # Errors
///
/// A slug that is not a valid path segment, a path too deep, or one already in
/// use — a new context is new, and choosing an existing one is a different
/// option.
pub fn new_context_id(
    top_context_id: &str,
    slug: &str,
    taken: impl Fn(&str) -> bool,
) -> Result<String, OpenVTCError> {
    let id = child_path(top_context_id, slug.trim())?;
    if taken(&id) {
        return Err(OpenVTCError::Config(format!(
            "{id} is already in use — choose it from the list to share it, or pick another name"
        )));
    }
    Ok(id)
}

/// How far a membership is kept apart from the account's other communities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    /// Its own sub-context, holding its persona's keys.
    Isolated,
    /// A sub-context that holds its persona's keys, shared with `n` other
    /// memberships.
    Shared(usize),
    /// Its own sub-context for faces, but the persona's keys live elsewhere —
    /// a persona minted before per-community contexts, or one shown to several.
    KeysElsewhere,
    /// The account's top context.
    Top,
}

impl Isolation {
    /// One line for the communities panel.
    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Isolation::Isolated => "own context — kept apart from your other communities".into(),
            Isolation::Shared(1) => "shared with 1 other community".into(),
            Isolation::Shared(n) => format!("shared with {n} other communities"),
            Isolation::KeysElsewhere => {
                "own context for faces — this persona's keys live in another context".into()
            }
            Isolation::Top => "top context — not kept apart".into(),
        }
    }
}

/// How `membership` is kept apart, given the account it belongs to.
#[must_use]
pub fn isolation(account: &Account, membership: &CommunityRecord) -> Isolation {
    let top = account.top_context_id.as_str();
    let context = membership.sub_context_id.as_str();
    if context.is_empty() || !is_sub_context(context, top) {
        return Isolation::Top;
    }
    let keys_here = account
        .personas
        .get(&membership.persona_ref)
        .is_some_and(|p| persona_context(p, top) == context);
    if !keys_here {
        return Isolation::KeysElsewhere;
    }
    let others = account
        .memberships()
        .filter(|m| m.sub_context_id == context)
        .count()
        .saturating_sub(1);
    match others {
        0 => Isolation::Isolated,
        n => Isolation::Shared(n),
    }
}

/// Make sure `context_id` exists at the VTA, creating it — and any missing
/// ancestor — beneath the account's top context. Returns whether anything was
/// created. The top context itself is never created here; it exists from setup.
///
/// Looked up before it is created, and a create that races another one
/// (`Conflict`) counts as existing, so a retried join reuses what an
/// interrupted one left behind.
///
/// # Errors
///
/// A path outside the account's top context, or a VTA that refuses.
pub async fn ensure_context(
    client: &VtaClient,
    top_context_id: &str,
    context_id: &str,
    name: &str,
) -> Result<bool, OpenVTCError> {
    if context_id == top_context_id {
        return Ok(false);
    }
    validate_context_path(context_id)?;
    if !is_sub_context(context_id, top_context_id) {
        return Err(OpenVTCError::Config(format!(
            "{context_id} is not inside this account's context {top_context_id}"
        )));
    }
    let mut created = false;
    let mut chain = Vec::new();
    let mut current = context_id;
    while current != top_context_id {
        chain.push(current);
        match parse_sub_context_id(current) {
            Some((parent, _)) => current = parent,
            None => break,
        }
    }
    for path in chain.into_iter().rev() {
        match client.get_context(path).await {
            Ok(_) => continue,
            Err(VtaError::NotFound(_)) => {}
            Err(e) => {
                return Err(OpenVTCError::Vta(format!(
                    "could not look up context {path}: {e}"
                )));
            }
        }
        let Some((parent, slug)) = parse_sub_context_id(path) else {
            continue;
        };
        let label = if path == context_id { name } else { slug };
        match client
            .create_context(
                CreateContextRequest::new(slug, label)
                    .description("A community context, created by OpenVTC")
                    .parent(parent),
            )
            .await
        {
            Ok(_) => created = true,
            Err(VtaError::Conflict(_)) => {}
            Err(e) => {
                return Err(OpenVTCError::Vta(format!(
                    "could not create context {path}: {e}"
                )));
            }
        }
    }
    Ok(created)
}

/// Whether `context_id` is already claimed: by a membership, a persona's keys,
/// or a vetting application's face. A new context must not be any of these.
#[must_use]
pub fn context_claimed(account: &Account, applications: &[Application], context_id: &str) -> bool {
    context_in_use(account, context_id)
        || applications
            .iter()
            .any(|a| a.context_id.as_deref() == Some(context_id))
}

/// The new sub-context to suggest for something called `name` — a community,
/// or a persona's label — slugified, made unique, and `fallback` when the name
/// has nothing a path segment can hold.
///
/// # Errors
///
/// Only a top context that cannot hold a child (invalid, or at the depth
/// limit).
pub fn suggested_context_id(
    top_context_id: &str,
    name: &str,
    fallback: &str,
    taken: impl Fn(&str) -> bool,
) -> Result<String, OpenVTCError> {
    let name = if slugify(name).is_empty() {
        fallback
    } else {
        name
    };
    // With a name that slugifies to something, the community-DID fallback of
    // `build_sub_context_id` is never consulted.
    build_sub_context_id(top_context_id, Some(name), "", taken)
}

/// Something that keeps a context in use, and so stops it being deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextUse {
    /// A membership lives in it.
    Membership {
        vtc_did: String,
        persona: PersonaId,
        /// The community's display name, or its DID.
        name: String,
    },
    /// A persona's keys and DID were minted in it; deleting the context
    /// deletes them.
    PersonaKeys {
        persona: PersonaId,
        /// The persona's label, or its DID.
        name: String,
    },
    /// A vetting application wears its face there.
    VettingApplication {
        community: String,
        persona: PersonaId,
    },
}

impl ContextUse {
    /// What uses the context, in words.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            ContextUse::Membership { name, .. } => format!("your membership of {name}"),
            ContextUse::PersonaKeys { name, .. } => format!("the keys and DID of persona {name}"),
            ContextUse::VettingApplication { community, .. } => {
                format!("your vetting application to {community}")
            }
        }
    }
}

/// Everything in the account that uses `context_id`.
#[must_use]
pub fn context_uses(
    account: &Account,
    applications: &[Application],
    context_id: &str,
) -> Vec<ContextUse> {
    let memberships = account
        .memberships()
        .filter(|m| m.sub_context_id == context_id)
        .map(|m| ContextUse::Membership {
            vtc_did: m.vtc_did.clone(),
            persona: m.persona_ref,
            name: m.display_name.clone().unwrap_or_else(|| m.vtc_did.clone()),
        });
    let mut personas: Vec<&PersonaRecord> = account
        .personas
        .values()
        .filter(|p| p.origin_context_id == context_id)
        .collect();
    personas.sort_by(|a, b| a.did.cmp(&b.did));
    let personas = personas.into_iter().map(|p| ContextUse::PersonaKeys {
        persona: p.persona_id,
        name: p.label.clone().unwrap_or_else(|| p.did.clone()),
    });
    let applications = applications
        .iter()
        .filter(|a| a.context_id.as_deref() == Some(context_id))
        .map(|a| ContextUse::VettingApplication {
            community: a.community.clone(),
            persona: a.persona,
        });
    memberships.chain(personas).chain(applications).collect()
}

/// Why a membership's context cannot be deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionRefusal {
    /// The membership lives in the account's top context (or names none of its
    /// own), and the top context is never deleted from here.
    TopContext,
    /// The membership is still live (Active or Pending); it has to be over
    /// first.
    StillLive,
    /// Something else still uses the context.
    InUse(Vec<ContextUse>),
}

impl DeletionRefusal {
    /// The refusal, in a sentence that names what to do about it.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            DeletionRefusal::TopContext => {
                "This community lives in your top context, which holds every community — it is \
                 never deleted from here."
                    .to_string()
            }
            DeletionRefusal::StillLive => {
                "Leave the community (or cancel the join) before deleting its context.".to_string()
            }
            DeletionRefusal::InUse(uses) => {
                let what: Vec<String> = uses.iter().map(ContextUse::describe).collect();
                format!(
                    "The context is still used by {} — it can be deleted once nothing uses it.",
                    what.join("; ")
                )
            }
        }
    }
}

/// The context `membership` lives in, if it may be deleted.
///
/// Only a membership that is over (left, withdrawn, rejected, removed,
/// expired), only a sub-context of the account's own, and only when nothing
/// else — another membership, any persona's keys, a vetting application —
/// uses it. The membership itself does not count as a use.
///
/// # Errors
///
/// The [`DeletionRefusal`] that applies.
pub fn deletable_context(
    account: &Account,
    applications: &[Application],
    membership: &CommunityRecord,
) -> Result<String, DeletionRefusal> {
    let context_id = membership.sub_context_id.as_str();
    if !is_sub_context(context_id, &account.top_context_id) {
        return Err(DeletionRefusal::TopContext);
    }
    if !membership.status.is_inactive() {
        return Err(DeletionRefusal::StillLive);
    }
    let uses: Vec<ContextUse> = context_uses(account, applications, context_id)
        .into_iter()
        .filter(|u| {
            !matches!(u, ContextUse::Membership { vtc_did, persona, .. }
                if *vtc_did == membership.vtc_did && *persona == membership.persona_ref)
        })
        .collect();
    if uses.is_empty() {
        Ok(context_id.to_string())
    } else {
        Err(DeletionRefusal::InUse(uses))
    }
}

/// The contexts strictly beneath `context_id` among `all`, in path order.
/// Segment-aware: `openvtc/kernel-evil` is not beneath `openvtc/kernel`.
#[must_use]
pub fn descendants_of(context_id: &str, all: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut below: Vec<String> = all
        .into_iter()
        .filter(|c| c != context_id && vta_sdk::context_path::is_ancestor_or_self(context_id, c))
        .collect();
    below.sort();
    below.dedup();
    below
}

/// What deleting a context would remove, as the VTA reports it: the context's
/// own resources, then each sub-context's, which the delete cascades to.
#[derive(Clone, Debug, Default)]
pub struct ContextDeletionPreview {
    /// The context being deleted.
    pub context_id: String,
    /// The VTA's preview for the context and for every sub-context beneath it,
    /// the context itself first.
    pub contexts: Vec<DeleteContextPreviewResultBody>,
}

impl ContextDeletionPreview {
    /// The sub-contexts the delete cascades to.
    pub fn sub_contexts(&self) -> impl Iterator<Item = &str> {
        self.contexts
            .iter()
            .map(|c| c.id.as_str())
            .filter(|id| *id != self.context_id)
    }

    /// Whether the subtree holds nothing but the contexts themselves.
    #[must_use]
    pub fn holds_nothing(&self) -> bool {
        self.contexts.iter().all(|c| {
            c.keys.is_empty()
                && c.webvh_dids.is_empty()
                && c.acl_entries_removed.is_empty()
                && c.acl_entries_updated.is_empty()
                && c.did_templates.is_empty()
        })
    }

    /// Everything that would be removed, one item per line, grouped by context.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for c in &self.contexts {
            lines.push(if c.id == self.context_id {
                format!("Context {}", c.id)
            } else {
                format!("Sub-context {}", c.id)
            });
            let before = lines.len();
            lines.extend(c.keys.iter().map(|k| format!("  key           {k}")));
            lines.extend(c.webvh_dids.iter().map(|d| format!("  DID           {d}")));
            lines.extend(
                c.acl_entries_removed
                    .iter()
                    .map(|s| format!("  access        {s}  (entry removed)")),
            );
            lines.extend(
                c.acl_entries_updated
                    .iter()
                    .map(|s| format!("  access        {s}  (loses this context only)")),
            );
            lines.extend(
                c.did_templates
                    .iter()
                    .map(|t| format!("  DID template  {t}")),
            );
            if lines.len() == before {
                lines.push("  nothing else".to_string());
            }
        }
        lines
    }
}

/// What has to be typed to confirm a context deletion.
pub const DELETE_CONFIRMATION: &str = "DELETE";

/// Whether `typed` confirms a deletion: exactly [`DELETE_CONFIRMATION`], so a
/// stray key or a lower-case habit never deletes anything.
#[must_use]
pub fn confirms_deletion(typed: &str) -> bool {
    typed == DELETE_CONFIRMATION
}

/// Map a VTA failure to an error that says which kind it was: the VTA could not
/// be reached, would not accept this session, or refused the request itself.
/// One message for all three sends the operator to check the network when the
/// fault is a permission, or the reverse.
pub(crate) fn vta_failure(action: &str, e: VtaError) -> OpenVTCError {
    match e {
        VtaError::Network(_) | VtaError::DidcommTransport(_) | VtaError::TspTransport(_) => {
            OpenVTCError::Vta(format!("could not reach your VTA to {action}: {e}"))
        }
        VtaError::Server { .. } => {
            OpenVTCError::Vta(format!("your VTA failed while trying to {action}: {e}"))
        }
        VtaError::Auth(_) => OpenVTCError::Auth(format!(
            "your VTA did not accept this session to {action}: {e}"
        )),
        VtaError::Forbidden(_) => OpenVTCError::Auth(format!(
            "your VTA does not allow this session to {action}: {e}"
        )),
        other => OpenVTCError::Vta(format!(
            "your VTA rejected the request to {action}: {other}"
        )),
    }
}

/// Refuse the top context, and anything outside it.
fn require_sub_context(top_context_id: &str, context_id: &str) -> Result<(), OpenVTCError> {
    if is_sub_context(context_id, top_context_id) {
        Ok(())
    } else {
        Err(OpenVTCError::Config(format!(
            "{context_id} is not a sub-context of {top_context_id}; only a community's own \
             context is deleted from here"
        )))
    }
}

/// Ask the VTA what deleting `context_id` would remove: its own preview, and
/// the preview of every sub-context beneath it (the VTA's preview covers only
/// the context named, while the delete cascades).
///
/// Either the whole subtree is previewed or the call fails — a preview missing
/// a sub-context would look complete and not be.
///
/// # Errors
///
/// The top context; the VTA unreachable or refusing any of the reads.
pub async fn preview_context_deletion(
    client: &VtaClient,
    top_context_id: &str,
    context_id: &str,
) -> Result<ContextDeletionPreview, OpenVTCError> {
    require_sub_context(top_context_id, context_id)?;
    let listing = client
        .list_contexts()
        .await
        .map_err(|e| vta_failure("list contexts", e))?;
    let below = descendants_of(context_id, listing.contexts.into_iter().map(|c| c.id));
    let mut contexts = Vec::with_capacity(below.len() + 1);
    for id in std::iter::once(context_id.to_string()).chain(below) {
        contexts.push(
            client
                .preview_delete_context(&id)
                .await
                .map_err(|e| vta_failure(&format!("preview deleting {id}"), e))?,
        );
    }
    Ok(ContextDeletionPreview {
        context_id: context_id.to_string(),
        contexts,
    })
}

/// Delete `context_id` and everything beneath it at the VTA (`force`, the
/// cascade the preview described).
///
/// # Errors
///
/// The top context; the VTA unreachable or refusing.
pub async fn delete_context(
    client: &VtaClient,
    top_context_id: &str,
    context_id: &str,
) -> Result<(), OpenVTCError> {
    require_sub_context(top_context_id, context_id)?;
    client
        .delete_context(context_id, true)
        .await
        .map_err(|e| vta_failure(&format!("delete {context_id}"), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::account::CommunityStatus;
    use chrono::Utc;
    use uuid::Uuid;

    const TOP: &str = "openvtc";

    fn persona(origin: &str) -> PersonaRecord {
        let persona_id = PersonaId::new();
        PersonaRecord {
            extra: serde_json::Map::new(),
            persona_id,
            did: format!("did:webvh:scid:example.com:{persona_id}"),
            did_document: None,
            key_refs: vec![],
            mediator_did: None,
            origin_context_id: origin.to_string(),
            created_at: Utc::now(),
            label: None,
        }
    }

    fn account() -> Account {
        Account {
            top_context_id: TOP.into(),
            ..Account::default()
        }
    }

    fn join(account: &mut Account, persona: &PersonaRecord, community: &str, context: &str) {
        account.personas.insert(persona.persona_id, persona.clone());
        account.add_membership(CommunityRecord::new_pending(
            community.into(),
            None,
            context.into(),
            persona.persona_id,
            Uuid::new_v4(),
            Utc::now(),
        ));
    }

    #[test]
    fn a_sub_context_is_strictly_below_the_top() {
        assert!(is_sub_context("openvtc/kernel", TOP));
        assert!(is_sub_context("openvtc/work/kernel", TOP));
        assert!(!is_sub_context("openvtc", TOP));
        assert!(!is_sub_context("openvtc-evil/kernel", TOP));
        assert!(!is_sub_context("openvtc/", TOP));
    }

    /// A new persona may go anywhere: a new sub-context first, then the ones in
    /// use, then the top context.
    #[test]
    fn a_new_persona_is_offered_new_existing_and_top() {
        let mut account = account();
        let work = persona("openvtc/work");
        join(&mut account, &work, "did:webvh:a", "openvtc/work");
        let options = context_options(&account, None, "openvtc/kernel");
        let kinds: Vec<_> = options.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            [ContextKind::New, ContextKind::Existing, ContextKind::Top]
        );
        assert_eq!(options[1].context_id, "openvtc/work");
        assert_eq!(options[1].communities, ["did:webvh:a"]);
        assert!(options.iter().all(|o| !o.holds_persona_keys));
    }

    /// A persona's keys live in one context, so a persona minted into a
    /// sub-context can only be presented from it.
    #[test]
    fn a_persona_with_keys_in_a_sub_context_has_one_option() {
        let mut account = account();
        let work = persona("openvtc/work");
        join(&mut account, &work, "did:webvh:a", "openvtc/work");
        let options = context_options(&account, Some(&work), "openvtc/kernel");
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].context_id, "openvtc/work");
        assert!(options[0].holds_persona_keys);
    }

    /// A persona from before per-community contexts keeps its keys in the top
    /// context; its faces can still go in a context of its own.
    #[test]
    fn a_legacy_persona_can_still_choose_where_its_faces_go() {
        let mut account = account();
        let legacy = persona("");
        join(&mut account, &legacy, "did:webvh:a", "openvtc/a");
        let options = context_options(&account, Some(&legacy), "openvtc/b");
        assert_eq!(options[0].kind, ContextKind::New);
        assert!(options.last().unwrap().holds_persona_keys);
        assert_eq!(options.last().unwrap().kind, ContextKind::Top);
    }

    #[test]
    fn isolation_reads_where_the_keys_are_and_who_shares() {
        let mut account = account();
        let alone = persona("openvtc/kernel");
        join(&mut account, &alone, "did:webvh:k", "openvtc/kernel");
        let shared = persona("openvtc/work");
        join(&mut account, &shared, "did:webvh:w1", "openvtc/work");
        join(&mut account, &shared, "did:webvh:w2", "openvtc/work");
        let legacy = persona("");
        join(&mut account, &legacy, "did:webvh:l", "openvtc/legacy");
        join(&mut account, &legacy, "did:webvh:t", TOP);

        let of = |vtc: &str| {
            let m = account.memberships().find(|m| m.vtc_did == vtc).unwrap();
            isolation(&account, m)
        };
        assert_eq!(of("did:webvh:k"), Isolation::Isolated);
        assert_eq!(of("did:webvh:w1"), Isolation::Shared(1));
        assert_eq!(of("did:webvh:l"), Isolation::KeysElsewhere);
        assert_eq!(of("did:webvh:t"), Isolation::Top);
    }

    #[test]
    fn a_new_context_must_be_new_and_well_formed() {
        let taken = |id: &str| id == "openvtc/work";
        assert_eq!(
            new_context_id(TOP, "kernel", taken).unwrap(),
            "openvtc/kernel"
        );
        assert!(new_context_id(TOP, "work", taken).is_err());
        assert!(new_context_id(TOP, "a/b", taken).is_err());
        assert!(new_context_id(TOP, "", taken).is_err());
    }

    fn end(account: &mut Account, community: &str) {
        let persona = account
            .memberships()
            .find(|m| m.vtc_did == community)
            .map(|m| m.persona_ref)
            .unwrap();
        account.membership_mut(community, persona).unwrap().status = CommunityStatus::Left;
    }

    fn membership<'a>(account: &'a Account, community: &str) -> &'a CommunityRecord {
        account
            .memberships()
            .find(|m| m.vtc_did == community)
            .unwrap()
    }

    fn application(persona: PersonaId, community: &str, context: &str) -> Application {
        let mut book = crate::vetting::VettingBook::default();
        let app = book
            .start_application(community, persona, "did:webvh:join", Utc::now())
            .unwrap();
        app.context_id = Some(context.to_string());
        book.applications.remove(0)
    }

    /// A context whose only user is the membership that is over, holding a
    /// legacy persona's faces, may be deleted.
    #[test]
    fn a_finished_membership_alone_in_its_context_may_delete_it() {
        let mut account = account();
        let legacy = persona("");
        join(&mut account, &legacy, "did:webvh:k", "openvtc/kernel");
        end(&mut account, "did:webvh:k");
        assert_eq!(
            deletable_context(&account, &[], membership(&account, "did:webvh:k")).as_deref(),
            Ok("openvtc/kernel")
        );
    }

    #[test]
    fn a_live_membership_or_the_top_context_is_never_deleted() {
        let mut account = account();
        let legacy = persona("");
        join(&mut account, &legacy, "did:webvh:k", "openvtc/kernel");
        join(&mut account, &legacy, "did:webvh:t", TOP);
        assert_eq!(
            deletable_context(&account, &[], membership(&account, "did:webvh:k")),
            Err(DeletionRefusal::StillLive)
        );
        end(&mut account, "did:webvh:t");
        assert_eq!(
            deletable_context(&account, &[], membership(&account, "did:webvh:t")),
            Err(DeletionRefusal::TopContext)
        );
    }

    /// Everything else that uses the context is named: another membership, the
    /// persona whose keys were minted there, a vetting application.
    #[test]
    fn every_other_use_of_the_context_is_named_in_the_refusal() {
        let mut account = account();
        let minted = persona("openvtc/kernel");
        let legacy = persona("");
        join(&mut account, &minted, "did:webvh:k", "openvtc/kernel");
        join(&mut account, &legacy, "did:webvh:k2", "openvtc/kernel");
        end(&mut account, "did:webvh:k");
        let applications = [application(
            legacy.persona_id,
            "did:webvh:v",
            "openvtc/kernel",
        )];

        let Err(DeletionRefusal::InUse(uses)) =
            deletable_context(&account, &applications, membership(&account, "did:webvh:k"))
        else {
            panic!("the context is in use");
        };
        assert!(
            !uses.iter().any(
                |u| matches!(u, ContextUse::Membership { vtc_did, .. } if vtc_did == "did:webvh:k")
            ),
            "the membership being cleaned up is not a use of its own context"
        );
        assert!(uses.iter().any(
            |u| matches!(u, ContextUse::Membership { vtc_did, .. } if vtc_did == "did:webvh:k2")
        ));
        assert!(uses.iter().any(
            |u| matches!(u, ContextUse::PersonaKeys { persona, .. } if *persona == minted.persona_id)
        ));
        assert!(
            uses.iter()
                .any(|u| matches!(u, ContextUse::VettingApplication { .. }))
        );
        let text = DeletionRefusal::InUse(uses).describe();
        assert!(
            text.contains("did:webvh:k2") && text.contains("did:webvh:v"),
            "{text}"
        );
    }

    #[test]
    fn a_claimed_context_includes_vetting_applications() {
        let account = account();
        let applications = [application(PersonaId::new(), "did:webvh:v", "openvtc/v")];
        assert!(context_claimed(&account, &applications, "openvtc/v"));
        assert!(!context_claimed(&account, &applications, "openvtc/w"));
    }

    #[test]
    fn descendants_are_segment_aware_and_exclude_the_context() {
        let all = [
            "openvtc",
            "openvtc/kernel",
            "openvtc/kernel/ci",
            "openvtc/kernel/ci/nightly",
            "openvtc/kernel-evil",
            "other/kernel",
        ]
        .map(String::from);
        assert_eq!(
            descendants_of("openvtc/kernel", all),
            ["openvtc/kernel/ci", "openvtc/kernel/ci/nightly"]
        );
    }

    #[test]
    fn a_preview_lists_every_item_under_its_context() {
        let preview = ContextDeletionPreview {
            context_id: "openvtc/kernel".into(),
            contexts: vec![
                DeleteContextPreviewResultBody {
                    id: "openvtc/kernel".into(),
                    keys: vec!["key-1".into()],
                    webvh_dids: vec!["did:webvh:scid:host:p".into()],
                    acl_entries_removed: vec!["did:key:zDevice".into()],
                    acl_entries_updated: vec!["did:key:zWide".into()],
                    did_templates: vec![],
                },
                DeleteContextPreviewResultBody {
                    id: "openvtc/kernel/ci".into(),
                    ..Default::default()
                },
            ],
        };
        assert_eq!(
            preview.sub_contexts().collect::<Vec<_>>(),
            ["openvtc/kernel/ci"]
        );
        assert!(!preview.holds_nothing());
        let lines = preview.lines().join("\n");
        for item in [
            "Context openvtc/kernel",
            "key-1",
            "did:webvh:scid:host:p",
            "did:key:zDevice  (entry removed)",
            "did:key:zWide  (loses this context only)",
            "Sub-context openvtc/kernel/ci",
            "nothing else",
        ] {
            assert!(lines.contains(item), "missing {item:?} in\n{lines}");
        }
    }

    #[test]
    fn only_the_exact_word_confirms() {
        assert!(confirms_deletion("DELETE"));
        for typed in ["", "delete", "DELET", "DELETE ", " DELETE"] {
            assert!(!confirms_deletion(typed), "{typed:?}");
        }
    }

    #[test]
    fn a_persona_label_suggests_its_own_context() {
        let taken = |id: &str| id == "openvtc/work";
        assert_eq!(
            suggested_context_id(TOP, "Work", "persona", taken).unwrap(),
            "openvtc/work-2"
        );
        assert_eq!(
            suggested_context_id(TOP, "日本", "persona", taken).unwrap(),
            "openvtc/persona"
        );
    }

    /// The top context and anything outside the account are refused before
    /// the VTA is asked.
    #[test]
    fn only_a_sub_context_is_previewed_or_deleted() {
        assert!(require_sub_context(TOP, TOP).is_err());
        assert!(require_sub_context(TOP, "elsewhere/kernel").is_err());
        assert!(require_sub_context(TOP, "openvtc/kernel").is_ok());
    }

    /// Unreachable, not accepted, and refused read differently.
    #[test]
    fn a_vta_failure_says_which_kind_it_was() {
        let unreachable = vta_failure("x", VtaError::DidcommTransport("timeout".into()));
        assert!(matches!(unreachable, OpenVTCError::Vta(ref m) if m.contains("could not reach")));
        let auth = vta_failure("x", VtaError::Auth("expired".into()));
        assert!(matches!(auth, OpenVTCError::Auth(ref m) if m.contains("did not accept")));
        let forbidden = vta_failure("x", VtaError::Forbidden("no".into()));
        assert!(matches!(forbidden, OpenVTCError::Auth(ref m) if m.contains("does not allow")));
        let rejected = vta_failure("x", VtaError::Validation("bad".into()));
        assert!(matches!(rejected, OpenVTCError::Vta(ref m) if m.contains("rejected")));
    }

    #[test]
    fn an_option_reads_as_a_line() {
        let option = ContextOption {
            context_id: "openvtc/work".into(),
            kind: ContextKind::Existing,
            communities: vec!["a".into(), "b".into()],
            holds_persona_keys: false,
        };
        assert_eq!(
            option.summary(),
            "openvtc/work  (shared with 2 communities)"
        );
    }
}
