//! Managing agent names on the account's own personas.
//!
//! The consumer side ([`openvtc_core::agent_name`]) *reads* agent names. This
//! module *writes* them: bind (`set`), release (`remove`), park (`disable`) and
//! resume (`enable`) a name on a persona the VTA hosts, plus `list` (the
//! authoritative registry, parked names included) and `check` (availability).
//!
//! Every verb is a VTA Trust Task (`spec/vta/webvh/agent-name/{op}/1.0`),
//! submitted through [`VtaClient::dispatch_trust_task`]. The VTA is the party
//! with authority over the account's webvh DIDs — it created them and holds
//! their update keys — so it resolves the DID's current document, edits
//! `alsoKnownAs`, signs a new version, and calls the hosting server. OpenVTC
//! only names the persona DID and the name; it never signs here.
//!
//! `remove` releases a name for anyone to reclaim; `disable` keeps it reserved
//! but stops it resolving. Both report `enabled: false`.

use anyhow::{Context, Result, anyhow};
use serde::de::DeserializeOwned;
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::did_management::agent_name::{
    AgentNameCheckResultBody, AgentNameEntry, AgentNameListResultBody, AgentNameResultBody,
};
use vta_sdk::trust_tasks;

/// Trust-task round-trips can involve a webvh publish (sign + host write), so
/// allow more headroom than a plain read.
const AGENT_NAME_TT_TIMEOUT: u64 = 60;

/// How much of an unexpected payload to quote back in an error.
///
/// Enough to see the shape — which keys are present, how they are cased — but
/// bounded, since this text reaches a one-line status message in the UI.
const PAYLOAD_EXCERPT_LIMIT: usize = 300;

/// Decode a trust-task payload, saying *why* it failed when it does.
///
/// `serde_json` names the exact field that was missing or mistyped, and the
/// payload shows what the VTA actually sent. Reporting neither — as a bare
/// `.context("decoding …")` does — produces "decoding agent-name list result",
/// which cannot be acted on: it looks identical whether the field is absent,
/// null, snake_cased, or the whole contract has drifted. That distinction is
/// the operator's only lead (VTI R6.4), and the mismatch it points at is
/// usually a version skew between this client and the VTA.
fn decode_payload<T: DeserializeOwned>(value: serde_json::Value, what: &str) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|e| {
        let mut excerpt = value.to_string();
        if excerpt.chars().count() > PAYLOAD_EXCERPT_LIMIT {
            excerpt = excerpt.chars().take(PAYLOAD_EXCERPT_LIMIT).collect();
            excerpt.push('…');
        }
        anyhow!("decoding {what}: {e}. VTA sent: {excerpt}")
    })
}

/// The host a `did:webvh` is served from (`example.com`, or `example.com:8443`
/// for a custom port) — the authority half of any agent name on it. Derived via
/// `didwebvh-rs` per the repo's did:webvh rule; `None` if the DID does not
/// parse. A did:scid DID URL is served from the host of its `src`, through the
/// did:webvh log it names (VTI-KEY-160); a bare did:scid names no host, so a
/// caller passes the persona's locator. Used only to build the scheme-less name
/// (`host/@local`) for the local display cache; the VTA derives the domain
/// itself for the actual operations.
pub(crate) fn derive_host(did: &str) -> Option<String> {
    let webvh = if vta_sdk::did_scid::is_scid(did) {
        vta_sdk::did_scid::webvh_did(did)?
    } else {
        did.to_string()
    };
    let url = didwebvh_rs::url::WebVHURL::parse_did_url(&webvh).ok()?;
    Some(match url.port {
        Some(port) => format!("{}:{port}", url.domain),
        None => url.domain,
    })
}

/// Bind (or refresh) `name` on `did`. The resulting document claims the name;
/// it resolves once the host serves the new version.
pub(crate) async fn set_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0,
        did,
        Some(name),
    )
    .await
}

/// Release `name` from `did` — it stops resolving and is free for anyone to
/// reclaim. Destructive.
pub(crate) async fn remove_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0,
        did,
        Some(name),
    )
    .await
}

/// Resume serving a parked `name` on `did`.
pub(crate) async fn enable_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0,
        did,
        Some(name),
    )
    .await
}

/// Park `name` on `did` — it stops resolving but stays reserved to this DID.
pub(crate) async fn disable_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameResultBody> {
    dispatch(
        vta,
        trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0,
        did,
        Some(name),
    )
    .await
}

/// The DID's agent-name registry as the host holds it — parked names included.
pub(crate) async fn list_names(vta: &VtaClient, did: &str) -> Result<Vec<AgentNameEntry>> {
    let value = vta
        .dispatch_trust_task(
            trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0,
            serde_json::json!({ "did": did }),
            AGENT_NAME_TT_TIMEOUT,
        )
        .await
        .context("agent-name list task failed")?;
    let body: AgentNameListResultBody = decode_payload(value, "agent-name list result")?;
    Ok(body.names)
}

/// Whether `name` is free to claim on `did`'s host. `available` is `false` for a
/// reserved name too — `reserved` distinguishes the two.
pub(crate) async fn check_name(
    vta: &VtaClient,
    did: &str,
    name: &str,
) -> Result<AgentNameCheckResultBody> {
    let value = vta
        .dispatch_trust_task(
            trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0,
            serde_json::json!({ "did": did, "name": name }),
            AGENT_NAME_TT_TIMEOUT,
        )
        .await
        .context("agent-name check task failed")?;
    decode_payload(value, "agent-name check result")
}

/// Shared submit for the four mutating verbs, which share the `{ did, name }`
/// body and `AgentNameResultBody` shape.
async fn dispatch(
    vta: &VtaClient,
    type_uri: &str,
    did: &str,
    name: Option<&str>,
) -> Result<AgentNameResultBody> {
    let mut payload = serde_json::json!({ "did": did });
    if let Some(name) = name {
        payload["name"] = serde_json::Value::String(name.to_string());
    }
    let value = vta
        .dispatch_trust_task(type_uri, payload, AGENT_NAME_TT_TIMEOUT)
        .await
        .with_context(|| format!("agent-name task {type_uri} failed"))?;
    decode_payload(value, "agent-name result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_host_pulls_the_domain_from_a_webvh_did() {
        assert_eq!(
            derive_host("did:webvh:QmScid:example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn derive_host_includes_a_custom_port() {
        // did:webvh encodes ports as %3A within the path segment.
        assert_eq!(
            derive_host("did:webvh:QmScid:example.com%3A8443").as_deref(),
            Some("example.com:8443")
        );
    }

    #[test]
    fn derive_host_rejects_a_non_webvh_did() {
        assert_eq!(derive_host("did:key:z6Mk"), None);
    }

    #[test]
    fn a_did_scid_is_served_from_its_src_host() {
        assert_eq!(
            derive_host("did:scid:vh:1:QmScid?src=example.com/alice").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            derive_host("did:scid:vh:1:QmScid?src=example.com%3A8443").as_deref(),
            Some("example.com:8443")
        );
        // A bare did:scid names no host.
        assert_eq!(derive_host("did:scid:vh:1:QmScid"), None);
    }

    #[test]
    fn decode_payload_passes_a_well_formed_result_through() {
        let value = serde_json::json!({
            "did": "did:webvh:QmScid:example.com",
            "names": [{ "name": "alice", "enabled": true, "createdAt": 1_700_000_000u64 }],
        });
        let body: AgentNameListResultBody =
            decode_payload(value, "agent-name list result").expect("should decode");
        assert_eq!(body.names.len(), 1);
        assert_eq!(body.names[0].name, "alice");
    }

    /// The failure that sent an operator hunting: the message must name the
    /// missing field and quote what actually arrived, not just say "decoding
    /// agent-name list result".
    #[test]
    fn decode_payload_names_the_missing_field_and_quotes_the_payload() {
        // `names` omitted — what a server that drops empty collections sends.
        let value = serde_json::json!({ "did": "did:webvh:QmScid:example.com" });
        let err = decode_payload::<AgentNameListResultBody>(value, "agent-name list result")
            .expect_err("must not decode");
        let msg = format!("{err:#}");

        assert!(msg.contains("agent-name list result"), "{msg}");
        assert!(
            msg.contains("names"),
            "must name the offending field: {msg}"
        );
        assert!(
            msg.contains("VTA sent:") && msg.contains("did:webvh:QmScid:example.com"),
            "must quote the payload: {msg}"
        );
    }

    /// Casing drift is the other likely cause, and reads very differently from a
    /// missing field — so the reported reason has to tell them apart.
    #[test]
    fn decode_payload_surfaces_casing_drift() {
        let value = serde_json::json!({
            "did": "did:webvh:QmScid:example.com",
            // snake_case, where the contract is camelCase `createdAt`.
            "names": [{ "name": "alice", "enabled": true, "created_at": 1_700_000_000u64 }],
        });
        let err = decode_payload::<AgentNameListResultBody>(value, "agent-name list result")
            .expect_err("must not decode");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("createdAt"),
            "must name the expected key: {msg}"
        );
    }

    /// The excerpt is bounded — this text lands in a one-line status message.
    #[test]
    fn decode_payload_truncates_a_large_payload() {
        let value = serde_json::json!({ "did": "x".repeat(2_000) });
        let err = decode_payload::<AgentNameListResultBody>(value, "agent-name list result")
            .expect_err("must not decode");
        let msg = format!("{err:#}");
        assert!(msg.contains('…'), "should be elided: {msg}");
        assert!(
            msg.len() < 600,
            "excerpt must stay bounded, got {}",
            msg.len()
        );
    }
}
