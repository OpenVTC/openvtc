//! Why an online provisioning attempt failed, in terms of what the operator
//! should do next.
//!
//! Setup is two steps: run a `pnm` command that grants the freshly minted setup
//! DID on the VTA, then connect as that DID and bootstrap. The most common way
//! to fail step 2 is to have skipped step 1 — pressing Enter on the
//! instructions page before running the command — and the raw failure did not
//! say so. It said `forbidden: DID not in ACL: did:key:…`, under a list of
//! diagnostics, with "`[ENTER] to return to the ACL instructions and retry`".
//!
//! R6.4 asks for the opposite of one fixed hint: the operator has to be able to
//! tell *the VTA said no* from *the VTA could not be reached* from *the VTA
//! answered something we did not expect*, because each is fixed in a different
//! place. [`classify`] makes that call, and the two setup pages route on it:
//!
//! | class | fixed where | the pages |
//! |---|---|---|
//! | [`ProvisionFailure::NotAuthorised`] | the PNM session | back to step 1, same DID, banner |
//! | [`ProvisionFailure::GrantSpent`] | the PNM session (re-grant) | back to step 1, delete + re-create |
//! | [`ProvisionFailure::Unreachable`] | the network / the VTA's host | stay on step 2, retry |
//! | [`ProvisionFailure::Other`] | it depends — the error says | verbatim, then step 1 or retry |
//!
//! # Why this reads strings
//!
//! It would rather match on [`vta_sdk::error::VtaError`] — `is_auth()`,
//! `Forbidden`, `Network` — and cannot. The provisioning runner flattens every
//! failure into the operator-facing `String` of [`VtaEvent::Failed`] and
//! [`DiagStatus::Failed`] before it reaches us; the URL-direct path's
//! `ProvisionError::WorkflowFailed` carries the same string. What survives the
//! flattening is:
//!
//! - **which diagnostic row failed** — typed ([`DiagCheck`]), and the
//!   strongest signal there is: a failed `ResolveDid` is reachability whatever
//!   its text says;
//! - **the SDK's own `Display` prefixes** — `forbidden: `, `network error: `,
//!   `tsp transport error: ` — which `thiserror` renders from the variant, so
//!   they move only when the variant does;
//! - **the VTA's refusal phrases** — `DID not in ACL`, `ACL entry expired`
//!   (`vti-common`'s `check_acl`), the hand-off refusals in `vta-service`'s
//!   `operations::acl` and `provision_integration` (VTI-ACL-053/054/055/058).
//!
//! Every needle is listed once, below, next to where it comes from, so a
//! wording change upstream is a one-line fix here. If the SDK ever carries a
//! typed failure on `VtaEvent::Failed`, match that instead.
//!
//! The order matters and is deliberate: a refusal outranks a transport fault.
//! The runner degrades TSP → DIDComm → REST on a pre-auth failure, so one run
//! can hold a failed TSP row (network) *and* a later `forbidden` from the leg
//! that did reach the VTA — and the VTA answering "no" is the finding.
//!
//! [`VtaEvent::Failed`]: vta_sdk::provision_client::VtaEvent::Failed

use super::{MessageType, VtaSetupState};
use vta_sdk::provision_client::{DiagCheck, DiagStatus};

/// What went wrong, as far as it decides the operator's next move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionFailure {
    /// The VTA answered and refused the setup DID: it has no ACL entry there.
    /// Almost always the PNM command was not run — or ran against another VTA
    /// or another context. The commands on step 1 are still the right ones.
    NotAuthorised,
    /// The VTA knows the setup DID, but its entry can no longer be used for the
    /// rollover. It has to be deleted and re-created, which is the
    /// existing-context command pair on step 1.
    GrantSpent(GrantProblem),
    /// The VTA (or its mediator, or the DID's publication host) could not be
    /// reached or did not answer. Nothing about the PNM step; retry.
    Unreachable,
    /// Anything else — a version skew, a 5xx, a rate limit, a malformed reply.
    /// Shown verbatim; the error itself is the hint.
    Other,
}

/// Why a grant that exists cannot be exercised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantProblem {
    /// The entry's one-hour expiry passed (`ACL entry expired`, VTI-ACL-055).
    Expired,
    /// The one-time hand-off was already exercised, so the entry is gone
    /// (VTI-ACL-055). Usually an earlier attempt whose reply was lost.
    AlreadyUsed,
    /// The entry was created without `--handoff`, so the VTA refuses to roll
    /// it over (VTI-ACL-053/054/058). The marker is fixed at creation.
    NoHandoff,
    /// This attempt got past the rollover — the VTA minted the long-term admin
    /// and retired the setup DID's entry — and then a later step failed. A
    /// retry needs the setup DID granted again.
    UsedByThisAttempt,
}

/// Re-grant needles, from `vta-service`. Checked first: each is also a
/// `forbidden`, and the fix differs — delete and re-create, not create.
///
/// - `no one-time hand-off` — `provision_integration::refuse_unmarked_expiring_rollover`
/// - `carries no hand-off marker` — `operations::acl::exercise_handoff` (VTI-ACL-058)
const NO_HANDOFF: &[&str] = &["no one-time hand-off", "carries no hand-off marker"];

/// - `acl entry expired` — `vti_common::acl::check_acl{,_entry}`
/// - `hand-off entry for … has expired`, `… hand-off is bounded by has
///   expired` — `operations::acl::exercise_handoff` (VTI-ACL-055)
const EXPIRED: &[&str] = &[
    "acl entry expired",
    "hand-off entry for",
    "hand-off is bounded by has expired",
];

/// - `there is no hand-off to exercise` — `operations::acl` (VTI-ACL-055): the
///   entry is gone, which after a hand-off means it was exercised.
const ALREADY_USED: &[&str] = &["there is no hand-off to exercise"];

/// The VTA refusing the DID outright.
///
/// - `did not in acl` — `vti_common::acl::check_acl{,_entry}`
/// - `is not authorized on` — the SDK's `provision_client::authz` probe, which
///   turns a `permissionDenied` into that sentence
/// - `forbidden: ` / `authentication failed: ` — `VtaError::{Forbidden,Auth}`'s
///   `Display`, i.e. `is_auth()` after flattening
/// - `failed (401` / `failed (403` — the SDK's REST challenge/authenticate
///   (`provision_client::auth_rest`) renders the HTTP status that way
/// - `permissiondenied` — the Trust Task code, should a body carry it raw
const NOT_AUTHORISED: &[&str] = &[
    "did not in acl",
    "is not authorized on",
    "forbidden: ",
    "authentication failed: ",
    "failed (401",
    "failed (403",
    "permissiondenied",
];

/// Transport faults: the request never got an answer.
///
/// - `network error: ` — `VtaError::Network`'s `Display` (`is_network()`)
/// - `tsp transport error: ` / `didcomm transport error: ` /
///   `mediator handshake failed` — the session-transport variants
/// - `could not connect to vta` — `provision_client::auth_rest`
/// - `could not resolve ` — the runner's own resolve failure
/// - the rest are `reqwest`/`hyper`/OS phrasings for refused, DNS, TLS and
///   timeouts, which reach us inside a `({msg})` suffix
const UNREACHABLE: &[&str] = &[
    "network error: ",
    "tsp transport error: ",
    "didcomm transport error: ",
    "mediator handshake failed",
    "could not connect to vta",
    "could not resolve ",
    "error sending request",
    "error trying to connect",
    "tcp connect error",
    "connection refused",
    "connection reset",
    "dns error",
    "failed to lookup address",
    "certificate",
    "timed out",
];

/// Classify a failed provisioning attempt from what the runner left on the
/// state: its error messages and the diagnostics rows.
///
/// Call only once `completed` is `CompletedFail`; on any other state it
/// answers [`ProvisionFailure::Other`], which is never wrong, only unhelpful.
pub fn classify(vta: &VtaSetupState) -> ProvisionFailure {
    // Past the rollover the setup DID was accepted and its entry retired. A
    // failure from here is about the long-term admin's session, never the PNM
    // step — but a retry starts from the setup DID again, so it needs
    // re-granting whatever went wrong.
    if !vta.credential_did.is_empty() {
        return ProvisionFailure::GrantSpent(GrantProblem::UsedByThisAttempt);
    }

    let haystack = failure_text(vta);
    let has = |needles: &[&str]| needles.iter().any(|n| haystack.contains(n));

    if has(NO_HANDOFF) {
        return ProvisionFailure::GrantSpent(GrantProblem::NoHandoff);
    }
    if has(EXPIRED) {
        return ProvisionFailure::GrantSpent(GrantProblem::Expired);
    }
    if has(ALREADY_USED) {
        return ProvisionFailure::GrantSpent(GrantProblem::AlreadyUsed);
    }
    if has(NOT_AUTHORISED) {
        return ProvisionFailure::NotAuthorised;
    }

    // The DID never resolved: nothing reached the VTA, whatever the text.
    let resolve_failed = vta
        .diagnostics
        .iter()
        .any(|e| e.check == DiagCheck::ResolveDid && matches!(e.status, DiagStatus::Failed(_)));
    if resolve_failed || has(UNREACHABLE) {
        return ProvisionFailure::Unreachable;
    }
    ProvisionFailure::Other
}

/// Every failure string the attempt produced, lower-cased into one haystack:
/// the terminal error messages and each failed diagnostics row (whose detail
/// is often the un-prefixed inner error the terminal message wraps).
fn failure_text(vta: &VtaSetupState) -> String {
    let mut out = String::new();
    for m in &vta.messages {
        if let MessageType::Error(e) = m {
            out.push_str(&e.to_lowercase());
            out.push('\n');
        }
    }
    for e in &vta.diagnostics {
        if let DiagStatus::Failed(s) = &e.status {
            out.push_str(&s.to_lowercase());
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::provision_client::DiagEntry;

    fn failed_with(message: &str) -> VtaSetupState {
        VtaSetupState {
            messages: vec![MessageType::Error(message.to_string())],
            ..Default::default()
        }
    }

    fn row(check: DiagCheck, status: DiagStatus) -> DiagEntry {
        DiagEntry { check, status }
    }

    /// The case this module exists for: Enter pressed before the PNM command
    /// ran. Each of the shapes the three transports produce for it.
    #[test]
    fn a_setup_did_the_vta_does_not_know_is_not_authorised() {
        for msg in [
            // TSP / DIDComm: the authz probe's permissionDenied.
            "did:key:z6Mk is not authorized on did:webvh:Qm:vta.example. Run `pnm acl \
             create …` against that VTA (permission denied)",
            // The provision call itself, wrapped by ProvisionError::Rpc.
            "AdminRotation provisioning failed after auth. (provision-integration call \
             failed: forbidden: DID not in ACL: did:key:z6Mk)",
            // REST: the challenge refused with a status.
            "Could not complete REST authentication against the VTA. Confirm the `pnm acl \
             create` command ran successfully for this setup DID and that the VTA's REST \
             endpoint is reachable. (challenge request failed (403 Forbidden): DID not in ACL)",
            "Could not complete REST authentication against the VTA. (authentication \
             failed (401 Unauthorized): )",
        ] {
            assert_eq!(
                classify(&failed_with(msg)),
                ProvisionFailure::NotAuthorised,
                "{msg}"
            );
        }
    }

    /// An expired or exercised grant is a re-grant, not a first grant: the
    /// operator has to delete the entry before `acl create` will take it.
    #[test]
    fn an_unusable_grant_is_told_apart_from_a_missing_one() {
        let cases = [
            (
                "provision-integration call failed: forbidden: ACL entry expired: did:key:z6Mk",
                GrantProblem::Expired,
            ),
            (
                "forbidden: the hand-off entry for did:key:z6Mk has expired; an expired \
                 marker cannot be exercised (VTI-ACL-055)",
                GrantProblem::Expired,
            ),
            (
                "forbidden: did:key:z6Mk has no ACL entry, so there is no hand-off to \
                 exercise — it may already have been exercised (VTI-ACL-055)",
                GrantProblem::AlreadyUsed,
            ),
            (
                "provision-integration call failed: forbidden: did:key:z6Mk's entry expires \
                 at 1790859174 and carries no one-time hand-off, so it cannot roll over",
                GrantProblem::NoHandoff,
            ),
        ];
        for (msg, problem) in cases {
            let class = classify(&failed_with(msg));
            assert_eq!(class, ProvisionFailure::GrantSpent(problem), "{msg}");
        }
    }

    /// R6.4: a VTA that cannot be reached must not be blamed on the PNM step —
    /// even though the SDK's own pre-auth sentence mentions `pnm acl create`.
    #[test]
    fn an_unreachable_vta_is_not_blamed_on_the_pnm_step() {
        for msg in [
            "Could not open a TSP session to the VTA's `#tsp` mediator (did:webvh:m). \
             Confirm the mediator is reachable and that the `pnm acl create` command ran \
             successfully for setup DID did:key:z6Mk. (tsp transport error: connection \
             closed)",
            "Could not complete REST authentication against the VTA. Confirm the `pnm acl \
             create` command ran successfully for this setup DID and that the VTA's REST \
             endpoint is reachable. (could not connect to VTA at https://vta.example/\
             trust-tasks: error sending request)",
            "URL-direct provisioning failed: workflow failed: … (dns error: failed to \
             lookup address information)",
            "Could not open an authenticated DIDComm session to the VTA. (didcomm \
             transport error: timed out)",
        ] {
            let class = classify(&failed_with(msg));
            assert_eq!(class, ProvisionFailure::Unreachable, "{msg}");
        }
    }

    /// A failed resolve is a reachability failure by construction — the runner
    /// words it as advice ("Verify the DID is correct…"), not as a transport
    /// error, so the row is what tells.
    #[test]
    fn a_failed_resolve_row_is_unreachable_whatever_the_message_says() {
        let mut state = failed_with(
            "Could not resolve did:webvh:Qm:vta.example. Verify the DID is correct and its \
             publication endpoint is reachable.",
        );
        state.diagnostics = vec![row(
            DiagCheck::ResolveDid,
            DiagStatus::Failed("HTTP 404".into()),
        )];
        assert_eq!(classify(&state), ProvisionFailure::Unreachable);
    }

    /// One run can carry both: TSP failed to connect, the fallback leg reached
    /// the VTA and was refused. The refusal is the finding.
    #[test]
    fn a_refusal_outranks_an_earlier_transport_fault() {
        let mut state = failed_with("forbidden: DID not in ACL: did:key:z6Mk");
        state.diagnostics = vec![row(
            DiagCheck::AuthenticateTSP,
            DiagStatus::Failed("tsp transport error: connection refused".into()),
        )];
        assert_eq!(classify(&state), ProvisionFailure::NotAuthorised);
    }

    /// The row detail counts too: the terminal message is sometimes only the
    /// SDK's advice, with the VTA's own words on the row.
    #[test]
    fn a_refusal_on_a_diagnostics_row_is_found() {
        let mut state = failed_with("Provisioning ended without an admin credential.");
        state.diagnostics = vec![row(
            DiagCheck::ProvisionIntegration,
            DiagStatus::Failed("forbidden: DID not in ACL: did:key:z6Mk".into()),
        )];
        assert_eq!(classify(&state), ProvisionFailure::NotAuthorised);
    }

    /// Everything else is shown as it came — a skew, a 5xx, a rate limit — and
    /// is neither blamed on PNM nor called a network fault.
    #[test]
    fn anything_else_is_other() {
        for msg in [
            "this VTA does not serve https://trusttasks.org/spec/provision/integration/0.3",
            "AdminRotation provisioning failed after auth. (server error (500): boom)",
            "rate limited by vta — retry after 30s",
            "Setup DID not generated yet — restart the setup wizard.",
        ] {
            let class = classify(&failed_with(msg));
            assert_eq!(class, ProvisionFailure::Other, "{msg}");
        }
        // Info lines are progress, not failure, and never classify.
        let state = VtaSetupState {
            messages: vec![MessageType::Info("forbidden: DID not in ACL".into())],
            ..Default::default()
        };
        assert_eq!(classify(&state), ProvisionFailure::Other);
    }

    /// Once the VTA has rolled the setup DID over, it has said yes; what failed
    /// came after. But its entry is retired, so a retry needs a re-grant — and
    /// a network fault after the rollover must not read as "retry as-is".
    #[test]
    fn a_failure_after_the_rollover_needs_a_regrant_not_a_first_grant() {
        let mut state = failed_with("TSP session open failed: tsp transport error: timed out");
        state.credential_did = "did:key:z6MkLongTermAdmin".into();
        assert_eq!(
            classify(&state),
            ProvisionFailure::GrantSpent(GrantProblem::UsedByThisAttempt)
        );
    }
}
