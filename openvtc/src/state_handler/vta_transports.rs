//! Off-loop probe of the transports a VTA advertises.
//!
//! A bare `VTA URL` on the VTA panel says nothing about *how* the CLI is
//! talking to the VTA — the URL stays populated on the DIDComm path
//! too, where it is only the REST fallback. What the operator needs is the pair
//! "what does this VTA offer" / "which one are we on".
//!
//! The second half is free (see
//! [`VtaTransports::in_use`](crate::state_handler::main_page::content::VtaTransports::in_use)).
//! The first needs the VTA's DID document resolved, so it runs here as a
//! background job on its own dispatch domain and is applied to the panel state
//! on the loop thread, preserving the single-mutator invariant.
//!
//! The endpoint extraction is **not** hand-rolled: `vta_sdk`'s
//! `provision_client::resolve_vta` already reads the `#tsp` (`TSPTransport`),
//! `#vta-rest` and `DIDCommMessaging` services out of the document, and the
//! setup flow calls the same function — so the panel and the bootstrap
//! diagnostics can never disagree about what a VTA advertises.
//!
//! `ResolvedVta` surfaces `#tsp` as well as DIDComm and REST (upstream
//! OpenVTC/verifiable-trust-infrastructure#765). A resolver that surfaced only
//! those two would render a TSP-enabled VTA that advertises nothing else as
//! `DIDComm (in use) · only transport offered` — a claim the panel has no way
//! to know is false. Taking the transports from the SDK rather than reaching
//! into the DID document here keeps the panel and the SDK from disagreeing in
//! either direction.

use crate::state_handler::main_page::content::AdvertisedTransports;

/// One probe of `vta_did`, by [`probe`].
pub(crate) struct VtaTransportsProbe {
    pub(crate) vta_did: String,
}

impl crate::state_handler::background_dispatch::Job for VtaTransportsProbe {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::VtaTransports
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::VtaTransports(
            probe(self.vta_did).await,
        )
    }
}

/// Ceiling on one probe. `resolve_vta` resolves a DID document through the
/// resolver cache and sets no deadline of its own, so the bound is imposed here
/// (VTI R1.2): a hung publication endpoint must produce an error the panel can
/// show, not a job that never returns. A job that never returns would also hold
/// the `VtaTransports` dispatch domain for the life of the process, which is
/// what stops the tick from ever retrying.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Probe `vta_did` for its advertised transports.
///
/// Never fails: a resolve error or a timeout comes back as an
/// `AdvertisedTransports` with [`error`](AdvertisedTransports::error) set and
/// both endpoints `None`, so the panel can say "could not check" instead of
/// rendering an unreachable VTA as one that offers nothing (VTI R6.4). The two
/// cases carry distinct messages so the operator can tell an unreachable
/// endpoint from one that answered with something unusable.
pub(crate) async fn probe(vta_did: String) -> AdvertisedTransports {
    let failed = |reason: String| {
        tracing::debug!("VTA transport probe for {vta_did} failed: {reason}");
        AdvertisedTransports {
            tsp_mediator_did: None,
            mediator_did: None,
            rest_url: None,
            error: Some(reason),
        }
    };

    match tokio::time::timeout(
        PROBE_TIMEOUT,
        vta_sdk::provision_client::resolve_vta(&vta_did),
    )
    .await
    {
        Ok(Ok(resolved)) => AdvertisedTransports {
            tsp_mediator_did: resolved.tsp_mediator_did,
            mediator_did: resolved.mediator_did,
            rest_url: resolved.rest_url,
            error: None,
        },
        Ok(Err(e)) => failed(e.to_string()),
        Err(_) => failed(format!(
            "timed out after {}s resolving the VTA's DID document",
            PROBE_TIMEOUT.as_secs()
        )),
    }
}
