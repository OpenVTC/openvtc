//! Off-loop batch resolution of agent names.
//!
//! The runtime loop collects the DIDs whose names are uncached or stale
//! ([`Config::agent_name_refresh_targets`](openvtc_core::config::Config::agent_name_refresh_targets))
//! and hands the whole list to [`resolve_batch`] as a single background job. One
//! job (not one per DID) because the background-dispatch busy-guard is
//! per-domain: per-DID jobs on the shared `AgentName` domain would serialise.
//!
//! Inside the job the DIDs resolve concurrently but **bounded** — a sliding
//! window of at most [`CONCURRENCY`] in flight — so a large account does not
//! open an unbounded fan of connections at the resolver (VTI R1.4). The job does
//! I/O only; its `(did, name)` results are applied to the config on the loop
//! thread by `background_dispatch::apply_outcome`, preserving the single-mutator
//! invariant.

// The resolver type, re-exported by the TDK facade so this crate needs no
// direct dependency on the cache SDK.
use affinidi_tdk::did_resolver::DIDCacheClient;
use tokio::task::JoinSet;
use tracing::debug;

/// Maximum concurrent DID resolutions inside one batch job.
const CONCURRENCY: usize = 4;

/// One sweep: every uncached or stale DID, resolved by [`resolve_batch`].
pub(crate) struct AgentNameRefreshJob {
    pub(crate) resolver: DIDCacheClient,
    pub(crate) dids: Vec<String>,
}

impl crate::state_handler::background_dispatch::Job for AgentNameRefreshJob {
    fn domain(&self) -> crate::state_handler::background_dispatch::DispatchDomain {
        crate::state_handler::background_dispatch::DispatchDomain::AgentName
    }

    async fn execute(self) -> crate::state_handler::background_dispatch::DispatchOutcome {
        crate::state_handler::background_dispatch::DispatchOutcome::AgentName(
            resolve_batch(self.resolver, self.dids).await,
        )
    }
}

/// Resolve each DID to a verified agent name (or `None`), bounded to
/// [`CONCURRENCY`] in flight. The result pairs each input DID with its verified
/// name; order is not preserved (the caller keys by DID).
pub(crate) async fn resolve_batch(
    resolver: DIDCacheClient,
    dids: Vec<String>,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::with_capacity(dids.len());
    let mut pending = dids.into_iter();
    let mut in_flight: JoinSet<(String, Option<String>)> = JoinSet::new();

    let spawn_one = |set: &mut JoinSet<(String, Option<String>)>, did: String| {
        let resolver = resolver.clone();
        set.spawn(async move {
            // Resolve via the reason-carrying entry point and log the outcome.
            // A DID that renders as a raw DID is otherwise indistinguishable on
            // screen from one that has no name at all, so without this line the
            // only way to tell an unreachable naming host from an unclaimed name
            // from a spoof is to reproduce it by hand (VTI R6.4).
            let name = match openvtc_core::agent_name::resolve_name_outcome(&resolver, &did).await {
                Ok(outcome) => {
                    debug!("agent name for {did}: {}", outcome.summary());
                    outcome.name().map(str::to_owned)
                }
                Err(e) => {
                    debug!("agent name for {did}: DID did not resolve: {e}");
                    None
                }
            };
            (did, name)
        });
    };

    // Prime the window, then keep it full: each completion spawns the next DID.
    for _ in 0..CONCURRENCY {
        if let Some(did) = pending.next() {
            spawn_one(&mut in_flight, did);
        }
    }
    while let Some(joined) = in_flight.join_next().await {
        // A resolution task does not panic (its body is fallible-by-Option), so
        // a JoinError would be a cancellation; drop it and keep going.
        if let Ok(pair) = joined {
            out.push(pair);
        }
        if let Some(did) = pending.next() {
            spawn_one(&mut in_flight, did);
        }
    }

    let resolved = out.iter().filter(|(_, name)| name.is_some()).count();
    debug!(
        "agent name sweep: {} DID(s) checked, {resolved} name(s) verified",
        out.len()
    );
    out
}
