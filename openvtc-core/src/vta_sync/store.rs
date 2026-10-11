//! The VTA's application-state store, as the sync engine needs it.
//!
//! A trait rather than direct [`VtaClient`] calls so the engine is testable
//! against an in-memory store with real version and tombstone semantics; the
//! [`VtaClient`] implementation is a thin mapping onto
//! `vta/app-state/{list,put-many,delete}/1.0`.
//!
//! Every call goes through the SDK's Trust-Task dispatch, which carries the
//! app-state timeout, so a VTA that stops answering produces an error rather
//! than a hung sync (R1.2).

use std::future::Future;

use serde_json::Value;
use vta_sdk::client::VtaClient;
use vta_sdk::error::VtaError;
use vta_sdk::protocols::app_state::{
    AppStateListResponse, AppStatePutManyResponse, AppStateWrite, PutManyMode, WriteResult,
};

use super::NAMESPACE;

/// Records per page when reading. The VTA caps a page itself; asking for a
/// modest one keeps each response well under the message-size limits.
const PAGE_SIZE: usize = 100;

/// Writes per `put-many`. The VTA accepts up to 64; fewer keeps a batch of
/// large records under its aggregate request budget.
pub(crate) const PUT_BATCH: usize = 16;

/// Why a sync could not complete — kept apart so each gets its own words
/// (R6.4): an unreachable VTA, a refusal, and a VTA without the store are
/// three different things for the user to do about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The VTA does not serve `vta/app-state/*` — it predates the store.
    Unsupported,
    /// The VTA could not be reached, or did not answer in time.
    Unreachable(String),
    /// The VTA refused this account's credential for the store.
    Refused(String),
    /// The VTA answered with something this build did not expect.
    Contract(String),
    /// The VTA has reaped deletions older than our watermark; resuming the
    /// change feed would silently miss them, so a snapshot is needed.
    WatermarkTooOld,
}

impl SyncError {
    /// One sentence for the activity log.
    #[must_use]
    pub fn explain(&self) -> String {
        match self {
            SyncError::Unsupported => "This VTA does not offer application-state storage, so \
                 settings stay on this device only. Upgrading the VTA enables sync."
                .to_string(),
            SyncError::Unreachable(e) => {
                format!("Could not reach the VTA to sync settings ({e}); will retry.")
            }
            SyncError::Refused(e) => format!(
                "The VTA refused to store this account's settings ({e}). Check this \
                 account's access to its context."
            ),
            SyncError::Contract(e) => format!(
                "The VTA answered the settings sync in an unexpected way ({e}). This build \
                 and the VTA may disagree on the app-state contract."
            ),
            SyncError::WatermarkTooOld => {
                "The VTA no longer holds the change history this device needs; \
                 re-reading everything."
                    .to_string()
            }
        }
    }

    /// Whether trying again later could succeed.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, SyncError::Unreachable(_) | SyncError::WatermarkTooOld)
    }
}

impl From<VtaError> for SyncError {
    fn from(e: VtaError) -> Self {
        match e {
            VtaError::UnsupportedTaskType { .. } => SyncError::Unsupported,
            VtaError::Network(_)
            | VtaError::DidcommTransport(_)
            | VtaError::TspTransport(_)
            | VtaError::Server { .. }
            | VtaError::Unavailable { .. } => SyncError::Unreachable(e.to_string()),
            VtaError::Auth(_) | VtaError::Forbidden(_) => SyncError::Refused(e.to_string()),
            VtaError::Protocol(ref m) if m.contains("watermarkTooOld") => {
                SyncError::WatermarkTooOld
            }
            other => SyncError::Contract(other.to_string()),
        }
    }
}

/// What a delete did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The record is gone (or was already).
    Deleted,
    /// The record changed since we last saw it; the next pull brings it.
    Conflict,
}

/// The app-state operations the sync engine uses, scoped to the `openvtc`
/// namespace of one context.
pub trait AppStateStore: Send + Sync {
    /// One page of the change feed after `since`, tombstones included.
    fn changes_since(
        &self,
        context_id: &str,
        since: u64,
        cursor: Option<&str>,
    ) -> impl Future<Output = Result<AppStateListResponse, SyncError>> + Send;

    /// One page of a snapshot of every live record.
    fn snapshot(
        &self,
        context_id: &str,
        cursor: Option<&str>,
    ) -> impl Future<Output = Result<AppStateListResponse, SyncError>> + Send;

    /// Apply a batch of writes (at most 64, the VTA's cap), each on its own
    /// merits.
    fn put_many(
        &self,
        context_id: &str,
        writes: Vec<AppStateWrite>,
    ) -> impl Future<Output = Result<Vec<WriteResult>, SyncError>> + Send;

    /// Delete one record, if it is still at `expected_version`.
    fn delete(
        &self,
        context_id: &str,
        key: &str,
        expected_version: u64,
    ) -> impl Future<Output = Result<DeleteOutcome, SyncError>> + Send;
}

fn parse<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, SyncError> {
    serde_json::from_value(v).map_err(|e| SyncError::Contract(e.to_string()))
}

impl AppStateStore for VtaClient {
    async fn changes_since(
        &self,
        context_id: &str,
        since: u64,
        cursor: Option<&str>,
    ) -> Result<AppStateListResponse, SyncError> {
        let v = self
            .app_state_changes_since(
                context_id,
                NAMESPACE,
                since,
                None,
                true,
                Some(PAGE_SIZE),
                cursor,
            )
            .await?;
        parse(v)
    }

    async fn snapshot(
        &self,
        context_id: &str,
        cursor: Option<&str>,
    ) -> Result<AppStateListResponse, SyncError> {
        let v = self
            .app_state_list(
                context_id,
                Some(NAMESPACE),
                None,
                true,
                Some(PAGE_SIZE),
                cursor,
            )
            .await?;
        parse(v)
    }

    async fn put_many(
        &self,
        context_id: &str,
        writes: Vec<AppStateWrite>,
    ) -> Result<Vec<WriteResult>, SyncError> {
        let v = self
            .app_state_put_many(context_id, NAMESPACE, writes, PutManyMode::Independent)
            .await?;
        Ok(parse::<AppStatePutManyResponse>(v)?.results)
    }

    async fn delete(
        &self,
        context_id: &str,
        key: &str,
        expected_version: u64,
    ) -> Result<DeleteOutcome, SyncError> {
        match self
            .app_state_delete(context_id, NAMESPACE, key, Some(expected_version))
            .await
        {
            Ok(_) => Ok(DeleteOutcome::Deleted),
            Err(VtaError::Conflict(_)) => Ok(DeleteOutcome::Conflict),
            Err(VtaError::Protocol(m)) if m.contains("versionConflict") => {
                Ok(DeleteOutcome::Conflict)
            }
            Err(e) => Err(e.into()),
        }
    }
}
