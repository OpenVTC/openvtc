//! Task queue for tracking in-progress OpenVTC workflows.
//!
//! Tasks represent pending actions such as relationship handshakes, trust pings,
//! and VRC exchanges. Each task has a unique ID, a [`TaskType`], and a creation
//! timestamp.

use std::{collections::HashMap, fmt::Display, sync::Arc};

use chrono::{DateTime, Utc};
use dtg_credentials::DTGCredential;
use serde::{Deserialize, Serialize};

use tracing::debug;

use crate::{config::account::PersonaId, relationships::RelationshipRequestBody, vrc::VrcRequest};

/// Defined Task Types for OpenVTC.
///
/// Each variant represents a discrete workflow step that the user may need to
/// act on or that is awaiting a remote response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskType {
    /// We sent a relationship request to a remote party.
    RelationshipRequestOutbound { to: Arc<String> },
    /// A remote party sent us a relationship request awaiting our response.
    RelationshipRequestInbound {
        from: Arc<String>,
        to: Arc<String>,
        request: RelationshipRequestBody,
    },
    /// Our relationship request was rejected by the remote party.
    RelationshipRequestRejected,
    /// Our relationship request was accepted by the remote party.
    RelationshipRequestAccepted,
    /// The relationship handshake has been finalized (fully established).
    RelationshipRequestFinalized,
    /// A trust-ping was sent to verify connectivity with the remote party.
    ///
    /// `remote_p_did` is the relationship's remote persona DID — the key into
    /// `Relationships`. Look the relationship up there at the use site rather
    /// than holding an embedded snapshot.
    ///
    /// On-disk compatibility (R20): pre-R20 configs serialized an embedded
    /// `relationship` object here instead of `remote_p_did`. Such configs still
    /// load — `remote_p_did` is `#[serde(default)]` (empty) and the now-extra
    /// `relationship` field is ignored. The acceptable degradation: a pre-R20
    /// *in-flight* TrustPing task (these live for seconds) loads with an empty
    /// `remote_p_did`, so its remote display falls back to blank until the task
    /// is replaced; the relationship itself still exists in `Relationships`.
    TrustPing {
        from: Arc<String>,
        to: Arc<String>,
        #[serde(default)]
        remote_p_did: Arc<String>,
    },
    /// A trust-pong response was received from the remote party.
    TrustPong,
    /// We sent a VRC request to a remote party.
    ///
    /// `remote_p_did` is the relationship key into `Relationships`. See
    /// [`TaskType::TrustPing`] for the pre-R20 on-disk compatibility note.
    VRCRequestOutbound {
        #[serde(default)]
        remote_p_did: Arc<String>,
    },
    /// A remote party sent us a VRC request awaiting our response.
    ///
    /// `remote_p_did` is the relationship key into `Relationships`. See
    /// [`TaskType::TrustPing`] for the pre-R20 on-disk compatibility note.
    VRCRequestInbound {
        request: VrcRequest,
        #[serde(default)]
        remote_p_did: Arc<String>,
    },
    /// Our VRC request was rejected by the remote party.
    VRCRequestRejected,
    /// A VRC has been issued (either by us or received from a remote party).
    VRCIssued { vrc: Box<DTGCredential> },
    /// Vetter: an applicant redeemed one of our tickets. Open a session when
    /// the two of you are together.
    VettingRequestInbound {
        /// Our desk handle (`crate::vetting::VettingBook::desk_entry`).
        request_id: String,
        /// The applicant's join DID.
        applicant: Arc<String>,
        /// The community they are applying to.
        community: String,
    },
    /// Applicant: a vetter opened a session. Read the match code to each
    /// other, then send the card.
    VettingSessionInbound {
        /// The application.
        application_id: String,
        /// The session document id.
        session_id: String,
        /// The vetter.
        vetter: Arc<String>,
    },
    /// Vetter: the applicant's card arrived and verified. Check the person,
    /// then attest or decline.
    VettingCardReceived {
        /// Our desk handle.
        request_id: String,
        /// The applicant's join DID.
        applicant: Arc<String>,
    },
}

impl Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let friendly_name = match self {
            TaskType::RelationshipRequestOutbound { .. } => "Relationship Request (Outbound)",
            TaskType::RelationshipRequestInbound { .. } => "Relationship Request (Inbound)",
            TaskType::RelationshipRequestRejected => "Relationship Request Rejected",
            TaskType::RelationshipRequestAccepted => "Relationship Request Accepted",
            TaskType::RelationshipRequestFinalized => "Relationship Request Finalized",
            TaskType::TrustPing { .. } => "Trust Ping Sent",
            TaskType::TrustPong => "Trust Pong Received",
            TaskType::VRCRequestOutbound { .. } => "VRC Request Sent",
            TaskType::VRCRequestInbound { .. } => "VRC Request Received",
            TaskType::VRCRequestRejected => "VRC Request Rejected",
            TaskType::VRCIssued { .. } => "VRC Issued",
            TaskType::VettingRequestInbound { .. } => "Vetting Request (Inbound)",
            TaskType::VettingSessionInbound { .. } => "Vetting Session (Send Card)",
            TaskType::VettingCardReceived { .. } => "Vetting Card Received",
        };
        write!(f, "{}", friendly_name)
    }
}

/// Collection of in-progress tasks, indexed by task ID.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tasks {
    /// key: Task ID
    ///
    /// Plain values (no `Arc<Mutex>`): there is exactly one mutating task (the
    /// `StateHandler` loop), so mutation goes through `&mut` and is infallible.
    pub tasks: HashMap<Arc<String>, Task>,
}

impl Tasks {
    /// Removes a task by ID. Returns `true` if the task was found and removed.
    pub fn remove(&mut self, id: &Arc<String>) -> bool {
        let removed = self.tasks.remove(id).is_some();
        if removed {
            debug!("task removed: id={}", id);
        }
        removed
    }

    /// Creates a new untagged task (no owning persona) with the given ID and
    /// type, inserts it, and returns a reference to it. Use [`Tasks::new_task_for`]
    /// to attribute the task to a specific persona for community-scoping (D10).
    pub fn new_task(&mut self, id: &Arc<String>, type_: TaskType) -> &Task {
        self.new_task_for(id, type_, None)
    }

    /// Like [`Tasks::new_task`] but tags the task with the persona that owns it
    /// (D10 attribution): the working community's persona for an outbound task, or
    /// the addressed persona for an inbound one. The community-scoped inbox filters
    /// tasks to the selected community's persona via this tag (R-C-6).
    pub fn new_task_for(
        &mut self,
        id: &Arc<String>,
        type_: TaskType,
        our_persona: Option<PersonaId>,
    ) -> &Task {
        debug!("task created: type={:?}, id={}", type_, id);
        let task = Task {
            id: id.clone(),
            type_,
            created: Utc::now(),
            our_persona,
        };
        self.tasks.entry(id.clone()).insert_entry(task).into_mut()
    }

    /// Returns the task at the given iteration position, or `None` if out of bounds.
    ///
    /// Note: HashMap iteration order is not stable across insertions and removals.
    pub fn get_by_pos(&self, pos: usize) -> Option<&Task> {
        self.tasks.iter().nth(pos).map(|(_, task)| task)
    }

    /// Retrieves a task by ID or returns None
    pub fn get_by_id(&self, id: &Arc<String>) -> Option<&Task> {
        self.tasks.get(id)
    }

    /// Clears all tasks. Returns `true` if any tasks were removed.
    pub fn clear(&mut self) -> bool {
        let flag = !self.tasks.is_empty();
        self.tasks.clear();
        flag
    }
}

/// A single in-progress OpenVTC task.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Task {
    /// Unique task identifier.
    pub id: Arc<String>,

    /// The kind of workflow this task represents.
    pub type_: TaskType,

    /// Timestamp when this task was created.
    pub created: DateTime<Utc>,

    /// Which of our account personas owns this task (D10 attribution). Set to the
    /// working community's persona (outbound) or the addressed persona (inbound);
    /// the community-scoped inbox filters tasks to the selected community's
    /// persona via this tag (R-C-6). `None` on legacy/single-persona tasks,
    /// attributed to the sole persona at view time. Skipped when `None` so older
    /// configs round-trip byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub our_persona: Option<PersonaId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tasks_default_empty() {
        let tasks = Tasks::default();
        assert!(tasks.tasks.is_empty(), "Default Tasks should have no tasks");
    }

    /// Forward-load compatibility (R20): a pre-R20 `Tasks` config serialized the
    /// 3 relationship-embedding variants with an embedded `relationship` object
    /// instead of the new `remote_p_did` key. Such a config must still LOAD: the
    /// now-extra `relationship` field is ignored by serde (no
    /// `deny_unknown_fields`) and the missing `remote_p_did` defaults to empty.
    /// The acceptable degradation: the in-flight task loses its embedded
    /// snapshot (the relationship still exists in `Relationships`).
    #[test]
    fn pre_r20_task_with_embedded_relationship_still_loads() {
        // A pre-R20 VRCRequestOutbound task carried an embedded `relationship`
        // object (an `Arc<Mutex<Relationship>>` serializes as a bare object).
        let old_json = r#"{
            "tasks": {
                "msg-1": {
                    "id": "msg-1",
                    "type_": {
                        "VRCRequestOutbound": {
                            "relationship": {
                                "task_id": "t1",
                                "our_did": "did:webvh:example:us",
                                "remote_did": "did:webvh:example:them",
                                "remote_p_did": "did:webvh:example:them",
                                "created": "2024-01-02T03:04:05Z",
                                "state": "Established"
                            }
                        }
                    },
                    "created": "2024-01-02T03:04:05Z"
                }
            }
        }"#;

        let tasks: Tasks = serde_json::from_str(old_json).expect("pre-R20 config still loads");
        let task = tasks
            .get_by_id(&Arc::new("msg-1".to_string()))
            .expect("task present");
        match &task.type_ {
            TaskType::VRCRequestOutbound { remote_p_did } => {
                // The embedded `relationship` was ignored; the new key defaults
                // to empty (the documented transient degradation).
                assert!(
                    remote_p_did.is_empty(),
                    "remote_p_did defaults to empty when absent from an old config"
                );
            }
            other => panic!("unexpected variant: {other}"),
        }
    }

    #[test]
    fn test_new_task_and_retrieve() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-1".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestRejected);

        assert_eq!(tasks.tasks.len(), 1);
        assert!(tasks.get_by_id(&id).is_some(), "Should find task by ID");
    }

    #[test]
    fn test_remove_task() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-1".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestAccepted);

        assert!(
            tasks.remove(&id),
            "remove should return true for existing task"
        );
        assert!(
            tasks.tasks.is_empty(),
            "Tasks should be empty after removal"
        );

        let missing = Arc::new("nonexistent".to_string());
        assert!(
            !tasks.remove(&missing),
            "remove should return false for missing task"
        );
    }

    #[test]
    fn test_get_by_position() {
        let mut tasks = Tasks::default();
        let id = Arc::new("task-pos".to_string());
        tasks.new_task(&id, TaskType::TrustPong);

        let found = tasks.get_by_pos(0);
        assert!(found.is_some(), "Should retrieve task at position 0");

        let out_of_bounds = tasks.get_by_pos(99);
        assert!(
            out_of_bounds.is_none(),
            "Should return None for out-of-bounds position"
        );
    }

    #[test]
    fn test_clear_tasks() {
        let mut tasks = Tasks::default();
        assert!(!tasks.clear(), "Clearing empty tasks should return false");

        let id = Arc::new("task-clear".to_string());
        tasks.new_task(&id, TaskType::RelationshipRequestFinalized);
        assert!(tasks.clear(), "Clearing non-empty tasks should return true");
        assert!(tasks.tasks.is_empty());
    }

    #[test]
    fn test_task_type_display() {
        let variants: Vec<(TaskType, &str)> = vec![
            (
                TaskType::RelationshipRequestOutbound {
                    to: Arc::new("did:example:1".to_string()),
                },
                "Relationship Request (Outbound)",
            ),
            (
                TaskType::RelationshipRequestRejected,
                "Relationship Request Rejected",
            ),
            (
                TaskType::RelationshipRequestAccepted,
                "Relationship Request Accepted",
            ),
            (
                TaskType::RelationshipRequestFinalized,
                "Relationship Request Finalized",
            ),
            (TaskType::TrustPong, "Trust Pong Received"),
            (TaskType::VRCRequestRejected, "VRC Request Rejected"),
        ];

        for (variant, expected) in variants {
            let display = format!("{}", variant);
            assert_eq!(
                display, expected,
                "TaskType display mismatch for {:?}",
                variant
            );
        }
    }
}
