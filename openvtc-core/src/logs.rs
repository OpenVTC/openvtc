//! Local audit log for OpenVTC operations.
//!
//! Provides a bounded FIFO log ([`Logs`]) that records timestamped messages
//! categorized by [`LogFamily`].

use std::{collections::VecDeque, fmt::Display};

use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Category of a log message.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum LogFamily {
    /// Relationship lifecycle events.
    Relationship,
    /// Contact management events.
    Contact,
    /// Task creation and completion events.
    Task,
    /// Configuration changes.
    Config,
    /// Community membership lifecycle: join submitted, admitted, rejected,
    /// withdrawn, left; the credentials that carry those transitions.
    ///
    /// Added because none of the families above covered the ceremony that
    /// matters most. A join produced a detailed running commentary on the join
    /// screen and *nothing* durable, so after a restart there was no record
    /// that it had ever been attempted — which is exactly when you go looking.
    Community,
}

impl Display for LogFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LogFamily::Relationship => "RELATIONSHIP",
            LogFamily::Contact => "CONTACT",
            LogFamily::Task => "TASK",
            LogFamily::Config => "CONFIG",
            LogFamily::Community => "COMMUNITY",
        };
        write!(f, "{}", s)
    }
}

/// A single timestamped log entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct LogMessage {
    /// When the log message was created.
    pub created: chrono::DateTime<Utc>,

    /// Category of this log entry.
    pub type_: LogFamily,

    /// Human-readable log message.
    pub message: String,
}

/// Bounded FIFO log that evicts the oldest entries when the limit is reached.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Logs {
    /// Log entries in insertion order (oldest first).
    pub messages: VecDeque<LogMessage>,
    /// Maximum number of entries to retain.
    ///
    /// **Not persisted**, deliberately. It is a policy constant — nothing sets
    /// it but [`Default`] — and serializing it meant every config written
    /// before a change pinned the *old* value forever: raising the default
    /// would have silently done nothing for existing users, who are the only
    /// ones with logs to lose. `skip` makes it come from code on every load.
    ///
    /// A stored `limit` in an older config is simply ignored (nothing here
    /// denies unknown fields), so no migration is needed.
    #[serde(skip, default = "default_limit")]
    pub limit: usize,
}

/// Retained-entry ceiling. Raised 100 → 200: at 100, a single busy session's
/// inbound traffic could evict the community-lifecycle entries that are the
/// reason to keep a log at all.
fn default_limit() -> usize {
    200
}

impl Default for Logs {
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
            limit: default_limit(),
        }
    }
}

/// Longest message a log entry keeps, in characters. Entries routinely quote
/// text a peer chose (a rejection reason, an error message); the cap keeps one
/// peer from filling the persisted config with it.
pub const MAX_LOG_MESSAGE_CHARS: usize = 1024;

impl Logs {
    /// Appends a new log entry, evicting the oldest entry if the limit is exceeded.
    ///
    /// The message is sanitised here, so no caller can forget: ANSI escapes,
    /// control characters and bidi / zero-width characters are stripped
    /// ([`crate::display::sanitize_display`]) and it is cut to
    /// [`MAX_LOG_MESSAGE_CHARS`]. Many entries quote peer-supplied text, and
    /// this log is persisted and rendered in the TUI.
    pub fn insert(&mut self, type_: LogFamily, message: String) {
        self.messages.push_back(LogMessage {
            created: Utc::now(),
            type_,
            message: crate::display::sanitize_display(&message, MAX_LOG_MESSAGE_CHARS),
        });

        self.trim();
    }

    /// Takes in the entries of an older log (the plaintext `PublicConfig` log
    /// of a config written before the log moved to the encrypted tier),
    /// sanitising them as [`Logs::insert`] would, and keeps the newest
    /// [`Logs::limit`] of the combined set in time order.
    pub fn absorb(&mut self, older: Logs) {
        let mut combined: Vec<LogMessage> = older
            .messages
            .into_iter()
            .map(|mut m| {
                m.message = crate::display::sanitize_display(&m.message, MAX_LOG_MESSAGE_CHARS);
                m
            })
            .chain(self.messages.drain(..))
            .collect();
        // Stable: entries with the same timestamp keep their order.
        combined.sort_by_key(|m| m.created);
        self.messages = combined.into();
        self.trim();
    }

    /// Whether the log holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn trim(&mut self) {
        while self.messages.len() > self.limit {
            self.messages.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logs_default_empty() {
        let logs = Logs::default();
        assert!(
            logs.messages.is_empty(),
            "Default Logs should have no messages"
        );
        assert_eq!(logs.limit, 200, "Default limit should be 200");
    }

    #[test]
    fn test_logs_insert() {
        let mut logs = Logs::default();
        logs.insert(LogFamily::Config, "test message".to_string());

        assert_eq!(logs.messages.len(), 1);
        assert_eq!(logs.messages[0].message, "test message");
    }

    #[test]
    fn test_logs_fifo_limit() {
        let mut logs = Logs {
            messages: VecDeque::new(),
            limit: 3,
        };

        logs.insert(LogFamily::Task, "first".to_string());
        logs.insert(LogFamily::Task, "second".to_string());
        logs.insert(LogFamily::Task, "third".to_string());
        assert_eq!(logs.messages.len(), 3);

        // Inserting a fourth should evict the first (FIFO)
        logs.insert(LogFamily::Task, "fourth".to_string());
        assert_eq!(logs.messages.len(), 3, "Should not exceed limit");
        assert_eq!(
            logs.messages[0].message, "second",
            "Oldest message should have been removed"
        );
        assert_eq!(logs.messages[2].message, "fourth");
    }

    /// Peer-supplied text is cleaned and capped on the way in, whoever the
    /// caller is (#568).
    #[test]
    fn insert_strips_bidi_and_control_characters_and_caps_length() {
        let mut logs = Logs::default();
        logs.insert(
            LogFamily::Relationship,
            "Rejected: \u{202E}evil\u{2066}\x1b[31mred\x1b[0m\nnext\u{200B}".to_string(),
        );
        assert_eq!(logs.messages[0].message, "Rejected: evilrednext");

        logs.insert(LogFamily::Task, "x".repeat(MAX_LOG_MESSAGE_CHARS * 4));
        assert_eq!(
            logs.messages[1].message.chars().count(),
            MAX_LOG_MESSAGE_CHARS
        );
    }

    #[test]
    fn absorb_merges_in_time_order_sanitises_and_keeps_the_newest() {
        let t = |s: i64| chrono::DateTime::<Utc>::from_timestamp(s, 0).unwrap();
        let entry = |s: i64, m: &str| LogMessage {
            created: t(s),
            type_: LogFamily::Contact,
            message: m.to_string(),
        };
        let older = Logs {
            messages: VecDeque::from([entry(1, "one"), entry(3, "three\u{202E}")]),
            limit: 200,
        };
        let mut logs = Logs {
            messages: VecDeque::from([entry(2, "two"), entry(4, "four")]),
            limit: 3,
        };
        logs.absorb(older);
        let got: Vec<_> = logs.messages.iter().map(|m| m.message.as_str()).collect();
        assert_eq!(got, ["two", "three", "four"]);
    }

    #[test]
    fn test_log_family_display() {
        assert_eq!(format!("{}", LogFamily::Relationship), "RELATIONSHIP");
        assert_eq!(format!("{}", LogFamily::Contact), "CONTACT");
        assert_eq!(format!("{}", LogFamily::Task), "TASK");
        assert_eq!(format!("{}", LogFamily::Config), "CONFIG");
        assert_eq!(format!("{}", LogFamily::Community), "COMMUNITY");
    }

    /// An existing config picks up the current ceiling rather than the one it
    /// was written with.
    ///
    /// This is the whole reason `limit` is `skip`ped. A serialized limit pins
    /// every config on disk to the ceiling it was written with (`"limit": 100`),
    /// so raising the default would change nothing for exactly the users who
    /// have logs to lose, while passing every test written against a fresh
    /// `Default`.
    #[test]
    fn a_stored_limit_does_not_pin_an_old_ceiling() {
        let stored = r#"{"messages": [], "limit": 100}"#;
        let logs: Logs = serde_json::from_str(stored).expect("an older config still parses");
        assert_eq!(
            logs.limit, 200,
            "the ceiling comes from code, not from what the config was written with"
        );
    }

    /// And it is not written back out, so this cannot regress.
    #[test]
    fn the_limit_is_not_persisted() {
        let json = serde_json::to_value(Logs::default()).expect("serialises");
        assert!(
            json.get("limit").is_none(),
            "limit is policy, not user data — persisting it is what caused the bug above"
        );
    }
}
