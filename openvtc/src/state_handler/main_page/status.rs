//! A panel's status line, typed by severity.
//!
//! Every main-page panel shows at most one status line. Its colour comes from
//! the [`Severity`] the producer set — the code that knows whether the thing it
//! is reporting worked — never from the wording of the text. Deciding colour
//! from wording would draw failures phrased without "Error" ("Couldn't
//! archive: …", "Messaging unavailable — …") as successes (#577).

/// How a status line reads: its colour comes from this, never from its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Neutral information.
    Info,
    /// A request is on its way; cleared when its answer lands.
    Progress,
    /// A change that was made, or confirmed by the other side.
    Success,
    /// Nothing was done, and why (a key that does not apply here).
    Warning,
    /// A refusal, a failed send, a timeout, a contract mismatch.
    Error,
}

/// One status line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub text: String,
    pub severity: Severity,
}

impl Status {
    /// A status line with an explicit severity.
    #[must_use]
    pub fn new(severity: Severity, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            severity,
        }
    }

    #[must_use]
    pub fn info(text: impl Into<String>) -> Self {
        Self::new(Severity::Info, text)
    }

    #[must_use]
    pub fn progress(text: impl Into<String>) -> Self {
        Self::new(Severity::Progress, text)
    }

    #[must_use]
    pub fn success(text: impl Into<String>) -> Self {
        Self::new(Severity::Success, text)
    }

    #[must_use]
    pub fn warning(text: impl Into<String>) -> Self {
        Self::new(Severity::Warning, text)
    }

    #[must_use]
    pub fn error(text: impl Into<String>) -> Self {
        Self::new(Severity::Error, text)
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}
