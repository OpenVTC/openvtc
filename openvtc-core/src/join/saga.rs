//! What a join launch has done that a failure or a cancel must undo (#529).
//!
//! A join launch creates things before the community has the request: the
//! community's context at the VTA, possibly a freshly minted persona (persisted
//! to the account at once), and the applicant's mediator listener. Until the
//! request is out, each of those is speculative. Undoing them by hand at each
//! call site would rely on where each `.await` happens to sit when a cancel
//! drops the future.
//!
//! [`JoinSaga`] records the steps as they complete, in order:
//!
//! `ContextRegistered → Minted → ListenerUp → Submitted → Persisted`
//!
//! and [`JoinSaga::compensations`] says, from that record alone, what undoes
//! the launch at the point it stopped. One compensation per step:
//!
//! | Step | Compensation |
//! |------|--------------|
//! | context registered | none — an empty context at the VTA is harmless and reused by a retry (the cancel message says it may remain) |
//! | persona minted | forget the persona, unless something already references it |
//! | listener up | remove the listener |
//! | submitted / persisted | none — the request is out, and the community may answer it |
//!
//! A *reused* persona is never recorded as minted, so it is never forgotten.

use crate::config::account::PersonaId;

/// One thing to undo, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compensation {
    /// Tear down the applicant's mediator listener this launch installed.
    RemoveListener(String),
    /// Remove the persona this launch minted from the account (the caller checks
    /// it is not referenced, then saves).
    ForgetPersona(PersonaId),
}

/// The steps a join launch has completed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JoinSaga {
    context: Option<String>,
    minted: Option<PersonaId>,
    listener: Option<String>,
    submitted: bool,
    persisted: bool,
}

impl JoinSaga {
    /// The community's context exists at the VTA.
    pub fn context_registered(&mut self, context_id: impl Into<String>) {
        self.context = Some(context_id.into());
    }

    /// A persona was minted for this join and persisted to the account.
    pub fn minted(&mut self, persona: PersonaId) {
        self.minted = Some(persona);
    }

    /// This launch installed the applicant's listener (a listener that already
    /// existed — a reused persona's — is not ours and is never recorded).
    pub fn listener_up(&mut self, listener_id: impl Into<String>) {
        self.listener = Some(listener_id.into());
    }

    /// The listener could not be installed after all: nothing to remove.
    pub fn listener_failed(&mut self) {
        self.listener = None;
    }

    /// The join request left: from here nothing is undone.
    pub fn submitted(&mut self) {
        self.submitted = true;
    }

    /// The pending membership was recorded.
    pub fn persisted(&mut self) {
        self.persisted = true;
    }

    /// The context this launch registered, if it got that far.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// The persona this launch minted, if any.
    #[must_use]
    pub fn minted_persona(&self) -> Option<PersonaId> {
        self.minted
    }

    /// The listener this launch installed, if any.
    #[must_use]
    pub fn listener(&self) -> Option<&str> {
        self.listener.as_deref()
    }

    /// Whether the request went out.
    #[must_use]
    pub fn is_submitted(&self) -> bool {
        self.submitted
    }

    /// Whether the pending membership was recorded.
    #[must_use]
    pub fn is_persisted(&self) -> bool {
        self.persisted
    }

    /// What undoes this launch where it stopped, newest step first. Empty once
    /// the request is out.
    #[must_use]
    pub fn compensations(&self) -> Vec<Compensation> {
        if self.submitted || self.persisted {
            return Vec::new();
        }
        let mut undo = Vec::new();
        if let Some(listener) = &self.listener {
            undo.push(Compensation::RemoveListener(listener.clone()));
        }
        if let Some(persona) = self.minted {
            undo.push(Compensation::ForgetPersona(persona));
        }
        undo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_done_is_nothing_to_undo() {
        assert!(JoinSaga::default().compensations().is_empty());
    }

    #[test]
    fn a_registered_context_alone_is_left_in_place() {
        let mut saga = JoinSaga::default();
        saga.context_registered("ctx/community");
        assert!(saga.compensations().is_empty());
        assert_eq!(saga.context(), Some("ctx/community"));
    }

    #[test]
    fn a_failure_after_the_mint_forgets_the_persona() {
        let mut saga = JoinSaga::default();
        let persona = PersonaId::new();
        saga.context_registered("ctx");
        saga.minted(persona);
        assert_eq!(
            saga.compensations(),
            vec![Compensation::ForgetPersona(persona)]
        );
    }

    #[test]
    fn a_failure_after_the_listener_removes_it_before_forgetting_the_persona() {
        let mut saga = JoinSaga::default();
        let persona = PersonaId::new();
        saga.minted(persona);
        saga.listener_up("persona-listener");
        assert_eq!(
            saga.compensations(),
            vec![
                Compensation::RemoveListener("persona-listener".into()),
                Compensation::ForgetPersona(persona),
            ]
        );
    }

    #[test]
    fn a_reused_persona_is_never_forgotten() {
        let mut saga = JoinSaga::default();
        saga.listener_up("persona-listener");
        assert_eq!(
            saga.compensations(),
            vec![Compensation::RemoveListener("persona-listener".into())]
        );
    }

    #[test]
    fn a_listener_that_failed_to_install_is_not_removed() {
        let mut saga = JoinSaga::default();
        saga.listener_up("persona-listener");
        saga.listener_failed();
        assert!(saga.compensations().is_empty());
    }

    #[test]
    fn once_the_request_is_out_nothing_is_undone() {
        let mut saga = JoinSaga::default();
        saga.minted(PersonaId::new());
        saga.listener_up("persona-listener");
        saga.submitted();
        assert!(saga.compensations().is_empty());
        saga.persisted();
        assert!(saga.compensations().is_empty());
        assert!(saga.is_submitted() && saga.is_persisted());
    }
}
