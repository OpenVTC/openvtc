//! A page's view of the published [`State`] without copying it (#556).
//!
//! The state handler publishes an `Arc<State>`. [`Shared`] holds the `Arc` and
//! derefs to the part a page renders, so a props update is a reference-count
//! increment — not a clone of the whole main-page model or the join state on
//! every update, whether or not the page is on screen — and the page reads its
//! fields as if it owned them.
//!
//! A page that edits its props locally (a selection the next update
//! overwrites) still can: the first write copies the part, and only that page's
//! copy changes.

use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crate::state_handler::state::State;

/// One part of a published [`State`], borrowed from the shared snapshot.
pub struct Shared<T: 'static> {
    state: Arc<State>,
    part: fn(&State) -> &T,
    /// A local copy, made by the first write through [`DerefMut`].
    edited: Option<Box<T>>,
}

impl<T: 'static> Shared<T> {
    pub fn new(state: &Arc<State>, part: fn(&State) -> &T) -> Self {
        Shared {
            state: Arc::clone(state),
            part,
            edited: None,
        }
    }
}

impl<T: 'static> Deref for Shared<T> {
    type Target = T;

    fn deref(&self) -> &T {
        match &self.edited {
            Some(edited) => edited,
            None => (self.part)(&self.state),
        }
    }
}

impl<T: Clone + 'static> DerefMut for Shared<T> {
    fn deref_mut(&mut self) -> &mut T {
        let part = self.part;
        let state = &self.state;
        self.edited
            .get_or_insert_with(|| Box::new(part(state).clone()))
    }
}

impl<T: Clone + 'static> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Shared {
            state: Arc::clone(&self.state),
            part: self.part,
            edited: self.edited.clone(),
        }
    }
}

impl<T: fmt::Debug + 'static> fmt::Debug for Shared<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_reads_through_to_the_snapshot_without_copying_it() {
        let mut state = State::default();
        state.main_page.log("seen through the share");
        let state = Arc::new(state);
        let part = Shared::new(&state, |s| &s.main_page);
        assert_eq!(Arc::strong_count(&state), 2, "shared, not copied");
        assert!(
            part.activity_log
                .iter()
                .any(|e| e.summary.contains("seen through the share"))
        );
        let again = part.clone();
        assert_eq!(Arc::strong_count(&state), 3);
        assert!(std::ptr::eq(&*part, &*again));
    }

    #[test]
    fn a_local_edit_copies_the_part_and_leaves_the_snapshot_alone() {
        let state = Arc::new(State::default());
        let mut part = Shared::new(&state, |s| &s.main_page);
        part.log("only this page's copy");
        assert!(
            part.activity_log
                .iter()
                .any(|e| e.summary.contains("only this page's copy"))
        );
        assert!(state.main_page.activity_log.is_empty());
    }
}
