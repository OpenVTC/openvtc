//! Badges for the cryptographic properties a holder should not have to dig for.
//!
//! Drawn as filled blocks rather than coloured words so they read at a glance
//! in any list: whether a credential (or a community's signing) is
//! post-quantum, and whether a community proves vetting with a PCS
//! zero-knowledge proof that keeps vetters' identities from it. One definition
//! here, so the same property looks the same on every page.

use crate::colors::{COLOR_BORDER, COLOR_SOFT_PURPLE};
use ratatui::{
    style::{Color, Style},
    text::Span,
};

/// Signed with a post-quantum key (ML-DSA beside the classical signature).
#[must_use]
pub fn pqc() -> Span<'static> {
    badge(" PQC-SIGNED ", COLOR_BORDER)
}

/// Vetting is proven with a PCS zero-knowledge proof: the community learns
/// that enough vetters vetted the person, not who they were.
#[must_use]
pub fn pcs_zkp() -> Span<'static> {
    badge(" PCS ZKP ", COLOR_SOFT_PURPLE)
}

fn badge(text: &'static str, background: Color) -> Span<'static> {
    Span::styled(text, Style::new().fg(Color::Black).bg(background).bold())
}

/// What [`pqc`] means, for the line a page gives it once.
pub const PQC_MEANING: &str = "signed with a post-quantum key (ML-DSA) as well as a classical one";

/// What [`pcs_zkp`] means, for the line a page gives it once.
pub const PCS_ZKP_MEANING: &str = "vetting is proven with a PCS zero-knowledge proof — the community \
     learns that enough vetters vouched for you, not who they were";
