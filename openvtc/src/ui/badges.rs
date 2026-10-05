//! Badges for the cryptographic properties a holder should not have to dig for.
//!
//! Drawn as filled blocks rather than coloured words so they read at a glance
//! in any list: whether a credential (or a community's signing) is
//! post-quantum, and whether a community proves vetting with a PCS
//! zero-knowledge proof that keeps vetters' identities from it. One definition
//! here, so the same property looks the same on every page.

use crate::colors::{COLOR_BORDER, COLOR_ORANGE, COLOR_SUCCESS};
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
/// that enough vetters vetted the person, not who they were. Green: this is
/// the protected case, for applicant and vetter alike.
#[must_use]
pub fn pcs_zkp() -> Span<'static> {
    badge(" ✓ PCS ZKP ", COLOR_SUCCESS)
}

/// Vetting is by named statements: the community sees each vetter's DID
/// against the applicant. Not wrong — but a disclosure, for both parties, and
/// drawn in the caution colour so it is never mistaken for the protected case.
#[must_use]
pub fn vetters_named() -> Span<'static> {
    badge(" ⚠ VETTERS NAMED ", COLOR_ORANGE)
}

/// The style for a sentence explaining [`vetters_named`].
#[must_use]
pub fn caution() -> Style {
    Style::new().fg(COLOR_ORANGE)
}

/// The style for a sentence explaining [`pcs_zkp`].
#[must_use]
pub fn protected() -> Style {
    Style::new().fg(COLOR_SUCCESS)
}

fn badge(text: &'static str, background: Color) -> Span<'static> {
    Span::styled(text, Style::new().fg(Color::Black).bg(background).bold())
}

/// What [`pqc`] means, for the line a page gives it once.
pub const PQC_MEANING: &str = "signed with a post-quantum key (ML-DSA) as well as a classical one";

/// What [`vetters_named`] means to an applicant.
pub const NAMED_FOR_APPLICANT: &str = "the community will see which vetters vouched for you — \
     each statement carries its vetter's DID";

/// What [`vetters_named`] means to a vetter.
pub const NAMED_FOR_VETTER: &str = "your statement goes to the community with your DID on it — \
     it will know you vouched for this person";

/// What [`pcs_zkp`] means to a vetter.
pub const ZKP_FOR_VETTER: &str = "your attestation is counted in a zero-knowledge proof — the \
     community never learns it was you";

/// What [`pcs_zkp`] means, for the line a page gives it once.
pub const PCS_ZKP_MEANING: &str = "vetting is proven with a PCS zero-knowledge proof — the community \
     learns that enough vetters vouched for you, not who they were";
