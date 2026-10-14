//! Reading what builds that ran the hidden-vetting engine on this device stored, and dropping it.
//!
//! Those builds kept each PCS key in the protected config (an applicant's `hiddenState`, a
//! vetter's `snapshot` and its enrolments' blinding). The VTA holds every key now
//! ([`super::pcs_vta`]), and the old ones cannot move into it, so a stored record that still
//! carries one is read — the containing structs refuse unknown members — and the key is thrown
//! away. The next save writes the record without it.

use serde::{Deserialize, Deserializer, de::IgnoredAny};

/// Whether the member was there: read and discarded, answering `true`. With `#[serde(default)]`
/// an absent member is `false`.
pub(crate) fn present<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    IgnoredAny::deserialize(d).map(|_| true)
}

/// Read and discard the member.
pub(crate) fn discard<'de, D: Deserializer<'de>>(d: D) -> Result<(), D::Error> {
    IgnoredAny::deserialize(d).map(|_| ())
}
