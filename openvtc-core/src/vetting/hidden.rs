//! Hidden-vetter admission: reading what a community publishes, and refusing what this build
//! cannot honour.
//!
//! A community that counts vetting statements from a zero-knowledge proof publishes the
//! parameters an applicant proves against under `vetting.ext`, in a namespace it controls, and
//! marks that namespace in `vetting.extCritical` (Trust Tasks SPEC §4.5.1, manifest 0.2).
//!
//! Criticality is why this module exists at all. Without it, a client that does not implement
//! the namespace ignores it — per the framework's default rule — gathers ordinary named
//! statements and presents them to a criterion whose whole purpose is that it never receives
//! them. The community sees a named submission, the applicant sees a rejection, and neither
//! learns that a downgrade happened. Marked critical, this client stops instead.
//!
//! **Read from the raw criterion, not the parsed one.** `VettingRequirements` is a generated
//! type: it carries the members its schema declares and drops the rest. `ext` is a declared
//! member as of manifest 0.2 + framework 0.4 (`dtgwg-trust-tasks-tf#600`), so it survives the
//! parse once this workspace takes a `trust-tasks-rs` release carrying it — until then the raw
//! criterion is the only place it can be read from, and reading it there works either way.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The namespace this build implements.
pub const HIDDEN_VETTING_NS: &str = "org.openvtc.hidden-vetting";

/// The suite this build implements: Σ-PS with Tag_DDH over BLS12-381.
pub const SUITE: &str = "ps-ddh-bls12381";

/// What a community publishes so an applicant can build a proof, and a vetter can attest.
///
/// Public values only — verification keys and which labels are live. The secrets stay with the
/// community.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HiddenParams {
    /// The proof suite. This build implements [`SUITE`] and refuses the rest.
    pub suite: String,
    /// The community's helper verification key, multibase.
    pub helper_key: String,
    /// The attestation-token verification key, multibase. Never the same key as `helperKey`.
    pub token_key: String,
    /// Live vetter class labels, current first (`["vetter/2026-10", "vetter/2026-09"]`).
    pub vetter_labels: Vec<String>,
    /// Live token labels (`["token/2026-10", "token/event/summit"]`).
    pub token_labels: Vec<String>,
}

/// Why a criterion could not be adopted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HiddenError {
    /// The criterion marks a namespace critical that this build does not implement. The
    /// framework's `unsupportedExtension`: the client understood the task and refused over one
    /// namespace, rather than applying in a way the community did not ask for.
    #[error(
        "this community requires `{0}`, which this version of OpenVTC does not implement — \
         applying without it would send the community something it does not accept"
    )]
    UnsupportedExtension(String),
    /// Our own namespace is marked critical but is unreadable, which is the same refusal: we
    /// cannot honour what we cannot parse.
    #[error("this community's `{HIDDEN_VETTING_NS}` parameters could not be read: {0}")]
    Unreadable(String),
    /// A suite this build does not implement, in our own namespace.
    #[error("this community uses the `{0}` proof suite, which this version does not implement")]
    UnsupportedSuite(String),
}

/// What a criterion asks of this client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Statements name their vetters, as they always have.
    Named,
    /// Statements are counted from a proof, under these parameters.
    Hidden(Box<HiddenParams>),
}

/// Read the mode from a criterion **as received**.
///
/// `raw` is the criterion object from the manifest payload, not a re-serialised parse of it.
///
/// Returns [`Mode::Named`] when the criterion publishes no hidden-vetting namespace, which is
/// every criterion today. Returns an error only where the criterion marks something critical
/// that this build cannot honour — the one case where falling back would be worse than failing.
pub fn read_mode(raw: &Value) -> Result<Mode, HiddenError> {
    let vetting = raw.get("vetting");
    let critical: Vec<&str> = vetting
        .and_then(|v| v.get("extCritical"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    // Every critical namespace this build does not implement is a refusal, ours or not.
    if let Some(unknown) = critical.iter().find(|ns| **ns != HIDDEN_VETTING_NS) {
        return Err(HiddenError::UnsupportedExtension((*unknown).to_string()));
    }

    let ours = vetting
        .and_then(|v| v.get("ext"))
        .and_then(|e| e.get(HIDDEN_VETTING_NS));
    let Some(ours) = ours else {
        // Marked critical but absent is the community contradicting itself; refuse rather than
        // guess which half it meant.
        if critical.contains(&HIDDEN_VETTING_NS) {
            return Err(HiddenError::Unreadable(
                "named in extCritical but absent from ext".into(),
            ));
        }
        return Ok(Mode::Named);
    };

    let params: HiddenParams = match serde_json::from_value(ours.clone()) {
        Ok(p) => p,
        Err(e) => {
            // Unreadable parameters are only fatal where the community said they were
            // load-bearing. Unmarked, they are advisory and this client carries on named.
            return if critical.contains(&HIDDEN_VETTING_NS) {
                Err(HiddenError::Unreadable(e.to_string()))
            } else {
                Ok(Mode::Named)
            };
        }
    };
    if params.suite != SUITE {
        return if critical.contains(&HIDDEN_VETTING_NS) {
            Err(HiddenError::UnsupportedSuite(params.suite))
        } else {
            Ok(Mode::Named)
        };
    }
    Ok(Mode::Hidden(Box::new(params)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params() -> Value {
        json!({
            "suite": SUITE,
            "helperKey": "zHelperKey",
            "tokenKey": "zTokenKey",
            "vetterLabels": ["vetter/2026-10", "vetter/2026-09"],
            "tokenLabels": ["token/2026-10"]
        })
    }

    fn criterion(ext: Value, critical: Option<Value>) -> Value {
        let mut vetting = json!({ "version": "0.1", "minStatements": 2, "ext": ext });
        if let Some(c) = critical {
            vetting["extCritical"] = c;
        }
        json!({ "id": "kernel-developer", "vetting": vetting })
    }

    #[test]
    fn a_criterion_without_the_namespace_is_the_named_path() {
        assert_eq!(read_mode(&json!({ "id": "plain" })).unwrap(), Mode::Named);
        assert_eq!(
            read_mode(&json!({ "id": "plain", "vetting": { "minStatements": 2 } })).unwrap(),
            Mode::Named
        );
    }

    #[test]
    fn our_namespace_is_read_whether_or_not_it_is_marked() {
        let ext = json!({ HIDDEN_VETTING_NS: params() });
        for critical in [None, Some(json!([HIDDEN_VETTING_NS]))] {
            match read_mode(&criterion(ext.clone(), critical)).unwrap() {
                Mode::Hidden(p) => {
                    assert_eq!(p.helper_key, "zHelperKey");
                    assert_eq!(p.vetter_labels.len(), 2);
                }
                Mode::Named => panic!("the namespace is present and readable"),
            }
        }
    }

    #[test]
    fn a_critical_namespace_we_do_not_implement_is_refused() {
        // This is the whole point of criticality: no silent fallback to the named path.
        let raw = criterion(
            json!({ "com.example.some-scheme": { "a": 1 } }),
            Some(json!(["com.example.some-scheme"])),
        );
        assert_eq!(
            read_mode(&raw),
            Err(HiddenError::UnsupportedExtension(
                "com.example.some-scheme".into()
            ))
        );
    }

    #[test]
    fn an_unmarked_namespace_we_do_not_implement_is_ignored() {
        // The framework's default rule, and why marking has to be deliberate.
        let raw = criterion(json!({ "com.example.hint": { "a": 1 } }), None);
        assert_eq!(read_mode(&raw).unwrap(), Mode::Named);
    }

    #[test]
    fn marked_but_broken_parameters_refuse_and_unmarked_ones_do_not() {
        let broken = json!({ HIDDEN_VETTING_NS: { "suite": SUITE } }); // no keys, no labels
        assert!(matches!(
            read_mode(&criterion(broken.clone(), Some(json!([HIDDEN_VETTING_NS])))),
            Err(HiddenError::Unreadable(_))
        ));
        assert_eq!(read_mode(&criterion(broken, None)).unwrap(), Mode::Named);

        let mut other_suite = params();
        other_suite["suite"] = json!("bbs-ddh-bls12381");
        let ext = json!({ HIDDEN_VETTING_NS: other_suite });
        assert_eq!(
            read_mode(&criterion(ext.clone(), Some(json!([HIDDEN_VETTING_NS])))),
            Err(HiddenError::UnsupportedSuite("bbs-ddh-bls12381".into()))
        );
        assert_eq!(read_mode(&criterion(ext, None)).unwrap(), Mode::Named);
    }

    #[test]
    fn marked_but_absent_is_a_contradiction_and_refused() {
        let raw = criterion(
            json!({ "com.example.hint": {} }),
            Some(json!([HIDDEN_VETTING_NS])),
        );
        assert!(matches!(read_mode(&raw), Err(HiddenError::Unreadable(_))));
    }
}
