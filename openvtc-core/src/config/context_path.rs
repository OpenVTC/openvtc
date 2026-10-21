/*!
 * Context-path hierarchy convention (D2 / D9).
 *
 * The single source of truth for the `<top>/<slug>` sub-context naming scheme.
 * A community's VTA sub-context id is derived from the account's top context and
 * the community's display name (slugged), with a collision-suffix rule and a
 * stable DID-derived fallback when no usable name is available.
 *
 * The hierarchy is **real and VTA-enforced** (VTI #257): a context id *is* its
 * `/`-separated path, the VTA validates depth/segments and enforces
 * ancestry-aware ACL server-side. This module mirrors the path **construction
 * and validation** rules from `vti-common::context_path` /
 * `vti-common::identifier` so the CLI builds only paths the VTA will accept;
 * the VTA remains the enforcement source of truth (it re-validates). The rules
 * are mirrored rather than imported because `vti-common` is not consumable from
 * this workspace (it is not a `vta-sdk` dependency and `vta-sdk` does not
 * re-export it). The mirrored definitions are kept byte-for-byte faithful to
 * their `vti-common` originals to avoid drift on these security-relevant rules.
 *
 * TODO(VTI#392): the pure validators are being lifted into `vta-sdk` (the
 * lowest common dependency of server and clients). Once that lands and this
 * workspace bumps `vta-sdk`, delete this mirror and re-export from `vta-sdk`
 * instead — see OpenVTC/verifiable-trust-infrastructure#392.
 *
 * The ancestry/ACL helper (`is_ancestor_or_self`) is deliberately **not**
 * mirrored: this client never makes authorization decisions — the VTA owns the
 * "admin of a parent covers the subtree" gate — so a local copy would be unused
 * dead code and a drift hazard.
 *
 * Per `CLAUDE.md`, the no-name fallback derives its token from the VTC
 * `did:webvh` via `didwebvh-rs` rather than hand-rolled string surgery.
 */

use crate::errors::OpenVTCError;
use didwebvh_rs::url::WebVHURL;

/// Maximum length of a slug component (D9).
const MAX_SLUG_LEN: usize = 32;
/// Number of leading SCID characters kept for the no-name fallback token.
const FALLBACK_TOKEN_LEN: usize = 12;

/// Maximum nesting depth (number of path segments). Mirrors
/// `vti-common::context_path::MAX_CONTEXT_DEPTH`. A `<top>/<community>` path is
/// depth 2.
pub const MAX_CONTEXT_DEPTH: usize = 8;

/// The path separator. Mirrors `vti-common::context_path::SEPARATOR`. A context
/// identifier is segments joined by this; it never appears inside a segment.
pub const SEPARATOR: char = '/';

/// Maximum length of a single context-path segment in bytes. Mirrors
/// `vti-common::identifier::MAX_IDENTIFIER_LEN`.
pub const MAX_IDENTIFIER_LEN: usize = 64;

/// Validate a single context-path segment (one identifier). Mirrors
/// `vti-common::identifier::validate_identifier`: non-empty, ≤
/// [`MAX_IDENTIFIER_LEN`] bytes, and every character in `[A-Za-z0-9._-]`.
/// Anything else — including the separators `/`, `:`, and whitespace that could
/// let a caller traverse into or collide with adjacent VTA store namespaces — is
/// rejected.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] describing the first rule the segment
/// violates; `label` names the field for a self-describing message.
pub fn validate_identifier(label: &str, value: &str) -> Result<(), OpenVTCError> {
    if value.is_empty() {
        return Err(OpenVTCError::Config(format!("{label} must not be empty")));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(OpenVTCError::Config(format!(
            "{label} is {} bytes; maximum is {MAX_IDENTIFIER_LEN}",
            value.len()
        )));
    }
    for (i, ch) in value.chars().enumerate() {
        let ok = ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-';
        if !ok {
            return Err(OpenVTCError::Config(format!(
                "{label} contains an invalid character {ch:?} at position {i}; \
                 allowed: A-Z, a-z, 0-9, '.', '_', '-'"
            )));
        }
    }
    Ok(())
}

/// Validate a full context path. Mirrors
/// `vti-common::context_path::validate_context_path`: non-empty, no
/// leading/trailing/doubled separator, ≤ [`MAX_CONTEXT_DEPTH`] segments, and
/// every segment a valid [identifier](validate_identifier).
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] describing the first rule the path violates.
pub fn validate_context_path(value: &str) -> Result<(), OpenVTCError> {
    if value.is_empty() {
        return Err(OpenVTCError::Config(
            "context path must not be empty".into(),
        ));
    }
    if value.starts_with(SEPARATOR) || value.ends_with(SEPARATOR) {
        return Err(OpenVTCError::Config(format!(
            "context path must not start or end with '{SEPARATOR}'"
        )));
    }

    let segments: Vec<&str> = value.split(SEPARATOR).collect();
    if segments.len() > MAX_CONTEXT_DEPTH {
        return Err(OpenVTCError::Config(format!(
            "context path is {} levels deep; maximum is {MAX_CONTEXT_DEPTH}",
            segments.len()
        )));
    }
    for segment in &segments {
        // An empty segment means a leading/trailing/doubled separator — `split`
        // yields `""` for each. (The leading/trailing case is caught above; this
        // catches `a//b`.)
        if segment.is_empty() {
            return Err(OpenVTCError::Config(
                "context path must not contain an empty segment ('//')".into(),
            ));
        }
        validate_identifier("context path segment", segment)?;
    }
    Ok(())
}

/// Build a child path under `parent` by appending a single `segment`. Mirrors
/// `vti-common::context_path::child_path`: the `segment` must be one valid
/// identifier (it cannot itself contain a separator, else it would silently add
/// several levels) and the resulting path must [validate](validate_context_path),
/// depth included.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] if `segment` is not a valid identifier or
/// the resulting path violates [`validate_context_path`] (e.g. it would exceed
/// [`MAX_CONTEXT_DEPTH`]).
pub fn child_path(parent: &str, segment: &str) -> Result<String, OpenVTCError> {
    // Reject a `segment` that is empty or contains the separator: `child_path`
    // adds exactly one level.
    validate_identifier("context path segment", segment)?;
    let candidate = format!("{parent}{SEPARATOR}{segment}");
    validate_context_path(&candidate)?;
    Ok(candidate)
}

/// Slugify a community display name per D9.
///
/// Lowercases the name, keeps `[a-z0-9]`, collapses every run of other
/// characters (including spaces, punctuation, and `-`) to a single `-`, trims
/// leading/trailing `-`, and caps the result at `MAX_SLUG_LEN` characters.
/// Returns an empty string when nothing usable remains (e.g. a name with no
/// ASCII alphanumerics) — callers fall back to [`fallback_token`].
pub fn slugify(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_SLUG_LEN));
    let mut pending_dash = false;
    for c in name.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_lowercase() || lc.is_ascii_digit() {
            // A separator was pending and we have real content on both sides —
            // emit a single joining dash.
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(lc);
            if out.len() >= MAX_SLUG_LEN {
                break;
            }
        } else {
            // Any non-alphanumeric (including `-`) collapses to one dash, but we
            // only commit it once we know real content follows (avoids leading
            // and trailing dashes).
            pending_dash = true;
        }
    }
    out
}

/// A short, stable token derived from a VTC's SCID: of its `did:webvh`, parsed
/// via `didwebvh-rs`, or of its `did:scid:vh:1` (VTI-KEY-160).
///
/// Used as the slug when a community has no usable display name (D9). The token
/// is the lowercased, alphanumeric-only prefix of the DID's SCID — stable for a
/// given DID and safe as a context-path component.
///
/// # Errors
///
/// Returns an error if `vtc_did` is not a parseable `did:webvh` or
/// `did:scid:vh:1`, or its SCID yields no usable characters.
pub fn fallback_token(vtc_did: &str) -> Result<String, OpenVTCError> {
    let scid = if vta_sdk::did_scid::is_scid(vtc_did) {
        vta_sdk::did_scid::scid_of(vtc_did)
            .ok_or_else(|| OpenVTCError::Config(format!("Invalid VTC did:scid ({vtc_did})")))?
            .to_string()
    } else {
        WebVHURL::parse_did_url(vtc_did)
            .map_err(|e| OpenVTCError::Config(format!("Invalid VTC did:webvh ({vtc_did}): {e}")))?
            .scid
    };
    let token: String = scid
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .take(FALLBACK_TOKEN_LEN)
        .collect();
    if token.is_empty() {
        return Err(OpenVTCError::Config(format!(
            "VTC DID has no usable SCID for a context token: {vtc_did}"
        )));
    }
    Ok(token)
}

/// Build a `<top>/<slug>` sub-context id for a community (D9).
///
/// The slug is [`slugify`]'d from `display_name`, or [`fallback_token`]'d from
/// `vtc_did` when the name is absent/empty/unusable. `is_taken` reports whether
/// a candidate id already exists under the top context; on collision the slug
/// gains a `-2`, `-3`, … suffix until it is unique.
///
/// Every candidate is constructed via [`child_path`], so the returned id is
/// guaranteed to satisfy the mirrored `vti-common` rules — each segment a valid
/// identifier, the whole path within [`MAX_CONTEXT_DEPTH`] — exactly what the
/// VTA re-validates server-side. The slug is `[a-z0-9-]` capped at
/// `MAX_SLUG_LEN` and the collision suffix adds only `[0-9-]`, so a usable
/// slug always passes segment validation; the only construction failures are an
/// invalid/over-deep `top_context_id` or an unusable fallback DID.
///
/// # Errors
///
/// Returns [`OpenVTCError::Config`] when the fallback token is needed and
/// `vtc_did` is not a usable `did:webvh`, or when no valid path can be formed
/// under `top_context_id` (e.g. the top context is itself invalid or already at
/// [`MAX_CONTEXT_DEPTH`]).
pub fn build_sub_context_id(
    top_context_id: &str,
    display_name: Option<&str>,
    vtc_did: &str,
    is_taken: impl Fn(&str) -> bool,
) -> Result<String, OpenVTCError> {
    let base = match display_name.map(slugify) {
        Some(slug) if !slug.is_empty() => slug,
        _ => fallback_token(vtc_did)?,
    };

    let mut segment = base.clone();
    let mut n = 2u32;
    loop {
        let candidate = child_path(top_context_id, &segment)?;
        if !is_taken(&candidate) {
            return Ok(candidate);
        }
        segment = format!("{base}-{n}");
        n += 1;
    }
}

/// Split a `<top>/<slug>` id into `(top, slug)`.
///
/// The top context may itself contain `/` (nested), so the split is on the last
/// `/`. Returns `None` for an id with no `/` (not a sub-context id).
pub fn parse_sub_context_id(id: &str) -> Option<(&str, &str)> {
    id.rsplit_once('/')
}

/// The display form of a sub-context id: its slug (the final path segment), or
/// the whole string when it has no `/`.
pub fn render_for_display(id: &str) -> &str {
    id.rsplit_once('/').map_or(id, |(_, slug)| slug)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn slugify_basic_lowercasing_and_separators() {
        assert_eq!(slugify("Acme Corp"), "acme-corp");
        assert_eq!(slugify("ACME"), "acme");
        assert_eq!(slugify("Foo123"), "foo123");
    }

    #[test]
    fn slugify_collapses_runs_and_trims() {
        assert_eq!(slugify("  Hello,   World!!  "), "hello-world");
        assert_eq!(slugify("a___b---c"), "a-b-c");
        assert_eq!(slugify("--leading and trailing--"), "leading-and-trailing");
        assert_eq!(slugify("a - b"), "a-b");
    }

    #[test]
    fn slugify_strips_non_ascii_and_handles_empty() {
        assert_eq!(slugify(""), "");
        assert_eq!(slugify("!!!"), "");
        // Non-ASCII letters are treated as separators (collapsed to dashes).
        assert_eq!(slugify("café münchen"), "caf-m-nchen");
    }

    #[test]
    fn slugify_caps_at_max_len() {
        let long = "a".repeat(100);
        assert_eq!(slugify(&long).len(), MAX_SLUG_LEN);
    }

    #[test]
    fn fallback_token_is_stable_and_clean() {
        let did = "did:webvh:zQmTestScidValue:example.com";
        let t1 = fallback_token(did).unwrap();
        let t2 = fallback_token(did).unwrap();
        assert_eq!(t1, t2, "fallback token must be stable for a given DID");
        assert!(!t1.is_empty());
        assert!(t1.len() <= FALLBACK_TOKEN_LEN);
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "token must be a clean slug component, got {t1}"
        );
    }

    #[test]
    fn fallback_token_rejects_non_webvh() {
        assert!(fallback_token("did:key:z6Mk").is_err());
        // A did:scid VTC takes the token from its SCID, whatever its `src`.
        assert_eq!(
            fallback_token("did:scid:vh:1:QmAbCdEf?src=vtc.example.com").unwrap(),
            fallback_token("did:scid:vh:1:QmAbCdEf").unwrap(),
        );
        assert!(
            fallback_token("did:scid:vh:1:QmAbCdEf")
                .unwrap()
                .starts_with("qmabcd")
        );
        assert!(fallback_token("not-a-did").is_err());
    }

    #[test]
    fn build_uses_slug_under_top() {
        let taken = HashSet::<String>::new();
        let id = build_sub_context_id(
            "openvtc",
            Some("Acme Corp"),
            "did:webvh:zScid:example.com",
            |c| taken.contains(c),
        )
        .unwrap();
        assert_eq!(id, "openvtc/acme-corp");
    }

    #[test]
    fn build_falls_back_to_did_token_when_no_name() {
        let taken = HashSet::<String>::new();
        let did = "did:webvh:zQmTestScidValue:example.com";
        let expected = format!("openvtc/{}", fallback_token(did).unwrap());
        for name in [None, Some(""), Some("   "), Some("!!!")] {
            let id = build_sub_context_id("openvtc", name, did, |c| taken.contains(c)).unwrap();
            assert_eq!(id, expected, "name {name:?} should fall back to DID token");
        }
    }

    #[test]
    fn build_suffixes_on_collision() {
        let mut taken = HashSet::new();
        taken.insert("openvtc/acme".to_string());
        taken.insert("openvtc/acme-2".to_string());
        let id = build_sub_context_id(
            "openvtc",
            Some("ACME"),
            "did:webvh:zScid:example.com",
            |c| taken.contains(c),
        )
        .unwrap();
        assert_eq!(id, "openvtc/acme-3");
    }

    #[test]
    fn parse_and_render_round_trip() {
        assert_eq!(
            parse_sub_context_id("openvtc/acme"),
            Some(("openvtc", "acme"))
        );
        // Nested top context: split on the last slash.
        assert_eq!(
            parse_sub_context_id("org/openvtc/acme"),
            Some(("org/openvtc", "acme"))
        );
        assert_eq!(parse_sub_context_id("openvtc"), None);

        assert_eq!(render_for_display("openvtc/acme"), "acme");
        assert_eq!(render_for_display("org/openvtc/acme"), "acme");
        assert_eq!(render_for_display("openvtc"), "openvtc");
    }

    // --- mirrored `vti-common` validation rules ---------------------------

    #[test]
    fn validate_identifier_accepts_common_shapes() {
        for ok in ["myapp", "My-App_1", "context.v2", "a", "0", "CamelCase"] {
            validate_identifier("id", ok).unwrap_or_else(|e| panic!("{ok:?} rejected: {e:?}"));
        }
        // Exactly at the byte limit passes; one over fails.
        validate_identifier("id", &"a".repeat(MAX_IDENTIFIER_LEN)).unwrap();
        assert!(validate_identifier("id", &"a".repeat(MAX_IDENTIFIER_LEN + 1)).is_err());
    }

    #[test]
    fn validate_identifier_rejects_separators_and_injection() {
        for bad in [
            "",
            "global:evil",
            "../../etc",
            "a:b:c",
            "my/ctx",
            "with space",
            "café",
        ] {
            assert!(
                validate_identifier("id", bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_context_path_accepts_good_paths() {
        for p in [
            "acme",
            "acme/eng",
            "openvtc/acme-corp",
            "a.b_c/d-e",
            "x/y/z",
        ] {
            assert!(validate_context_path(p).is_ok(), "{p} should be valid");
        }
    }

    #[test]
    fn validate_context_path_rejects_malformed() {
        assert!(validate_context_path("").is_err()); // empty
        assert!(validate_context_path("/acme").is_err()); // leading separator
        assert!(validate_context_path("acme/").is_err()); // trailing separator
        assert!(validate_context_path("acme//eng").is_err()); // doubled separator
        assert!(validate_context_path("acme/ev il").is_err()); // space in a segment
        assert!(validate_context_path("acme/ev:il").is_err()); // keyspace separator
    }

    #[test]
    fn validate_context_path_enforces_max_depth() {
        let deep = (0..=MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(
            validate_context_path(&deep).is_err(),
            "{deep} exceeds max depth"
        );
        let ok = (0..MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(validate_context_path(&ok).is_ok());
    }

    #[test]
    fn child_path_builds_and_validates() {
        assert_eq!(child_path("acme", "eng").unwrap(), "acme/eng");
        assert!(child_path("acme", "ev/il").is_err()); // separator in the new segment
        assert!(child_path("acme", "").is_err()); // empty segment
        // A child that would exceed the depth cap is rejected.
        let at_cap = (0..MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(child_path(&at_cap, "more").is_err());
    }

    #[test]
    fn build_always_yields_a_valid_context_path() {
        let did = "did:webvh:zQmTestScidValue:example.com";
        let cases: &[(Option<&str>, &str)] = &[
            (Some("Acme Corp"), "openvtc"),
            (Some("!!!"), "openvtc"), // unusable name → DID fallback
            (None, "org/openvtc"),    // nested top, no name
        ];
        for (name, top) in cases {
            let id =
                build_sub_context_id(top, *name, did, |_| false).expect("build should succeed");
            validate_context_path(&id)
                .unwrap_or_else(|e| panic!("built id {id:?} failed validation: {e:?}"));
        }
    }

    #[test]
    fn build_collision_suffix_stays_a_valid_identifier() {
        let mut taken = HashSet::new();
        taken.insert("openvtc/acme".to_string());
        let id = build_sub_context_id(
            "openvtc",
            Some("ACME"),
            "did:webvh:zScid:example.com",
            |c| taken.contains(c),
        )
        .unwrap();
        assert_eq!(id, "openvtc/acme-2");
        validate_context_path(&id).unwrap();
    }

    #[test]
    fn build_rejects_an_invalid_top_context() {
        // An over-deep top context cannot accept a child.
        let at_cap = (0..MAX_CONTEXT_DEPTH)
            .map(|i| format!("s{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let r = build_sub_context_id(&at_cap, Some("acme"), "did:webvh:zScid:example.com", |_| {
            false
        });
        assert!(r.is_err(), "child under a max-depth top must fail");
    }
}
