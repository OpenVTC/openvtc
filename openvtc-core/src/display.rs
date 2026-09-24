//! Display helpers for DIDs and other long identifiers shown in logs
//! and UI surfaces. Pure functions, no UI deps — both the TUI and any
//! future tooling can share these so we don't grow yet another local
//! "truncate this string" implementation per call site.

use std::borrow::Cow;

/// Returns true for unicode codepoints that can spoof or mangle TUI
/// display when rendered: bidirectional overrides, isolates, zero-width
/// spaces/joiners, BOM. These are silently stripped by [`sanitize_display`].
fn is_dangerous_format_char(c: char) -> bool {
    matches!(
        c as u32,
        // Bidi marks, embeddings, overrides
        0x200E | 0x200F |               // LRM, RLM
        0x202A..=0x202E |               // LRE, RLE, PDF, LRO, RLO
        0x2066..=0x2069 |               // LRI, RLI, FSI, PDI
        // Zero-width space / joiner / non-joiner
        0x200B..=0x200D |
        0xFEFF                          // BOM / zero-width non-breaking space
    )
}

/// Sanitize a string from an untrusted source for safe terminal display
/// and persistence (e.g. contact aliases captured from inbound messages).
///
/// Strips, in order:
///   1. ANSI CSI escape sequences (ESC `[` … letter pattern)
///   2. Other ASCII control characters, keeping space
///   3. Bidi-override / zero-width / BOM characters that allow visual
///      spoofing (e.g. RLO-flipping a contact alias to display text the
///      operator didn't approve).
///
/// Truncates to `max_len` *characters* (not bytes).
#[must_use]
pub fn sanitize_display(input: &str, max_len: usize) -> String {
    let mut stripped = String::with_capacity(input.len());
    let mut in_escape = false;
    for c in input.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        stripped.push(c);
    }
    stripped
        .chars()
        .filter(|c| (!c.is_control() || *c == ' ') && !is_dangerous_format_char(*c))
        .take(max_len)
        .collect()
}

/// Cut `s` down to at most `max_chars` characters, borrowing throughout.
///
/// The cut always lands on a character boundary, so this never panics on any
/// input — which a byte slice (`&s[..n]`) does not guarantee. Every truncation
/// in the tree goes through here or [`truncate_did`]: the strings we shorten
/// (DIDs, agent names, peer-supplied error text, timestamps off the wire) are
/// attacker-controlled, and a mid-scalar cut on one of them is a remote crash,
/// not a cosmetic bug.
///
/// Counts characters, not display columns — wide glyphs still render wider than
/// `max_chars` cells. Callers sizing a TUI column should treat it as an upper
/// bound, not an exact width.
#[must_use]
pub fn truncate_chars(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((end, _)) => &s[..end],
        None => s,
    }
}

/// Tail-truncate `did` to at most `max_len` characters, replacing the dropped
/// suffix with `...`. Returns the input borrowed when it already fits, so
/// the common no-truncation case avoids an allocation.
///
/// `max_len` counts characters and the cut is always character-aligned: DIDs
/// are ASCII by spec, but this is also the truncator for agent names, friendly
/// names and DIDs that arrive off the wire *before* validation, none of which
/// are ASCII by construction.
#[must_use]
pub fn truncate_did(did: &str, max_len: usize) -> Cow<'_, str> {
    if did.char_indices().nth(max_len).is_none() {
        Cow::Borrowed(did)
    } else if max_len > 3 {
        Cow::Owned(format!("{}...", truncate_chars(did, max_len - 3)))
    } else {
        Cow::Owned(truncate_chars(did, max_len).to_string())
    }
}

/// Middle-truncate `did` to at most `max_len` characters, keeping a
/// roughly equal slice from each end and inserting `...` in between.
/// Useful when the DID's distinguishing bits live in both the prefix
/// (method, host) and the suffix (key fragment).
#[must_use]
pub fn truncate_did_centered(did: &str, max_len: usize) -> Cow<'_, str> {
    let char_count = did.chars().count();
    if char_count <= max_len {
        return Cow::Borrowed(did);
    }
    let ellipsis = "...";
    let keep = (max_len.saturating_sub(ellipsis.len())) / 2;
    let start: String = did.chars().take(keep).collect();
    let end: String = did.chars().skip(char_count - keep).collect();
    Cow::Owned(format!("{start}...{end}"))
}

/// Shorten a `did:webvh` by eliding its SCID, keeping the host and path.
///
/// A `did:webvh` is about a hundred characters, and tail-truncating one keeps
/// the part nobody can read — the SCID is a hash — while dropping the part they
/// can: the host, and the path they may well have chosen themselves. On screen
/// that turns every persona into `did:webvh:QmUFMgMsbGpei5bGSx6…` and every
/// persona into the same thing as every other.
///
/// So the SCID is what gives way:
///
/// ```text
/// did:webvh:QmUFMgMsbGpei5bGSx6yXT8ZTkmKUT7sQMGWFkx28aFtL3:webvh.storm.ws:kid-long
/// did:webvh:QmUF…aFtL3:webvh.storm.ws:kid-long
/// ```
///
/// Parsed with `didwebvh-rs` rather than split on colons, per the repository
/// rule: a port is `%3A`-encoded inside the host segment, so counting colons
/// finds the wrong boundary for exactly the DIDs a developer runs locally.
///
/// Anything that is not a parseable `did:webvh` is returned untouched — this
/// shortens one method and says nothing about the others.
#[must_use]
pub fn shorten_webvh(did: &str, scid_keep: usize) -> Cow<'_, str> {
    let Ok(parsed) = didwebvh_rs::url::WebVHURL::parse_did_url(did) else {
        return Cow::Borrowed(did);
    };
    let scid = &parsed.scid;
    // Nothing to gain from eliding a SCID that is already short.
    if scid.chars().count() <= scid_keep * 2 + 1 {
        return Cow::Borrowed(did);
    }
    let head: String = scid.chars().take(scid_keep).collect();
    let tail: String = scid
        .chars()
        .skip(scid.chars().count() - scid_keep)
        .collect();
    // Rebuilt by replacing the SCID *in the original*, so every other part —
    // host, port encoding, path, fragment, query — survives exactly as it
    // arrived. Re-emitting from the parse would risk normalising something the
    // reader is trying to compare by eye.
    Cow::Owned(did.replacen(scid.as_str(), &format!("{head}…{tail}"), 1))
}

/// Shorten `did` to at most `max_len` characters for display, giving up the
/// middle and keeping the end.
///
/// The truncator for every identifier shown to be *read* — a status line, a
/// summary, a row label. What distinguishes two `did:webvh`s is their host and
/// path, and both sit at the end; the SCID is a hash in the middle that nobody
/// reads and cannot compare by eye. A tail truncation drops exactly the half
/// worth keeping, so every persona on a host renders as the same prefix as
/// every other:
///
/// ```text
/// did:webvh:QmZBWtbz1VVTwyFNUHjx8YfL9fZ8XDc6KrBQ66tj9xq6Eh:dids.ic3.dev:firstperson-vtc
/// did:webvh:QmZBWtbz1VVTwyFNUHjx8YfL9fZ8XDc6KrB...          ← tail-truncated at 48
/// did:webvh:QmZB…q6Eh:dids.ic3.dev:firstperson-vtc          ← this, at 48
/// ```
///
/// The SCID goes first, via [`shorten_webvh`], which is usually enough on its
/// own. Only when that still does not fit is the identifier cut again, and the
/// budget then goes to the tail: a short head says what kind of identifier this
/// is, and everything else is spent on the part that identifies it.
///
/// Anything that is not a parseable `did:webvh` keeps its whole head and loses
/// its middle the same way — a `did:key` has nothing readable at either end, and
/// a name or a URL reads from the front, which the head preserves.
#[must_use]
pub fn shorten_for_display(did: &str, max_len: usize) -> Cow<'_, str> {
    let short = shorten_webvh(did, 4);
    let count = short.chars().count();
    if count <= max_len {
        return short;
    }
    // Too narrow to say anything either way: fall back to the plain cut rather
    // than emit an ellipsis with a character on each side of it.
    if max_len < 8 {
        return Cow::Owned(truncate_did(&short, max_len).into_owned());
    }
    let head_len = (max_len / 4).min(10);
    let tail_len = max_len - head_len - 1;
    let head: String = short.chars().take(head_len).collect();
    let tail: String = short.chars().skip(count - tail_len).collect();
    // The SCID may already have been elided at exactly this seam, and
    // `did:webv\u{2026}\u{2026}AAAA:host:path` reads as a rendering fault rather than as
    // one cut. Two adjacent ellipses say no more than one.
    let head = head.trim_end_matches(ELLIPSIS);
    let tail = tail.trim_start_matches(ELLIPSIS);
    Cow::Owned(format!("{head}{ELLIPSIS}{tail}"))
}

/// What a shortened identifier puts where the dropped characters were.
const ELLIPSIS: char = '\u{2026}';

/// Pick what to show for an identifier: a verified agent name when one is
/// known, otherwise the shortened DID.
///
/// A name (`example.com/@alice`) is short and human-memorable, so it is shown
/// whole (only truncated in the rare case it exceeds `max_len`); the DID is the
/// fallback. The shared primitive for name-or-DID surfaces — those without a
/// user alias in front. Surfaces that also honour a user alias (relationships,
/// contacts) layer that check ahead of this, since an explicit alias outranks a
/// resolved name. The `name` passed here must already be **verified** (see
/// [`crate::agent_name`]); this function does no checking, it only formats.
#[must_use]
pub fn display_identifier<'a>(name: Option<&'a str>, did: &'a str, max_len: usize) -> Cow<'a, str> {
    match name {
        Some(name) => truncate_did(name, max_len),
        // A `did:webvh` gives up its SCID, then its middle: the hash is the
        // part nobody reads, and the host and path are the parts they
        // recognise. Tail-truncation dropped exactly the wrong half, and every
        // persona on a host rendered as the same prefix as every other.
        None => shorten_for_display(did, max_len),
    }
}

/// A short, human-meaningful label for a message type URI.
///
/// The obvious implementation — take the last path segment — is wrong for every
/// Trust Task, because a Trust Task URI *ends in its version*:
///
/// ```text
/// https://trusttasks.org/spec/credential-exchange/issue/0.1
///                                                      ^^^ last segment
/// ```
///
/// The activity log did exactly that and rendered every inbound message as
/// `Inbound: 0.1`. It went unnoticed because legacy DIDComm types end in the
/// action (`…/relationship/1.0/request` → `request`), so the label only became
/// useless once the stack moved to Trust Tasks — precisely when the log became
/// worth reading.
///
/// This keeps the part that identifies the task, dropping the scheme, the host
/// and the `spec/` prefix, so the example above renders as
/// `credential-exchange/issue/0.1`.
#[must_use]
pub fn task_label(type_uri: &str) -> String {
    // Canonical Trust Task shape: strip everything up to and including `/spec/`.
    if let Some((_, tail)) = type_uri.split_once("/spec/")
        && !tail.is_empty()
    {
        return tail.to_string();
    }

    // Anything else (legacy DIDComm types, bare strings): keep the last two
    // segments, which is the action plus enough context to disambiguate it.
    let segments: Vec<&str> = type_uri.rsplit('/').take(2).collect();
    match segments.len() {
        0 => type_uri.to_string(),
        1 => segments[0].to_string(),
        _ => format!("{}/{}", segments[1], segments[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this exists for: a Trust Task URI ends in its version, so the
    /// last-segment label named the version and nothing else.
    #[test]
    fn a_trust_task_label_names_the_task_not_its_version() {
        assert_eq!(
            task_label("https://trusttasks.org/spec/credential-exchange/issue/0.1"),
            "credential-exchange/issue/0.1"
        );
        assert_eq!(
            task_label("https://trusttasks.org/spec/keys/create/0.1"),
            "keys/create/0.1"
        );
    }

    /// Legacy DIDComm types end in the action, and still read correctly.
    #[test]
    fn a_legacy_didcomm_label_keeps_its_action() {
        assert_eq!(
            task_label("https://didcomm.org/trust-ping/2.0/ping"),
            "2.0/ping"
        );
    }

    /// No panics and no empty labels on degenerate input — this runs on
    /// whatever a peer put in `typ`, which is not ours to trust.
    #[test]
    fn a_degenerate_type_still_produces_something() {
        assert_eq!(task_label("bare"), "bare");
        assert_eq!(task_label(""), "");
        // A trailing `/spec/` with nothing after it falls through to the
        // segment path rather than returning an empty label.
        assert!(!task_label("https://trusttasks.org/spec/").is_empty());
    }

    #[test]
    fn truncate_did_passes_through_short_input() {
        let short = "did:web:example.com";
        let out = truncate_did(short, 60);
        assert_eq!(out, short);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn truncate_did_appends_ellipsis() {
        let long = "did:webvh:abcdef0123456789:example.com:custom:path:here";
        let out = truncate_did(long, 20);
        assert_eq!(out.len(), 20);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn truncate_did_below_ellipsis_width_returns_raw_truncation() {
        let out = truncate_did("did:web:example.com", 2);
        assert_eq!(out, "di");
    }

    /// OVTC-01, display side: the truncators run on unvalidated inbound DIDs
    /// (log lines) and on agent / friendly names, so a byte-aligned cut was a
    /// panic waiting on any multi-byte input. Cuts must land on a boundary for
    /// 2-, 3- and 4-byte scalars alike.
    #[test]
    fn truncators_cut_on_char_boundaries() {
        for scalar in ['\u{0281}', '\u{20AC}', '\u{1F600}'] {
            let s = format!("{}{scalar}{}", "x".repeat(19), "y".repeat(40));
            for max in 0..25 {
                let out = truncate_did(&s, max);
                assert!(out.chars().count() <= max.max(3), "max {max}: over budget");
                assert!(truncate_chars(&s, max).chars().count() <= max);
            }
        }
    }

    #[test]
    fn truncate_chars_counts_characters_not_bytes() {
        assert_eq!(truncate_chars("😀😀😀", 2), "😀😀");
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(truncate_chars("abc", 0), "");
    }

    #[test]
    fn truncate_did_centered_passes_through_short() {
        let short = "did:web:x.io";
        let out = truncate_did_centered(short, 60);
        assert_eq!(out, short);
        assert!(matches!(out, Cow::Borrowed(_)));
    }

    #[test]
    fn truncate_did_centered_keeps_both_ends() {
        let long = "did:webvh:abcdef0123456789:example.com:custom:path";
        let out = truncate_did_centered(long, 20);
        assert!(out.starts_with("did:web"));
        assert!(out.contains("..."));
        assert!(out.ends_with("path"));
    }

    /// The SCID is a hash and the path is often chosen by the person; when
    /// something has to give, it is the hash. Tail-truncation dropped the
    /// readable half and made every persona on a host look alike.
    #[test]
    fn shortening_a_webvh_keeps_the_host_and_path() {
        let did =
            "did:webvh:QmUFMgMsbGpei5bGSx6yXT8ZTkmKUT7sQMGWFkx28aFtL3:webvh.storm.ws:kid-long";
        let short = shorten_webvh(did, 4);
        assert_eq!(short, "did:webvh:QmUF\u{2026}FtL3:webvh.storm.ws:kid-long");
        assert!(short.ends_with("kid-long"), "the path survives");
        assert!(short.contains("webvh.storm.ws"), "and so does the host");
        assert!(short.chars().count() < did.chars().count());
    }

    /// One method only. Anything else is returned exactly as it came, because
    /// this knows where a `did:webvh` keeps its SCID and nothing more.
    #[test]
    fn shortening_leaves_other_identifiers_alone() {
        for other in [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "example.com/@alice",
            "not a did at all",
        ] {
            assert_eq!(shorten_webvh(other, 4), other);
        }
    }

    #[test]
    fn display_identifier_prefers_the_name() {
        let did = "did:webvh:abcdef0123456789:example.com:alice";
        assert_eq!(
            display_identifier(Some("example.com/@alice"), did, 40),
            "example.com/@alice"
        );
    }

    /// The fallback keeps the end. The path is the only part of two DIDs on one
    /// host that differs, so a truncation that drops it makes them identical on
    /// screen.
    #[test]
    fn display_identifier_falls_back_to_a_did_that_keeps_its_path() {
        let did = "did:webvh:QmZBWtbz1VVTwyFNUHjx8YfL9fZ8XDc6KrBQ66tj9xq6Eh:dids.ic3.dev:alice";
        let out = display_identifier(None, did, 30);
        assert!(out.starts_with("did:web"), "{out}");
        assert!(out.ends_with(":alice"), "{out}");
        assert!(out.chars().count() <= 30, "{out}");
    }

    /// The whole point, on the two DIDs that shared a prefix on screen.
    #[test]
    fn shortening_for_display_keeps_two_dids_on_one_host_apart() {
        let host = "QmZBWtbz1VVTwyFNUHjx8YfL9fZ8XDc6KrBQ66tj9xq6Eh:dids.ic3.dev";
        let a = format!("did:webvh:{host}:firstperson-vtc");
        let b = format!("did:webvh:{host}:earn-auction");
        for width in [24, 32, 48, 64] {
            let (sa, sb) = (
                shorten_for_display(&a, width),
                shorten_for_display(&b, width),
            );
            assert_ne!(sa, sb, "width {width}");
            assert!(sa.ends_with("firstperson-vtc"), "width {width}: {sa}");
            assert!(sb.ends_with("earn-auction"), "width {width}: {sb}");
            assert!(sa.chars().count() <= width, "width {width}: {sa}");
        }
    }

    /// It runs on whatever is handed to it, including identifiers it knows
    /// nothing about and widths too small to say anything in.
    #[test]
    fn shortening_for_display_survives_anything() {
        for s in [
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "example.com/@alice",
            "",
            "😀😀😀😀😀😀😀😀😀😀😀😀",
        ] {
            for width in 0..20 {
                let out = shorten_for_display(s, width);
                assert!(out.chars().count() <= width.max(3), "{s:?} at {width}");
            }
        }
    }

    #[test]
    fn display_identifier_truncates_an_overlong_name() {
        let did = "did:web:x";
        let out = display_identifier(
            Some("verylonghost.example.com/@a-very-long-handle"),
            did,
            20,
        );
        assert_eq!(out.len(), 20);
        assert!(out.ends_with("..."));
    }
}
