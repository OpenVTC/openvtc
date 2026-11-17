//! A source check for one mistake in user-facing text: a string literal wrapped
//! across lines without a trailing `\`, so the next line's indentation lands in
//! the message as a long run of spaces mid-sentence ("update                one
//! or the other"). `rustfmt` does not touch string contents, so nothing else
//! catches it.
//!
//! A run is flagged when it sits inside a string literal on one line, follows a
//! letter or punctuation, is followed by a lowercase letter, and is longer than
//! any column alignment the code uses on purpose (the widest, in `health_cmd`,
//! is twelve).

use std::path::{Path, PathBuf};

/// Shorter runs are left alone: column-aligned help and report lines use up
/// to twelve spaces between a label and its value.
const LONGEST_ALIGNMENT: usize = 12;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether byte `at` of `line` is inside a string literal that opened on this
/// line: an odd number of unescaped quotes before it.
fn inside_literal(line: &str, at: usize) -> bool {
    let bytes = line.as_bytes();
    let mut quotes = 0;
    let mut i = 0;
    while i < at {
        match bytes[i] {
            b'\\' => i += 1,
            b'"' => quotes += 1,
            _ => {}
        }
        i += 1;
    }
    quotes % 2 == 1
}

/// The runs in `line` that look like a lost line continuation.
fn lost_continuations(line: &str) -> Vec<usize> {
    if line.trim_start().starts_with("//") {
        return Vec::new();
    }
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b' ' {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && bytes[i] == b' ' {
            i += 1;
        }
        let run = i - start;
        let before = start.checked_sub(1).map(|b| bytes[b]);
        let after = bytes.get(i).copied();
        if run > LONGEST_ALIGNMENT
            && before.is_some_and(|b| b.is_ascii_alphabetic() || b",.:;)".contains(&b))
            && after.is_some_and(|a| a.is_ascii_lowercase())
            && inside_literal(line, start)
        {
            found.push(start);
        }
    }
    found
}

#[test]
fn no_string_literal_carries_a_lost_line_continuation() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    // This crate, and the core library beside it in the workspace (absent
    // from a packaged crate, where only this one is checked).
    rust_files(&crate_dir.join("src"), &mut files);
    rust_files(&crate_dir.join("../openvtc-core/src"), &mut files);
    assert!(!files.is_empty(), "no sources found under {crate_dir:?}");

    let mut offences = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            for column in lost_continuations(line) {
                offences.push(format!(
                    "{}:{}:{}: {}",
                    file.display(),
                    n + 1,
                    column + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "string literals with a run of spaces mid-sentence — a wrapped line missing its \
         trailing `\\`:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_check_finds_a_lost_continuation_and_spares_alignment() {
    let lost = r#"        "this client and your VTA disagree — update                          one or the other""#;
    assert_eq!(lost_continuations(lost).len(), 1);
    let aligned = r#"    println!("  faces            could not tell: {why}");"#;
    assert!(lost_continuations(aligned).is_empty());
    let continued = r#"        "a sentence wrapped \"#;
    assert!(lost_continuations(continued).is_empty());
    let outside = r#"    let x = 1;                      // a comment after code"#;
    assert!(lost_continuations(outside).is_empty());
}
