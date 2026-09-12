//! What OpenVTC learns about the terminal: whether its background is dark or
//! light, for the `auto` theme, and whether it draws 24-bit colour.
//!
//! The background is asked for with OSC 11, which most terminals answer with
//! their background colour. The answer arrives as input, so the question is put
//! once, before the TUI starts reading keys; after that the answer is only
//! looked up. A terminal that does not answer is judged by `COLORFGBG`, and
//! failing that taken to be dark.

use std::sync::OnceLock;
use std::time::Duration;

use ratatui::style::Color;

use super::Mode;

/// How long to wait for the terminal's answer. Most answer within milliseconds,
/// and a device-attributes query sent straight after the background query ends
/// the wait as soon as the terminal has answered that — so only a terminal that
/// answers neither waits this long. Long enough not to leave a slow SSH link's
/// late answer to be read as typing.
#[cfg_attr(not(unix), allow(dead_code))]
const QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// Background colour query (OSC 11), then primary device attributes (DA1),
/// which virtually every terminal answers.
#[cfg_attr(not(unix), allow(dead_code))]
const QUERY: &[u8] = b"\x1b]11;?\x07\x1b[c";

/// How the terminal's background was learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The terminal said.
    Asked,
    /// `COLORFGBG` said.
    ColorFgBg,
    /// Nothing said; dark was assumed.
    Assumed,
}

static DETECTED: OnceLock<(Mode, Source)> = OnceLock::new();

/// Ask the terminal for its background, once per process, and remember the
/// answer. Only call this before the TUI takes the terminal over: the answer
/// arrives as input, which the TUI would read as keys.
pub fn detect() -> (Mode, Source) {
    *DETECTED.get_or_init(|| match query_background(QUERY_TIMEOUT) {
        Some(rgb) => (
            Mode::of_background(Some(Color::Rgb(rgb.0, rgb.1, rgb.2))),
            Source::Asked,
        ),
        None => fallback(),
    })
}

/// The terminal's background as [`detect`] found it, or — when it was never
/// asked — as `COLORFGBG` suggests, else dark. Never asks the terminal.
#[must_use]
pub fn mode() -> (Mode, Source) {
    DETECTED.get().copied().unwrap_or_else(fallback)
}

fn fallback() -> (Mode, Source) {
    std::env::var("COLORFGBG")
        .ok()
        .and_then(|value| mode_from_colorfgbg(&value))
        .map_or((Mode::Dark, Source::Assumed), |mode| {
            (mode, Source::ColorFgBg)
        })
}

/// `COLORFGBG` is `fg;bg`, or `fg;default;bg`, in ANSI colour numbers. By
/// rxvt's convention, which the terminals that set it follow, a background of
/// 7 or 9–15 is light.
fn mode_from_colorfgbg(value: &str) -> Option<Mode> {
    let background: u8 = value.rsplit(';').next()?.trim().parse().ok()?;
    Some(if background == 7 || (9..=15).contains(&background) {
        Mode::Light
    } else {
        Mode::Dark
    })
}

/// Whether the terminal draws 24-bit colour, as `COLORTERM` declares.
#[must_use]
pub fn truecolor() -> bool {
    std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit")
}

/// Ask the terminal on `/dev/tty` for its background colour.
#[cfg(unix)]
fn query_background(timeout: Duration) -> Option<(u8, u8, u8)> {
    use crossterm::terminal;
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || std::env::var("TERM").is_ok_and(|t| t == "dumb")
    {
        return None;
    }
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    // Raw, so the answer is neither echoed nor held back for a newline.
    let was_raw = terminal::is_raw_mode_enabled().unwrap_or(false);
    if !was_raw {
        terminal::enable_raw_mode().ok()?;
    }
    let reply = tty
        .write_all(QUERY)
        .and_then(|()| tty.flush())
        .ok()
        .map(|()| read_reply(&tty, timeout));
    if !was_raw {
        let _ = terminal::disable_raw_mode();
    }
    parse_background(&reply?)
}

#[cfg(not(unix))]
fn query_background(_timeout: Duration) -> Option<(u8, u8, u8)> {
    None
}

/// Read what the terminal sends until it has answered the device-attributes
/// query, or `timeout` passes.
#[cfg(unix)]
fn read_reply(tty: &std::fs::File, timeout: Duration) -> Vec<u8> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    let deadline = Instant::now() + timeout;
    let mut reply = Vec::new();
    let mut chunk = [0u8; 256];
    while !answered(&reply) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut fd = libc::pollfd {
            fd: tty.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(left.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        // SAFETY: one initialised pollfd, for a descriptor `tty` keeps open
        // for the whole call.
        if unsafe { libc::poll(&raw mut fd, 1, millis) } <= 0 {
            break;
        }
        match (&*tty).read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => reply.extend_from_slice(&chunk[..n]),
        }
    }
    reply
}

/// Whether `reply` holds the answer to the device-attributes query:
/// `ESC [ ? <digits and semicolons> c`.
#[cfg_attr(not(unix), allow(dead_code))]
fn answered(reply: &[u8]) -> bool {
    reply.windows(3).enumerate().any(|(i, window)| {
        window == b"\x1b[?"
            && reply[i + 3..]
                .iter()
                .find(|b| !(b.is_ascii_digit() || **b == b';'))
                == Some(&b'c')
    })
}

/// The colour in an OSC 11 answer: `ESC ] 11 ; rgb:RRRR/GGGG/BBBB`, ended by
/// BEL or ST, with one to four hex digits a channel.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_background(reply: &[u8]) -> Option<(u8, u8, u8)> {
    let text = String::from_utf8_lossy(reply);
    let body = &text[text.find("]11;")? + 4..];
    let spec = &body[..body.find(['\x07', '\x1b']).unwrap_or(body.len())];
    let channels = spec
        .strip_prefix("rgb:")
        .or_else(|| spec.strip_prefix("rgba:"))?;
    let mut parts = channels.split('/').map(|hex| {
        if hex.is_empty() || hex.len() > 4 {
            return None;
        }
        let value = u32::from_str_radix(hex, 16).ok()?;
        let max = (1u32 << (4 * hex.len())) - 1;
        u8::try_from((value * 255 + max / 2) / max).ok()
    });
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_background_answer_is_read_in_the_forms_terminals_send() {
        // xterm, with ST, then its device attributes.
        let xterm = b"\x1b]11;rgb:eeee/f1f1/f5f5\x1b\\\x1b[?64;1;2;6;9;15;18;21;22c";
        assert_eq!(parse_background(xterm), Some((0xee, 0xf1, 0xf5)));
        assert!(answered(xterm));
        // BEL-terminated, two digits a channel.
        assert_eq!(
            parse_background(b"\x1b]11;rgb:1a/1b/26\x07"),
            Some((0x1a, 0x1b, 0x26))
        );
        // One digit a channel is scaled, not truncated.
        assert_eq!(
            parse_background(b"\x1b]11;rgb:f/0/8\x07"),
            Some((255, 0, 136))
        );
        assert_eq!(parse_background(b"\x1b[?62;22c"), None, "no answer");
        assert_eq!(parse_background(b"\x1b]11;rgb:zz/00/00\x07"), None);
    }

    #[test]
    fn device_attributes_end_the_wait() {
        assert!(answered(b"\x1b[?62;22c"));
        assert!(!answered(b"\x1b]11;rgb:0000/0000/0000\x07"));
        assert!(!answered(b"\x1b[?62;22"), "not finished yet");
    }

    #[test]
    fn colorfgbg_names_the_background_last() {
        assert_eq!(mode_from_colorfgbg("15;0"), Some(Mode::Dark));
        assert_eq!(mode_from_colorfgbg("0;15"), Some(Mode::Light));
        assert_eq!(mode_from_colorfgbg("0;default;7"), Some(Mode::Light));
        assert_eq!(mode_from_colorfgbg("12;8"), Some(Mode::Dark));
        assert_eq!(mode_from_colorfgbg("default;default"), None);
    }
}
