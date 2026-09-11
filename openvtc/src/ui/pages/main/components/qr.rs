//! QR codes drawn with Unicode half-blocks, for a vetting ticket someone scans
//! off the screen.
//!
//! One character cell holds one module across and two down: `▀` is a dark
//! upper module, `▄` a dark lower one, `█` both and a space neither. That is the
//! densest a terminal can draw a code and still keep it square enough to scan.
//!
//! The colours are fixed black on white, whatever the theme. A scanner needs
//! dark modules on a light ground with a light margin (the quiet zone), and a
//! theme's foreground and background are chosen for reading text, not for
//! that.

use qrcode::{Color as Module, EcLevel, QrCode};
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};

/// Why no code was drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    /// The narrowest code needs this many columns.
    TooNarrow {
        /// Columns needed.
        needed: usize,
    },
    /// The data does not fit in any QR code.
    TooLong,
}

/// Quiet zones tried, widest first. The specification asks for four modules;
/// phones read two, and usually one, so a narrow window still gets a code.
const QUIET_ZONES: [usize; 3] = [4, 2, 1];

/// Error correction tried, strongest first. A phone photographing a screen
/// gets a clean image, so the lower level is an acceptable price for a code
/// that fits.
const LEVELS: [EcLevel; 2] = [EcLevel::M, EcLevel::L];

/// `data` as a QR code at most `max_width` columns wide, one line per text row.
///
/// # Errors
///
/// [`QrError::TooNarrow`] when even the smallest code with a one-module margin
/// is wider than `max_width`; [`QrError::TooLong`] when no code holds `data`.
pub fn qr_lines(data: &str, max_width: usize) -> Result<Vec<Line<'static>>, QrError> {
    let mut narrowest: Option<usize> = None;
    for level in LEVELS {
        let Ok(code) = QrCode::with_error_correction_level(data, level) else {
            continue;
        };
        let width = code.width();
        for quiet in QUIET_ZONES {
            if width + 2 * quiet <= max_width {
                let modules = with_quiet_zone(&code.to_colors(), width, quiet);
                let style = Style::new().fg(Color::Black).bg(Color::White);
                return Ok(half_block_rows(&modules)
                    .into_iter()
                    .map(|row| Line::from(Span::styled(row, style)))
                    .collect());
            }
        }
        let needed = width + 2 * QUIET_ZONES[QUIET_ZONES.len() - 1];
        narrowest = Some(narrowest.map_or(needed, |n| n.min(needed)));
    }
    Err(narrowest.map_or(QrError::TooLong, |needed| QrError::TooNarrow { needed }))
}

/// The module matrix, `true` for dark, surrounded by `quiet` light modules.
fn with_quiet_zone(colors: &[Module], width: usize, quiet: usize) -> Vec<Vec<bool>> {
    let side = width + 2 * quiet;
    let mut rows = vec![vec![false; side]; side];
    for (i, color) in colors.iter().enumerate() {
        rows[quiet + i / width][quiet + i % width] = *color == Module::Dark;
    }
    rows
}

/// Rows of modules as rows of half-block characters, two module rows per text
/// row. An odd last row is paired with a light one.
pub(crate) fn half_block_rows(modules: &[Vec<bool>]) -> Vec<String> {
    modules
        .chunks(2)
        .map(|pair| {
            let upper = &pair[0];
            let lower = pair.get(1);
            upper
                .iter()
                .enumerate()
                .map(|(x, &top)| {
                    let bottom = lower.is_some_and(|row| row.get(x).copied().unwrap_or(false));
                    match (top, bottom) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    }
                })
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "vetting-ticket:?v=1&community=did%3Awebvh%3AQmCommunity%3Avtc.example.com\
                        &vetter=did%3Awebvh%3AQmVetter%3Aexample.com%3Acarol\
                        &ticket=vt-0123456789abcdef0123456789abcdef\
                        &secret=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn each_cell_is_an_upper_and_a_lower_module() {
        let modules = vec![
            vec![true, true, false, false],
            vec![true, false, true, false],
            vec![false, true, false, true],
        ];
        assert_eq!(half_block_rows(&modules), vec!["█▀▄ ", " ▀ ▀"]);
    }

    #[test]
    fn a_ticket_link_is_drawn_square_with_a_full_quiet_zone_when_there_is_room() {
        let lines = qr_lines(LINK, 200).unwrap();
        let columns = lines[0].width();
        assert!(
            lines.iter().all(|l| l.width() == columns),
            "every row is as wide"
        );
        assert_eq!(lines.len(), columns.div_ceil(2), "two modules per text row");
        let code = QrCode::with_error_correction_level(LINK, EcLevel::M).unwrap();
        assert_eq!(columns, code.width() + 8);
    }

    #[test]
    fn a_narrow_window_gets_a_tighter_code_or_is_told_how_wide_to_be() {
        let full = qr_lines(LINK, 200).unwrap()[0].width();
        let tight = qr_lines(LINK, full - 1).unwrap()[0].width();
        assert!(tight < full);
        match qr_lines(LINK, 20) {
            Err(QrError::TooNarrow { needed }) => {
                assert!(needed > 20);
                assert!(
                    qr_lines(LINK, needed).is_ok(),
                    "the width it names is enough"
                );
            }
            other => panic!("expected TooNarrow, got {other:?}"),
        }
    }

    #[test]
    fn data_no_code_can_hold_is_refused() {
        assert_eq!(qr_lines(&"x".repeat(8000), 500), Err(QrError::TooLong));
    }
}
