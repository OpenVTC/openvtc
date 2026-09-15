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
    /// The smallest code still does not fit the space it was given.
    ///
    /// Carries what the smallest code needs in each direction, so the message
    /// can say how much bigger the window has to be rather than only that it is
    /// too small. Either figure may already be satisfied — the code failed on
    /// the other one.
    TooBig {
        /// Columns the smallest code needs.
        needed_width: usize,
        /// Text rows the smallest code needs.
        needed_height: usize,
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

/// The text rows a code of `side` modules occupies: two module rows per row,
/// and an odd last row still needs a row of its own.
fn rows_for(side: usize) -> usize {
    side.div_ceil(2)
}

/// `data` as a QR code fitting `max_width` columns and `max_height` text rows,
/// one line per text row.
///
/// # Why height is a hard limit and not something to scroll
///
/// A scanner needs the whole code — finder patterns in three corners, quiet
/// zone all round — in one view. Half a QR code is not a degraded QR code, it
/// is nothing, so a code that overflows the panel is no more useful than no
/// code at all while being much more convincing. Sizing by width alone drew
/// exactly that: on a wide, short terminal the widest, tallest code was chosen
/// and ran off the bottom.
///
/// Both budgets shrink the same two dials — the error-correction level and the
/// quiet zone — so the first combination that fits is the strongest one that
/// does.
///
/// # Errors
///
/// [`QrError::TooBig`] when the smallest code still does not fit, carrying what
/// it would need; [`QrError::TooLong`] when no code holds `data`.
pub fn qr_lines(
    data: &str,
    max_width: usize,
    max_height: usize,
) -> Result<Vec<Line<'static>>, QrError> {
    let mut smallest: Option<usize> = None;
    for level in LEVELS {
        let Ok(code) = QrCode::with_error_correction_level(data, level) else {
            continue;
        };
        let width = code.width();
        for quiet in QUIET_ZONES {
            let side = width + 2 * quiet;
            if side <= max_width && rows_for(side) <= max_height {
                let modules = with_quiet_zone(&code.to_colors(), width, quiet);
                let style = Style::new().fg(Color::Black).bg(Color::White);
                return Ok(half_block_rows(&modules)
                    .into_iter()
                    .map(|row| Line::from(Span::styled(row, style)))
                    .collect());
            }
        }
        let side = width + 2 * QUIET_ZONES[QUIET_ZONES.len() - 1];
        smallest = Some(smallest.map_or(side, |s: usize| s.min(side)));
    }
    Err(smallest.map_or(QrError::TooLong, |side| QrError::TooBig {
        needed_width: side,
        needed_height: rows_for(side),
    }))
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

    /// Plenty of room in both directions.
    const ROOMY: usize = 200;

    #[test]
    fn a_ticket_link_is_drawn_square_with_a_full_quiet_zone_when_there_is_room() {
        let lines = qr_lines(LINK, ROOMY, ROOMY).unwrap();
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
        let full = qr_lines(LINK, ROOMY, ROOMY).unwrap()[0].width();
        let tight = qr_lines(LINK, full - 1, ROOMY).unwrap()[0].width();
        assert!(tight < full);
        match qr_lines(LINK, 20, ROOMY) {
            Err(QrError::TooBig { needed_width, .. }) => {
                assert!(needed_width > 20);
                assert!(
                    qr_lines(LINK, needed_width, ROOMY).is_ok(),
                    "the width it names is enough"
                );
            }
            other => panic!("expected TooBig, got {other:?}"),
        }
    }

    /// Height is a budget like width, and for a harder reason: a code taller
    /// than the panel used to be drawn anyway and run off the bottom, which is
    /// not a smaller code but a picture of nothing.
    #[test]
    fn a_short_window_gets_a_shorter_code_or_is_told_how_tall_to_be() {
        let full = qr_lines(LINK, ROOMY, ROOMY).unwrap();
        let rows = full.len();

        // One row short of the strongest code: a weaker one fits instead.
        let tighter = qr_lines(LINK, ROOMY, rows - 1).unwrap();
        assert!(tighter.len() < rows);
        assert_eq!(
            tighter.len(),
            tighter[0].width().div_ceil(2),
            "still two modules per row — a shorter code, not a cropped one"
        );

        match qr_lines(LINK, ROOMY, 5) {
            Err(QrError::TooBig {
                needed_height,
                needed_width,
            }) => {
                assert!(needed_height > 5);
                assert!(
                    qr_lines(LINK, ROOMY, needed_height).is_ok(),
                    "the height it names is enough"
                );
                assert!(
                    needed_width <= ROOMY,
                    "width was never the problem here, and the message says so \
                     by comparing each figure against what it was given"
                );
            }
            other => panic!("expected TooBig, got {other:?}"),
        }
    }

    /// The case that was shipped: a wide, short panel. Width alone said yes.
    #[test]
    fn a_wide_but_short_window_is_refused_rather_than_overflowed() {
        let rows = qr_lines(LINK, ROOMY, ROOMY).unwrap().len();
        assert!(
            qr_lines(LINK, ROOMY, rows / 2).is_err(),
            "a code twice the height of the space is not drawn at all"
        );
    }

    #[test]
    fn data_no_code_can_hold_is_refused() {
        assert_eq!(qr_lines(&"x".repeat(8000), 500, 500), Err(QrError::TooLong));
    }
}
