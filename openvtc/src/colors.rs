use console::StyledObject;
use ratatui::style::Color;

use crate::theme::{self, Role};

// Command-line colours
//
// What `openvtc` prints outside the TUI — before it starts, and from its
// subcommands — is coloured by role too, in the active theme's colours:
// `crate::theme::init` chooses the theme before anything is printed. Style with
// `.themed(CLI_*)` rather than a literal colour.

/// General information.
pub const CLI_INFO: Role = Role::Accent;
/// Error messages.
pub const CLI_ERROR: Role = Role::Danger;
/// Cautionary data.
pub const CLI_CAUTION: Role = Role::Warning;
/// Example data and values.
pub const CLI_EXAMPLE: Role = Role::Highlight;

/// Colour command-line output by role.
pub trait Themed {
    /// Draw in the active theme's colour for `role`: 24-bit where the terminal
    /// says it draws 24-bit colour, else the nearest of the 256 colours, and in
    /// no colour at all under `NO_COLOR`.
    #[must_use]
    fn themed(self, role: Role) -> Self;
}

impl<D> Themed for StyledObject<D> {
    fn themed(self, role: Role) -> Self {
        if theme::no_color() {
            return self;
        }
        match theme::active_palette().get(role) {
            Color::Rgb(r, g, b) if theme::terminal::truecolor() => self.true_color(r, g, b),
            Color::Rgb(r, g, b) => self.color256(nearest_256((r, g, b))),
            Color::Indexed(n) => self.color256(n),
            named => match theme::ansi_index(named) {
                Some(n) => self.color256(n),
                None => self,
            },
        }
    }
}

/// The xterm 256-colour index nearest `rgb`: from the 6×6×6 colour cube or the
/// grey ramp, whichever is closer.
fn nearest_256((r, g, b): (u8, u8, u8)) -> u8 {
    const LEVELS: [i32; 6] = [0, 95, 135, 175, 215, 255];
    let step = |v: u8| -> usize {
        match v {
            0..48 => 0,
            48..115 => 1,
            _ => usize::from((v - 35) / 40),
        }
    };
    let distance = |(x, y, z): (i32, i32, i32)| {
        let (dr, dg, db) = (x - i32::from(r), y - i32::from(g), z - i32::from(b));
        dr * dr + dg * dg + db * db
    };
    let (qr, qg, qb) = (step(r), step(g), step(b));
    let cube = (LEVELS[qr], LEVELS[qg], LEVELS[qb]);
    let cube_index = 16 + 36 * qr + 6 * qg + qb;

    let average = (i32::from(r) + i32::from(g) + i32::from(b)) / 3;
    let grey_step = if average > 238 {
        23
    } else {
        (average - 3).max(0) / 10
    };
    let grey = 8 + 10 * grey_step;
    if distance((grey, grey, grey)) < distance(cube) {
        u8::try_from(232 + grey_step).unwrap_or(255)
    } else {
        u8::try_from(cube_index).unwrap_or(255)
    }
}

// ****************************************************************************

// Ratatui colour roles
//
// Each constant below names a *role*, and these are OpenVTC's own colours for
// it. Panels style with the roles; after every frame `crate::theme::paint`
// swaps each role for the active theme's colour (docs/themes.md). Keep styling
// with these rather than literal colours, or a panel will ignore the theme.

/// Success state - Completed actions, valid inputs, positive feedback
pub const COLOR_SUCCESS: Color = Color::Rgb(61, 220, 132); // #3DDC84 - Android Green

///Using bright blue for professional, accessible appearance
pub const COLOR_BORDER: Color = Color::Rgb(97, 175, 239); // #61AFEF - Blue

/// Warning state - Warnings, cautions, important notices, loading/processing
pub const COLOR_ORANGE: Color = Color::Rgb(255, 184, 108); // #FFB86C - Orange

/// Warning state - Accessible red for important warnings and cautions
pub const COLOR_WARNING_ACCESSIBLE_RED: Color = Color::Rgb(220, 100, 100); // #DC6464 - Accessible Red

/// Default text color
pub const COLOR_TEXT_DEFAULT: Color = Color::White;

/// Muted Text
pub const COLOR_DARK_GRAY: Color = Color::DarkGray;

/// Copy/Export actions and sensitive data shortcuts (\[C\], \[C1\], \[C2\], \[C3\])
/// Soft Purple to distinguish special operations
pub const COLOR_SOFT_PURPLE: Color = Color::Rgb(189, 147, 249); // #BD93F9

#[cfg(test)]
mod tests {
    use super::*;

    /// The 256-colour fallback lands on the colours OpenVTC used before
    /// command-line output was themed.
    #[test]
    fn rgb_falls_back_to_the_nearest_of_256() {
        assert_eq!(nearest_256((95, 135, 255)), 69);
        assert_eq!(nearest_256((255, 0, 0)), 196);
        assert_eq!(nearest_256((128, 128, 128)), 244);
        assert_eq!(nearest_256((0, 0, 0)), 16);
        assert_eq!(nearest_256((255, 255, 255)), 231);
        assert_eq!(nearest_256((0x61, 0xaf, 0xef)), 75);
    }
}
