//! Join flow — collect a credential from the applicant's wallet.
//!
//! A community whose criterion asks for an SD-JWT VC (a swiyu or EUDI
//! credential) can be answered by a wallet over OpenID4VP. This page offers
//! that, then shows the code the wallet scans and where the session stands.
//! The wallet answers the community directly; nothing it presents passes
//! through this client, which only opens the session and asks how it went.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Layout, Margin,
    },
    style::{Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::{
    colors::{COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT},
    state_handler::{
        actions::Action,
        join::{JoinState, WalletPhase, WalletStep},
        main_page::sanitize_display,
    },
    ui::pages::{join_flow::JoinFlow, main::components::qr::qr_lines},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct WalletPage;

impl WalletPage {
    pub fn handle_key_event(state: &mut JoinFlow, key: KeyEvent) {
        let offered = state
            .props
            .state
            .wallet
            .as_ref()
            .is_some_and(|w| matches!(w.phase, WalletPhase::Offered { .. }));
        let action = match key.code {
            KeyCode::F(10) => Action::Exit,
            KeyCode::Enter if offered => Action::JoinWalletStart,
            KeyCode::Char('s') if offered => Action::JoinWalletSkip,
            // While the session runs, Esc stops waiting for it; on the offer,
            // it leaves the join as on every other page.
            KeyCode::Esc => Action::JoinCancel,
            _ => return,
        };
        let _ = state.action_tx.send(action);
    }

    pub fn render(&self, state: &JoinState, frame: &mut Frame<'_>) {
        let [middle, bottom] = Layout::vertical([Min(0), Length(3)]).areas(frame.area());
        frame.render_widget(
            Block::bordered()
                .fg(COLOR_BORDER)
                .padding(Padding::proportional(1))
                .title(" Present from your wallet "),
            middle,
        );
        let inner = middle.inner(Margin::new(3, 2));
        let (lines, keys) = match state.wallet.as_ref() {
            Some(wallet) => content(wallet, inner.width as usize, inner.height as usize),
            None => (
                vec![Line::styled(
                    "Nothing to present.",
                    Style::new().fg(COLOR_DARK_GRAY),
                )],
                "Esc cancel",
            ),
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        frame.render_widget(
            Paragraph::new(Line::styled(keys, Style::new().fg(COLOR_DARK_GRAY)))
                .block(Block::bordered().fg(COLOR_BORDER)),
            bottom,
        );
    }
}

/// The page's lines and its key help, for `width` × `height` cells.
fn content(wallet: &WalletStep, width: usize, height: usize) -> (Vec<Line<'static>>, &'static str) {
    let text = |t: String| Line::styled(t, Style::new().fg(COLOR_TEXT_DEFAULT));
    let dim = |t: String| Line::styled(t, Style::new().fg(COLOR_DARK_GRAY));
    let community = sanitize_display(&wallet.community, 120);
    match &wallet.phase {
        WalletPhase::Offered { note } => {
            let mut lines = vec![
                text(format!(
                    "{community} accepts a credential from a digital-identity wallet (swiyu or \
                     EUDI) for joining:"
                )),
                Line::default(),
            ];
            if let Some(description) = &wallet.description {
                lines.push(text(format!("  {}", sanitize_display(description, 300))));
            }
            for vct in &wallet.types {
                lines.push(dim(format!(
                    "  credential type  {}",
                    sanitize_display(vct, 200)
                )));
            }
            lines.push(Line::default());
            lines.push(text(
                "Present it now and the request names that criterion: the community counts \
                 what your wallet showed it. Your wallet asks before it shares anything, and \
                 what it shares goes to the community, not through this client."
                    .to_string(),
            ));
            if let Some(note) = note {
                lines.push(Line::default());
                lines.push(Line::styled(
                    sanitize_display(note, 400),
                    Style::new().fg(COLOR_ORANGE),
                ));
            }
            (
                lines,
                "Enter open a wallet session   s continue without it   Esc cancel",
            )
        }
        WalletPhase::Opening => (
            vec![text(format!("Asking {community} for a wallet session…"))],
            "Esc stop waiting",
        ),
        WalletPhase::Scan {
            wallet_uri,
            expires_at,
            retrieved,
        } => {
            let mut lines = vec![text(
                "Scan this with your wallet, or open the link on the device that holds it:"
                    .to_string(),
            )];
            let qr_height = height.saturating_sub(7);
            match qr_lines(wallet_uri, width, qr_height) {
                Ok(code) => lines.extend(code),
                Err(_) => lines.push(dim(
                    "(The window is too small for the code — enlarge it, or use the link.)"
                        .to_string(),
                )),
            }
            lines.push(dim(sanitize_display(wallet_uri, 2048)));
            lines.push(Line::default());
            lines.push(if *retrieved {
                Line::from(vec![
                    Span::styled("✓ ", Style::new().fg(COLOR_SUCCESS)),
                    Span::styled(
                        "Your wallet has the request — answer it there.",
                        Style::new().fg(COLOR_TEXT_DEFAULT),
                    ),
                ])
            } else {
                text("Waiting for your wallet…".to_string())
            });
            lines.push(dim(format!(
                "The session lapses at {}.",
                expires_at.format("%H:%M UTC")
            )));
            (lines, "Esc stop waiting")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(phase: WalletPhase) -> WalletStep {
        WalletStep {
            community: "Example community".into(),
            requirements_digest: "zDigest".into(),
            description: Some("A Swiss e-ID".into()),
            types: vec!["urn:eudi:pid:1".into()],
            phase,
            parked: None,
        }
    }

    fn joined(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_offer_names_what_is_asked_and_why_it_failed_last_time() {
        let (lines, keys) = content(
            &step(WalletPhase::Offered {
                note: Some("The session expired.".into()),
            }),
            80,
            40,
        );
        let text = joined(&lines);
        assert!(text.contains("urn:eudi:pid:1"), "{text}");
        assert!(text.contains("A Swiss e-ID"), "{text}");
        assert!(text.contains("The session expired."), "{text}");
        assert!(keys.contains("continue without"), "{keys}");
    }

    #[test]
    fn an_open_session_shows_its_link_and_what_the_wallet_has_done() {
        let uri = "swiyu-verify://?client_id=decentralized_identifier%3Adid%3Aexample&request_uri=https%3A%2F%2Fvtc.example%2Fv1%2Foid4vp%2Frequest%2Fabc";
        let phase = |retrieved| WalletPhase::Scan {
            wallet_uri: uri.into(),
            expires_at: chrono::Utc::now(),
            retrieved,
        };
        let text = joined(&content(&step(phase(false)), 120, 60).0);
        assert!(text.contains(uri), "{text}");
        assert!(text.contains("Waiting for your wallet"), "{text}");
        let text = joined(&content(&step(phase(true)), 120, 60).0);
        assert!(text.contains("answer it there"), "{text}");
    }
}
