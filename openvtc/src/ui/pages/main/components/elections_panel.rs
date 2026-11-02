//! Elections panel — a community's elections, opened from the Communities panel with `e`.
//!
//! Five screens: the list (what can be done first), one election's detail and disclosure, the
//! ballot, its confirmation, and the result. What the member is told before taking a ticket or
//! voting is the disclosure the community publishes (VTI-VOT-090): who runs the ballot box,
//! whether that is the community itself, who can read the board, whether a later vote replaces
//! an earlier one, that a vote can be proven to someone who demands it, and — where written answers
//! are released after fewer than 10 ballots — that one may identify its author (VTI-VOT-065).

use std::time::Instant;

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
};
use crate::state_handler::main_page::content::ContentPanelState;
use crate::state_handler::main_page::elections::{
    BallotForm, ElectionsPhase, ElectionsView, Screen, Severity, Status, VoteResult,
};
use crate::state_handler::main_page::shorten_did;
use crate::state_handler::state::ConnectionState;
use openvtc_core::elections::{
    self, AnswerDraft, Kept, Question, ShownElection, Standing, option_label, question_options,
    question_text,
};

use super::panel::Panel;

pub struct ElectionsPanel;

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_DARK_GRAY))
}

fn text(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_TEXT_DEFAULT))
}

fn warn(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().fg(COLOR_ORANGE))
}

fn wrap(lines: &mut Vec<Line<'static>>, body: &str, indent: usize, style: Style) {
    let pad = " ".repeat(indent);
    for part in super::status::wrap_text(
        body,
        super::status::content_width()
            .saturating_sub(indent + 2)
            .max(20),
    ) {
        lines.push(Line::from(Span::styled(format!("{pad}{part}"), style)));
    }
}

fn push_status(lines: &mut Vec<Line<'static>>, status: &Status) {
    let style = match status.severity {
        Severity::Info | Severity::Progress => Style::default().fg(COLOR_TEXT_DEFAULT),
        Severity::Success => Style::default().fg(COLOR_SUCCESS),
        Severity::Warning => Style::default().fg(COLOR_ORANGE),
        Severity::Error => Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
    };
    wrap(lines, &status.text, 4, style);
}

fn standing_style(s: Standing) -> Style {
    Style::default().fg(match s {
        Standing::VotingOpen => COLOR_SUCCESS,
        Standing::TicketsOpen => COLOR_ORANGE,
        Standing::Upcoming => COLOR_TEXT_DEFAULT,
        Standing::Over => COLOR_DARK_GRAY,
    })
}

fn keys(lines: &mut Vec<Line<'static>>, keys: &[&str]) {
    lines.push(Line::from(""));
    lines.push(Line::from(dim(format!("    {}", keys.join("   ")))));
}

impl Panel for ElectionsPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        let Some(view) = &state.elections.view else {
            return vec![Line::from("no elections view open")];
        };
        let mut lines = vec![Line::from(vec![
            Span::styled(
                format!("  Elections — {}", view.community),
                Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            dim(format!("    as {}", shorten_did(&view.me, 40))),
        ])];
        match view.screen {
            Screen::List => render_list(view, &mut lines),
            Screen::Detail => render_detail(view, &mut lines),
            Screen::Ballot => {
                let recent = view.shown.as_ref().is_some_and(|s| {
                    state.elections.ticket_taken_recently(
                        &view.vtc_did,
                        s.election_id(),
                        Instant::now(),
                    )
                });
                render_ballot(view, recent, &mut lines);
            }
            Screen::Confirm => render_confirm(view, &mut lines),
            Screen::Result => render_result(view, &mut lines),
        }
        lines
    }
}

fn render_list(view: &ElectionsView, lines: &mut Vec<Line<'static>>) {
    match &view.phase {
        ElectionsPhase::Loading => {
            lines.push(Line::from(""));
            lines.push(Line::from(dim(
                "    asking the community which elections you may take part in…",
            )));
            keys(lines, &["r retry", "Esc back"]);
            return;
        }
        ElectionsPhase::Failed(detail) => {
            lines.push(Line::from(""));
            push_status(
                lines,
                &Status {
                    text: detail.clone(),
                    severity: Severity::Error,
                },
            );
            keys(lines, &["r retry", "Esc back"]);
            return;
        }
        ElectionsPhase::Loaded => {}
    }
    lines.push(Line::from(""));
    if view.elections.is_empty() {
        lines.push(Line::from(dim(
            "    The community has no elections you may take part in.",
        )));
    } else {
        lines.push(Line::from(dim(format!(
            "      {:<34}{:<15}{:<24}{}",
            "ELECTION", "STATE", "VOTING CLOSES", "TICKET"
        ))));
        for (i, e) in view.elections.iter().enumerate() {
            let selected = i == view.selected;
            let standing = Standing::of(&e.state);
            let name_style = if selected {
                Style::default().fg(COLOR_SUCCESS).bold()
            } else {
                Style::default().fg(COLOR_TEXT_DEFAULT)
            };
            let title: String = elections::display_title(e).chars().take(32).collect();
            lines.push(Line::from(vec![
                Span::raw(if selected { "    ▸ " } else { "      " }),
                Span::styled(format!("{title:<34}"), name_style),
                Span::styled(
                    format!("{:<15}", elections::state_label(&e.state.to_string())),
                    standing_style(standing),
                ),
                text(format!(
                    "{:<24}",
                    e.voting_closes_at.format("%Y-%m-%d %H:%M UTC")
                )),
                if e.ticket_held {
                    Span::styled("held", Style::default().fg(COLOR_SUCCESS))
                } else {
                    dim("—")
                },
            ]));
        }
    }
    if let Some(status) = &view.status {
        lines.push(Line::from(""));
        push_status(lines, status);
    }
    keys(lines, &["↑/↓ navigate", "⏎ open", "r refresh", "Esc back"]);
}

/// The warning an election whose written answers are released after fewer than 10 ballots
/// carries, wherever the member is about to take a ticket or vote (VTI-VOT-065, VTI-VOT-090).
fn push_text_release_warning(shown: &ShownElection, lines: &mut Vec<Line<'static>>) {
    if let Some(warning) = shown.text_release_warning() {
        lines.push(Line::from(""));
        wrap(
            lines,
            &format!("⚠ {warning}"),
            4,
            Style::default().fg(COLOR_ORANGE).bold(),
        );
    }
}

/// What a member is told about an election before taking a ticket or voting (VTI-VOT-090).
fn render_disclosure(shown: &ShownElection, lines: &mut Vec<Line<'static>>) {
    let m = shown.manifest();
    let d = &shown.typed.disclosure;
    lines.push(Line::from(vec![
        Span::styled(
            format!("    {}", shown.title()),
            Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
        ),
        dim(format!("   {}", shown.state_label())),
    ]));
    if let Some(desc) = &m.description {
        wrap(
            lines,
            &crate::state_handler::main_page::sanitize_display(desc.as_str(), 1200),
            6,
            Style::default().fg(COLOR_DARK_GRAY),
        );
    }
    lines.push(Line::from(""));
    let fmt = |t: &chrono::DateTime<chrono::Utc>| t.format("%Y-%m-%d %H:%M UTC").to_string();
    lines.push(Line::from(vec![
        dim("    tickets from  "),
        text(fmt(&m.registration_opens_at)),
    ]));
    lines.push(Line::from(vec![
        dim("    voting        "),
        text(format!(
            "{} → {}",
            fmt(&m.voting_opens_at),
            fmt(&m.voting_closes_at)
        )),
    ]));
    lines.push(Line::from(vec![
        dim("    ballot box    "),
        text(format!(
            "run by {}",
            crate::state_handler::main_page::sanitize_display(d.ballot_box_operator.as_str(), 120)
        )),
        dim(format!("  {}", shorten_did(d.ballot_box.as_str(), 40))),
    ]));
    if d.same_operator {
        lines.push(Line::from(""));
        wrap(
            lines,
            "⚠ The same operator runs this community and its ballot box: together they could \
             link your ticket to your ballot, and so learn how you voted.",
            4,
            Style::default().fg(COLOR_ORANGE).bold(),
        );
    }
    push_text_release_warning(shown, lines);
    lines.push(Line::from(vec![
        dim("    the board     "),
        text(match d.board_visibility.to_string().as_str() {
            "public" => "public: anyone can read every cast ballot's entry".to_string(),
            _ => "private: only the community and its auditors can read it".to_string(),
        }),
    ]));
    lines.push(Line::from(vec![
        dim("    voting again  "),
        text(match d.revote.to_string().as_str() {
            "replace" => "a later vote replaces your earlier one",
            _ => "refused: your first vote is final",
        }),
    ]));
    lines.push(Line::from(vec![
        dim("    secrecy       "),
        text(match m.secrecy.to_string().as_str() {
            "open" => "open: ballots are counted as cast",
            "sealed" => "sealed: ballots are opened by the trustees after the close",
            _ => "encrypted: only the totals are ever decrypted",
        }),
    ]));
    wrap(
        lines,
        "You can prove how you voted, so this election cannot protect you against being made \
         to vote a certain way.",
        4,
        Style::default().fg(COLOR_DARK_GRAY),
    );
    lines.push(Line::from(""));
    lines.push(Line::from(dim("    Questions")));
    for q in &m.questions {
        let kind = match q {
            Question::Choice {
                min_selections,
                max_selections,
                ..
            } => {
                if max_selections.get() == 1 {
                    "choose one".to_string()
                } else {
                    format!("choose {min_selections}–{}", max_selections.get())
                }
            }
            Question::Ranking { partial, .. } => if *partial {
                "rank as many as you like"
            } else {
                "rank every option"
            }
            .to_string(),
            Question::Score { min, max, .. } => format!("score each {min}–{max}"),
            Question::Text { max_length, .. } => format!("up to {} characters", max_length.get()),
            _ => "a kind this version cannot answer".to_string(),
        };
        let optional = if elections::question_optional(q) {
            ", optional"
        } else {
            ""
        };
        lines.push(Line::from(vec![
            text(format!("      • {}", question_text(q))),
            dim(format!("  ({kind}{optional})")),
        ]));
        let opts: Vec<String> = question_options(q).iter().map(option_label).collect();
        if !opts.is_empty() {
            wrap(
                lines,
                &opts.join(" · "),
                10,
                Style::default().fg(COLOR_DARK_GRAY),
            );
        }
    }
}

fn render_detail(view: &ElectionsView, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    let Some(shown) = view.shown.as_ref() else {
        if let Some(status) = &view.status {
            push_status(lines, status);
        }
        keys(lines, &["r retry", "Esc back"]);
        return;
    };
    render_disclosure(shown, lines);
    if let Some(flow) = &view.flow {
        lines.push(Line::from(""));
        lines.push(Line::from(dim(format!("    {}…", flow.step.words()))));
    }
    if let Some(status) = &view.status {
        lines.push(Line::from(""));
        push_status(lines, status);
    }
    let mut k = Vec::new();
    if view.flow.is_none() && shown.tickets_open() {
        k.push("t take ticket");
    }
    if view.flow.is_none() && shown.voting_open() {
        k.push("v vote");
    }
    k.extend(["r refresh", "Esc back"]);
    keys(lines, &k);
}

/// One question's rows on the ballot.
fn render_question(
    q: &Question,
    draft: &AnswerDraft,
    abstain: bool,
    focused: Option<usize>,
    lines: &mut Vec<Line<'static>>,
) {
    let head_style = if focused.is_some() {
        Style::default().fg(COLOR_SUCCESS).bold()
    } else {
        Style::default().fg(COLOR_TEXT_DEFAULT).bold()
    };
    lines.push(Line::from(vec![
        Span::raw(if focused.is_some() {
            "    ▸ "
        } else {
            "      "
        }),
        Span::styled(question_text(q), head_style),
        if abstain {
            warn("   left blank")
        } else {
            dim("")
        },
    ]));
    let cursor = |i: usize| if focused == Some(i) { "›" } else { " " };
    match draft {
        AnswerDraft::Choice(chosen) => {
            let single =
                matches!(q, Question::Choice { max_selections, .. } if max_selections.get() == 1);
            for (i, o) in question_options(q).iter().enumerate() {
                let on = chosen.iter().any(|k| k.as_str() == o.key.as_str());
                let mark = match (single, on) {
                    (true, true) => "(•)",
                    (true, false) => "( )",
                    (false, true) => "[x]",
                    (false, false) => "[ ]",
                };
                lines.push(Line::from(text(format!(
                    "        {} {mark} {}",
                    cursor(i),
                    option_label(o)
                ))));
            }
        }
        AnswerDraft::Ranking(order) => {
            for (i, o) in question_options(q).iter().enumerate() {
                let rank = order
                    .iter()
                    .position(|k| k.as_str() == o.key.as_str())
                    .map_or_else(|| "  ".to_string(), |p| format!("{:>2}", p + 1));
                lines.push(Line::from(text(format!(
                    "        {} [{rank}] {}",
                    cursor(i),
                    option_label(o)
                ))));
            }
        }
        AnswerDraft::Scores(scores) => {
            for (i, o) in question_options(q).iter().enumerate() {
                let value = scores
                    .get(i)
                    .and_then(|(_, v)| *v)
                    .map_or_else(|| "–".to_string(), |v| v.to_string());
                lines.push(Line::from(text(format!(
                    "        {} {value:>3}  {}",
                    cursor(i),
                    option_label(o)
                ))));
            }
        }
        AnswerDraft::Text(t) => {
            let caret = if focused.is_some() { "▏" } else { "" };
            lines.push(Line::from(text(format!(
                "        › {}{caret}",
                crate::state_handler::main_page::sanitize_display(t, 4096)
            ))));
        }
    }
}

fn render_ballot(view: &ElectionsView, recent_ticket: bool, lines: &mut Vec<Line<'static>>) {
    let (Some(form), Some(shown)) = (view.form.as_ref(), view.shown.as_ref()) else {
        return;
    };
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        format!("    Ballot — {}", shown.title()),
        Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
    )]));
    if recent_ticket {
        wrap(
            lines,
            "⚠ You took this election's ticket less than an hour ago. Voting now lets the \
             community and the ballot box pair the two by when each arrived; voting later \
             keeps them apart.",
            4,
            Style::default().fg(COLOR_ORANGE).bold(),
        );
    }
    push_text_release_warning(shown, lines);
    lines.push(Line::from(""));
    render_form(form, shown, lines);
    if let Some(e) = &form.error {
        lines.push(Line::from(""));
        wrap(
            lines,
            e,
            4,
            Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
        );
    }
    if let Some(status) = &view.status {
        lines.push(Line::from(""));
        push_status(lines, status);
    }
    let typing = form.typing(shown.manifest());
    let mut k = vec!["Tab/Shift-Tab question", "↑/↓ option"];
    if typing {
        k.push("type to answer");
        k.push("Ctrl-a blank");
    } else {
        k.push("space choose/rank");
        k.push("+/- score");
        k.push("a blank");
    }
    k.extend(["⏎ review", "Esc back"]);
    keys(lines, &k);
}

fn render_form(form: &BallotForm, shown: &ShownElection, lines: &mut Vec<Line<'static>>) {
    for (i, (key, draft, abstain)) in form.draft.answers.iter().enumerate() {
        let Some(q) = shown
            .manifest()
            .questions
            .iter()
            .find(|q| elections::question_key(q) == Some(key.as_str()))
        else {
            continue;
        };
        let focused = (i == form.question).then_some(form.option);
        render_question(q, draft, *abstain, focused, lines);
    }
}

fn render_confirm(view: &ElectionsView, lines: &mut Vec<Line<'static>>) {
    let (Some(form), Some(shown)) = (view.form.as_ref(), view.shown.as_ref()) else {
        return;
    };
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("    Cast this ballot in {}?", shown.title()),
        Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
    )));
    lines.push(Line::from(""));
    for (key, draft, abstain) in &form.draft.answers {
        let Some(q) = shown
            .manifest()
            .questions
            .iter()
            .find(|q| elections::question_key(q) == Some(key.as_str()))
        else {
            continue;
        };
        let label = |k: &str| {
            question_options(q)
                .iter()
                .find(|o| o.key.as_str() == k)
                .map_or_else(|| k.to_string(), option_label)
        };
        let answer = if *abstain {
            "left blank".to_string()
        } else {
            match draft {
                AnswerDraft::Choice(c) => c.iter().map(|k| label(k)).collect::<Vec<_>>().join(", "),
                AnswerDraft::Ranking(r) => r
                    .iter()
                    .enumerate()
                    .map(|(i, k)| format!("{}. {}", i + 1, label(k)))
                    .collect::<Vec<_>>()
                    .join("  "),
                AnswerDraft::Scores(s) => s
                    .iter()
                    .map(|(k, v)| format!("{} {}", label(k), v.unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join(", "),
                AnswerDraft::Text(t) => crate::state_handler::main_page::sanitize_display(t, 4096),
            }
        };
        lines.push(Line::from(vec![text(format!(
            "      {}",
            question_text(q)
        ))]));
        wrap(lines, &answer, 10, Style::default().fg(COLOR_SUCCESS));
    }
    push_text_release_warning(shown, lines);
    lines.push(Line::from(""));
    wrap(
        lines,
        "Your VTA seals this ballot under a key made for this vote alone, and this app sends it \
         to the ballot box itself after a short random pause. The community never sees it.",
        4,
        Style::default().fg(COLOR_DARK_GRAY),
    );
    if let Some(status) = &view.status {
        lines.push(Line::from(""));
        push_status(lines, status);
    }
    keys(lines, &["y cast", "any other key: back to the ballot"]);
}

fn render_result(view: &ElectionsView, lines: &mut Vec<Line<'static>>) {
    lines.push(Line::from(""));
    if let Some(flow) = &view.flow {
        lines.push(Line::from(dim(format!("    {}…", flow.step.words()))));
    }
    match &view.result {
        Some(VoteResult::Counted {
            outcome,
            leaf_index,
            kept,
            keep_error,
        }) => {
            lines.push(Line::from(Span::styled(
                format!("    ✓ Voted — {}", outcome.words()),
                Style::default().fg(COLOR_SUCCESS).bold(),
            )));
            lines.push(Line::from(vec![
                dim("    board entry   "),
                text(leaf_index.to_string()),
            ]));
            match (kept, keep_error) {
                (Some(Kept::Included), _) => lines.push(Line::from(dim(
                    "    Your VTA kept the receipt and found your vote on the board.",
                ))),
                (Some(Kept::NotIncluded), _) => wrap(
                    lines,
                    "Your VTA kept the receipt, but the board the community holds does not \
                     include your vote. Keep the receipt: it is your evidence.",
                    4,
                    Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
                ),
                (Some(Kept::Kept), _) => lines.push(Line::from(dim(
                    "    Your VTA kept the receipt; it checks it against the board later.",
                ))),
                (None, Some(e)) => wrap(
                    lines,
                    &format!("Your vote was counted, but your VTA did not keep the receipt: {e}"),
                    4,
                    Style::default().fg(COLOR_ORANGE),
                ),
                (None, None) => {}
            }
        }
        Some(VoteResult::Failed { why, resend }) => {
            lines.push(Line::from(Span::styled(
                "    ✗ Not voted",
                Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED).bold(),
            )));
            wrap(
                lines,
                why,
                4,
                Style::default().fg(COLOR_WARNING_ACCESSIBLE_RED),
            );
            if *resend {
                lines.push(Line::from(dim(
                    "    r sends the same cast again — it is never counted twice.",
                )));
            }
        }
        None => {}
    }
    if let Some(status) = &view.status
        && view.flow.is_none()
    {
        lines.push(Line::from(""));
        push_status(lines, status);
    }
    let resendable = matches!(view.result, Some(VoteResult::Failed { resend: true, .. }));
    if resendable && view.flow.is_none() {
        keys(lines, &["r resend", "Esc back"]);
    } else {
        keys(lines, &["Esc back"]);
    }
}
