//! The startup loading screen (`ActivePage::Loading`).
//!
//! Shown while the app loads its config and establishes the mediator
//! connection, replacing the previous behaviour of rendering the full (but not
//! yet interactive) main page during startup. It surfaces the current startup
//! phase, a tail of the activity log, a rotating tip, and — on failure — the
//! full error plus a recovery suggestion.
//!
//! A small [`Component`] mirroring the shape of the other pages: a `Props`
//! struct mapped `From<&State>` carries everything the screen renders, so the
//! component itself stays free of business logic.

use crate::{
    colors::{
        COLOR_BORDER, COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS,
        COLOR_TEXT_DEFAULT, COLOR_WARNING_ACCESSIBLE_RED,
    },
    state_handler::{
        actions::Action,
        state::{LoadingTask, MediatorStatus, State, StepStatus},
    },
    ui::component::{Component, ComponentRender},
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::{
    Frame,
    layout::{
        Constraint::{Length, Min},
        Flex, Layout,
    },
    style::Style,
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};
use tokio::sync::mpsc::UnboundedSender;

/// Rotating friendly/fun tips about verifiable trust shown during startup.
/// Indexed by `tip_index % TIPS.len()`.
const TIPS: &[&str] = &[
    "Tip: A DID is an identifier you control — no central registrar required.",
    "Did you know? Verifiable credentials are cryptographically tamper-evident.",
    "Tip: Your keys never leave your device — trust is proven, not surrendered.",
    "Did you know? did:webvh anchors your DID to a verifiable history log.",
    "Tip: DIDComm messages are end-to-end encrypted between peers.",
    "Tip: A relationship is mutual — both parties prove who they are.",
];

/// Multi-line banner shown at the top of the loading screen.
const BANNER: &[&str] = &[
    "  ___                __     _______ ___ ",
    " / _ \\ _ __  ___ _ _ \\ \\   / |_   _/ __|",
    "| (_) | '_ \\/ -_) ' \\ \\ \\ / /  | || (__ ",
    " \\___/| .__/\\___|_||_| \\_V_/   |_| \\___|",
    "      |_|                               ",
];

/// State-mapped props for the loading screen.
#[derive(Clone, Debug)]
pub struct Props {
    /// Cause-specific troubleshooting for a startup failure, when there is one.
    /// Its presence — not `MediatorStatus::Failed` — is what switches the screen
    /// into its troubleshooting layout.
    pub diagnosis: Option<std::sync::Arc<openvtc_core::diagnostics::Diagnosis>>,
    /// What loaded but shouldn't have been missing, when the profile came up
    /// only partially. Turns the continue prompt into an acknowledgement.
    pub integrity: Option<std::sync::Arc<openvtc_core::config::integrity::LoadIntegrity>>,
    /// Current mediator/connection status, driving the phase + error display.
    pub status: MediatorStatus,
    /// Hierarchical, timed startup tasks (the last may still be in progress).
    pub tasks: Vec<LoadingTask>,
    /// Rotating-tip index (advanced as startup steps stream); also drives the
    /// running-step spinner frame.
    pub tip_index: usize,
    /// True once phase 1 finished — show the "Press Enter to continue" prompt.
    pub complete: bool,
}

impl From<&State> for Props {
    fn from(state: &State) -> Self {
        Props {
            diagnosis: state.startup_diagnosis.clone(),
            integrity: state.integrity.clone(),
            status: state.connection.status.clone(),
            tasks: state.loading.clone(),
            tip_index: state.tip_index,
            complete: state.loading_complete,
        }
    }
}

/// Human-friendly duration: milliseconds (2 dp) under a second, seconds (2 dp)
/// at or above — e.g. `3.42ms`, `842.10ms`, `5.83s`.
fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs_f64();
    if secs >= 1.0 {
        format!("{secs:.2}s")
    } else {
        format!("{:.2}ms", d.as_micros() as f64 / 1000.0)
    }
}

/// The startup loading screen.
pub struct LoadingScreen {
    /// Action sender (used only to request exit on F10).
    pub action_tx: UnboundedSender<Action>,
    /// State-mapped props.
    pub props: Props,
    /// First body line shown, for scrolling a failure report that is taller
    /// than the terminal. A truncated diagnosis helps nobody, and the remedies
    /// — the part the user needs most — are at the bottom.
    pub scroll: u16,
    /// Body line count from the last frame, so scroll clamping matches what was
    /// actually drawn at the terminal's actual width. Interior mutability
    /// because `render` takes `&self`.
    rendered_lines: std::cell::Cell<u16>,
}

impl Component for LoadingScreen {
    fn new(state: &State, action_tx: UnboundedSender<Action>) -> Self
    where
        Self: Sized,
    {
        LoadingScreen {
            action_tx,
            props: Props::from(state),
            scroll: 0,
            rendered_lines: std::cell::Cell::new(0),
        }
    }

    fn move_with_state(self, state: &State) -> Self
    where
        Self: Sized,
    {
        LoadingScreen {
            props: Props::from(state),
            ..self
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return;
        }
        match key.code {
            KeyCode::F(10) => {
                let _ = self.action_tx.send(Action::Exit);
            }
            // Once phase 1 has finished, Enter dismisses the loading screen and
            // reveals the main page (phase-2 connections already run in the bg).
            KeyCode::Enter if self.props.complete => {
                let _ = self.action_tx.send(Action::DismissLoading);
            }
            // A failure report is usually taller than the viewport. Clamp
            // against the rendered line count so scrolling cannot run off into
            // blank space the user then has to scroll back out of.
            KeyCode::Down | KeyCode::Char('j') if self.props.diagnosis.is_some() => {
                self.scroll = (self.scroll + 1).min(self.max_scroll());
            }
            KeyCode::Up | KeyCode::Char('k') if self.props.diagnosis.is_some() => {
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::PageDown if self.props.diagnosis.is_some() => {
                self.scroll = (self.scroll + 10).min(self.max_scroll());
            }
            KeyCode::PageUp if self.props.diagnosis.is_some() => {
                self.scroll = self.scroll.saturating_sub(10);
            }
            KeyCode::Home if self.props.diagnosis.is_some() => self.scroll = 0,
            KeyCode::End if self.props.diagnosis.is_some() => self.scroll = self.max_scroll(),
            _ => {}
        }
    }
}

impl LoadingScreen {
    /// Width of the content column. A failure report is denser than a progress
    /// list and needs the room; the normal startup view keeps its narrow,
    /// centred column.
    fn content_width(&self, available: u16) -> u16 {
        if self.props.diagnosis.is_some() || self.props.integrity.is_some() {
            96u16.min(available.saturating_sub(2))
        } else {
            64u16.min(available.saturating_sub(2))
        }
    }

    /// Largest useful scroll offset, taken from what the last frame actually
    /// drew — an estimate would leave `End` short of the remedies on a narrow
    /// terminal, which is exactly where they are hardest to reach.
    fn max_scroll(&self) -> u16 {
        // Leave a few lines on screen rather than scrolling to pure blank.
        self.rendered_lines.get().saturating_sub(4)
    }

    /// Wrap `text` into lines of at most `width` columns.
    ///
    /// Callers add their own prefix spans (a list marker, a key column) and must
    /// subtract those from `width` first: a prefix added afterwards would push
    /// the line past the render area, and ratatui's `Wrap` would then re-wrap it
    /// back to the left margin — undoing the hanging indent this exists to keep.
    /// `Wrap` stays enabled underneath purely as a safety net for a terminal
    /// narrower than we sized for.
    fn wrap_to(text: &str, width: usize) -> Vec<String> {
        let width = width.max(8);
        let mut lines = vec![String::new()];
        for word in text.split_whitespace() {
            let line = lines.last_mut().expect("seeded with one line");
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                lines.push(word.to_string());
            } else {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            }
        }
        lines
    }

    /// Wrapped lines, each carrying a prefix: `first` on line one and `rest` on
    /// every continuation, so a list item stays visually one item.
    fn wrap_with_prefix(
        text: &str,
        width: usize,
        first: &str,
        rest: &str,
    ) -> Vec<(String, String)> {
        let indent = first.chars().count().max(rest.chars().count());
        Self::wrap_to(text, width.saturating_sub(indent))
            .into_iter()
            .enumerate()
            .map(|(i, line)| {
                (
                    if i == 0 {
                        first.to_string()
                    } else {
                        rest.to_string()
                    },
                    line,
                )
            })
            .collect()
    }

    /// Render one labelled section: a heading, then indented body lines.
    fn section(lines: &mut Vec<Line<'static>>, heading: &str, body: Vec<Line<'static>>) {
        if body.is_empty() {
            return;
        }
        lines.push(Line::default());
        lines.push(Line::styled(
            heading.to_string(),
            Style::new().fg(COLOR_BORDER).bold(),
        ));
        lines.extend(body);
    }

    /// The full troubleshooting report.
    ///
    /// Ordered by what the user needs first: what failed, what it means, the
    /// state of the things involved, how to confirm it, and only then what to
    /// do — with the destructive options last, where [`openvtc_core::diagnostics`]
    /// puts them.
    fn diagnosis_lines(
        d: &openvtc_core::diagnostics::Diagnosis,
        width: usize,
    ) -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::new();
        let red = Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED);
        let body = Style::new().fg(COLOR_TEXT_DEFAULT);
        let dim = Style::new().fg(COLOR_DARK_GRAY);

        let plain = |text: String, style: Style| Line::from(Span::styled(text, style));
        let prefixed = |(prefix, text): (String, String), pstyle: Style, tstyle: Style| {
            Line::from(vec![
                Span::styled(prefix, pstyle),
                Span::styled(text, tstyle),
            ])
        };

        lines.extend(
            Self::wrap_to(&d.headline, width)
                .into_iter()
                .map(|l| plain(l, red.bold())),
        );
        lines.push(Line::default());
        lines.extend(
            Self::wrap_with_prefix(&d.error, width, "", "  ")
                .into_iter()
                .map(|p| prefixed(p, red, red)),
        );

        if !d.cause.is_empty() {
            lines.push(Line::default());
            lines.extend(
                Self::wrap_to(&d.cause, width)
                    .into_iter()
                    .map(|l| plain(l, body)),
            );
        }

        // Values line up in a column, and a wrapped value stays inside it
        // rather than running back to the left margin.
        let key_width = d.context.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        let mut details = Vec::new();
        for (k, v) in &d.context {
            let first = format!("  {k:<key_width$}  ");
            let rest = " ".repeat(first.len());
            details.extend(
                Self::wrap_with_prefix(v, width, &first, &rest)
                    .into_iter()
                    .map(|p| prefixed(p, dim, body)),
            );
        }
        Self::section(&mut lines, "Details", details);

        let mut checks = Vec::new();
        for c in &d.checks {
            checks.extend(
                Self::wrap_with_prefix(c, width, "  $ ", "    ")
                    .into_iter()
                    .map(|p| prefixed(p, dim, Style::new().fg(COLOR_SOFT_PURPLE))),
            );
        }
        Self::section(&mut lines, "Check for yourself", checks);

        let mut remedies = Vec::new();
        for (i, r) in d.remedies.iter().enumerate() {
            let first = format!("  {}. ", i + 1);
            let rest = " ".repeat(first.len());
            remedies.extend(
                Self::wrap_with_prefix(r, width, &first, &rest)
                    .into_iter()
                    .map(|p| prefixed(p, dim, body)),
            );
        }
        Self::section(&mut lines, "What to try, in order", remedies);

        lines
    }

    /// The degraded-load report.
    ///
    /// Says three things in order, because they are three different questions
    /// the user has: what is missing, what still works, and what to do about it.
    /// The "what still works" half is not padding — the whole change this
    /// belongs to exists so that one broken persona no longer means nothing
    /// loads, and a report that only lists damage would hide that.
    fn integrity_lines(
        integrity: &openvtc_core::config::integrity::LoadIntegrity,
        width: usize,
    ) -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::new();
        let warn = Style::new().fg(COLOR_ORANGE);
        let body = Style::new().fg(COLOR_TEXT_DEFAULT);
        let dim = Style::new().fg(COLOR_DARK_GRAY);

        lines.extend(
            Self::wrap_to("This profile did not load completely.", width)
                .into_iter()
                .map(|l| Line::from(Span::styled(l, warn.bold()))),
        );

        let mut missing = Vec::new();
        for persona in &integrity.degraded_personas {
            let name = persona.label.clone().unwrap_or_else(|| {
                openvtc_core::display::shorten_for_display(&persona.did, 44).into_owned()
            });
            missing.extend(
                Self::wrap_with_prefix(
                    &format!("Persona {name} — {}", persona.reason.summary()),
                    width,
                    "  • ",
                    "    ",
                )
                .into_iter()
                .map(|(p, t)| Line::from(vec![Span::styled(p, dim), Span::styled(t, body)])),
            );
        }
        for membership in &integrity.stranded_memberships {
            let name = membership.label.clone().unwrap_or_else(|| {
                openvtc_core::display::shorten_for_display(&membership.vtc_did, 44).into_owned()
            });
            missing.extend(
                Self::wrap_with_prefix(
                    &format!("Community {name} — inactive, its persona did not load"),
                    width,
                    "  • ",
                    "    ",
                )
                .into_iter()
                .map(|(p, t)| Line::from(vec![Span::styled(p, dim), Span::styled(t, body)])),
            );
        }
        if !integrity.orphaned_key_ids.is_empty() {
            missing.extend(
                Self::wrap_with_prefix(
                    &format!(
                        "{} key record(s) belong to no persona in this account — \
                         evidence of the same interrupted save",
                        integrity.orphaned_key_ids.len()
                    ),
                    width,
                    "  • ",
                    "    ",
                )
                .into_iter()
                .map(|(p, t)| Line::from(vec![Span::styled(p, dim), Span::styled(t, body)])),
            );
        }
        Self::section(&mut lines, "Not available this session", missing);

        Self::section(
            &mut lines,
            "Everything else loaded normally",
            Self::wrap_with_prefix(
                "Your other personas, communities and relationships are unaffected. \
                 Nothing has been deleted: the records above are still in your \
                 configuration and are skipped, not removed.",
                width,
                "  ",
                "  ",
            )
            .into_iter()
            .map(|(p, t)| Line::from(vec![Span::styled(p, dim), Span::styled(t, body)]))
            .collect(),
        );

        // The advice divides on one question: is this loss, or a bad moment?
        let advice: Vec<String> = if integrity.is_all_transient() {
            vec![
                "This looks temporary — the VTA or the network could not be reached for \
                 these personas rather than anything being lost."
                    .to_string(),
                "Restart OpenVTC once connectivity is back; they should load normally.".to_string(),
            ]
        } else {
            vec![
                "A persona recorded with no key material is the signature of a save that \
                 was interrupted — most often a crash or a power loss part-way through \
                 creating that persona."
                    .to_string(),
                "If you have an encrypted export from before the interruption, restoring \
                 it (Settings -> Import / Restore Backup) is the way to get the persona \
                 back."
                    .to_string(),
                "Otherwise the affected persona cannot be recovered and will need to be \
                 created again, and any community joined with it re-joined. It is left \
                 in your configuration until you remove it."
                    .to_string(),
                "This does not affect your other personas — carry on using them.".to_string(),
            ]
        };
        let mut advice_lines = Vec::new();
        for (i, item) in advice.iter().enumerate() {
            let first = format!("  {}. ", i + 1);
            let rest = " ".repeat(first.len());
            advice_lines.extend(
                Self::wrap_with_prefix(item, width, &first, &rest)
                    .into_iter()
                    .map(|(p, t)| Line::from(vec![Span::styled(p, dim), Span::styled(t, body)])),
            );
        }
        Self::section(&mut lines, "What this means", advice_lines);

        lines
    }

    /// The human-readable phase line derived from the connection status.
    /// `Failed` is handled separately (rendered as a prominent error block).
    fn phase_line(status: &MediatorStatus) -> Line<'static> {
        let (text, color) = match status {
            MediatorStatus::Unknown => ("Starting…".to_string(), COLOR_DARK_GRAY),
            MediatorStatus::Initializing(step) => (step.clone(), COLOR_SOFT_PURPLE),
            MediatorStatus::Connecting => {
                ("Connecting to the mediator…".to_string(), COLOR_SOFT_PURPLE)
            }
            MediatorStatus::Connected => ("Connected".to_string(), COLOR_SUCCESS),
            MediatorStatus::NoActiveCommunity => ("Ready".to_string(), COLOR_SUCCESS),
            MediatorStatus::Failed(_) => {
                ("Startup failed".to_string(), COLOR_WARNING_ACCESSIBLE_RED)
            }
        };
        Line::styled(text, Style::new().fg(color).bold())
    }

    /// Per-status leading icon + colour. A `Running` step gets a simple
    /// frame-based spinner driven by `tick` (the tip index, bumped each step).
    fn status_icon(status: StepStatus, tick: usize) -> (String, ratatui::style::Color) {
        const SPINNER: &[char] = &['▸', '▹', '▸', '▹'];
        match status {
            StepStatus::Queued => ("◦".to_string(), COLOR_DARK_GRAY),
            StepStatus::Running => (SPINNER[tick % SPINNER.len()].to_string(), COLOR_SOFT_PURPLE),
            StepStatus::Done => ("✓".to_string(), COLOR_SUCCESS),
            StepStatus::Failed => ("✗".to_string(), COLOR_WARNING_ACCESSIBLE_RED),
        }
    }

    /// Column the timing annotation starts at, so times line up neatly.
    const TIME_COL: usize = 34;

    /// A right-aligned `(time)` annotation, padded so it lands in `TIME_COL`.
    /// `prefix_len` is the visible width already consumed on the line.
    fn time_span(
        duration: Option<std::time::Duration>,
        prefix_len: usize,
    ) -> Option<Span<'static>> {
        let d = duration?;
        let text = format!("({})", format_duration(d));
        let pad = Self::TIME_COL.saturating_sub(prefix_len).max(1);
        Some(Span::styled(
            format!("{}{text}", " ".repeat(pad)),
            Style::new().fg(COLOR_DARK_GRAY),
        ))
    }

    /// Render a major task line: bold, leading status icon, combined time once
    /// the major is Done.
    fn major_line(task: &LoadingTask, tick: usize) -> Line<'static> {
        let (icon, icon_color) = Self::status_icon(task.status, tick);
        let label_color = match task.status {
            StepStatus::Failed => COLOR_WARNING_ACCESSIBLE_RED,
            StepStatus::Queued => COLOR_DARK_GRAY,
            _ => COLOR_TEXT_DEFAULT,
        };
        let clock = task.started.as_deref().unwrap_or("--:--:--");
        let time_prefix = format!("[{clock}] ");
        let mut spans = vec![
            Span::styled(format!("  {icon} "), Style::new().fg(icon_color)),
            Span::styled(time_prefix.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(task.label.clone(), Style::new().fg(label_color).bold()),
        ];
        // prefix = "  " + icon(1) + " " + "[HH:MM:SS] " + label
        let prefix_len = 4 + time_prefix.chars().count() + task.label.chars().count();
        if let Some(t) = Self::time_span(task.duration, prefix_len) {
            spans.push(t);
        }
        Line::from(spans)
    }

    /// Render a sub-step line: indented under its major, dimmer, prefixed with
    /// its start time and annotated with its own per-step time once Done.
    fn sub_line(step: &crate::state_handler::state::LoadingStep, tick: usize) -> Line<'static> {
        let (icon, icon_color) = Self::status_icon(step.status, tick);
        let label_color = match step.status {
            StepStatus::Failed => COLOR_WARNING_ACCESSIBLE_RED,
            StepStatus::Running => COLOR_TEXT_DEFAULT,
            _ => COLOR_DARK_GRAY,
        };
        let clock = step.started.as_deref().unwrap_or("--:--:--");
        let time_prefix = format!("[{clock}] ");
        let mut spans = vec![
            Span::styled(format!("      {icon} "), Style::new().fg(icon_color)),
            Span::styled(time_prefix.clone(), Style::new().fg(COLOR_DARK_GRAY)),
            Span::styled(step.label.clone(), Style::new().fg(label_color)),
        ];
        // prefix = 6 spaces + icon(1) + " " + "[HH:MM:SS] " + label
        let prefix_len = 8 + time_prefix.chars().count() + step.label.chars().count();
        if let Some(t) = Self::time_span(step.duration, prefix_len) {
            spans.push(t);
        }
        Line::from(spans)
    }
}

impl ComponentRender<()> for LoadingScreen {
    fn render(&self, frame: &mut Frame, _props: ()) {
        let area = frame.area();

        // Centre the content column; a failure report gets a wider one.
        let content_width = self.content_width(area.width);
        let [col] = Layout::horizontal([Length(content_width)])
            .flex(Flex::Center)
            .areas(area);

        // +2: one line for the version under the logo, one as a spacer.
        let [banner_area, body_area, footer_area] =
            Layout::vertical([Length(BANNER.len() as u16 + 2), Min(0), Length(1)]).areas(col);

        // Banner, with the build version under the logo.
        let mut banner: Vec<Line> = BANNER
            .iter()
            .map(|l| Line::styled(*l, Style::new().fg(COLOR_SOFT_PURPLE).bold()))
            .collect();
        banner.push(Line::styled(
            format!("v{}", env!("CARGO_PKG_VERSION")),
            Style::new().fg(COLOR_DARK_GRAY),
        ));
        frame.render_widget(Paragraph::new(banner).centered(), banner_area);

        let mut lines: Vec<Line> = Vec::new();

        // Phase line.
        lines.push(Self::phase_line(&self.props.status));
        lines.push(Line::default());

        // On failure, show the full error + a recovery suggestion. The error is
        // intentionally NOT truncated here — this screen is where the full
        // message lives (the main status bar truncates elsewhere).
        // On failure the screen becomes a troubleshooting report. It used to
        // print one fixed line — "check your network and that your VTA/mediator
        // are reachable" — for every failure including the many with no network
        // in them, which is the practice dev-guide R6.4 exists to forbid. What
        // is shown now is derived from the typed error.
        if let Some(diagnosis) = &self.props.diagnosis {
            // Padding is 1 either side, inside the already-centred column.
            let text_width = usize::from(content_width.saturating_sub(2));
            lines.extend(Self::diagnosis_lines(diagnosis, text_width));
            lines.push(Line::default());
        } else if let Some(integrity) = &self.props.integrity {
            let text_width = usize::from(content_width.saturating_sub(2));
            lines.extend(Self::integrity_lines(integrity, text_width));
            lines.push(Line::default());
        } else if let MediatorStatus::Failed(reason) = &self.props.status {
            // Failed with no diagnosis attached: a phase-2 (post-load)
            // connection failure. Show it plainly rather than inventing advice.
            lines.push(Line::styled(
                reason.clone(),
                Style::new().fg(COLOR_WARNING_ACCESSIBLE_RED),
            ));
            lines.push(Line::default());
        }

        // Hierarchical startup tasks — majors in bold with their combined time,
        // sub-steps indented and dimmer with their own time, so a slow task (and
        // which sub-step caused it) is obvious at a glance.
        if !self.props.tasks.is_empty() {
            lines.push(Line::styled(
                "Startup",
                Style::new().fg(COLOR_BORDER).bold(),
            ));
            for task in &self.props.tasks {
                lines.push(Self::major_line(task, self.props.tip_index));
                for step in &task.children {
                    lines.push(Self::sub_line(step, self.props.tip_index));
                }
            }
            lines.push(Line::default());
        }

        // Rotating tip — suppressed on failure. "Tip: your keys never leave
        // your device" under "your keys could not be found" is not a good look.
        if !TIPS.is_empty() && self.props.diagnosis.is_none() && self.props.integrity.is_none() {
            let tip = TIPS[self.props.tip_index % TIPS.len()];
            lines.push(Line::styled(
                tip,
                Style::new().fg(COLOR_SOFT_PURPLE).italic(),
            ));
        }

        // Once phase 1 is done, prompt to continue (phase-2 connections are
        // already running in the background).
        if self.props.complete {
            lines.push(Line::default());
            let (prompt, style) = match &self.props.integrity {
                Some(integrity) => (
                    format!(
                        "Press [ENTER] to acknowledge — {} — and continue",
                        integrity
                            .headline()
                            .trim_start_matches("Loaded with problems: ")
                    ),
                    Style::new().fg(COLOR_ORANGE).bold(),
                ),
                None => (
                    "Press [ENTER] to continue — connecting in the background".to_string(),
                    Style::new().fg(COLOR_SUCCESS).bold(),
                ),
            };
            lines.push(Line::styled(prompt, style));
        }

        self.rendered_lines
            .set(u16::try_from(lines.len()).unwrap_or(u16::MAX));
        let body = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0))
            .block(Block::new().padding(Padding::new(1, 1, 1, 0)));
        frame.render_widget(body, body_area);

        // Footer.
        let footer = if self.props.diagnosis.is_some() {
            Line::from(vec![
                Span::styled("[↑/↓ PgUp/PgDn]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" scroll   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])
        } else if self.props.complete {
            Line::from(vec![
                Span::styled("[ENTER]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" continue   ", Style::new().fg(COLOR_TEXT_DEFAULT)),
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])
        } else {
            Line::from(vec![
                Span::styled("[F10]", Style::new().fg(COLOR_BORDER).bold()),
                Span::styled(" quit", Style::new().fg(COLOR_TEXT_DEFAULT)),
            ])
        };
        frame.render_widget(Paragraph::new(footer).centered(), footer_area);
    }
}

#[cfg(test)]
mod tests {
    //! The failure screen is the whole point of the diagnostics work, so these
    //! render it for real and read the terminal buffer back. A report that is
    //! built correctly but clipped off the bottom of the screen helps nobody.
    use super::*;
    use crate::state_handler::state::State;
    use crossterm::event::KeyModifiers;
    use openvtc_core::{
        diagnostics::{DiagnosisContext, diagnose},
        errors::{OpenVTCError, SecureStoreFault},
    };
    use ratatui::{Terminal, backend::TestBackend};
    use tokio::sync::mpsc::unbounded_channel;

    /// The failure the user reported: config file present, credential gone.
    fn missing_credential_state() -> State {
        let err = OpenVTCError::SecureStore {
            fault: SecureStoreFault::Missing,
            profile: "default".to_string(),
            detail: "No matching credential found".to_string(),
        };
        let mut state = State::default();
        state.connection.status = MediatorStatus::Failed(err.to_string());
        state.startup_diagnosis = Some(std::sync::Arc::new(diagnose(
            &err,
            &DiagnosisContext::new("default"),
        )));
        state
    }

    /// Render at `width`×`height` and return the drawn rows, trailing spaces
    /// trimmed.
    fn rows(screen: &LoadingScreen, width: u16, height: u16) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        terminal
            .draw(|frame| screen.render(frame, ()))
            .expect("render");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    fn screen(state: &State) -> LoadingScreen {
        let (tx, _rx) = unbounded_channel();
        LoadingScreen::new(state, tx)
    }

    #[test]
    fn failure_screen_shows_the_cause_not_a_network_hint() {
        let state = missing_credential_state();
        // Flattened: these sentences wrap, and the assertion is about the
        // content being present, not about where the column breaks it.
        let text = flat(&rows(&screen(&state), 100, 60));
        assert!(
            text.contains("No matching credential found"),
            "the raw error must still be shown:\n{text}"
        );
        assert!(
            !text.contains("Check your network"),
            "the old blanket hint must be gone:\n{text}"
        );
        assert!(text.contains("Details"), "context block missing:\n{text}");
        assert!(
            text.contains("What to try, in order"),
            "remedies missing:\n{text}"
        );
        assert!(
            text.contains("Profile") && text.contains("default"),
            "the profile must be named:\n{text}"
        );
    }

    /// The tip line is charming during a load and tone-deaf under a fatal
    /// error — "your keys never leave your device" beneath "your keys could not
    /// be found" is how the reported screenshot looked.
    #[test]
    fn failure_screen_suppresses_the_rotating_tip() {
        let state = missing_credential_state();
        let text = rows(&screen(&state), 100, 60).join("\n");
        for tip in TIPS {
            assert!(!text.contains(tip), "tip shown on a failure screen: {tip}");
        }
    }

    /// A normal startup keeps the tip and shows no diagnosis.
    #[test]
    fn healthy_screen_is_unchanged() {
        let mut state = State::default();
        state.connection.status = MediatorStatus::Initializing("Starting…".to_string());
        // The tip wraps inside the narrow column, so compare on the flattened
        // text rather than on any single row.
        let text = flat(&rows(&screen(&state), 100, 40));
        assert!(
            text.contains(TIPS[0]),
            "tip missing from a healthy screen:\n{text}"
        );
        assert!(!text.contains("What to try, in order"));
    }

    /// Rendered rows as one whitespace-normalised string, so an assertion about
    /// a sentence is not defeated by the column wrapping it.
    fn flat(rows: &[String]) -> String {
        rows.join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The remedies are the part the user needs, and they sit at the bottom of
    /// a report that is taller than most terminals. Scrolling must reach them.
    #[test]
    fn remedies_are_reachable_by_scrolling_on_a_short_terminal() {
        let state = missing_credential_state();
        let mut screen = screen(&state);

        let unscrolled = rows(&screen, 100, 24).join("\n");
        assert!(
            !unscrolled.contains("Only if none of the above apply"),
            "this test is pointless if the report already fits"
        );

        screen.handle_key_event(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        assert!(screen.scroll > 0, "End must scroll a too-tall report");
        let scrolled = rows(&screen, 100, 24).join("\n");
        assert!(
            scrolled.contains("Only if none of the above apply"),
            "the last remedy must be reachable:\n{scrolled}"
        );
    }

    /// Scrolling must not run past the report into blank space the user then
    /// has to scroll back out of.
    #[test]
    fn scrolling_is_clamped_at_both_ends() {
        let state = missing_credential_state();
        let mut screen = screen(&state);
        // Clamping is measured against what was drawn, so draw first —
        // otherwise this passes trivially with both sides at zero.
        let _ = rows(&screen, 100, 24);
        assert!(
            screen.max_scroll() > 0,
            "report should be taller than 24 rows"
        );

        screen.handle_key_event(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(screen.scroll, 0, "must not scroll above the top");

        for _ in 0..500 {
            screen.handle_key_event(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        }
        assert_eq!(screen.scroll, screen.max_scroll(), "must clamp at the end");
    }

    /// A remedy that wraps must stay one visual item: the continuation line is
    /// indented under the text, not flushed to the margin. Prefix spans have to
    /// be budgeted out of the wrap width for this to hold — get that wrong and
    /// ratatui's own `Wrap` re-wraps the line and undoes the indent.
    #[test]
    fn wrapped_remedies_keep_their_hanging_indent() {
        let state = missing_credential_state();
        let drawn = rows(&screen(&state), 100, 60);
        let first = drawn
            .iter()
            .position(|r| r.trim_start().starts_with("1. "))
            .expect("first remedy rendered");
        let continuation = &drawn[first + 1];
        assert!(
            !continuation.trim().is_empty(),
            "the first remedy is expected to wrap at this width"
        );
        assert!(
            continuation.starts_with("        "),
            "continuation line lost its indent: {continuation:?}"
        );
        // And nothing may run past the column we sized for.
        for row in &drawn {
            assert!(row.chars().count() <= 100, "row overflows: {row:?}");
        }
    }

    /// A partially-loaded profile: one persona lost its key material, the rest
    /// of the account is fine.
    fn degraded_state() -> State {
        use openvtc_core::config::{
            account::PersonaId,
            integrity::{DegradedPersona, DegradedReason, LoadIntegrity, StrandedMembership},
        };
        let persona_id = PersonaId(uuid::Uuid::nil());
        State {
            loading_complete: true,
            integrity: Some(std::sync::Arc::new(LoadIntegrity {
                degraded_personas: vec![DegradedPersona {
                    persona_id,
                    did: "did:webvh:QmAlice:example.com:alice".to_string(),
                    label: Some("Work identity".to_string()),
                    created_at: chrono::Utc::now(),
                    reason: DegradedReason::MissingKeyInfo {
                        key_id: "did:webvh:QmAlice:example.com:alice#key-1".to_string(),
                    },
                }],
                stranded_memberships: vec![StrandedMembership {
                    vtc_did: "did:webvh:QmV:vtc.example.com:acme".to_string(),
                    persona_id,
                    label: Some("Acme Community".to_string()),
                }],
                orphaned_key_ids: Vec::new(),
            })),
            ..Default::default()
        }
    }

    /// The user must be told three things, and the reassurance is not optional:
    /// the entire point of isolating the fault is that the rest of the account
    /// survived, and a report listing only damage would hide that.
    #[test]
    fn degraded_load_names_what_is_lost_and_what_survived() {
        let state = degraded_state();
        let text = flat(&rows(&screen(&state), 100, 60));
        assert!(text.contains("did not load completely"), "{text}");
        assert!(text.contains("Work identity"), "{text}");
        assert!(text.contains("Acme Community"), "{text}");
        assert!(
            text.contains("unaffected") && text.contains("Nothing has been deleted"),
            "the report must say what still works:\n{text}"
        );
    }

    /// Enter must read as an acknowledgement, not as an ordinary "continue" —
    /// this is the interaction that makes the warning something the user has
    /// been shown rather than something that scrolled past.
    #[test]
    fn degraded_load_turns_continue_into_an_acknowledgement() {
        let degraded = flat(&rows(&screen(&degraded_state()), 100, 60));
        assert!(degraded.contains("[ENTER] to acknowledge"), "{degraded}");

        let healthy = State {
            loading_complete: true,
            ..Default::default()
        };
        let healthy = flat(&rows(&screen(&healthy), 100, 40));
        assert!(healthy.contains("[ENTER] to continue"), "{healthy}");
        assert!(!healthy.contains("acknowledge"), "{healthy}");
    }

    /// An interrupted write is loss and must be described as such; an
    /// unreachable VTA is not, and telling a user their persona is gone when it
    /// is merely offline would be worse than saying nothing.
    #[test]
    fn transient_faults_are_not_described_as_loss() {
        use openvtc_core::config::{
            account::PersonaId,
            integrity::{DegradedPersona, DegradedReason, LoadIntegrity},
        };
        let state = State {
            loading_complete: true,
            integrity: Some(std::sync::Arc::new(LoadIntegrity {
                degraded_personas: vec![DegradedPersona {
                    persona_id: PersonaId(uuid::Uuid::nil()),
                    did: "did:webvh:QmAlice:example.com:alice".to_string(),
                    label: None,
                    created_at: chrono::Utc::now(),
                    reason: DegradedReason::KeyUnavailable {
                        detail: "connection refused".to_string(),
                    },
                }],
                ..Default::default()
            })),
            ..Default::default()
        };
        let text = flat(&rows(&screen(&state), 100, 60));
        assert!(text.contains("looks temporary"), "{text}");
        assert!(
            !text.contains("cannot be recovered"),
            "a transient fault must not be reported as permanent loss:\n{text}"
        );

        let lossy = flat(&rows(&screen(&degraded_state()), 100, 60));
        assert!(lossy.contains("interrupted"), "{lossy}");
        assert!(lossy.contains("cannot be recovered"), "{lossy}");
    }

    /// Scroll keys are inert on a healthy startup, where they would otherwise
    /// silently swallow keystrokes the user meant for something else.
    #[test]
    fn scroll_keys_do_nothing_without_a_diagnosis() {
        let state = State::default();
        let mut screen = screen(&state);
        screen.handle_key_event(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(screen.scroll, 0);
    }
}
