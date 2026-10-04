//! Capabilities panel — the per-community `governance/capability/*` view,
//! opened from the Communities panel with `c`.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use serde_json::Value;

use crate::colors::{
    COLOR_DARK_GRAY, COLOR_ORANGE, COLOR_SOFT_PURPLE, COLOR_SUCCESS, COLOR_TEXT_DEFAULT,
};
use crate::state_handler::main_page::content::{CapabilitiesPhase, ContentPanelState};
use crate::state_handler::state::ConnectionState;

use super::panel::Panel;

pub struct CapabilitiesPanel;

impl Panel for CapabilitiesPanel {
    fn render(
        &self,
        state: &ContentPanelState,
        _connection: &ConnectionState,
    ) -> Vec<Line<'static>> {
        let Some(view) = &state.capabilities.view else {
            return vec![Line::from("no capabilities view open")];
        };
        let mut lines = Vec::new();

        let enabled_count = view.items.iter().filter(|i| i.enabled).count();
        lines.push(Line::from(vec![
            Span::styled(
                format!("  Capabilities — {}", view.community_name),
                Style::default().fg(COLOR_TEXT_DEFAULT).bold(),
            ),
            Span::styled(
                if matches!(view.phase, CapabilitiesPhase::Loaded) {
                    format!("    ● {enabled_count} enabled")
                } else {
                    String::new()
                },
                Style::default().fg(COLOR_SUCCESS),
            ),
        ]));
        lines.push(Line::from(""));

        match &view.phase {
            CapabilitiesPhase::Loading => {
                lines.push(Line::from(Span::styled(
                    "    querying the community's governance host…",
                    Style::default().fg(COLOR_DARK_GRAY),
                )));
            }
            CapabilitiesPhase::Failed(detail) => {
                lines.push(Line::from(Span::styled(
                    format!("    {detail}"),
                    Style::default().fg(COLOR_ORANGE),
                )));
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "    r retry   Esc back",
                    Style::default().fg(COLOR_DARK_GRAY),
                )));
                return lines;
            }
            CapabilitiesPhase::Loaded if view.items.is_empty() => {
                lines.push(Line::from(Span::styled(
                    "    this community has no capabilities available",
                    Style::default().fg(COLOR_DARK_GRAY),
                )));
            }
            CapabilitiesPhase::Loaded => {
                for (i, item) in view.items.iter().enumerate() {
                    let selected = i == view.selected;
                    let (glyph, glyph_style) = if item.enabled {
                        ("●", Style::default().fg(COLOR_SUCCESS))
                    } else if item.delegate.is_some() {
                        ("◈", Style::default().fg(COLOR_SOFT_PURPLE))
                    } else {
                        ("○", Style::default().fg(COLOR_DARK_GRAY))
                    };
                    let title = item.title.clone().unwrap_or_else(|| item.slug.clone());
                    let name_style = if selected {
                        Style::default().fg(COLOR_SUCCESS).bold()
                    } else if item.enabled {
                        Style::default().fg(COLOR_TEXT_DEFAULT)
                    } else {
                        Style::default().fg(COLOR_DARK_GRAY)
                    };
                    let mut spans = vec![
                        Span::raw(if selected { "    ▸ " } else { "      " }),
                        Span::styled(format!("{glyph} "), glyph_style),
                        Span::styled(format!("{title:<24}"), name_style),
                        Span::styled(
                            format!("{}@{}", item.slug, item.version),
                            Style::default().fg(COLOR_DARK_GRAY),
                        ),
                    ];
                    if item.enabled {
                        if let Some(at) = &item.enabled_at {
                            spans.push(Span::styled(
                                format!(
                                    "   enabled {}",
                                    openvtc_core::display::truncate_chars(at, 10)
                                ),
                                Style::default().fg(COLOR_DARK_GRAY),
                            ));
                        }
                    } else {
                        spans.push(Span::styled(
                            "   available",
                            Style::default().fg(COLOR_DARK_GRAY),
                        ));
                    }
                    lines.push(Line::from(spans));

                    if selected {
                        if view.detail {
                            render_manifest(&mut lines, item);
                        } else {
                            render_summary(&mut lines, item);
                        }
                    }
                }
            }
        }

        if let Some(idx) = view.confirm_toggle
            && let Some(item) = view.items.get(idx)
        {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                    format!(
                        "    {} {}? This is a signed governance write. y/⏎ confirm · any other key cancels",
                        if item.enabled { "Disable" } else { "Enable" },
                        item.slug,
                    ),
                    Style::default().fg(COLOR_ORANGE).bold(),
                )));
        }

        if let Some(status) = &view.status_message {
            lines.push(Line::from(""));
            super::status::push_status(&mut lines, status, "");
        }

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "    ↑/↓ navigate   ⏎ details   e enable/disable (administrators)   r refresh   Esc back",
            Style::default().fg(COLOR_DARK_GRAY),
        )));
        lines
    }
}

fn kv(lines: &mut Vec<Line<'static>>, key: &str, value: String) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("        {key:<13}"),
            Style::default().fg(COLOR_DARK_GRAY),
        ),
        Span::styled(value, Style::default().fg(COLOR_TEXT_DEFAULT)),
    ]));
}

/// The collapsed (non-detail) summary under the selected row.
fn render_summary(
    lines: &mut Vec<Line<'static>>,
    item: &openvtc_core::capabilities::CapabilitySummary,
) {
    let manifest = &item.manifest;
    if let Some(actions) = manifest
        .get("vocabulary")
        .and_then(|v| v.get("actions"))
        .and_then(Value::as_array)
    {
        let actions: Vec<&str> = actions.iter().filter_map(Value::as_str).collect();
        kv(lines, "registry", actions.join(", "));
    }
    if let Some(delegate) = &item.delegate {
        kv(lines, "served by", delegate.clone());
    }
    if let Some(description) = manifest.get("description").and_then(Value::as_str) {
        kv(lines, "about", description.to_string());
    }
}

/// The full manifest, rendered when the detail view (⏎) is open.
fn render_manifest(
    lines: &mut Vec<Line<'static>>,
    item: &openvtc_core::capabilities::CapabilitySummary,
) {
    let manifest = &item.manifest;
    if let Some(description) = manifest.get("description").and_then(Value::as_str) {
        kv(lines, "about", description.to_string());
    }
    if let Some(specs) = manifest.get("specs").and_then(Value::as_array) {
        let specs: Vec<&str> = specs.iter().filter_map(Value::as_str).collect();
        kv(lines, "serves", specs.join(", "));
    }
    if let Some(vocabulary) = manifest.get("vocabulary") {
        if let Some(actions) = vocabulary.get("actions").and_then(Value::as_array) {
            let actions: Vec<&str> = actions.iter().filter_map(Value::as_str).collect();
            kv(lines, "actions", actions.join(", "));
        }
        if let Some(pattern) = vocabulary.get("resourcePattern").and_then(Value::as_str) {
            kv(lines, "resources", pattern.to_string());
        }
    }
    if let Some(roles) = manifest.get("roles").and_then(Value::as_object) {
        for (op, who) in roles {
            let who: Vec<&str> = who
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            kv(lines, &format!("role: {op}"), who.join(", "));
        }
    }
    if let Some(hooks) = manifest.get("lifecycleHooks").and_then(Value::as_array) {
        let hooks: Vec<&str> = hooks.iter().filter_map(Value::as_str).collect();
        if !hooks.is_empty() {
            kv(lines, "hooks", hooks.join(", "));
        }
    }
    if let Some(adapters) = manifest.get("externalAdapters").and_then(Value::as_array) {
        for adapter in adapters {
            let kind = adapter.get("kind").and_then(Value::as_str).unwrap_or("?");
            let reference = adapter.get("ref").and_then(Value::as_str).unwrap_or("?");
            kv(lines, "adapter", format!("{kind} · {reference}"));
        }
    }
    if let Some(config_schema) = manifest.get("configSchema").and_then(Value::as_str) {
        kv(lines, "config", config_schema.to_string());
    }
    if let Some(delegate) = &item.delegate {
        kv(lines, "served by", delegate.clone());
    }
    if let Some(at) = &item.enabled_at {
        kv(lines, "enabled at", at.clone());
    }
}
