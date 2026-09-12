# Themes

The OpenVTC TUI can be drawn in any theme: one of those built in, one you make,
one of Omarchy's, or one imported from Neovim, base16/base24, Alacritty, Kitty
or Ghostty. A theme can follow your terminal's background, and one you make can
be exported for your terminal, editor or desktop.

## Choosing a theme

- **In the TUI:** Settings → **Theme**. Moving through the list previews each
  theme on the whole screen; **Enter** keeps it, **Esc** puts back the one you
  had.
- **From the command line:** `openvtc theme list`, then `openvtc theme set <id>`.

The choice is kept in `~/.config/openvtc/tui.toml` (or under
`OPENVTC_CONFIG_PATH`). It belongs to you rather than to a profile, so every
profile uses it, and no unlock is needed to change it.

A running TUI notices within a second when the theme changes, and redraws —
see [Changes while the TUI runs](#changes-while-the-tui-runs).

### Following your terminal: `auto`

```sh
openvtc theme set auto                                   # openvtc when dark, catppuccin-latte when light
openvtc theme set auto --dark nord --light high-contrast-light
```

With `auto`, OpenVTC asks the terminal for its background colour as it starts
(the OSC 11 query most terminals answer), then draws with one theme on a dark
background and another on a light one. A terminal that does not answer within
half a second is judged by `COLORFGBG`, and failing that taken to be dark. The
two themes live in `tui.toml`:

```toml
theme = "auto"
auto_dark = "nord"
auto_light = "high-contrast-light"
```

The terminal can only be asked before the TUI starts, because its answer arrives
as input. If you choose Auto in the picker of a TUI that did not start with it,
Auto goes by `COLORFGBG` (or dark) until the next start.

### For one session: `OPENVTC_THEME`

```sh
OPENVTC_THEME=high-contrast-dark openvtc
```

`OPENVTC_THEME=<id>` draws that session in a theme other than the one chosen,
without changing `tui.toml`. An id that cannot be loaded is reported, and the
chosen theme used instead. Choosing a theme while that session runs — in its
picker, or with `openvtc theme set` — still takes effect.

### Without colour: `NO_COLOR`

When `NO_COLOR` is set to anything but an empty string
([no-color.org](https://no-color.org)), OpenVTC draws in your terminal's own
colours, and keeps the roles apart with text attributes instead:

| Role | Drawn as |
|------|----------|
| accent | **bold** |
| danger | **bold**, underlined |
| warning | underlined |
| success (and selected rows) | reversed |
| highlight | *italic* |
| muted | dim |
| text | plain |

Anything drawn on a role's colour as a background is reversed too. The
command-line output printed before the TUI starts, and the prompts, are
uncoloured as well.

## Where themes come from

| Id | Source |
|----|--------|
| `auto` | follows your terminal's background (see above) |
| `openvtc` | OpenVTC's own colours (the default) |
| `catppuccin-mocha`, `catppuccin-latte`, `dracula`, `gruvbox-dark`, `nord`, `tokyo-night` | built in |
| `high-contrast-dark`, `high-contrast-light`, `colourblind-dark`, `colourblind-light` | built in, for accessibility |
| `user/<name>` | your theme files, in `~/.config/openvtc/themes/<name>.toml` |
| `omarchy/current` | whichever Omarchy theme is current, followed as you switch |
| `omarchy/<name>` | an Omarchy theme, read in place from `~/.config/omarchy/themes` or `/usr/share/omarchy/themes` |

### Accessibility themes

- **High Contrast Dark** and **High Contrast Light** hold every colour to at
  least 7:1 against the background (WCAG AAA for body text).
- **Colourblind Safe Dark** and **Colourblind Safe Light** colour the roles in
  the hues of the [Okabe–Ito palette](https://jfly.uni-koeln.de/color/), which
  stay distinct under the common colour-vision deficiencies. The dark theme uses
  Okabe–Ito's own colours; on white those are too pale to read, so the light
  theme darkens each hue until it reaches 4.5:1. Every colour in both is at
  least 4.5:1 against its background (WCAG AA).

A test measures the contrast of every built-in theme's text against its
background, and of every colour in these four.

## Changes while the TUI runs

About once a second the TUI checks — by modification time, size and link
target, never by reading files that have not changed — for:

- **Another theme chosen:** `tui.toml` changing, for example by
  `openvtc theme set` in another terminal.
- **The theme in use changing where it is read from:**
  - your theme file, `themes/<name>.toml`, saved after an edit;
  - Omarchy switching theme, for `omarchy/current` — current releases record
    the name in `~/.local/state/omarchy/current/theme.name`, earlier ones
    repoint the `~/.config/omarchy/current/theme` link;
  - an Omarchy theme's `colors.toml` (or `alacritty.toml`) edited;
  - under `auto`, `auto_dark` or `auto_light` changing.

A file caught half-saved keeps the theme on screen until it is saved whole.
While the picker is open nothing is redrawn under your preview; a change made
meanwhile is picked up once the picker closes.

## Making your own

Start from any theme and edit the copy:

```sh
openvtc theme new "My Theme" --from nord
```

Or press **c** in Settings → Theme to copy the highlighted theme. The copy lands
in your themes directory. Edit it, save, and a TUI using it redraws; in the
picker, press **r** to see your changes to a theme you are previewing.

A theme file names seven roles, plus an optional background:

```toml
name = "My Theme"
mode = "dark"            # or "light"

[colors]
accent     = "#88c0d0"   # borders, headings and key hints
success    = "#a3be8c"   # selection, completed and valid things
warning    = "#d08770"   # cautions and work in progress
danger     = "#bf616a"   # errors and destructive actions
text       = "#d8dee9"   # ordinary text
muted      = "#616e88"   # secondary text and hints
highlight  = "#b48ead"   # values and special actions
background = "#2e3440"   # "none" keeps your terminal's own
```

Colours are `#rrggbb` (or `#rgb`, `0xrrggbb`, or a terminal colour name such as
`white`). A role you leave out keeps OpenVTC's own colour, so a theme can be as
short as one line.

## Importing

```sh
openvtc theme import ~/schemes/rose-pine.yaml        # base16 or base24 scheme
openvtc theme import ~/.config/omarchy/themes/kanagawa # Omarchy theme directory
openvtc theme import ~/.config/alacritty/theme.toml  # Alacritty
openvtc theme import ~/.config/kitty/theme.conf      # Kitty
openvtc theme import ~/ghostty/themes/Everforest     # Ghostty
openvtc theme import nvim:tokyonight-storm --use     # a Neovim colorscheme
```

An import writes an OpenVTC theme file into your themes directory, so you can
edit it afterwards. Add `--name` to name it, and `--use` to choose it straight
away. An import whose text is under 4.5:1 against its background says so.

### Neovim

`nvim:<colorscheme>` runs Neovim headless with your own configuration, so
colorschemes installed by a plugin manager work. It loads the colorscheme and
reads back the highlight groups every colorscheme defines. `--clean` skips your
configuration, which limits the choice to the colorschemes Neovim bundles. Set
`OPENVTC_NVIM` if `nvim` is not on your `PATH`.

### How other formats map onto the roles

| Role | base16 | Omarchy `colors.toml` | Alacritty / Kitty / Ghostty | Neovim |
|------|--------|-----------------------|-----------------------------|--------|
| accent | `base0D` | `accent` | blue (4) | `Function` |
| success | `base0B` | `green` | green (2) | `DiagnosticOk` |
| warning | `base09` | `yellow` | yellow (3) | `DiagnosticWarn` |
| danger | `base08` | `red` | red (1) | `DiagnosticError` |
| text | `base05` | `foreground` | foreground | `Normal` |
| muted | `base03` | `dark_foreground` | bright black (8) | `Comment` |
| highlight | `base0E` | `magenta` | magenta (5) | `Keyword` |
| background | `base00` | `background` | background | `Normal` background |

## Exporting

A theme — one you made, or any other — can be written out for another tool:

```sh
openvtc theme export user/my-theme --format kitty > ~/.config/kitty/current-theme.conf
openvtc theme export user/my-theme --format alacritty -o ~/.config/alacritty/my-theme.toml
openvtc theme export user/my-theme --format omarchy -o ~/.config/omarchy/themes/my-theme
openvtc theme export nord --format base16 -o nord.yaml
```

| `--format` | Writes |
|------------|--------|
| `openvtc` (the default) | an OpenVTC theme file |
| `base16` | a base16 scheme (YAML) |
| `omarchy` | with `-o`, an Omarchy theme directory: `colors.toml`, and `light.mode` for a light theme (or just the file, if the path ends in `.toml`) |
| `alacritty` | an Alacritty colour file |
| `kitty` | a Kitty colour file |

Without `--output` the theme is printed, bare, to be piped or redirected.

The roles go where the table above reads them from, so an exported theme
imports back as the same theme — tests check this for every format. The other
colours a format expects are derived from the roles: black and white from the
background and text, cyan from accent and success, bright colours a step toward
the text, and base16's in-between shades from blends of background, muted and
text. A theme drawn on your terminal's own background is exported on black
(dark) or white (light).

## For contributors

Panels draw with the `COLOR_*` role constants in `openvtc/src/colors.rs` and
need know nothing about themes. After each frame, `theme::paint` swaps each role
for the active theme's colour — or, under `NO_COLOR`, for the terminal's own and
a text attribute. Keep using the roles, and a new panel is themed for free.

Command-line output printed outside the TUI styles by role too:
`style(..).themed(CLI_INFO)` (or `CLI_ERROR`, `CLI_CAUTION`, `CLI_EXAMPLE`), which
uses the active theme's colour, in 24-bit where `COLORTERM` says the terminal
draws it and the nearest of 256 colours otherwise. `theme::init` loads the theme
at the top of `main`, before anything is printed.

`theme::live::Watcher` does the checking described above. The UI loop runs it on
a blocking thread once a second and only takes what it found when the picker is
closed, so the render loop never waits on the file system.

The active theme is process-wide. A test that sets it restores the default
before it ends, and tests that need a particular theme on screen belong in one
test rather than several running in parallel.
