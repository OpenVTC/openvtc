# Themes

The OpenVTC TUI can be drawn in any theme: one of those built in, one you make,
one of Omarchy's, or one imported from Neovim, base16/base24, Alacritty, Kitty
or Ghostty.

## Choosing a theme

- **In the TUI:** Settings → **Theme**. Moving through the list previews each
  theme on the whole screen; **Enter** keeps it, **Esc** puts back the one you
  had.
- **From the command line:** `openvtc theme list`, then `openvtc theme set <id>`.

The choice is kept in `~/.config/openvtc/tui.toml` (or under
`OPENVTC_CONFIG_PATH`). It belongs to you rather than to a profile, so every
profile uses it, and no unlock is needed to change it.

## Where themes come from

| Id | Source |
|----|--------|
| `openvtc` | OpenVTC's own colours (the default) |
| `catppuccin-mocha`, `catppuccin-latte`, `dracula`, `gruvbox-dark`, `nord`, `tokyo-night` | built in |
| `user/<name>` | your theme files, in `~/.config/openvtc/themes/<name>.toml` |
| `omarchy/current` | whichever Omarchy theme is current, followed as you switch |
| `omarchy/<name>` | an Omarchy theme, read in place from `~/.config/omarchy/themes` or `/usr/share/omarchy/themes` |

## Making your own

Start from any theme and edit the copy:

```sh
openvtc theme new "My Theme" --from nord
```

Or press **c** in Settings → Theme to copy the highlighted theme. The copy lands
in your themes directory. Edit it, then press **r** in the picker to see your
changes.

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
away.

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

## For contributors

Panels draw with the `COLOR_*` role constants in `openvtc/src/colors.rs` and
need know nothing about themes. After each frame, `theme::paint` swaps each role
for the active theme's colour. Keep using the roles, and a new panel is themed
for free.

The command-line output printed before the TUI starts (prompts and errors) uses
the terminal's own colours and is not themed.
