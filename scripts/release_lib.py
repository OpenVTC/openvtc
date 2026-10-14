"""Shared helpers for the release tooling (RELEASES.md).

A release is named `major.minor` (`0.7`) and lives on `release/<major.minor>`.
The workspace is versioned in **lockstep**: `[workspace.package] version` in
the root Cargo.toml is the one version every crate carries
(`version.workspace = true`), and every internal dependency on a workspace
member requires exactly that version (`{ version = "0.7.0", path = ... }`).
`main` carries the next release's `major.minor.0` and publishes nothing.

The release branch's current version is the `RELEASE` file at its root:
`0.7.0-rc.0`, `0.7.0-rc.1`, `0.7.0`, `0.7.1`, … The tag is `v` + that. An
rc never changes the crates' version (they are already `0.7.0`); only GA and
patches publish.

CHANGELOG.md follows Keep a Changelog: `## [Unreleased]` on main, and a
released version's section is `## [0.7.0] - 2026-10-20`.
"""

import pathlib
import re
import subprocess
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

RELEASE_NAME = re.compile(r"(\d+)\.(\d+)")
RELEASE_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?")
CRATE_VERSION = re.compile(r"\d+\.\d+\.\d+")

# Dependency tables a manifest may name a workspace member in.
DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def run(*args, cwd=ROOT, check=True):
    out = subprocess.run(args, capture_output=True, text=True, cwd=cwd)
    if check and out.returncode:
        raise SystemExit(f"`{' '.join(args)}` failed in {cwd}:\n{out.stderr.strip()}")
    return out


def git(*args, cwd=ROOT, check=True):
    return run("git", *args, cwd=cwd, check=check)


def root_manifest(root):
    return tomllib.loads((root / "Cargo.toml").read_text())


def members(root):
    """Manifest paths of every workspace member (no globs are used here)."""
    data = root_manifest(root)
    return [root / m / "Cargo.toml" for m in data["workspace"]["members"]]


def member_names(root):
    return [tomllib.loads(m.read_text())["package"]["name"] for m in members(root)]


def workspace_version(root):
    return root_manifest(root)["workspace"]["package"]["version"]


def is_publishable(pkg, root):
    """`publish` as cargo reads it: absent/true -> yes, false/[] -> no."""
    publish = pkg.get("publish", True)
    if isinstance(publish, dict) and publish.get("workspace"):
        publish = root_manifest(root)["workspace"].get("package", {}).get("publish", True)
    if publish is False or publish == []:
        return False
    return True


def publishable_crates(root):
    """name -> manifest path for every member cargo would publish."""
    out = {}
    for manifest in members(root):
        pkg = tomllib.loads(manifest.read_text())["package"]
        if is_publishable(pkg, root):
            out[pkg["name"]] = manifest
    return out


def _dep_tables(data):
    """Yield every dependency table in a parsed manifest, target-specific ones included."""
    for t in DEP_TABLES:
        if t in data:
            yield data[t]
    for target in data.get("target", {}).values():
        for t in DEP_TABLES:
            if t in target:
                yield target[t]


def internal_requirements(root):
    """[(manifest, dep name, requirement or None)] for every dep on a workspace member."""
    names = set(member_names(root))
    out = []
    for manifest in [root / "Cargo.toml", *members(root)]:
        data = tomllib.loads(manifest.read_text())
        tables = list(_dep_tables(data))
        if manifest == root / "Cargo.toml":
            ws_deps = data.get("workspace", {}).get("dependencies")
            if ws_deps:
                tables.append(ws_deps)
        for table in tables:
            for key, spec in table.items():
                name = spec.get("package", key) if isinstance(spec, dict) else key
                if name not in names:
                    continue
                req = spec if isinstance(spec, str) else spec.get("version")
                if isinstance(spec, dict) and spec.get("workspace"):
                    continue  # inherits from [workspace.dependencies], checked there
                out.append((manifest, name, req))
    return out


def lockstep_problems(root):
    """Every way the tree breaks the lockstep invariant (empty list = holds)."""
    problems = []
    version = workspace_version(root)
    for manifest in members(root):
        pkg = tomllib.loads(manifest.read_text())["package"]
        v = pkg.get("version")
        if not (isinstance(v, dict) and v.get("workspace")):
            problems.append(
                f"{manifest.relative_to(root)}: [package] version must be "
                f"`version.workspace = true` (found {v!r})"
            )
    for manifest, name, req in internal_requirements(root):
        if req != version:
            problems.append(
                f"{manifest.relative_to(root)}: `{name}` requires {req!r}; lockstep requires "
                f'`version = "{version}"` on every internal dependency'
            )
    return problems


def set_version(root, version):
    """Move the whole workspace to `version`, lockstep.

    Sets `[workspace.package] version` in the root Cargo.toml and rewrites
    every internal requirement — `<member> = { version = "…", path = … }` in
    any member's [dependencies], [dev-dependencies], [build-dependencies] or
    target-specific table — to the same version. Only names that are
    workspace members are touched: an external crate that happens to share
    the number is never rewritten.

    Then refreshes Cargo.lock for the members only (`cargo update -w`) and
    re-verifies the invariant, so a dependency written in a shape the regex
    does not know (a `[dependencies.<name>]` table, say) fails loudly here
    instead of shipping a stale requirement.
    """
    # Validated before it reaches any file: the replacements below insert it
    # verbatim, and only a plain crate version belongs there.
    if not CRATE_VERSION.fullmatch(version):
        raise SystemExit(f"{version!r} is not major.minor.patch")

    cargo_toml = root / "Cargo.toml"
    text = cargo_toml.read_text()
    head, sep, rest = text.partition("[workspace.package]")
    if not sep:
        raise SystemExit(f"{cargo_toml}: no [workspace.package] section")
    rest, n = re.subn(
        r'^version\s*=\s*"[^"]*"', lambda _: f'version = "{version}"', rest, count=1, flags=re.M
    )
    if n != 1:
        raise SystemExit(f"{cargo_toml}: no version line in [workspace.package]")
    cargo_toml.write_text(head + sep + rest)

    names = member_names(root)
    pin_re = re.compile(
        r'^(\s*(?:' + "|".join(map(re.escape, names)) + r')\s*=\s*\{[^}\n]*?\bversion\s*=\s*")[^"]*(")',
        re.M,
    )
    for manifest in [cargo_toml, *members(root)]:
        text = manifest.read_text()
        new = pin_re.sub(lambda m: f"{m.group(1)}{version}{m.group(2)}", text)
        if new != text:
            manifest.write_text(new)

    problems = lockstep_problems(root)
    if problems:
        raise SystemExit("set_version left the lockstep invariant broken:\n  " + "\n  ".join(problems))
    run("cargo", "update", "-w", cwd=root)


def version_heading(version, when):
    """A version's CHANGELOG heading: `## [0.7.0] - 2026-10-20`."""
    return f"## [{version}] - {when}"


def has_version_section(changelog, version):
    """Whether CHANGELOG.md has `## [<version>]` (or the bare `## <version>`)."""
    v = re.escape(version)
    return re.search(rf"^## (\[{v}\]|{v})( |$)", changelog, re.M) is not None


def parse_release(text):
    m = RELEASE_VERSION.fullmatch(text.strip())
    if not m:
        raise SystemExit(f"RELEASE holds {text.strip()!r}, not major.minor.patch[-rc.N]")
    major, minor, patch, rc = m.groups()
    return int(major), int(minor), int(patch), (None if rc is None else int(rc))


def unreleased_split(changelog):
    """(before, body, after) around the `## [Unreleased]` section, or None."""
    m = re.search(r"^## \[?Unreleased\]?[^\n]*\n", changelog, re.M)
    if not m:
        return None
    nxt = re.search(r"^## ", changelog[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(changelog)
    return changelog[: m.start()], changelog[m.end(): end], changelog[end:]
