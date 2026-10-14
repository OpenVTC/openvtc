#!/usr/bin/env python3
"""Cut a release: create `release/<major.minor>` and move main to the next one.

    python3 scripts/cut-release.py 0.7 [--from origin/nightly] [--dry-run]

Run by the release manager from a clean checkout with push access and `gh`
authenticated. It:

  1. resolves the source commit — `origin/nightly` by default, the newest main
     commit the full CI suite passed (RELEASES.md);
  2. pushes `release/<name>` = source commit + one commit that moves the
     workspace (lockstep: `[workspace.package] version` and every internal
     requirement) to `<name>.0` and writes `RELEASE` = `<name>.0-rc.0`.
     `release-tag.yml` then tags `v<name>.0-rc.0` (a prerelease; crates are
     not published);
  3. opens a PR to main (`release-cut/<name>`) that moves the workspace to the
     next minor (`0.8.0` after `0.7`) and starts a fresh `## [Unreleased]`
     section in CHANGELOG.md, the old one becoming `## [<name>.0]`;
  4. creates the `backport release/<name>` label backport.yml reads.

The CHANGELOG split is only automatic when main's `## [Unreleased]` section is
the one the source commit has (nothing changelogged landed after nightly). If
it differs, main's CHANGELOG is left alone and the script says so: move the
entries that shipped in the release under its heading by hand, in the PR.
"""

import argparse
import datetime
import pathlib
import sys
import tempfile

from release_lib import RELEASE_NAME, git, run, set_version, unreleased_split, version_heading


def worktree(rev, tmp, name):
    path = pathlib.Path(tmp) / name
    git("worktree", "add", "--detach", str(path), rev)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name", help="major.minor, e.g. 0.7")
    ap.add_argument("--from", dest="source", default="origin/nightly")
    ap.add_argument("--dry-run", action="store_true", help="build both commits, push nothing")
    args = ap.parse_args()

    m = RELEASE_NAME.fullmatch(args.name)
    if not m:
        sys.exit(f"release name {args.name!r} is not major.minor")
    major, minor = map(int, m.groups())
    branch = f"release/{args.name}"
    version = f"{args.name}.0"
    next_version = f"{major}.{minor + 1}.0"

    git("fetch", "origin", "--tags", "--prune")
    if git("ls-remote", "--exit-code", "--heads", "origin", branch, check=False).returncode == 0:
        sys.exit(f"{branch} already exists")
    source = git("rev-parse", "--verify", f"{args.source}^{{commit}}").stdout.strip()
    main_sha = git("rev-parse", "--verify", "origin/main^{commit}").stdout.strip()
    print(f"cutting {branch} from {args.source} ({source[:12]}); main is {main_sha[:12]}")

    # Prune after the temporary directory is gone: pruned inside it, the
    # worktrees still exist and their records are left behind.
    try:
        with tempfile.TemporaryDirectory() as tmp:
            # The release branch.
            rel = worktree(source, tmp, "release")
            set_version(rel, version)
            (rel / "RELEASE").write_text(f"{version}-rc.0\n")
            git("add", "-A", cwd=rel)
            git("commit", "-s", "-m", f"chore(release): cut {branch} at {version}-rc.0", cwd=rel)

            # main's half.
            mn = worktree(main_sha, tmp, "main")
            set_version(mn, next_version)
            split = False
            main_changelog = mn / "CHANGELOG.md"
            if main_changelog.exists():
                source_log = git("show", f"{source}:CHANGELOG.md", check=False).stdout
                src, cur = unreleased_split(source_log), unreleased_split(main_changelog.read_text())
                split = bool(src and cur and src[1] == cur[1])
                if split:
                    before, body, after = cur
                    # The GA prep on the branch writes the release date; main
                    # records when the release left it.
                    cut = f"{datetime.date.today().isoformat()} (cut to {branch})"
                    main_changelog.write_text(
                        f"{before}## [Unreleased]\n\n{version_heading(version, cut)}\n{body}{after}"
                    )
            git("add", "-A", cwd=mn)
            git(
                "commit", "-s", "-m",
                f"chore(release): cut {branch}; main moves to {next_version}",
                cwd=mn,
            )

            print(git("show", "--stat", "HEAD", cwd=rel).stdout)
            print(git("show", "--stat", "HEAD", cwd=mn).stdout)
            if not split:
                print(
                    "WARNING: main's `## [Unreleased]` differs from the cut's (or CHANGELOG.md is "
                    "missing); CHANGELOG.md on main was not split. Move the shipped entries under "
                    f"`## [{version}]` by hand in the release-cut PR.",
                    file=sys.stderr,
                )
            if args.dry_run:
                print("dry run: nothing pushed")
                return 0

            git("push", "origin", f"HEAD:refs/heads/{branch}", cwd=rel)
            cut_head = f"release-cut/{args.name}"
            git("push", "origin", f"HEAD:refs/heads/{cut_head}", cwd=mn)
            run(
                "gh", "label", "create", f"backport {branch}", "--force",
                "--color", "5319e7", "--description", f"Cherry-pick onto {branch} once merged",
            )
            run(
                "gh", "pr", "create", "--base", "main", "--head", cut_head,
                "--title", f"chore(release): cut {branch}; main moves to {next_version}",
                "--body",
                f"Cuts `{branch}` from `{source[:12]}` ({args.source}). "
                f"`main` moves to `{next_version}`."
                + ("" if split else "\n\n**CHANGELOG.md needs splitting by hand** — see the cut output."),
            )
            print(f"pushed {branch}; opened the {cut_head} PR. Update the table in RELEASES.md.")
    finally:
        git("worktree", "prune")
    return 0


if __name__ == "__main__":
    sys.exit(main())
