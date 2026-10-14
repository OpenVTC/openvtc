#!/usr/bin/env python3
"""Publish the workspace to crates.io one crate at a time (publish.yml).

    publish-crates.py gate             should this push publish at all?
    publish-crates.py plan             print the publish order and what is pending
    publish-crates.py next [--no-verify]
                                       pick the first unpublished crate in order
                                       and verify-build it (`cargo package`)
    publish-crates.py upload CRATE     upload it (`cargo publish --no-verify`)
                                       and wait until the index serves it
    publish-crates.py check-all        fail unless every crate is on crates.io

Why split "verify" from "upload": a crates.io Trusted Publishing token lives
30 minutes, and a cold verify build of the openvtc binary takes a good part
of that. publish.yml therefore runs `next` (the long build, needing no
token), then mints a fresh token, then `upload` (seconds). Each crate gets its
own token, so no release is ever cut short by expiry, and a failed upload is
simply retried by the next slot with another fresh token.

Order: derived from `cargo metadata` — a topological sort of the publishable
workspace members over their normal and build dependencies on each other, with
dev-dependency edges honoured too wherever they do not form a cycle (cargo
keeps a versioned dev-dependency in the published manifest, so it must be
resolvable when the dependent is verified). Ties break on name, so the order is
deterministic. Today that gives: openvtc-core, openvtc (run `plan`).

"Already published" is read from the crates.io sparse index, so re-running the
workflow resumes where a previous run stopped. A crate that does not exist on
crates.io at all is an error: a Trusted Publishing token cannot create a crate,
so its first version is published by hand (RELEASES.md).

Outputs go to $GITHUB_OUTPUT when set (stdout otherwise).
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
INDEX = "https://index.crates.io"
USER_AGENT = "openvtc publish.yml (https://github.com/OpenVTC/openvtc)"
INDEX_WAIT_SECONDS = 15 * 60


def output(**kv):
    if "reason" in kv and os.environ.get("GITHUB_ACTIONS"):
        print(f"::notice::{kv['reason']}")
    path = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{k}={v}\n" for k, v in kv.items())
    if path:
        with open(path, "a") as f:
            f.write(lines)
    print(lines, end="")


def cargo(*args, check=True, env=None):
    print(f"$ cargo {' '.join(args)}", flush=True)
    out = subprocess.run(["cargo", *args], cwd=ROOT, env=env)
    if check and out.returncode:
        sys.exit(f"cargo {' '.join(args)} failed (exit {out.returncode})")
    return out.returncode


def metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def publishable(pkg):
    # cargo metadata: null = anywhere, [] = publish = false, [..] = named registries.
    return pkg["publish"] is None or "crates-io" in pkg["publish"]


def publish_order():
    """[(name, version)] in an order every dependency precedes its dependents."""
    meta = metadata()
    members = set(meta["workspace_members"])
    pkgs = {p["name"]: p for p in meta["packages"] if p["id"] in members and publishable(p)}

    hard, soft = {n: set() for n in pkgs}, {n: set() for n in pkgs}
    for name, pkg in pkgs.items():
        for dep in pkg["dependencies"]:
            if dep["name"] not in pkgs or dep["name"] == name:
                continue
            (soft if dep["kind"] == "dev" else hard)[name].add(dep["name"])

    def reaches(graph, start, goal):
        seen, stack = set(), [start]
        while stack:
            n = stack.pop()
            if n == goal:
                return True
            if n not in seen:
                seen.add(n)
                stack.extend(graph[n])
        return False

    edges = {n: set(d) for n, d in hard.items()}
    for name in sorted(soft):
        for dep in sorted(soft[name]):
            if not reaches(edges, dep, name):  # adding name -> dep makes no cycle
                edges[name].add(dep)

    order, done = [], set()
    while len(order) < len(pkgs):
        ready = sorted(n for n in pkgs if n not in done and edges[n] <= done)
        if not ready:
            sys.exit(f"dependency cycle among {sorted(set(pkgs) - done)}")
        order.append(ready[0])
        done.add(ready[0])
    return [(n, pkgs[n]["version"]) for n in order]


def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def published_versions(name):
    """Set of versions on crates.io, or None when the crate does not exist."""
    url = f"{INDEX}/{index_path(name)}"
    for attempt in range(5):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode()
            return {json.loads(line)["vers"] for line in body.splitlines() if line.strip()}
        except urllib.error.HTTPError as e:
            if e.code in (403, 404, 410):
                return None
            err = e
        except (urllib.error.URLError, TimeoutError) as e:
            err = e
        time.sleep(5 * (attempt + 1))
    sys.exit(f"could not read the crates.io index for {name}: {err}")


def pending(order):
    out = []
    for name, version in order:
        versions = published_versions(name)
        if versions is None:
            sys.exit(
                f"{name} does not exist on crates.io. A Trusted Publishing token cannot create a "
                "crate: an owner publishes its first version by hand, then adds this repository's "
                "publish.yml as its trusted publisher (RELEASES.md, 'A new crate')."
            )
        if version not in versions:
            out.append((name, version))
    return out


def cmd_gate(_args):
    release = ROOT / "RELEASE"
    if not release.exists():
        output(publish="false", reason="no RELEASE file: not a release branch")
        return 0
    rel = release.read_text().strip()
    ws = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if "-" in rel:
        output(publish="false", reason=f"RELEASE {rel} is a release candidate; crates publish at GA")
        return 0
    if rel != ws:
        print(f"::error::RELEASE says {rel} but the workspace version is {ws}; refusing to publish")
        return 1
    # No cargo here (the toolchain is not installed yet): the publishable
    # members come straight from the manifests.
    sys.path.insert(0, str(ROOT / "scripts"))
    from release_lib import publishable_crates

    todo = pending([(name, ws) for name in sorted(publishable_crates(ROOT))])
    if not todo:
        output(publish="false", reason=f"every crate is already on crates.io at {ws}")
        return 0
    output(publish="true", reason=f"{len(todo)} crate(s) to publish at {ws}", version=ws)
    return 0


def cmd_plan(_args):
    order = publish_order()
    todo = {n for n, _ in pending(order)}
    for i, (name, version) in enumerate(order, 1):
        print(f"{i}. {name} {version} {'(pending)' if name in todo else '(on crates.io)'}")
    return 0


def cmd_next(args):
    todo = pending(publish_order())
    if not todo:
        output(crate="")
        print("nothing left to publish")
        return 0
    name, version = todo[0]
    print(f"next: {name} {version}")
    if not args.no_verify:
        # The verify build: the packaged tarball, built in isolation against
        # registry-resolved dependencies — exactly what `cargo publish` would
        # build, minus the upload. No token exists yet.
        cargo("package", "-p", name, "--locked")
    output(crate=name, version=version)
    return 0


def cmd_upload(args):
    name = args.crate
    order = dict(publish_order())
    if name not in order:
        sys.exit(f"{name} is not a publishable workspace member")
    version = order[name]
    if not os.environ.get("CARGO_REGISTRY_TOKEN"):
        sys.exit("CARGO_REGISTRY_TOKEN is not set (the Trusted Publishing exchange did not run?)")
    versions = published_versions(name) or set()
    if version in versions:
        print(f"{name} {version} is already on crates.io")
        return 0
    # Verified by `next` moments ago; this is only the upload.
    rc = cargo("publish", "-p", name, "--locked", "--no-verify", check=False)
    if rc:
        # A previous attempt may have uploaded it and then failed on the wait.
        if version in (published_versions(name) or set()):
            print(f"{name} {version} is on crates.io despite the error; continuing")
            return 0
        sys.exit(f"cargo publish -p {name} failed (exit {rc})")
    deadline = time.monotonic() + INDEX_WAIT_SECONDS
    while time.monotonic() < deadline:
        if version in (published_versions(name) or set()):
            print(f"{name} {version} is in the index")
            return 0
        print(f"waiting for {name} {version} to reach the index…", flush=True)
        time.sleep(15)
    sys.exit(f"{name} {version} uploaded but not visible in the index after {INDEX_WAIT_SECONDS}s")


def cmd_check_all(_args):
    todo = pending(publish_order())
    if todo:
        for name, version in todo:
            print(f"::error::{name} {version} is not on crates.io")
        print("Re-run publish.yml (it resumes from the first missing crate). See RELEASES.md.")
        return 1
    print("every publishable crate is on crates.io")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gate").set_defaults(fn=cmd_gate)
    sub.add_parser("plan").set_defaults(fn=cmd_plan)
    p = sub.add_parser("next")
    p.add_argument("--no-verify", action="store_true", help="pick the crate without building it")
    p.set_defaults(fn=cmd_next)
    p = sub.add_parser("upload")
    p.add_argument("crate")
    p.set_defaults(fn=cmd_upload)
    sub.add_parser("check-all").set_defaults(fn=cmd_check_all)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
