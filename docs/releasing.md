# Releasing

Publishing to crates.io is manual for now; there is no release workflow.

The workspace publishes two crates, both on the one workspace version
(`[workspace.package] version` in the root `Cargo.toml`). They must go out in
dependency order, which `cargo publish --workspace` handles:

1. `openvtc-core`
2. `openvtc`

`openvtc-vetting-pcs` was published from here up to 0.6.0. The hidden-vetting
engine now runs in the VTA (`vta/pcs/*`, VTI's `vti-vetting-pcs`), and the crate
is no longer part of this workspace.

## Steps

1. Bump `version` in `[workspace.package]`, and the matching version
   requirement on the path dependency `openvtc-core` in
   `[workspace.dependencies]`.
2. Update `CHANGELOG.md`, open a PR, and merge it.
3. From a clean checkout of `main`:

   ```bash
   cargo publish --workspace --dry-run
   cargo publish --workspace
   ```

   `cargo login` first if this machine has no crates.io token.
4. Tag the release and push the tag:

   ```bash
   git tag -s v<version> -m "v<version>"
   git push origin v<version>
   ```

A crates.io version can be yanked but never replaced. If a publish fails
partway, the crates before the failure are already out: fix the problem and
publish the rest with `cargo publish -p <crate>` in the order above. If the
fix has to change a crate that is already out, bump the version and publish
all three again.
