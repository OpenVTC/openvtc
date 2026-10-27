// Generates $OUT_DIR/trust_tasks_generated.rs — the Trust Task specifications
// this crate speaks, and only those — from trust-tasks.lock and the bundles
// vendored under trust-tasks/, after checking each bundle against its digest.
// `trust-tasks add|update` moves a pin; `trust-tasks check` verifies them in CI.
fn main() -> Result<(), trust_tasks_build::Error> {
    trust_tasks_build::Config::new()
        .lockfile("trust-tasks.lock")
        .compile()?;
    Ok(())
}
