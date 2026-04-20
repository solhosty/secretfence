use std::process::Command;

use anyhow::Result;

use super::matches_env_pattern;

pub fn exec_sandboxed(
    deny_paths: &[String],
    deny_env: &[String],
    command: &[String],
) -> Result<()> {
    // On Linux, we'd use Landlock LSM for kernel-enforced file access control.
    // For now, fall back to env scrubbing since Landlock requires specific kernel
    // versions and the landlock crate as a dependency.
    //
    // TODO: Add Landlock support via the `landlock` crate
    // - Create a ruleset handling ReadFile/ReadDir
    // - Allow full filesystem, then restrict deny_paths
    // - prctl(PR_SET_NO_NEW_PRIVS) + landlock_restrict_self()
    // - Fall back to this approach if kernel < 5.13

    eprintln!(
        "[secretfence] Note: Landlock sandboxing not yet implemented. Using env scrubbing."
    );

    let (cmd, args) = command.split_first().unwrap();
    let mut child = Command::new(cmd);
    child.args(args);

    // Scrub denied env vars
    for pattern in deny_env {
        for (key, _) in std::env::vars() {
            if matches_env_pattern(&key, pattern) {
                child.env_remove(&key);
            }
        }
    }

    let status = child.status()?;
    std::process::exit(status.code().unwrap_or(1));
}
