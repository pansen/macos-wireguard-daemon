use anyhow::Context;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Output;
use tracing::{debug, trace};

#[cfg(unix)]
pub(super) fn write_runtime_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // This runs as the privileged helper, so a symlink planted under the runtime
    // dir could otherwise redirect the write (and the chmod) to clobber an
    // arbitrary file. O_NOFOLLOW makes open() fail rather than follow a final-
    // component symlink, and mode(0o600) creates the file private from the start.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    // Pin permissions for the case where the file already existed (open() does not
    // re-apply mode to an existing file).
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn write_runtime_file_atomic(
    path: &std::path::Path,
    contents: &str,
) -> anyhow::Result<()> {
    let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    write_runtime_file(&temp_path, contents)?;
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn run_command(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
pub(super) fn run_command_with_exists_ok(name: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("File exists") || stdout.contains("File exists") {
        return Ok(false);
    }
    let detail = stderr.trim();
    if detail.is_empty() {
        anyhow::bail!("{} {} failed", name, args.join(" "));
    }
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
pub(super) fn run_command_capture_output(name: &str, args: &[&str]) -> anyhow::Result<Output> {
    trace!(command = %format_command_for_log(name, args), "userspace_helper_command");
    let output = crate::trusted_exec::command(name)?
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))?;
    if !output.status.success() {
        debug!(
            command = %format_command_for_log(name, args),
            status = %output.status,
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_command_failed"
        );
    }
    Ok(output)
}

#[cfg(unix)]
pub(super) fn format_command_for_log(name: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return name.to_string();
    }
    format!("{} {}", name, args.join(" "))
}
