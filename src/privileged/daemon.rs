use crate::error::{AppError, Result};

pub(super) fn self_executable_for_spawn() -> Result<std::path::PathBuf> {
    let current = std::env::current_exe()
        .map_err(|e| AppError::Other(format!("cannot resolve current executable: {e}")))?;
    if current.exists() {
        // Finding 3 — Executable substitution through PATH: the helper itself
        // must also be immutable to unprivileged users before root respawns it.
        crate::trusted_exec::validate_root_owned_path(
            &current,
            crate::trusted_exec::TrustedPath::Executable,
        )?;
        return Ok(current);
    }
    Err(AppError::Other(format!(
        "current executable path does not exist: {}",
        current.display()
    )))
}
