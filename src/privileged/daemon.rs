use crate::error::{AppError, Result};

pub(super) fn self_executable_for_spawn() -> Result<std::path::PathBuf> {
    let current = std::env::current_exe()
        .map_err(|e| AppError::Other(format!("cannot resolve current executable: {e}")))?;
    if current.exists() {
        return Ok(current);
    }
    Err(AppError::Other(format!(
        "current executable path does not exist: {}",
        current.display()
    )))
}
