use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WgBackend {
    Userspace,
    Kernel,
}

impl WgBackend {
    /// Parse a CLI argument string into a backend choice.
    pub fn from_str_arg(s: &str) -> anyhow::Result<Self> {
        match s {
            "userspace" => Ok(Self::Userspace),
            "kernel" => Ok(Self::Kernel),
            other => anyhow::bail!("unknown backend {:?} (expected userspace, kernel)", other),
        }
    }
}

impl fmt::Display for WgBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Userspace => write!(f, "userspace"),
            Self::Kernel => write!(f, "kernel"),
        }
    }
}
