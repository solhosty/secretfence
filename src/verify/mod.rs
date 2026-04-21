#[cfg(feature = "verify")]
mod validators;

#[cfg(feature = "verify")]
pub use validators::{validate_secrets, VerifyResult, VerifyStatus};

#[cfg(not(feature = "verify"))]
pub fn validate_secrets(
    _matches: &[crate::rules::SecretMatch],
    _project_dir: &std::path::Path,
) -> Vec<VerifyResult> {
    eprintln!("[secretfence] --verify requires the 'verify' feature. Rebuild with: cargo install secretfence --features verify");
    Vec::new()
}

#[cfg(not(feature = "verify"))]
#[derive(Debug)]
pub struct VerifyResult {
    pub file_path: String,
    pub rule_id: String,
    pub status: VerifyStatus,
}

#[cfg(not(feature = "verify"))]
#[derive(Debug)]
pub enum VerifyStatus {
    Active,
    Inactive,
    NotVerifiable,
    Error(String),
}
