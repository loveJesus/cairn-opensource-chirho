// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The served-request limits, as configured from the host TOML: the abuse gate's per-actor and global windows, and the
//! sign-in velocity limits (brick 4a) and the per-source failure limit (R12). Configuration only; the gates that enforce
//! them hold their own state.

use anyhow::{bail, Result};
use cairn_chirho::identity_chirho;

#[derive(Clone, Copy)]
pub struct ServedRequestAbuseLimitsChirho {
    pub window_ms_chirho: u64,
    pub actor_max_requests_chirho: u64,
    pub actor_max_body_bytes_chirho: u64,
    pub global_max_requests_chirho: u64,
    pub global_max_body_bytes_chirho: u64,
    pub actor_bucket_cap_chirho: usize,
    /// Successful sign-ins per principal per hour, checked before the credential (brick 4a; host TOML).
    pub sign_in_principal_successes_per_hour_chirho: u64,
    /// Successful sign-ins per normalized client network per hour, in process memory (brick 4a; host TOML).
    pub sign_in_source_successes_per_hour_chirho: u64,
    /// Recorded FAILED attempts per normalized client network per failure window (15 minutes), one budget across
    /// login, token and recover, in process memory (R12; host TOML).
    pub sign_in_source_failures_per_window_chirho: u64,
}

impl Default for ServedRequestAbuseLimitsChirho {
    fn default() -> Self {
        Self {
            window_ms_chirho: 60_000,
            actor_max_requests_chirho: 60,
            actor_max_body_bytes_chirho: 8 * 1024 * 1024,
            global_max_requests_chirho: 600,
            global_max_body_bytes_chirho: 64 * 1024 * 1024,
            actor_bucket_cap_chirho: 4_096,
            sign_in_principal_successes_per_hour_chirho:
                identity_chirho::SIGN_IN_PRINCIPAL_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO,
            sign_in_source_successes_per_hour_chirho:
                identity_chirho::SIGN_IN_SOURCE_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO,
            sign_in_source_failures_per_window_chirho:
                identity_chirho::SIGN_IN_SOURCE_FAILURES_PER_WINDOW_DEFAULT_CHIRHO,
        }
    }
}

impl ServedRequestAbuseLimitsChirho {
    pub fn validate_chirho(&self) -> Result<()> {
        if self.window_ms_chirho == 0
            || self.actor_max_requests_chirho == 0
            || self.actor_max_body_bytes_chirho == 0
            || self.global_max_requests_chirho == 0
            || self.global_max_body_bytes_chirho == 0
            || self.actor_bucket_cap_chirho == 0
            || self.sign_in_principal_successes_per_hour_chirho == 0
            || self.sign_in_source_successes_per_hour_chirho == 0
            || self.sign_in_source_failures_per_window_chirho == 0
        {
            bail!("served request abuse limits cannot be zero or disabled");
        }
        if self.global_max_requests_chirho < self.actor_max_requests_chirho
            || self.global_max_body_bytes_chirho < self.actor_max_body_bytes_chirho
        {
            bail!("served request global limits cannot be below per-actor limits");
        }
        Ok(())
    }
}
