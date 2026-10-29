// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Operator listing of one principal's sessions with their live/expired/revoked state, so a
//! `--session-seq` revocation can be chosen without reading the session log by hand.
//!
//! Every row comes from a signature-verified session record; a session whose record fails to
//! verify fails the whole listing rather than being skipped, because an operator choosing a seq to
//! revoke must not be shown a row nobody signed. Token hashes are deliberately not part of the row.

use super::*;
use std::collections::HashSet;

/// The state an operator acts on. `LiveChirho` is the only state a revocation changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentitySessionStateChirho {
    LiveChirho,
    ExpiredChirho,
    RevokedChirho,
}

impl IdentitySessionStateChirho {
    pub fn label_chirho(self) -> &'static str {
        match self {
            Self::LiveChirho => "live",
            Self::ExpiredChirho => "expired",
            Self::RevokedChirho => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySessionStatusChirho {
    pub seq_chirho: u64,
    pub issued_ms_chirho: u64,
    pub expires_ms_chirho: u64,
    pub state_chirho: IdentitySessionStateChirho,
}

/// Verified sessions of `principal_chirho`, oldest first. Both logs are loaded and verified ONCE
/// before any row is routed on its principal field, so a tampered row fails the listing instead of
/// slipping past the filter; revocation membership is one set lookup per row. The listing therefore
/// costs one verification of each log, never a verification per row.
pub fn list_principal_sessions_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<Vec<IdentitySessionStatusChirho>> {
    let now_ms_chirho = now_ms_chirho();
    let revoked_keys_chirho: HashSet<(String, u64, String)> =
        load_verified_session_revocations_chirho(root_chirho)?
            .into_iter()
            .map(|revocation_chirho| {
                (
                    revocation_chirho.principal_chirho,
                    revocation_chirho.session_seq_chirho,
                    revocation_chirho.token_hash_chirho,
                )
            })
            .collect();
    let mut rows_chirho = Vec::new();
    for session_chirho in load_verified_sessions_chirho(root_chirho)? {
        if session_chirho.principal_chirho != principal_chirho {
            continue;
        }
        let revoked_chirho = revoked_keys_chirho.contains(&(
            session_chirho.principal_chirho.clone(),
            session_chirho.seq_chirho,
            session_chirho.token_hash_chirho.clone(),
        ));
        let state_chirho = if revoked_chirho {
            IdentitySessionStateChirho::RevokedChirho
        } else if session_chirho.expires_ms_chirho < now_ms_chirho {
            IdentitySessionStateChirho::ExpiredChirho
        } else {
            IdentitySessionStateChirho::LiveChirho
        };
        rows_chirho.push(IdentitySessionStatusChirho {
            seq_chirho: session_chirho.seq_chirho,
            issued_ms_chirho: session_chirho.issued_ms_chirho,
            expires_ms_chirho: session_chirho.expires_ms_chirho,
            state_chirho,
        });
    }
    rows_chirho.sort_by_key(|row_chirho| row_chirho.seq_chirho);
    Ok(rows_chirho)
}
