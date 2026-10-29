// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A connection key's issuance (K4 Part 2): prove the credential, decide the daily limit (Part 3) and the cap, then
//! write the connection's 30-day session and its key, in one section under the principal's credential lock and the
//! root append lock, so a refusal appends neither a session nor a key (the proof may still re-hash a legacy credential,
//! as every sign-in does). A failure after the first write names what is on disk and what is uncertain.
//!
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 2, as built;
//! the daily limit, Part 3's placement, as decided).

use super::super::key_listing_chirho::{
    connection_issue_instants_chirho, live_rate_limited_keys_chirho,
};
use super::super::key_row_chirho::draft_key_row_chirho;
use super::super::{
    IssuedKeyKindChirho, OauthClientRecordChirho, ScopedTokenCapReachedChirho,
    ScopedTokenIssueChirho, ScopedTokenRateLimitChirho,
    LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO,
};
use super::{run_issuance_hold_chirho, KeyStoreChirho};
use crate::{identity_chirho, seqlog_chirho};
use anyhow::{bail, Result};
use cairn_capability_chirho::capability_key_grant_chirho::LimitedKeyGrantsChirho;
use std::path::Path;

/// How many connections one principal may create in any 24 hours, across apps (K4 Part 3, PFE #26801). A fixed engine
/// limit at this one door, which the served road and the operator CLI both go through: no caller bypasses it and no
/// process sets another. Ended keys count, so ending connections frees slots, not the day's allowance.
pub const CONNECTION_ISSUANCES_PER_DAY_CHIRHO: usize = 10;

/// The daily limit's window: 24 hours, closed at both ends.
pub const CONNECTION_ISSUANCE_WINDOW_MS_CHIRHO: u64 = 24 * 60 * 60 * 1000;

/// Where the daily window counted at `now_ms_chirho` starts: 24 hours earlier, and never before zero. A key issued
/// exactly then still counts, and so does a key dated after now (a wall clock moved back), so any 24 hours, endpoints
/// included, hold at most the limit's keys written under it.
pub fn connection_issuance_window_start_chirho(now_ms_chirho: u64) -> u64 {
    now_ms_chirho.saturating_sub(CONNECTION_ISSUANCE_WINDOW_MS_CHIRHO)
}

/// The daily limit's decision at `now_ms_chirho`, over the issue instants of the principal's connection keys: whether
/// one more may be created. A key counts when it was issued at or after the window's start, with no upper end, and the
/// limit admits while fewer than `CONNECTION_ISSUANCES_PER_DAY_CHIRHO` count. The door decides through this function,
/// and so does the 30-day simulation, so a boundary mutant here fails both.
pub fn daily_limit_admits_chirho(
    issue_instants_chirho: impl IntoIterator<Item = u64>,
    now_ms_chirho: u64,
) -> bool {
    let window_start_chirho = connection_issuance_window_start_chirho(now_ms_chirho);
    issue_instants_chirho
        .into_iter()
        .filter(|issued_ms_chirho| *issued_ms_chirho >= window_start_chirho)
        .count()
        < CONNECTION_ISSUANCES_PER_DAY_CHIRHO
}

/// The principal has created the day's connections: `CONNECTION_ISSUANCES_PER_DAY_CHIRHO` of her connection keys were
/// issued at or after the window's start, ended ones included. Decided before the cap, after the proof, and appends
/// neither a session nor a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionDailyLimitReachedChirho;

impl std::fmt::Display for ConnectionDailyLimitReachedChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter_chirho,
            "ConnectionDailyLimitChirho: this principal has created {CONNECTION_ISSUANCES_PER_DAY_CHIRHO} connections in \
             the last 24 hours, the most one day allows; ended connections count too. Try again later."
        )
    }
}

impl std::error::Error for ConnectionDailyLimitReachedChirho {}

/// A connection's issuance that stopped after it began writing. Its session and its key are two logs, not one
/// transaction, so this names what is on disk and what is uncertain, and is never "nothing was created". The key's
/// bearer was never shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionIssueFaultChirho {
    /// The session's append failed, so a session row may or may not be on disk, and no key was written. Nobody holds
    /// such a session's token, so it cannot be signed in with, and it holds no connection slot.
    SessionUncertainChirho { cause_chirho: String },
    /// The session at `session_seq_chirho` is on disk; the key's append then failed, so the key may or may not be on
    /// disk. If it is, it is live and holds one of the owner's slots until it is ended or expires, though nobody holds
    /// its bearer.
    KeyUncertainChirho {
        session_seq_chirho: u64,
        cause_chirho: String,
    },
}

impl std::fmt::Display for ConnectionIssueFaultChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionUncertainChirho { cause_chirho } => write!(
                formatter_chirho,
                "ConnectionSessionUncertainChirho: the connection's session could not be written ({cause_chirho}). A \
                 session row may or may not be on disk; no key was written. Nobody holds that session's token, so it \
                 cannot be signed in with and holds no connection slot."
            ),
            Self::KeyUncertainChirho {
                session_seq_chirho,
                cause_chirho,
            } => write!(
                formatter_chirho,
                "ConnectionKeyUncertainChirho: the connection's session {session_seq_chirho} is on disk, and its key \
                 could not be written ({cause_chirho}). The key may or may not be on disk, and its bearer was not \
                 shown. Do not issue again blindly: list the owner's connections first and end any she did not \
                 receive, since such a key is live and holds a slot."
            ),
        }
    }
}

impl std::error::Error for ConnectionIssueFaultChirho {}

/// Issue a connection key for `principal_chirho` through `client_chirho`, a connection-store client, holding
/// `grants_chirho` under `rate_limit_chirho`. It decides before it creates:
/// 1. the credential is proved under the principal's credential lock, outside the root append lock;
/// 2. under the root append lock, at `clock_chirho()`, the daily limit is decided over her connection keys, then the cap
///    over both stores, and a refusal appends neither a session nor a key. The daily limit goes first, so a cap refusal
///    means that at this decision the day had room and the cap refused;
/// 3. the connection's 30-day session is appended, then the key, bound to the session's instants and signed.
///
/// Workflow: the connection issuance DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md`
/// (Part 2, as built).
pub(in crate::oauth_chirho) fn issue_connection_key_at_chirho(
    root_chirho: &Path,
    client_chirho: &OauthClientRecordChirho,
    principal_chirho: &str,
    credential_chirho: &str,
    grants_chirho: LimitedKeyGrantsChirho,
    rate_limit_chirho: ScopedTokenRateLimitChirho,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<ScopedTokenIssueChirho> {
    let (draft_chirho, token_chirho) = draft_key_row_chirho(
        client_chirho,
        IssuedKeyKindChirho::LimitedChirho(grants_chirho),
        Some(rate_limit_chirho),
    )?;
    if draft_chirho.store_chirho() != KeyStoreChirho::ConnectionChirho {
        bail!("a connection key is issued only for a connection client");
    }
    identity_chirho::with_connection_session_door_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        |door_chirho| {
            let now_chirho = clock_chirho();
            if !daily_limit_admits_chirho(
                connection_issue_instants_chirho(
                    root_chirho,
                    door_chirho.principal_chirho(),
                    connection_issuance_window_start_chirho(now_chirho),
                )?,
                now_chirho,
            ) {
                return Err(ConnectionDailyLimitReachedChirho.into());
            }
            if live_rate_limited_keys_chirho(
                root_chirho,
                door_chirho.principal_chirho(),
                now_chirho,
            )? >= LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO
            {
                return Err(ScopedTokenCapReachedChirho.into());
            }
            run_issuance_hold_chirho()?;
            let session_chirho =
                door_chirho
                    .append_session_chirho(now_chirho)
                    .map_err(
                        |error_chirho| ConnectionIssueFaultChirho::SessionUncertainChirho {
                            cause_chirho: format!("{error_chirho:#}"),
                        },
                    )?;
            let record_chirho = seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
                &KeyStoreChirho::ConnectionChirho.tokens_path_chirho(root_chirho),
                |seq_chirho| {
                    draft_chirho.signed_at_chirho(root_chirho, seq_chirho, &session_chirho)
                },
            )
            .map_err(|error_chirho| {
                ConnectionIssueFaultChirho::KeyUncertainChirho {
                    session_seq_chirho: session_chirho.seq_chirho,
                    cause_chirho: format!("{error_chirho:#}"),
                }
            })?;
            Ok(ScopedTokenIssueChirho {
                record_chirho,
                token_chirho,
            })
        },
    )
}
