// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The session log as an incremental, verified index (brick 4b): each session is checked ONCE, when folded, so a cookie
//! or bearer request finds its session in memory instead of scanning and re-verifying the whole log.
//!
//! - **The fold** runs the full verifier's per-session checks, in its order (`load_verified_sessions_chirho`): the
//!   loader's parse and schema, the seq, then `verify_session_record_chirho` (the identity, the session's proof under
//!   the identity's key, the instance signature). A session and the identity it names are append-only, so its verdict
//!   is fixed once checked.
//! - **A full pass** (the first build, the hourly integrity pass, a write-access fallback) is today's full verifier.
//! - **The whole log answers for each lookup.** A bad record anywhere refuses every lookup until it is repaired, where
//!   today's scan refused only a lookup whose newest matching row was the bad one. That is the token view's posture
//!   (agy #25928, ruling (a)); a bad record needs write access to the root.
//! - **Cost:** a fold is O(I) for its identity lookup, once per sign-in (4a-1 holds a principal to 10 an hour); a lookup
//!   is O(1). The index keeps every session, O(S) memory, as the token view keeps every token.
//! - **Locks:** the append-log lock where a caller holds it, then a view whose fold reads this one (the token view, the
//!   revocation set), then this view's slot. This fold reads the identity log through its loader, never a view.

use super::*;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::HashMap;

/// The verified session log, folded: every session by seq, and the seqs of each token hash.
#[derive(Default)]
pub(super) struct SessionIndexChirho {
    records_chirho: Vec<IdentitySessionChirho>,
    seqs_by_hash_chirho: HashMap<String, Vec<u64>>,
}

static SESSION_REGISTRY_CHIRHO: RegistryChirho<SessionIndexChirho> = RegistryChirho::new_chirho();

const SESSION_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const SESSION_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const SESSION_SLOT_CAP_CHIRHO: usize = 8192;

fn session_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: SESSION_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: SESSION_SLOT_CAP_CHIRHO,
    }
}

struct SessionLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
}

impl SessionLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: sessions_path_chirho(root_chirho),
            verifier_id_chirho: format!("identity-sessions-v1-chirho:{pubkey_chirho}"),
            pubkey_chirho: pubkey_chirho.to_string(),
        }
    }
}

impl PrefixLogChirho for SessionLogChirho {
    type RecordChirho = IdentitySessionChirho;
    type IndexChirho = SessionIndexChirho;
    type JobLogChirho = SessionLogChirho;

    fn job_log_chirho(&self) -> SessionLogChirho {
        SessionLogChirho::new_chirho(&self.root_chirho, &self.pubkey_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies the instance signature, so the id names the key: a changed key verifies every session again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<SessionIndexChirho> {
        &SESSION_REGISTRY_CHIRHO
    }

    /// The loader's parse.
    fn parse_chirho(&self, line_chirho: &str) -> Result<IdentitySessionChirho> {
        parse_session_line_chirho(line_chirho)
    }

    /// The full verifier's checks for one session, in its order.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut SessionIndexChirho,
        record_chirho: IdentitySessionChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "identity session seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_session_record_chirho(&self.root_chirho, &self.pubkey_chirho, &record_chirho)?;
        index_chirho
            .seqs_by_hash_chirho
            .entry(record_chirho.token_hash_chirho.clone())
            .or_default()
            .push(record_chirho.seq_chirho);
        index_chirho.records_chirho.push(record_chirho);
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-session-view-job-chirho"
    }
}

/// Bring the root's session index current and read it; the closure only copies out. A missing log reads as no index.
fn with_session_index_chirho<T>(
    root_chirho: &Path,
    pubkey_chirho: &str,
    read_chirho: impl FnOnce(Option<&SessionIndexChirho>) -> T,
) -> Result<T> {
    if log_missing_chirho(&SESSION_REGISTRY_CHIRHO, &sessions_path_chirho(root_chirho))? {
        return Ok(read_chirho(None));
    }
    let (value_chirho, _status_chirho) = with_current_view_chirho(
        &SessionLogChirho::new_chirho(root_chirho, pubkey_chirho),
        &session_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| read_chirho(index_chirho),
    )?;
    Ok(value_chirho)
}

/// The newest verified session of `principal_chirho` whose token hash is `token_hash_chirho`, as today's newest-first
/// scan picks it. The map finds the hash's sessions; the constant-time compare is kept as today's.
pub(super) fn session_by_token_hash_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    token_hash_chirho: &str,
) -> Result<Option<IdentitySessionChirho>> {
    with_session_index_chirho(root_chirho, pubkey_chirho, |index_chirho| {
        let index_chirho = index_chirho?;
        index_chirho
            .seqs_by_hash_chirho
            .get(token_hash_chirho)?
            .iter()
            .rev()
            .map(|seq_chirho| &index_chirho.records_chirho[*seq_chirho as usize])
            .find(|session_chirho| {
                session_chirho.principal_chirho == principal_chirho
                    && constant_time_string_eq_chirho(
                        &session_chirho.token_hash_chirho,
                        token_hash_chirho,
                    )
            })
            .cloned()
    })
}

/// The verified session at `session_seq_chirho`, when it is `principal_chirho`'s.
pub(super) fn session_by_seq_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    session_seq_chirho: u64,
) -> Result<Option<IdentitySessionChirho>> {
    with_session_index_chirho(root_chirho, pubkey_chirho, |index_chirho| {
        index_chirho?
            .records_chirho
            .get(usize::try_from(session_seq_chirho).ok()?)
            .filter(|session_chirho| session_chirho.principal_chirho == principal_chirho)
            .cloned()
    })
}

/// Build the root's session index now, so the first requests find it ready.
pub(super) fn warm_session_index_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Result<()> {
    with_session_index_chirho(root_chirho, pubkey_chirho, |_| ())
}
