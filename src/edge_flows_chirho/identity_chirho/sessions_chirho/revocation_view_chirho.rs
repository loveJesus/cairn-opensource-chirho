// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The session revocation log as an incremental, verified set (brick 4b), with its append door: a request asks whether
//! its session is revoked with one lookup, and a revocation is decided and written as one act.
//!
//! - **The fold** runs the full verifier's per-record checks, in its order (`load_verified_session_revocations_chirho`):
//!   the loader's parse and schema, the seq, then `verify_session_revocation_record_chirho`. That check finds the
//!   target session in the session index and verifies it again, as today's verifier does from the whole log.
//! - **The set** holds each revoked (principal, session seq, token hash), the triple today's check matches, with the
//!   FIRST record that revoked it: what a repeated revocation answers.
//! - **The door** brings the set current under the append-log lock, answers an existing revocation without writing,
//!   and appends only when the seqlog's recovered length equals the set's verified count. Today's revoke verified the
//!   whole log twice, and looked for an existing revocation outside the lock, so two concurrent revocations of one
//!   session could both append.
//! - **Cost:** a fold is one session lookup and that session's re-verification, once per revocation; a lookup is O(1).
//! - **Locks:** the append-log lock (the door), then this view's slot, then the session index's slot (the fold).

use super::*;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::HashMap;

/// (principal, session seq, token hash): what a revocation names, and what today's check matched.
type RevokedSessionKeyChirho = (String, u64, String);

fn revoked_session_key_chirho(session_chirho: &IdentitySessionChirho) -> RevokedSessionKeyChirho {
    (
        session_chirho.principal_chirho.clone(),
        session_chirho.seq_chirho,
        session_chirho.token_hash_chirho.clone(),
    )
}

/// The verified revocation log, folded: the first record for each revoked session.
#[derive(Default)]
pub(super) struct RevocationSetChirho {
    first_by_session_chirho:
        HashMap<RevokedSessionKeyChirho, IdentitySessionRevocationRecordChirho>,
}

static REVOCATION_REGISTRY_CHIRHO: RegistryChirho<RevocationSetChirho> =
    RegistryChirho::new_chirho();

const REVOCATION_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const REVOCATION_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const REVOCATION_SLOT_CAP_CHIRHO: usize = 8192;

fn revocation_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: REVOCATION_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: REVOCATION_SLOT_CAP_CHIRHO,
    }
}

struct RevocationLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
}

impl RevocationLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: session_revocations_path_chirho(root_chirho),
            verifier_id_chirho: format!("identity-session-revocations-v1-chirho:{pubkey_chirho}"),
            pubkey_chirho: pubkey_chirho.to_string(),
        }
    }
}

impl PrefixLogChirho for RevocationLogChirho {
    type RecordChirho = IdentitySessionRevocationRecordChirho;
    type IndexChirho = RevocationSetChirho;
    type JobLogChirho = RevocationLogChirho;

    fn job_log_chirho(&self) -> RevocationLogChirho {
        RevocationLogChirho::new_chirho(&self.root_chirho, &self.pubkey_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies signatures, so the id names the key: a changed key verifies every revocation again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<RevocationSetChirho> {
        &REVOCATION_REGISTRY_CHIRHO
    }

    /// The loader's parse.
    fn parse_chirho(&self, line_chirho: &str) -> Result<IdentitySessionRevocationRecordChirho> {
        parse_session_revocation_line_chirho(line_chirho)
    }

    /// The full verifier's checks for one revocation, in its order; the target session comes from the session index.
    fn verify_and_fold_chirho(
        &self,
        set_chirho: &mut RevocationSetChirho,
        record_chirho: IdentitySessionRevocationRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "identity session revocation seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_session_revocation_record_chirho(
            &self.root_chirho,
            &self.pubkey_chirho,
            |revocation_chirho| {
                Ok(session_view_chirho::session_by_seq_chirho(
                    &self.root_chirho,
                    &self.pubkey_chirho,
                    &revocation_chirho.principal_chirho,
                    revocation_chirho.session_seq_chirho,
                )?
                .filter(|session_chirho| {
                    session_chirho.token_hash_chirho == revocation_chirho.token_hash_chirho
                }))
            },
            &record_chirho,
        )?;
        set_chirho
            .first_by_session_chirho
            .entry((
                record_chirho.principal_chirho.clone(),
                record_chirho.session_seq_chirho,
                record_chirho.token_hash_chirho.clone(),
            ))
            .or_insert(record_chirho);
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-session-revocation-view-job-chirho"
    }
}

/// Bring the root's revocation set current and read it, with the count of records it verified; the closure only copies
/// out. A missing log reads as no set and zero records.
fn with_revocation_set_chirho<T>(
    root_chirho: &Path,
    pubkey_chirho: &str,
    read_chirho: impl FnOnce(Option<&RevocationSetChirho>) -> T,
) -> Result<(T, u64)> {
    if log_missing_chirho(
        &REVOCATION_REGISTRY_CHIRHO,
        &session_revocations_path_chirho(root_chirho),
    )? {
        return Ok((read_chirho(None), 0));
    }
    let (value_chirho, status_chirho) = with_current_view_chirho(
        &RevocationLogChirho::new_chirho(root_chirho, pubkey_chirho),
        &revocation_view_rules_chirho(),
        now_ms_chirho,
        |set_chirho, _now_ms_chirho| read_chirho(set_chirho),
    )?;
    Ok((value_chirho, status_chirho.verified_records_chirho))
}

/// Whether `session_chirho` is revoked: one lookup in the verified set.
pub(super) fn session_revoked_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    session_chirho: &IdentitySessionChirho,
) -> Result<bool> {
    let key_chirho = revoked_session_key_chirho(session_chirho);
    Ok(
        with_revocation_set_chirho(root_chirho, pubkey_chirho, |set_chirho| {
            set_chirho.is_some_and(|set_chirho| {
                set_chirho.first_by_session_chirho.contains_key(&key_chirho)
            })
        })?
        .0,
    )
}

/// THE APPEND DOOR: revoke `session_chirho` as one act under the append-log lock. The set is brought current first
/// (verifying only new revocations, refusing on a bad one still in the log); a session already revoked answers its
/// first record and appends nothing; otherwise the seqlog's recovery may repair a torn tail, and the two counts must
/// agree before the record is appended. The caller has validated the actor and reason.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
pub(super) fn revoke_through_door_chirho(
    root_chirho: &Path,
    session_chirho: &IdentitySessionChirho,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        revoke_under_append_lock_chirho(root_chirho, session_chirho, actor_chirho, reason_chirho)
    })
}

/// The same door for a caller that already holds the root-wide append-log lock (the limited-key opt-in, which retires
/// and records its opening in one locked section, K1). It decides and appends exactly as the door does.
pub(super) fn revoke_under_append_lock_chirho(
    root_chirho: &Path,
    session_chirho: &IdentitySessionChirho,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    let path_chirho = session_revocations_path_chirho(root_chirho);
    let key_chirho = revoked_session_key_chirho(session_chirho);
    {
        let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
        let (existing_chirho, verified_chirho) =
            with_revocation_set_chirho(root_chirho, &pubkey_chirho, |set_chirho| {
                set_chirho
                    .and_then(|set_chirho| set_chirho.first_by_session_chirho.get(&key_chirho))
                    .cloned()
            })?;
        if let Some(existing_chirho) = existing_chirho {
            return Ok(existing_chirho);
        }
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        if seq_chirho != verified_chirho {
            bail!(
                "session revocation log holds {seq_chirho} records by recovery but {verified_chirho} verified \
                 records; refusing to append"
            );
        }
        let mut record_chirho = IdentitySessionRevocationRecordChirho {
            seq_chirho,
            schema_chirho: IDENTITY_SESSION_REVOCATION_RECORD_SCHEMA_CHIRHO.to_string(),
            principal_chirho: session_chirho.principal_chirho.clone(),
            session_seq_chirho: session_chirho.seq_chirho,
            token_hash_chirho: session_chirho.token_hash_chirho.clone(),
            actor_chirho: actor_chirho.to_string(),
            reason_chirho: reason_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = session_revocation_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    }
}

/// Build the root's revocation set now, so the first requests find it ready.
pub(super) fn warm_revocation_set_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Result<()> {
    with_revocation_set_chirho(root_chirho, pubkey_chirho, |_| ()).map(|_| ())
}
