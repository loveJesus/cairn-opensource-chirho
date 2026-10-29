// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The cut an elected erasure fixes before it removes any key, and the port that makes its propagation requirement durable first.
//!
//! C5 B3-a1 (design doc section 5a, "B3-a build decisions"). The capture is taken under the
//! erasure-records lock, after the erasure's seq is fixed and before the first key file is unlinked.
//! Its key ids are a union: every id the SIGNED blob log recorded for the subject, plus every id among
//! the subject's local key files. The log alone misses an orphan key file left by a crash between a key
//! file and its blob record; the files alone miss a key an earlier attempt already unlinked (agy R-C5-3,
//! agy #29608). Its bound is the blob log's length, exclusive because blob seqs start at 0.
//!
//! The log is authenticated before anything is derived from it: dense seqs, schema, shape and every
//! signature, against the public key of the key pair the caller proved it holds. A namespace check is not
//! a signature check, and a public key alone does not prove the root can still sign its erasure row, so
//! the elected road proves possession of the EXISTING pair first and never mints (gpt #29699, #29719).
//!
//! C5 B3-a2-ii adds the caller's required ids to a new cut, and gives the sink two more methods: its unbound
//! seqs, read before the requirement, and the binding, made after the record's append.

use super::{
    load_privacy_blob_records_chirho, local_subject_key_ids_chirho,
    private_blob_key_subject_chirho, validate_key_id_chirho,
    verify_privacy_blob_records_with_pubkey_chirho,
};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What one erasure fixed before it removed anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureCaptureChirho {
    /// The seq the erasure's own record takes.
    pub erasure_seq_chirho: u64,
    pub subject_chirho: String,
    /// The subject's signed blob records' key ids, its local key files' ids, and the ids its caller
    /// requires from a frozen inventory (C5 B3-a2-ii).
    pub key_ids_chirho: BTreeSet<String>,
    /// The authenticated blob log's length at the cut: every blob below it is covered.
    pub erased_below_blob_seq_chirho: u64,
}

/// What the root's own authenticated erasure log holds at one of the subject's unbound earlier seqs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EarlierErasureEvidenceChirho {
    /// The record at that seq is this subject's, with this digest: the requirement there is bound to it.
    RecordedChirho {
        erasure_record_digest_chirho: String,
    },
    /// The record at that seq is another subject's: that attempt was never recorded, and is carried.
    NeverRecordedChirho,
}

/// Where an elected erasure makes its propagation requirement durable, and later binds it to its record.
///
/// It is called with the subject-rights, account-attribution and erasure-records locks held, before
/// any key is removed. It does local durable capture only: it must not take any of those locks and must
/// not wait on the network. `record_requirement_chirho` returns only once the requirement is durable. An
/// error from it, or from `unbound_requirement_seqs_chirho`, stops the erasure: no key is removed and no
/// erasure record is appended, though any durable state the sink itself left is the sink's to
/// reconcile. `record_binding_chirho` is different: it runs after the keys are removed and the record is
/// appended, so its error leaves the erasure recorded, and the root returns
/// `ErasureRecordedBindingPendingChirho`. A requirement already stored for the same seq and subject is
/// authoritative: a retry keeps it and never recomputes it.
///
/// The sink's unbound seqs are read under the same locks before the requirement, so the root can classify
/// each earlier attempt from its own authenticated log. The binding is made after the record's append,
/// still under the erasure-records lock. No method may call back into the root (C5 B3-a2-ii).
pub trait ErasureRequirementSinkChirho {
    /// The seqs of the subject's requirements that have no binding yet.
    fn unbound_requirement_seqs_chirho(&self, subject_chirho: &str) -> Result<Vec<u64>>;
    /// Make the in-flight erasure's requirement durable. `earlier_chirho` classifies every unbound seq
    /// below the in-flight one.
    fn record_requirement_chirho(
        &self,
        capture_chirho: &ErasureCaptureChirho,
        earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()>;
    /// Bind the requirement at `erasure_seq_chirho` to the digest of the record appended there.
    fn record_binding_chirho(
        &self,
        erasure_seq_chirho: u64,
        subject_chirho: &str,
        erasure_record_digest_chirho: &str,
    ) -> Result<()>;
}

/// Take the cut from one load of the blob log, authenticated with `possessed_pubkey_chirho`: the public
/// key of the existing pair the caller just proved it holds. The caller holds the erasure lock.
pub(super) fn capture_erasure_unlocked_chirho(
    root_chirho: &Path,
    erasure_seq_chirho: u64,
    subject_chirho: &str,
    possessed_pubkey_chirho: &str,
    required_key_ids_chirho: &BTreeSet<String>,
) -> Result<ErasureCaptureChirho> {
    let records_chirho = load_privacy_blob_records_chirho(root_chirho)?;
    let key_subjects_chirho = if records_chirho.is_empty() {
        BTreeMap::new()
    } else {
        verify_privacy_blob_records_with_pubkey_chirho(
            root_chirho,
            &records_chirho,
            possessed_pubkey_chirho,
        )?
    };
    // A key the caller requires from a frozen inventory joins a NEW cut even when neither the log nor the
    // files still show it (gpt #29850). The caller proves the subject OWNS it; the root refuses one that its
    // own authenticated log or key files give to another subject, before any key is removed. The refusal
    // names neither the key nor the other subject.
    for key_id_chirho in required_key_ids_chirho {
        validate_key_id_chirho(key_id_chirho)?;
        let logged_owner_chirho = key_subjects_chirho.get(key_id_chirho);
        let file_owner_chirho = private_blob_key_subject_chirho(root_chirho, key_id_chirho)?;
        let another_subjects_chirho = logged_owner_chirho
            .into_iter()
            .chain(file_owner_chirho.as_ref())
            .any(|owner_chirho| owner_chirho != subject_chirho);
        if another_subjects_chirho {
            bail!(
                "ErasureRequiredKeyNotTheSubjectsChirho: a required key belongs to another subject"
            );
        }
    }
    let mut key_ids_chirho = key_subjects_chirho
        .into_iter()
        .filter(|(_, record_subject_chirho)| record_subject_chirho == subject_chirho)
        .map(|(key_id_chirho, _)| key_id_chirho)
        .collect::<BTreeSet<_>>();
    key_ids_chirho.extend(local_subject_key_ids_chirho(root_chirho, subject_chirho)?);
    key_ids_chirho.extend(required_key_ids_chirho.iter().cloned());
    Ok(ErasureCaptureChirho {
        erasure_seq_chirho,
        subject_chirho: subject_chirho.to_string(),
        key_ids_chirho,
        erased_below_blob_seq_chirho: records_chirho.len() as u64,
    })
}
