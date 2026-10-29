// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! What an elected erasure learns about its subject's earlier attempts from the root's own authenticated erasure log, how a recorded attempt is bound to its record, and how one left unbound is bound later without erasing again.
//!
//! C5 B3-a2-ii (design doc section 5a, items 4, 9 and 12). The erasure log is authenticated with the
//! POSSESSED key before anything is read from it: dense seqs, schema, shape and every signature. An unbound
//! earlier seq whose record is this subject's was recorded, and is bound to that record's digest. One whose
//! record is another subject's was never recorded, and the next erasure carries it. The record digest
//! covers the record's canonical serialization, signature included, so the binding made right after the
//! append and the one reconcile makes later always agree.

use super::erasure_capture_chirho::{EarlierErasureEvidenceChirho, ErasureRequirementSinkChirho};
use super::{
    load_privacy_erasure_records_chirho, validate_subject_chirho,
    verify_privacy_erasure_records_with_pubkey_chirho, with_account_attribution_lock_chirho,
    PrivacyErasureRecordChirho, PRIVACY_ERASURE_RECORDS_LOCK_CHIRHO,
};
use crate::legal_hold_chirho;
use crate::seqlog_chirho;
use anyhow::{bail, Result};
use cairn_signer_chirho::signer_chirho;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

const ERASURE_RECORD_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-privacy-erasure-record-v1-chirho";

/// An erasure the root RECORDED whose propagation binding did not become durable. The erasure is not to be
/// repeated: reconcile binds this exact record later. It names the seq and the record's digest, and its
/// text is fixed. The sink's own refusal is not carried, because any implementation of a public trait
/// can return it and its text is not bounded (gpt #29956).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureRecordedBindingPendingChirho {
    pub erasure_seq_chirho: u64,
    pub erasure_record_digest_chirho: String,
}

impl fmt::Display for ErasureRecordedBindingPendingChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter_chirho,
            "ErasureRecordedBindingPendingChirho: the erasure at seq {} is recorded as {}, but its \
             propagation binding is not durable; reconcile binds it",
            self.erasure_seq_chirho, self.erasure_record_digest_chirho
        )
    }
}

impl std::error::Error for ErasureRecordedBindingPendingChirho {}

/// The digest a propagation binding names: blake3 over a fixed domain and the record's canonical
/// serialization, signature included.
pub fn erasure_record_digest_hex_chirho(
    record_chirho: &PrivacyErasureRecordChirho,
) -> Result<String> {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(ERASURE_RECORD_DIGEST_DOMAIN_V1_CHIRHO);
    hasher_chirho.update(&serde_json::to_vec(record_chirho)?);
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

/// For each of the subject's unbound seqs below the in-flight one, what the authenticated log holds there.
/// The in-flight seq is the exact retry, and a seq beyond it is the store's to refuse as rollback, so
/// neither is classified.
pub(super) fn classify_unbound_chirho(
    records_chirho: &[PrivacyErasureRecordChirho],
    subject_chirho: &str,
    unbound_chirho: &[u64],
    in_flight_chirho: u64,
) -> Result<BTreeMap<u64, EarlierErasureEvidenceChirho>> {
    let mut earlier_chirho = BTreeMap::new();
    for &seq_chirho in unbound_chirho {
        if seq_chirho >= in_flight_chirho {
            continue;
        }
        // The in-flight seq is the log's length, so every seq below it has a record.
        let record_chirho = &records_chirho[seq_chirho as usize];
        let evidence_chirho = if record_chirho.subject_chirho == subject_chirho {
            EarlierErasureEvidenceChirho::RecordedChirho {
                erasure_record_digest_chirho: erasure_record_digest_hex_chirho(record_chirho)?,
            }
        } else {
            EarlierErasureEvidenceChirho::NeverRecordedChirho
        };
        earlier_chirho.insert(seq_chirho, evidence_chirho);
    }
    Ok(earlier_chirho)
}

/// Bind every unbound requirement of the subject whose erasure the root recorded, without erasing again.
///
/// It takes the subject-rights, account-attribution and erasure-records locks, as an erasure does, proves
/// the root's existing key pair, and authenticates the whole erasure log with it. For each unbound seq u
/// against the log's length L:
/// - u > L refuses as rollback, before anything is bound;
/// - u = L is the in-flight tip and stays pending;
/// - a seq whose record is another subject's stays pending, for the next erasure to carry;
/// - a seq whose record is this subject's is bound to that record's digest.
///
/// It writes no record and no requirement, unlinks nothing and widens no cut. It returns the seqs it bound.
pub fn reconcile_subject_erasure_bindings_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    sink_chirho: &dyn ErasureRequirementSinkChirho,
) -> Result<Vec<u64>> {
    validate_subject_chirho(subject_chirho)?;
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        legal_hold_chirho::SUBJECT_RIGHTS_LOCK_CHIRHO,
        || {
            with_account_attribution_lock_chirho(root_chirho, || {
                seqlog_chirho::with_named_lock_chirho(
                    root_chirho,
                    PRIVACY_ERASURE_RECORDS_LOCK_CHIRHO,
                    || {
                        let possessed_pubkey_chirho =
                            signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
                        let records_chirho = load_privacy_erasure_records_chirho(root_chirho)?;
                        verify_privacy_erasure_records_with_pubkey_chirho(
                            &records_chirho,
                            &possessed_pubkey_chirho,
                        )?;
                        let log_len_chirho = records_chirho.len() as u64;
                        let unbound_chirho =
                            sink_chirho.unbound_requirement_seqs_chirho(subject_chirho)?;
                        // A store ahead of the log means the root's log went back: bind nothing.
                        if unbound_chirho
                            .iter()
                            .any(|&seq_chirho| seq_chirho > log_len_chirho)
                        {
                            bail!(
                                "ErasureRequirementSeqRollbackRefusedChirho: an unbound requirement lies \
                                 beyond the erasure log"
                            );
                        }
                        let mut bound_chirho = Vec::new();
                        for seq_chirho in unbound_chirho {
                            if seq_chirho == log_len_chirho {
                                continue;
                            }
                            let record_chirho = &records_chirho[seq_chirho as usize];
                            if record_chirho.subject_chirho != subject_chirho {
                                continue;
                            }
                            sink_chirho.record_binding_chirho(
                                seq_chirho,
                                subject_chirho,
                                &erasure_record_digest_hex_chirho(record_chirho)?,
                            )?;
                            bound_chirho.push(seq_chirho);
                        }
                        Ok(bound_chirho)
                    },
                )
            })
        },
    )
}
