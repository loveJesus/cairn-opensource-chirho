// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The concrete sink an elected erasure is composed with: the root's erasure-requirement port, carried out by the leader's erasure-propagation store.
//!
//! C5 B3-a2-ii, composed above the root as gpt #29883 placed it. The root crate keeps no key-custody
//! dependency, and the store keeps no root dependency, so this wrapper only converts:
//! - the root's subject becomes the custody contract's subject digest;
//! - the root's evidence about earlier attempts becomes the store's;
//! - the store's refusals pass through unchanged. Each is a fixed name, and nothing here adds a subject,
//!   a path or any other context to them.
//!
//! It holds no lock of its own and never calls back into the root. Each store method takes and releases
//! the store's own lock, which the root's erasure-records lock always encloses. The account-close door
//! (R3) opens the store for its context and names the current holders. Until it does, nothing in
//! production constructs this. Design: `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`,
//! section 5a, items 12 and 13.

use anyhow::Result;
use cairn_chirho::privacy_chirho::{
    EarlierErasureEvidenceChirho, ErasureCaptureChirho, ErasureRequirementSinkChirho,
};
use cairn_key_custody_chirho::subject_digest_hex_chirho;
use cairn_key_custody_http_chirho::{
    EarlierErasureChirho, ErasurePropagationStoreChirho, RecordRequirementRequestChirho,
};
use std::collections::{BTreeMap, BTreeSet};

/// The leader's propagation store, seen through the root's sink port, for one set of current holders.
pub struct ErasurePropagationSinkChirho<'store_chirho> {
    store_chirho: &'store_chirho ErasurePropagationStoreChirho,
    holders_chirho: BTreeSet<String>,
}

impl<'store_chirho> ErasurePropagationSinkChirho<'store_chirho> {
    /// `holders_chirho` are the node ids of the current serving members. When a requirement carries an
    /// earlier one, the store adds that one's holders itself, so a holder is never let go.
    pub fn new_chirho(
        store_chirho: &'store_chirho ErasurePropagationStoreChirho,
        holders_chirho: BTreeSet<String>,
    ) -> Self {
        Self {
            store_chirho,
            holders_chirho,
        }
    }
}

impl ErasureRequirementSinkChirho for ErasurePropagationSinkChirho<'_> {
    fn unbound_requirement_seqs_chirho(&self, subject_chirho: &str) -> Result<Vec<u64>> {
        Ok(self
            .store_chirho
            .subject_view_chirho(&subject_digest_hex_chirho(subject_chirho))?
            .unbound_seqs_chirho())
    }

    fn record_requirement_chirho(
        &self,
        capture_chirho: &ErasureCaptureChirho,
        earlier_chirho: &BTreeMap<u64, EarlierErasureEvidenceChirho>,
    ) -> Result<()> {
        let request_chirho = RecordRequirementRequestChirho {
            subject_digest_chirho: subject_digest_hex_chirho(&capture_chirho.subject_chirho),
            erasure_seq_chirho: capture_chirho.erasure_seq_chirho,
            erased_below_blob_seq_chirho: capture_chirho.erased_below_blob_seq_chirho,
            key_ids_chirho: capture_chirho.key_ids_chirho.clone(),
            holders_chirho: self.holders_chirho.clone(),
            earlier_chirho: earlier_chirho
                .iter()
                .map(|(seq_chirho, evidence_chirho)| {
                    (*seq_chirho, store_evidence_chirho(evidence_chirho))
                })
                .collect(),
        };
        self.store_chirho
            .record_requirement_chirho(&request_chirho)?;
        Ok(())
    }

    fn record_binding_chirho(
        &self,
        erasure_seq_chirho: u64,
        subject_chirho: &str,
        erasure_record_digest_chirho: &str,
    ) -> Result<()> {
        self.store_chirho.record_binding_chirho(
            &subject_digest_hex_chirho(subject_chirho),
            erasure_seq_chirho,
            erasure_record_digest_chirho,
        )?;
        Ok(())
    }
}

fn store_evidence_chirho(evidence_chirho: &EarlierErasureEvidenceChirho) -> EarlierErasureChirho {
    match evidence_chirho {
        EarlierErasureEvidenceChirho::RecordedChirho {
            erasure_record_digest_chirho,
        } => EarlierErasureChirho::RecordedChirho {
            erasure_record_digest_chirho: erasure_record_digest_chirho.clone(),
        },
        EarlierErasureEvidenceChirho::NeverRecordedChirho => {
            EarlierErasureChirho::NeverRecordedChirho
        }
    }
}

#[cfg(test)]
#[path = "sink_tests_chirho.rs"]
mod sink_tests_chirho;
