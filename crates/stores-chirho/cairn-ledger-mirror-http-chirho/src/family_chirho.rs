// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! F1-specific conversion and verification behind the generic mirror protocol.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorCandidateChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_mirror_chirho::{MirrorClosureManifestChirho, MirrorFamilyMemberChirho};
use serde::{Deserialize, Serialize};

pub(crate) const LEDGER_MIRROR_RECORD_MAX_BYTES_CHIRHO: usize = 256 * 1024;

/// Public-only journal verifier selected by the already custody-checked host configuration.
///
/// The enclosing mirror frames remain signed by the elected node-control key. This binding is
/// deliberately separate: a journal line carries its role-bound journal key label and must verify
/// under the configured journal root, never under the Raft node identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorJournalVerifierBindingChirho {
    expected_key_id_chirho: String,
    verifying_key_hex_chirho: String,
}

impl LedgerMirrorJournalVerifierBindingChirho {
    pub fn new_chirho(
        expected_key_id_chirho: String,
        verifying_key_hex_chirho: String,
    ) -> Result<Self> {
        let secret_label_chirho = expected_key_id_chirho
            .strip_prefix("journal-chirho:")
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorJournalKeyRoleRefusedChirho"))?;
        if secret_label_chirho.is_empty()
            || secret_label_chirho.len() > 128
            || verifying_key_hex_chirho.len() != 64
            || !verifying_key_hex_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
            })
            || verifying_key_hex_chirho
                .bytes()
                .all(|byte_chirho| byte_chirho == b'0')
        {
            bail!("LedgerMirrorJournalVerifierBindingRefusedChirho");
        }
        Ok(Self {
            expected_key_id_chirho,
            verifying_key_hex_chirho,
        })
    }

    pub(crate) fn verifying_key_hex_chirho(&self) -> &str {
        &self.verifying_key_hex_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorRecordChirho {
    pub(crate) cluster_id_chirho: String,
    pub(crate) journal_genesis_digest_chirho: String,
    pub(crate) predecessor_seq_chirho: u64,
    pub(crate) predecessor_digest_chirho: String,
    pub(crate) record_seq_chirho: u64,
    pub(crate) record_digest_chirho: String,
    pub(crate) record_epoch_chirho: u64,
    pub(crate) record_hlc_physical_ms_chirho: u64,
    pub(crate) record_hlc_logical_chirho: u32,
    pub(crate) canonical_record_line_chirho: String,
}

impl LedgerMirrorRecordChirho {
    pub(crate) fn from_verified_record_chirho(
        cluster_id_chirho: &str,
        journal_genesis_digest_chirho: &str,
        record_chirho: &LedgerRecordChirho,
    ) -> Result<Self> {
        let canonical_record_line_chirho = canonical_ledger_record_line_chirho(record_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixRecordEncodingRefusedChirho"))?;
        let predecessor_seq_chirho = record_chirho
            .seq_chirho
            .checked_sub(1)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixRecordSequenceRefusedChirho"))?;
        Ok(Self {
            cluster_id_chirho: cluster_id_chirho.to_string(),
            journal_genesis_digest_chirho: journal_genesis_digest_chirho.to_string(),
            predecessor_seq_chirho,
            predecessor_digest_chirho: record_chirho.prev_chirho.0.clone(),
            record_seq_chirho: record_chirho.seq_chirho,
            record_digest_chirho: stored_line_digest_chirho(&canonical_record_line_chirho).0,
            record_epoch_chirho: record_chirho.epoch_chirho,
            record_hlc_physical_ms_chirho: record_chirho.hlc_chirho.physical_ms_chirho,
            record_hlc_logical_chirho: record_chirho.hlc_chirho.logical_chirho,
            canonical_record_line_chirho,
        })
    }

    pub(crate) fn from_candidate_chirho(
        candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Self {
        Self {
            cluster_id_chirho: candidate_chirho.cluster_id_chirho().0.clone(),
            journal_genesis_digest_chirho: candidate_chirho
                .journal_genesis_digest_chirho()
                .0
                .clone(),
            predecessor_seq_chirho: candidate_chirho.predecessor_seq_chirho(),
            predecessor_digest_chirho: candidate_chirho.predecessor_digest_chirho().0.clone(),
            record_seq_chirho: candidate_chirho.record_seq_chirho(),
            record_digest_chirho: candidate_chirho.record_digest_chirho().0.clone(),
            record_epoch_chirho: candidate_chirho.record_epoch_chirho(),
            record_hlc_physical_ms_chirho: candidate_chirho.record_hlc_chirho().physical_ms_chirho,
            record_hlc_logical_chirho: candidate_chirho.record_hlc_chirho().logical_chirho,
            canonical_record_line_chirho: candidate_chirho
                .canonical_record_line_chirho()
                .to_string(),
        }
    }

    pub(crate) fn into_member_chirho(self) -> MirrorFamilyMemberChirho {
        MirrorFamilyMemberChirho::SignedLedgerRecordChirho {
            cluster_id_chirho: self.cluster_id_chirho,
            journal_genesis_digest_chirho: self.journal_genesis_digest_chirho,
            predecessor_seq_chirho: self.predecessor_seq_chirho,
            predecessor_digest_chirho: self.predecessor_digest_chirho,
            record_seq_chirho: self.record_seq_chirho,
            record_digest_chirho: HashChirho(self.record_digest_chirho),
            record_epoch_chirho: self.record_epoch_chirho,
            record_hlc_physical_ms_chirho: self.record_hlc_physical_ms_chirho,
            record_hlc_logical_chirho: self.record_hlc_logical_chirho,
            canonical_record_line_chirho: self.canonical_record_line_chirho,
        }
    }

    pub(crate) fn from_manifest_chirho(
        manifest_chirho: &MirrorClosureManifestChirho,
    ) -> Result<Self> {
        let [member_chirho] = manifest_chirho.members_chirho() else {
            bail!("LedgerMirrorF1MemberPopulationRefusedChirho");
        };
        let member_chirho = member_chirho
            .signed_ledger_record_chirho()
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorF1MemberKindRefusedChirho"))?;
        Ok(Self {
            cluster_id_chirho: member_chirho.cluster_id_chirho.to_string(),
            journal_genesis_digest_chirho: member_chirho.journal_genesis_digest_chirho.to_string(),
            predecessor_seq_chirho: member_chirho.predecessor_seq_chirho,
            predecessor_digest_chirho: member_chirho.predecessor_digest_chirho.to_string(),
            record_seq_chirho: member_chirho.record_seq_chirho,
            record_digest_chirho: member_chirho.record_digest_chirho.0.clone(),
            record_epoch_chirho: member_chirho.record_epoch_chirho,
            record_hlc_physical_ms_chirho: member_chirho.record_hlc_physical_ms_chirho,
            record_hlc_logical_chirho: member_chirho.record_hlc_logical_chirho,
            canonical_record_line_chirho: member_chirho.canonical_record_line_chirho.to_string(),
        })
    }

    /// Re-derive the canonical F1 bindings and verify the record under the distinct configured
    /// journal authority. Election authority is checked independently on the enclosing frame.
    pub(crate) fn verify_with_journal_chirho(
        &self,
        verifier_chirho: &LedgerMirrorJournalVerifierBindingChirho,
    ) -> Result<()> {
        if self.canonical_record_line_chirho.len() > LEDGER_MIRROR_RECORD_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorF1RecordTooLargeChirho");
        }
        let parsed_chirho =
            parse_canonical_ledger_journal_line_chirho(&self.canonical_record_line_chirho)
                .map_err(|_| anyhow::anyhow!("LedgerMirrorCanonicalRecordRefusedChirho"))?;
        let LedgerJournalLineChirho::RecordChirho(record_chirho) = parsed_chirho else {
            bail!("LedgerMirrorRecordKindRefusedChirho");
        };
        if record_chirho.seq_chirho != self.record_seq_chirho
            || record_chirho.prev_chirho.0 != self.predecessor_digest_chirho
            || record_chirho.epoch_chirho != self.record_epoch_chirho
            || record_chirho.hlc_chirho.physical_ms_chirho != self.record_hlc_physical_ms_chirho
            || record_chirho.hlc_chirho.logical_chirho != self.record_hlc_logical_chirho
            || stored_line_digest_chirho(&self.canonical_record_line_chirho).0
                != self.record_digest_chirho
            || self.predecessor_seq_chirho.checked_add(1) != Some(self.record_seq_chirho)
        {
            bail!("LedgerMirrorCandidateBindingRefusedChirho");
        }
        if record_chirho.key_id_chirho != verifier_chirho.expected_key_id_chirho {
            bail!("LedgerMirrorJournalSignerBindingRefusedChirho");
        }
        let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecordSigningContentRefusedChirho"))?;
        if !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
            &verifier_chirho.verifying_key_hex_chirho,
            signed_content_chirho.as_bytes(),
            &record_chirho.sig_chirho,
        )? {
            bail!("LedgerMirrorRecordSignatureRefusedChirho");
        }
        Ok(())
    }
}
