// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Compact holder evidence for selecting one F1 recovery cut.
//!
//! A receipt is minted only after the follower store re-verifies its signed high-water and immutable
//! record object. Two receipts are required because those same two non-leader holders authorized the
//! original mirror-gated ACK. The pair selects a cut; it never substitutes for replay-verifying the
//! dense journal chain to that cut. Like the fixed high-water itself, an older valid pair remains a
//! rollback exposure owed to the shared monotonic-head substrate.

use crate::store_chirho::{
    LedgerMirrorBootstrapHeadChirho, LedgerMirrorHighWaterChirho,
    LedgerMirrorRecoverySourceHeadChirho,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::Path;

const RECOVERY_HEAD_SCHEMA_V2_CHIRHO: &str = "ledger-mirror-recovery-head-v2-chirho";
const RECOVERY_HEAD_DOMAIN_V2_CHIRHO: &[u8] = b"ledger-mirror-recovery-head-v2-chirho";
pub(super) const RECOVERY_SOURCE_LIVE_CHIRHO: &str = "live-high-water-chirho";
pub(super) const RECOVERY_SOURCE_BOOTSTRAP_CHIRHO: &str = "verified-prefix-bootstrap-chirho";
pub(crate) const RECOVERY_HEAD_MAX_BYTES_CHIRHO: usize = 16 * 1024;
pub const LEDGER_MIRROR_LIVE_HEAD_REPORT_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-live-head-report-v1-chirho";
pub const LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-live-head-bound-verdict-v1-chirho";
pub const MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO: usize =
    RECOVERY_HEAD_MAX_BYTES_CHIRHO + 4 * 1024;
pub const MAX_LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerMirrorLiveHeadReportStatusChirho {
    LiveHighWaterAvailableChirho,
    LiveHighWaterAbsentChirho,
}

/// One bounded host-local envelope. The tagged writer-fence group and the mirror's raw consistency
/// group digest are intentionally separate domains; the later fleet join binds each to its own
/// projection coordinate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMirrorLiveHeadReportChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    pub writer_fence_group_digest_chirho: String,
    pub status_chirho: LedgerMirrorLiveHeadReportStatusChirho,
    pub receipt_chirho: Option<LedgerMirrorRecoveryHeadReceiptChirho>,
}

/// One path-free Rust verdict bound to the exact captured report bytes. Recovery-oriented
/// `historical_*` names become healthy-window `writer_*` names only at this checked boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMirrorLiveHeadBoundVerdictChirho {
    pub schema_chirho: String,
    pub report_sha256_chirho: String,
    pub node_id_chirho: String,
    pub writer_fence_group_digest_chirho: String,
    pub status_chirho: LedgerMirrorLiveHeadReportStatusChirho,
    pub mirror_consistency_group_digest_chirho: Option<String>,
    pub assignment_digest_chirho: Option<String>,
    pub ordered_assigned_node_ids_chirho: Option<[String; 3]>,
    pub writer_node_id_chirho: Option<String>,
    pub holder_node_id_chirho: Option<String>,
    pub writer_membership_view_digest_chirho: Option<String>,
    pub writer_term_chirho: Option<u64>,
    pub cluster_id_sha256_chirho: Option<String>,
    pub journal_genesis_digest_chirho: Option<String>,
    pub tail_seq_chirho: Option<u64>,
    pub tail_record_digest_chirho: Option<String>,
    pub tail_epoch_chirho: Option<u64>,
    pub tail_hlc_physical_ms_chirho: Option<u64>,
    pub tail_hlc_logical_chirho: Option<u32>,
    pub source_head_digest_chirho: Option<String>,
    pub receipt_digest_chirho: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerMirrorLiveHeadReportRefusalChirho {
    BytesRefusedChirho,
    DecodeRefusedChirho,
    NonCanonicalRefusedChirho,
    ShapeRefusedChirho,
    ReceiptRefusedChirho,
    LiveSourceRequiredChirho,
    BindingRefusedChirho,
}

impl LedgerMirrorLiveHeadReportRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::BytesRefusedChirho => "LedgerMirrorLiveHeadReportBytesRefusedChirho",
            Self::DecodeRefusedChirho => "LedgerMirrorLiveHeadReportDecodeRefusedChirho",
            Self::NonCanonicalRefusedChirho => {
                "LedgerMirrorLiveHeadReportNonCanonicalRefusedChirho"
            }
            Self::ShapeRefusedChirho => "LedgerMirrorLiveHeadReportShapeRefusedChirho",
            Self::ReceiptRefusedChirho => "LedgerMirrorLiveHeadReportReceiptRefusedChirho",
            Self::LiveSourceRequiredChirho => "LedgerMirrorLiveHeadReportLiveSourceRequiredChirho",
            Self::BindingRefusedChirho => "LedgerMirrorLiveHeadReportBindingRefusedChirho",
        }
    }
}

impl fmt::Display for LedgerMirrorLiveHeadReportRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for LedgerMirrorLiveHeadReportRefusalChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerMirrorLiveHeadBoundVerdictRefusalChirho {
    ReportRefusedChirho(LedgerMirrorLiveHeadReportRefusalChirho),
    BytesRefusedChirho,
    DecodeRefusedChirho,
    NonCanonicalRefusedChirho,
    BindingRefusedChirho,
}

impl LedgerMirrorLiveHeadBoundVerdictRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ReportRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::BytesRefusedChirho => "LedgerMirrorLiveHeadBoundVerdictBytesRefusedChirho",
            Self::DecodeRefusedChirho => "LedgerMirrorLiveHeadBoundVerdictDecodeRefusedChirho",
            Self::NonCanonicalRefusedChirho => {
                "LedgerMirrorLiveHeadBoundVerdictNonCanonicalRefusedChirho"
            }
            Self::BindingRefusedChirho => "LedgerMirrorLiveHeadBoundVerdictBindingRefusedChirho",
        }
    }
}

impl fmt::Display for LedgerMirrorLiveHeadBoundVerdictRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for LedgerMirrorLiveHeadBoundVerdictRefusalChirho {}

/// One holder's compact re-attestation of its verified live or bootstrap continuity head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMirrorRecoveryHeadReceiptChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    assignment_digest_chirho: String,
    assigned_node_ids_chirho: [String; 3],
    historical_leader_node_id_chirho: String,
    holder_node_id_chirho: String,
    historical_membership_view_digest_chirho: String,
    historical_term_chirho: u64,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: String,
    tail_epoch_chirho: u64,
    tail_hlc_physical_ms_chirho: u64,
    tail_hlc_logical_chirho: u32,
    source_head_kind_chirho: String,
    source_head_digest_chirho: String,
    source_manifest_digest_chirho: Option<String>,
    receipt_digest_chirho: String,
    sig_hex_chirho: String,
}

impl LedgerMirrorRecoveryHeadReceiptChirho {
    pub(crate) fn sign_from_source_head_chirho(
        source_chirho: &LedgerMirrorRecoverySourceHeadChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        match source_chirho {
            LedgerMirrorRecoverySourceHeadChirho::LiveChirho(head_chirho) => {
                Self::sign_from_high_water_chirho(head_chirho, sign_root_chirho)
            }
            LedgerMirrorRecoverySourceHeadChirho::BootstrapChirho(head_chirho) => {
                Self::sign_from_bootstrap_head_chirho(head_chirho, sign_root_chirho)
            }
        }
    }

    pub(crate) fn sign_from_high_water_chirho(
        high_water_chirho: &LedgerMirrorHighWaterChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let record_chirho = high_water_chirho.record_chirho();
        let mut receipt_chirho = Self {
            schema_chirho: RECOVERY_HEAD_SCHEMA_V2_CHIRHO.to_string(),
            consistency_group_digest_chirho: high_water_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            assignment_digest_chirho: high_water_chirho.assignment_digest_chirho().to_string(),
            assigned_node_ids_chirho: high_water_chirho.assigned_node_ids_chirho().clone(),
            historical_leader_node_id_chirho: high_water_chirho
                .origin_leader_node_id_chirho()
                .to_string(),
            holder_node_id_chirho: high_water_chirho.holder_node_id_chirho().to_string(),
            historical_membership_view_digest_chirho: high_water_chirho
                .membership_view_digest_chirho()
                .to_string(),
            historical_term_chirho: high_water_chirho.historical_term_chirho(),
            cluster_id_chirho: record_chirho.cluster_id_chirho.clone(),
            journal_genesis_digest_chirho: record_chirho.journal_genesis_digest_chirho.clone(),
            tail_seq_chirho: record_chirho.record_seq_chirho,
            tail_record_digest_chirho: record_chirho.record_digest_chirho.clone(),
            tail_epoch_chirho: record_chirho.record_epoch_chirho,
            tail_hlc_physical_ms_chirho: record_chirho.record_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: record_chirho.record_hlc_logical_chirho,
            source_head_kind_chirho: RECOVERY_SOURCE_LIVE_CHIRHO.to_string(),
            source_head_digest_chirho: high_water_chirho.state_digest_chirho().to_string(),
            source_manifest_digest_chirho: None,
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        receipt_chirho.sign_chirho(sign_root_chirho)
    }

    pub(crate) fn sign_from_bootstrap_head_chirho(
        head_chirho: &LedgerMirrorBootstrapHeadChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let record_chirho = head_chirho.tail_record_chirho();
        let mut receipt_chirho = Self {
            schema_chirho: RECOVERY_HEAD_SCHEMA_V2_CHIRHO.to_string(),
            consistency_group_digest_chirho: head_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            assignment_digest_chirho: head_chirho.assignment_digest_chirho().to_string(),
            assigned_node_ids_chirho: head_chirho.assigned_node_ids_chirho().clone(),
            historical_leader_node_id_chirho: head_chirho
                .origin_leader_node_id_chirho()
                .to_string(),
            holder_node_id_chirho: head_chirho.holder_node_id_chirho().to_string(),
            historical_membership_view_digest_chirho: head_chirho
                .membership_view_digest_chirho()
                .to_string(),
            historical_term_chirho: head_chirho.historical_term_chirho(),
            cluster_id_chirho: head_chirho.cluster_id_chirho().to_string(),
            journal_genesis_digest_chirho: head_chirho.journal_genesis_digest_chirho().to_string(),
            tail_seq_chirho: record_chirho.record_seq_chirho,
            tail_record_digest_chirho: record_chirho.record_digest_chirho.clone(),
            tail_epoch_chirho: record_chirho.record_epoch_chirho,
            tail_hlc_physical_ms_chirho: record_chirho.record_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: record_chirho.record_hlc_logical_chirho,
            source_head_kind_chirho: RECOVERY_SOURCE_BOOTSTRAP_CHIRHO.to_string(),
            source_head_digest_chirho: head_chirho.state_digest_chirho().to_string(),
            source_manifest_digest_chirho: Some(head_chirho.manifest_digest_chirho().to_string()),
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        receipt_chirho.sign_chirho(sign_root_chirho)
    }

    fn sign_chirho(&mut self, sign_root_chirho: &Path) -> Result<Self> {
        self.validate_shape_chirho()?;
        let digest_chirho = self.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )?;
        if possession_chirho.key_id_chirho() != self.holder_node_id_chirho {
            bail!("LedgerMirrorRecoveryHeadSignerIdentityRefusedChirho");
        }
        self.receipt_digest_chirho = digest_chirho.to_hex().to_string();
        self.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(self.clone())
    }

    pub fn decode_and_verify_chirho(
        bytes_chirho: &[u8],
        expected_holder_node_id_chirho: &str,
    ) -> Result<Self> {
        if bytes_chirho.len() > RECOVERY_HEAD_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorRecoveryHeadTooLargeChirho");
        }
        let receipt_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecoveryHeadMalformedChirho"))?;
        if serde_json::to_vec(&receipt_chirho)? != bytes_chirho {
            bail!("LedgerMirrorRecoveryHeadNonCanonicalChirho");
        }
        receipt_chirho.verify_chirho(expected_holder_node_id_chirho)?;
        Ok(receipt_chirho)
    }

    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>> {
        self.verify_chirho(&self.holder_node_id_chirho)?;
        let bytes_chirho = serde_json::to_vec(self)?;
        if bytes_chirho.len() > RECOVERY_HEAD_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorRecoveryHeadTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    fn verify_chirho(&self, expected_holder_node_id_chirho: &str) -> Result<()> {
        self.validate_shape_chirho()?;
        if self.holder_node_id_chirho != expected_holder_node_id_chirho {
            bail!("LedgerMirrorRecoveryHeadHolderIdentityRefusedChirho");
        }
        let digest_chirho = self.compute_digest_chirho()?;
        if self.receipt_digest_chirho != digest_chirho.to_hex().as_str()
            || !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
                expected_holder_node_id_chirho,
                digest_chirho.as_bytes(),
                &self.sig_hex_chirho,
            )?
        {
            bail!("LedgerMirrorRecoveryHeadSignatureRefusedChirho");
        }
        Ok(())
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        let assigned_chirho = self
            .assigned_node_ids_chirho
            .iter()
            .collect::<BTreeSet<_>>();
        if self.schema_chirho != RECOVERY_HEAD_SCHEMA_V2_CHIRHO
            || !is_lower_hex_digest_chirho(&self.consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.historical_membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.journal_genesis_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.tail_record_digest_chirho)
            || !matches!(
                self.source_head_kind_chirho.as_str(),
                RECOVERY_SOURCE_LIVE_CHIRHO | RECOVERY_SOURCE_BOOTSTRAP_CHIRHO
            )
            || !is_lower_hex_digest_chirho(&self.source_head_digest_chirho)
            || match self.source_head_kind_chirho.as_str() {
                RECOVERY_SOURCE_LIVE_CHIRHO => self.source_manifest_digest_chirho.is_some(),
                RECOVERY_SOURCE_BOOTSTRAP_CHIRHO => self
                    .source_manifest_digest_chirho
                    .as_deref()
                    .is_none_or(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho)),
                _ => true,
            }
            || self.tail_seq_chirho == 0
            || self.historical_term_chirho == 0
            || self.cluster_id_chirho.is_empty()
            || self.cluster_id_chirho.len() > 256
            || self.tail_epoch_chirho == 0
            || self.tail_hlc_physical_ms_chirho == 0
            || assigned_chirho.len() != self.assigned_node_ids_chirho.len()
            || self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || !assigned_chirho.contains(&self.historical_leader_node_id_chirho)
            || !assigned_chirho.contains(&self.holder_node_id_chirho)
            || self.historical_leader_node_id_chirho == self.holder_node_id_chirho
            || (!self.receipt_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.receipt_digest_chirho))
            || (self.receipt_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            bail!("LedgerMirrorRecoveryHeadShapeRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.receipt_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(RECOVERY_HEAD_DOMAIN_V2_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn assigned_node_ids_chirho(&self) -> &[String; 3] {
        &self.assigned_node_ids_chirho
    }

    pub fn historical_leader_node_id_chirho(&self) -> &str {
        &self.historical_leader_node_id_chirho
    }

    pub fn holder_node_id_chirho(&self) -> &str {
        &self.holder_node_id_chirho
    }

    pub fn historical_membership_view_digest_chirho(&self) -> &str {
        &self.historical_membership_view_digest_chirho
    }

    pub fn historical_term_chirho(&self) -> u64 {
        self.historical_term_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &str {
        &self.journal_genesis_digest_chirho
    }

    pub fn cluster_id_chirho(&self) -> &str {
        &self.cluster_id_chirho
    }

    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }

    pub fn tail_record_digest_chirho(&self) -> &str {
        &self.tail_record_digest_chirho
    }

    pub fn tail_epoch_chirho(&self) -> u64 {
        self.tail_epoch_chirho
    }

    pub fn tail_hlc_physical_ms_chirho(&self) -> u64 {
        self.tail_hlc_physical_ms_chirho
    }

    pub fn tail_hlc_logical_chirho(&self) -> u32 {
        self.tail_hlc_logical_chirho
    }

    pub fn receipt_digest_chirho(&self) -> &str {
        &self.receipt_digest_chirho
    }

    pub fn source_head_digest_chirho(&self) -> &str {
        &self.source_head_digest_chirho
    }

    pub(crate) fn source_head_kind_chirho(&self) -> &str {
        &self.source_head_kind_chirho
    }

    pub(crate) fn source_manifest_digest_chirho(&self) -> Option<&str> {
        self.source_manifest_digest_chirho.as_deref()
    }
}

pub fn ledger_mirror_live_head_report_chirho(
    node_id_chirho: String,
    writer_fence_group_digest_chirho: String,
    receipt_chirho: Option<LedgerMirrorRecoveryHeadReceiptChirho>,
) -> std::result::Result<LedgerMirrorLiveHeadReportChirho, LedgerMirrorLiveHeadReportRefusalChirho>
{
    let report_chirho = LedgerMirrorLiveHeadReportChirho {
        schema_chirho: LEDGER_MIRROR_LIVE_HEAD_REPORT_SCHEMA_V1_CHIRHO.to_owned(),
        node_id_chirho,
        writer_fence_group_digest_chirho,
        status_chirho: if receipt_chirho.is_some() {
            LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAvailableChirho
        } else {
            LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAbsentChirho
        },
        receipt_chirho,
    };
    validate_live_head_report_chirho(&report_chirho)?;
    Ok(report_chirho)
}

pub fn ledger_mirror_live_head_report_bytes_chirho(
    report_chirho: &LedgerMirrorLiveHeadReportChirho,
) -> std::result::Result<Vec<u8>, LedgerMirrorLiveHeadReportRefusalChirho> {
    validate_live_head_report_chirho(report_chirho)?;
    let bytes_chirho = serde_json::to_vec(report_chirho)
        .map_err(|_| LedgerMirrorLiveHeadReportRefusalChirho::DecodeRefusedChirho)?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO
    {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::BytesRefusedChirho);
    }
    Ok(bytes_chirho)
}

pub fn ledger_mirror_live_head_bound_verdict_chirho(
    report_bytes_chirho: &[u8],
) -> std::result::Result<
    LedgerMirrorLiveHeadBoundVerdictChirho,
    LedgerMirrorLiveHeadBoundVerdictRefusalChirho,
> {
    let report_chirho = decode_verified_live_head_report_bytes_chirho(report_bytes_chirho)
        .map_err(LedgerMirrorLiveHeadBoundVerdictRefusalChirho::ReportRefusedChirho)?;
    let report_sha256_chirho = sha256_hex_chirho(report_bytes_chirho);
    let Some(receipt_chirho) = report_chirho.receipt_chirho else {
        return Ok(LedgerMirrorLiveHeadBoundVerdictChirho {
            schema_chirho: LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO.to_owned(),
            report_sha256_chirho,
            node_id_chirho: report_chirho.node_id_chirho,
            writer_fence_group_digest_chirho: report_chirho.writer_fence_group_digest_chirho,
            status_chirho: LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAbsentChirho,
            mirror_consistency_group_digest_chirho: None,
            assignment_digest_chirho: None,
            ordered_assigned_node_ids_chirho: None,
            writer_node_id_chirho: None,
            holder_node_id_chirho: None,
            writer_membership_view_digest_chirho: None,
            writer_term_chirho: None,
            cluster_id_sha256_chirho: None,
            journal_genesis_digest_chirho: None,
            tail_seq_chirho: None,
            tail_record_digest_chirho: None,
            tail_epoch_chirho: None,
            tail_hlc_physical_ms_chirho: None,
            tail_hlc_logical_chirho: None,
            source_head_digest_chirho: None,
            receipt_digest_chirho: None,
        });
    };
    Ok(LedgerMirrorLiveHeadBoundVerdictChirho {
        schema_chirho: LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO.to_owned(),
        report_sha256_chirho,
        node_id_chirho: report_chirho.node_id_chirho,
        writer_fence_group_digest_chirho: report_chirho.writer_fence_group_digest_chirho,
        status_chirho: LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAvailableChirho,
        mirror_consistency_group_digest_chirho: Some(
            receipt_chirho.consistency_group_digest_chirho().to_owned(),
        ),
        assignment_digest_chirho: Some(receipt_chirho.assignment_digest_chirho().to_owned()),
        ordered_assigned_node_ids_chirho: Some(receipt_chirho.assigned_node_ids_chirho().clone()),
        writer_node_id_chirho: Some(receipt_chirho.historical_leader_node_id_chirho().to_owned()),
        holder_node_id_chirho: Some(receipt_chirho.holder_node_id_chirho().to_owned()),
        writer_membership_view_digest_chirho: Some(
            receipt_chirho
                .historical_membership_view_digest_chirho()
                .to_owned(),
        ),
        writer_term_chirho: Some(receipt_chirho.historical_term_chirho()),
        cluster_id_sha256_chirho: Some(sha256_hex_chirho(
            receipt_chirho.cluster_id_chirho().as_bytes(),
        )),
        journal_genesis_digest_chirho: Some(
            receipt_chirho.journal_genesis_digest_chirho().to_owned(),
        ),
        tail_seq_chirho: Some(receipt_chirho.tail_seq_chirho()),
        tail_record_digest_chirho: Some(receipt_chirho.tail_record_digest_chirho().to_owned()),
        tail_epoch_chirho: Some(receipt_chirho.tail_epoch_chirho()),
        tail_hlc_physical_ms_chirho: Some(receipt_chirho.tail_hlc_physical_ms_chirho()),
        tail_hlc_logical_chirho: Some(receipt_chirho.tail_hlc_logical_chirho()),
        source_head_digest_chirho: Some(receipt_chirho.source_head_digest_chirho().to_owned()),
        receipt_digest_chirho: Some(receipt_chirho.receipt_digest_chirho().to_owned()),
    })
}

pub fn ledger_mirror_live_head_bound_verdict_bytes_chirho(
    report_bytes_chirho: &[u8],
) -> std::result::Result<Vec<u8>, LedgerMirrorLiveHeadBoundVerdictRefusalChirho> {
    let verdict_chirho = ledger_mirror_live_head_bound_verdict_chirho(report_bytes_chirho)?;
    let bytes_chirho = serde_json::to_vec(&verdict_chirho)
        .map_err(|_| LedgerMirrorLiveHeadBoundVerdictRefusalChirho::DecodeRefusedChirho)?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_BYTES_CHIRHO
    {
        return Err(LedgerMirrorLiveHeadBoundVerdictRefusalChirho::BytesRefusedChirho);
    }
    Ok(bytes_chirho)
}

pub fn verify_ledger_mirror_live_head_bound_verdict_bytes_chirho(
    report_bytes_chirho: &[u8],
    verdict_bytes_chirho: &[u8],
) -> std::result::Result<
    LedgerMirrorLiveHeadBoundVerdictChirho,
    LedgerMirrorLiveHeadBoundVerdictRefusalChirho,
> {
    if verdict_bytes_chirho.is_empty()
        || verdict_bytes_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_BYTES_CHIRHO
    {
        return Err(LedgerMirrorLiveHeadBoundVerdictRefusalChirho::BytesRefusedChirho);
    }
    let supplied_chirho: LedgerMirrorLiveHeadBoundVerdictChirho =
        serde_json::from_slice(verdict_bytes_chirho)
            .map_err(|_| LedgerMirrorLiveHeadBoundVerdictRefusalChirho::DecodeRefusedChirho)?;
    if serde_json::to_vec(&supplied_chirho).ok().as_deref() != Some(verdict_bytes_chirho) {
        return Err(LedgerMirrorLiveHeadBoundVerdictRefusalChirho::NonCanonicalRefusedChirho);
    }
    let expected_chirho = ledger_mirror_live_head_bound_verdict_chirho(report_bytes_chirho)?;
    if supplied_chirho != expected_chirho {
        return Err(LedgerMirrorLiveHeadBoundVerdictRefusalChirho::BindingRefusedChirho);
    }
    Ok(expected_chirho)
}

fn decode_verified_live_head_report_bytes_chirho(
    bytes_chirho: &[u8],
) -> std::result::Result<LedgerMirrorLiveHeadReportChirho, LedgerMirrorLiveHeadReportRefusalChirho>
{
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO
    {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::BytesRefusedChirho);
    }
    let report_chirho: LedgerMirrorLiveHeadReportChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| LedgerMirrorLiveHeadReportRefusalChirho::DecodeRefusedChirho)?;
    if serde_json::to_vec(&report_chirho).ok().as_deref() != Some(bytes_chirho) {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::NonCanonicalRefusedChirho);
    }
    validate_live_head_report_chirho(&report_chirho)?;
    Ok(report_chirho)
}

fn validate_live_head_report_chirho(
    report_chirho: &LedgerMirrorLiveHeadReportChirho,
) -> std::result::Result<(), LedgerMirrorLiveHeadReportRefusalChirho> {
    if report_chirho.schema_chirho != LEDGER_MIRROR_LIVE_HEAD_REPORT_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&report_chirho.node_id_chirho)
        || !writer_fence_group_digest_has_shape_chirho(
            &report_chirho.writer_fence_group_digest_chirho,
        )
        || !matches!(
            (report_chirho.status_chirho, &report_chirho.receipt_chirho),
            (
                LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAvailableChirho,
                Some(_)
            ) | (
                LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAbsentChirho,
                None
            )
        )
    {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::ShapeRefusedChirho);
    }
    let Some(receipt_chirho) = &report_chirho.receipt_chirho else {
        return Ok(());
    };
    receipt_chirho
        .verify_chirho(receipt_chirho.holder_node_id_chirho())
        .map_err(|_| LedgerMirrorLiveHeadReportRefusalChirho::ReceiptRefusedChirho)?;
    if receipt_chirho.source_head_kind_chirho != RECOVERY_SOURCE_LIVE_CHIRHO
        || receipt_chirho.source_manifest_digest_chirho.is_some()
    {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::LiveSourceRequiredChirho);
    }
    if receipt_chirho.holder_node_id_chirho != report_chirho.node_id_chirho {
        return Err(LedgerMirrorLiveHeadReportRefusalChirho::BindingRefusedChirho);
    }
    Ok(())
}

fn writer_fence_group_digest_has_shape_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix("writer-fence-group-blake3-chirho:")
        .is_some_and(is_lower_hex_digest_chirho)
}

fn sha256_hex_chirho(bytes_chirho: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes_chirho))
}

/// Opaque exact pair. Construction requires the complete historical non-leader holder population.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLedgerMirrorRecoveryHeadPairChirho {
    receipts_chirho: [LedgerMirrorRecoveryHeadReceiptChirho; 2],
}

impl VerifiedLedgerMirrorRecoveryHeadPairChirho {
    pub fn join_chirho(
        first_chirho: LedgerMirrorRecoveryHeadReceiptChirho,
        second_chirho: LedgerMirrorRecoveryHeadReceiptChirho,
    ) -> Result<Self> {
        first_chirho.verify_chirho(first_chirho.holder_node_id_chirho())?;
        second_chirho.verify_chirho(second_chirho.holder_node_id_chirho())?;
        let common_binding_chirho = first_chirho.consistency_group_digest_chirho
            == second_chirho.consistency_group_digest_chirho
            && first_chirho.assignment_digest_chirho == second_chirho.assignment_digest_chirho
            && first_chirho.assigned_node_ids_chirho == second_chirho.assigned_node_ids_chirho
            && first_chirho.historical_leader_node_id_chirho
                == second_chirho.historical_leader_node_id_chirho
            && first_chirho.historical_membership_view_digest_chirho
                == second_chirho.historical_membership_view_digest_chirho
            && first_chirho.historical_term_chirho == second_chirho.historical_term_chirho
            && first_chirho.cluster_id_chirho == second_chirho.cluster_id_chirho
            && first_chirho.journal_genesis_digest_chirho
                == second_chirho.journal_genesis_digest_chirho
            && first_chirho.source_head_kind_chirho == second_chirho.source_head_kind_chirho
            && first_chirho.source_manifest_digest_chirho
                == second_chirho.source_manifest_digest_chirho;
        if !common_binding_chirho {
            bail!("LedgerMirrorRecoveryHeadBindingMismatchRefusedChirho");
        }
        if first_chirho.tail_seq_chirho != second_chirho.tail_seq_chirho
            || first_chirho.tail_record_digest_chirho != second_chirho.tail_record_digest_chirho
            || first_chirho.tail_epoch_chirho != second_chirho.tail_epoch_chirho
            || first_chirho.tail_hlc_physical_ms_chirho != second_chirho.tail_hlc_physical_ms_chirho
            || first_chirho.tail_hlc_logical_chirho != second_chirho.tail_hlc_logical_chirho
        {
            bail!("LedgerMirrorRecoveryHeadTailMismatchRefusedChirho");
        }
        let expected_holders_chirho = first_chirho
            .assigned_node_ids_chirho
            .iter()
            .filter(|node_id_chirho| {
                *node_id_chirho != &first_chirho.historical_leader_node_id_chirho
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let observed_holders_chirho = [
            first_chirho.holder_node_id_chirho.clone(),
            second_chirho.holder_node_id_chirho.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if expected_holders_chirho.len() != 2 || observed_holders_chirho != expected_holders_chirho
        {
            bail!("LedgerMirrorRecoveryHeadPopulationRefusedChirho");
        }
        Ok(Self {
            receipts_chirho: [first_chirho, second_chirho],
        })
    }

    pub fn receipts_chirho(&self) -> &[LedgerMirrorRecoveryHeadReceiptChirho; 2] {
        &self.receipts_chirho
    }

    pub fn tail_seq_chirho(&self) -> u64 {
        self.receipts_chirho[0].tail_seq_chirho
    }

    pub fn tail_record_digest_chirho(&self) -> &str {
        &self.receipts_chirho[0].tail_record_digest_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &str {
        &self.receipts_chirho[0].journal_genesis_digest_chirho
    }
}

#[cfg(test)]
impl LedgerMirrorRecoveryHeadReceiptChirho {
    pub(crate) fn resign_tail_for_test_chirho(
        &self,
        tail_seq_chirho: u64,
        tail_record_digest_chirho: String,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut receipt_chirho = self.clone();
        receipt_chirho.tail_seq_chirho = tail_seq_chirho;
        receipt_chirho.tail_record_digest_chirho = tail_record_digest_chirho;
        receipt_chirho.receipt_digest_chirho.clear();
        receipt_chirho.sig_hex_chirho.clear();
        receipt_chirho.sign_chirho(sign_root_chirho)
    }

    pub(crate) fn replace_signature_for_test_chirho(
        &self,
        foreign_sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut receipt_chirho = self.clone();
        receipt_chirho.sig_hex_chirho =
            cairn_signer_chirho::signer_chirho::sign_message_with_existing_key_chirho(
                foreign_sign_root_chirho,
                receipt_chirho.compute_digest_chirho()?.as_bytes(),
            )?;
        Ok(receipt_chirho)
    }

    pub(crate) fn resign_source_for_test_chirho(
        &self,
        source_head_kind_chirho: &str,
        source_manifest_digest_chirho: Option<String>,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut receipt_chirho = self.clone();
        receipt_chirho.source_head_kind_chirho = source_head_kind_chirho.to_owned();
        receipt_chirho.source_manifest_digest_chirho = source_manifest_digest_chirho;
        receipt_chirho.receipt_digest_chirho.clear();
        receipt_chirho.sig_hex_chirho.clear();
        receipt_chirho.sign_chirho(sign_root_chirho)
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
mod live_head_tests_chirho {
    use super::*;
    use crate::store_chirho::{LedgerMirrorHighWaterChirho, LedgerMirrorHighWaterInputChirho};
    use crate::tests_chirho::{provision_node_chirho, signed_record_chirho, JOURNAL_KEY_ID_CHIRHO};

    struct LiveReceiptFixtureChirho {
        receipt_chirho: LedgerMirrorRecoveryHeadReceiptChirho,
        holder_root_chirho: tempfile::TempDir,
        writer_node_id_chirho: String,
        holder_node_id_chirho: String,
    }

    fn live_receipt_fixture_chirho() -> LiveReceiptFixtureChirho {
        let journal_root_chirho = tempfile::tempdir().unwrap();
        let writer_root_chirho = tempfile::tempdir().unwrap();
        let holder_root_chirho = tempfile::tempdir().unwrap();
        let third_root_chirho = tempfile::tempdir().unwrap();
        provision_node_chirho(journal_root_chirho.path());
        let writer_node_id_chirho = provision_node_chirho(writer_root_chirho.path());
        let holder_node_id_chirho = provision_node_chirho(holder_root_chirho.path());
        let third_node_id_chirho = provision_node_chirho(third_root_chirho.path());
        let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
        let high_water_chirho = LedgerMirrorHighWaterChirho::sign_chirho(
            LedgerMirrorHighWaterInputChirho {
                consistency_group_digest_chirho: "1".repeat(64),
                origin_leader_node_id_chirho: writer_node_id_chirho.clone(),
                holder_node_id_chirho: holder_node_id_chirho.clone(),
                assignment_digest_chirho: "2".repeat(64),
                assigned_node_ids_chirho: [
                    writer_node_id_chirho.clone(),
                    holder_node_id_chirho.clone(),
                    third_node_id_chirho,
                ],
                membership_view_digest_chirho: "3".repeat(64),
                historical_term_chirho: 7,
                mirror_closure_id_chirho: "4".repeat(64),
                prepare_frame_digest_chirho: "5".repeat(64),
                caller_idempotency_key_digest_chirho: "6".repeat(64),
                record_chirho,
            },
            holder_root_chirho.path(),
        )
        .unwrap();
        let receipt_chirho = LedgerMirrorRecoveryHeadReceiptChirho::sign_from_high_water_chirho(
            &high_water_chirho,
            holder_root_chirho.path(),
        )
        .unwrap();
        LiveReceiptFixtureChirho {
            receipt_chirho,
            holder_root_chirho,
            writer_node_id_chirho,
            holder_node_id_chirho,
        }
    }

    fn writer_group_chirho() -> String {
        format!("writer-fence-group-blake3-chirho:{}", "a".repeat(64))
    }

    #[test]
    fn absent_live_head_stays_named_and_carries_no_recovery_authority_chirho() {
        let node_id_chirho = "a".repeat(64);
        let writer_group_digest_chirho = writer_group_chirho();
        let report_chirho = ledger_mirror_live_head_report_chirho(
            node_id_chirho.clone(),
            writer_group_digest_chirho.clone(),
            None,
        )
        .unwrap();
        let report_bytes_chirho =
            ledger_mirror_live_head_report_bytes_chirho(&report_chirho).unwrap();
        let verdict_chirho =
            ledger_mirror_live_head_bound_verdict_chirho(&report_bytes_chirho).unwrap();
        let expected_chirho = LedgerMirrorLiveHeadBoundVerdictChirho {
            schema_chirho: LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO.to_owned(),
            report_sha256_chirho: sha256_hex_chirho(&report_bytes_chirho),
            node_id_chirho,
            writer_fence_group_digest_chirho: writer_group_digest_chirho,
            status_chirho: LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAbsentChirho,
            mirror_consistency_group_digest_chirho: None,
            assignment_digest_chirho: None,
            ordered_assigned_node_ids_chirho: None,
            writer_node_id_chirho: None,
            holder_node_id_chirho: None,
            writer_membership_view_digest_chirho: None,
            writer_term_chirho: None,
            cluster_id_sha256_chirho: None,
            journal_genesis_digest_chirho: None,
            tail_seq_chirho: None,
            tail_record_digest_chirho: None,
            tail_epoch_chirho: None,
            tail_hlc_physical_ms_chirho: None,
            tail_hlc_logical_chirho: None,
            source_head_digest_chirho: None,
            receipt_digest_chirho: None,
        };
        assert_eq!(verdict_chirho, expected_chirho);
    }

    #[test]
    fn bound_verdict_renames_and_preserves_each_verified_live_value_chirho() {
        let first_chirho = live_receipt_fixture_chirho();
        let second_chirho = live_receipt_fixture_chirho();
        let fixtures_chirho = [&first_chirho, &second_chirho];
        assert_ne!(
            first_chirho.writer_node_id_chirho,
            second_chirho.writer_node_id_chirho
        );
        assert_ne!(
            first_chirho.holder_node_id_chirho,
            second_chirho.holder_node_id_chirho
        );
        let verdicts_chirho = fixtures_chirho
            .iter()
            .map(|fixture_chirho| {
                let writer_group_chirho = writer_group_chirho();
                let report_chirho = ledger_mirror_live_head_report_chirho(
                    fixture_chirho.holder_node_id_chirho.clone(),
                    writer_group_chirho.clone(),
                    Some(fixture_chirho.receipt_chirho.clone()),
                )
                .unwrap();
                let report_bytes_chirho =
                    ledger_mirror_live_head_report_bytes_chirho(&report_chirho).unwrap();
                let verdict_chirho =
                    ledger_mirror_live_head_bound_verdict_chirho(&report_bytes_chirho).unwrap();
                let expected_chirho = LedgerMirrorLiveHeadBoundVerdictChirho {
                    schema_chirho: LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_SCHEMA_V1_CHIRHO
                        .to_owned(),
                    report_sha256_chirho: sha256_hex_chirho(&report_bytes_chirho),
                    node_id_chirho: fixture_chirho.holder_node_id_chirho.clone(),
                    writer_fence_group_digest_chirho: writer_group_chirho,
                    status_chirho:
                        LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAvailableChirho,
                    mirror_consistency_group_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .consistency_group_digest_chirho()
                            .to_owned(),
                    ),
                    assignment_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .assignment_digest_chirho()
                            .to_owned(),
                    ),
                    ordered_assigned_node_ids_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .assigned_node_ids_chirho()
                            .clone(),
                    ),
                    writer_node_id_chirho: Some(fixture_chirho.writer_node_id_chirho.clone()),
                    holder_node_id_chirho: Some(fixture_chirho.holder_node_id_chirho.clone()),
                    writer_membership_view_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .historical_membership_view_digest_chirho()
                            .to_owned(),
                    ),
                    writer_term_chirho: Some(
                        fixture_chirho.receipt_chirho.historical_term_chirho(),
                    ),
                    cluster_id_sha256_chirho: Some(sha256_hex_chirho(
                        fixture_chirho.receipt_chirho.cluster_id_chirho().as_bytes(),
                    )),
                    journal_genesis_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .journal_genesis_digest_chirho()
                            .to_owned(),
                    ),
                    tail_seq_chirho: Some(fixture_chirho.receipt_chirho.tail_seq_chirho()),
                    tail_record_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .tail_record_digest_chirho()
                            .to_owned(),
                    ),
                    tail_epoch_chirho: Some(fixture_chirho.receipt_chirho.tail_epoch_chirho()),
                    tail_hlc_physical_ms_chirho: Some(
                        fixture_chirho.receipt_chirho.tail_hlc_physical_ms_chirho(),
                    ),
                    tail_hlc_logical_chirho: Some(
                        fixture_chirho.receipt_chirho.tail_hlc_logical_chirho(),
                    ),
                    source_head_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .source_head_digest_chirho()
                            .to_owned(),
                    ),
                    receipt_digest_chirho: Some(
                        fixture_chirho
                            .receipt_chirho
                            .receipt_digest_chirho()
                            .to_owned(),
                    ),
                };
                assert_eq!(
                    verdict_chirho.report_sha256_chirho,
                    sha256_hex_chirho(&report_bytes_chirho)
                );
                assert_eq!(verdict_chirho, expected_chirho);
                verdict_chirho
            })
            .collect::<Vec<_>>();
        assert_ne!(verdicts_chirho[0], verdicts_chirho[1]);
    }

    #[test]
    fn bootstrap_receipt_cannot_enter_the_live_report_chirho() {
        let fixture_chirho = live_receipt_fixture_chirho();
        let bootstrap_chirho = fixture_chirho
            .receipt_chirho
            .resign_source_for_test_chirho(
                RECOVERY_SOURCE_BOOTSTRAP_CHIRHO,
                Some("f".repeat(64)),
                fixture_chirho.holder_root_chirho.path(),
            )
            .unwrap();
        let refusal_chirho = ledger_mirror_live_head_report_chirho(
            fixture_chirho.holder_node_id_chirho,
            writer_group_chirho(),
            Some(bootstrap_chirho),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::LiveSourceRequiredChirho
        );
        assert_ne!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::ShapeRefusedChirho
        );
        assert_ne!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::BindingRefusedChirho
        );
    }

    #[test]
    fn valid_holder_receipt_cannot_be_relabelled_as_another_node_chirho() {
        let fixture_chirho = live_receipt_fixture_chirho();
        let correct_report_chirho = ledger_mirror_live_head_report_chirho(
            fixture_chirho.holder_node_id_chirho.clone(),
            writer_group_chirho(),
            Some(fixture_chirho.receipt_chirho.clone()),
        )
        .unwrap();
        assert_eq!(
            correct_report_chirho.node_id_chirho,
            fixture_chirho.holder_node_id_chirho
        );
        let substituted_node_chirho = if fixture_chirho.holder_node_id_chirho == "f".repeat(64) {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        let refusal_chirho = ledger_mirror_live_head_report_chirho(
            substituted_node_chirho,
            writer_group_chirho(),
            Some(fixture_chirho.receipt_chirho),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::BindingRefusedChirho
        );
        assert_ne!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::ReceiptRefusedChirho
        );
        assert_ne!(
            refusal_chirho,
            LedgerMirrorLiveHeadReportRefusalChirho::ShapeRefusedChirho
        );
    }

    #[test]
    fn altered_bound_verdict_cannot_relabel_the_exact_report_chirho() {
        let fixture_chirho = live_receipt_fixture_chirho();
        let report_chirho = ledger_mirror_live_head_report_chirho(
            fixture_chirho.holder_node_id_chirho,
            writer_group_chirho(),
            Some(fixture_chirho.receipt_chirho),
        )
        .unwrap();
        let report_bytes_chirho =
            ledger_mirror_live_head_report_bytes_chirho(&report_chirho).unwrap();
        let mut newline_reframed_chirho = report_bytes_chirho.clone();
        newline_reframed_chirho.push(b'\n');
        assert_eq!(
            ledger_mirror_live_head_bound_verdict_chirho(&newline_reframed_chirho).unwrap_err(),
            LedgerMirrorLiveHeadBoundVerdictRefusalChirho::ReportRefusedChirho(
                LedgerMirrorLiveHeadReportRefusalChirho::NonCanonicalRefusedChirho,
            )
        );
        let verdict_bytes_chirho =
            ledger_mirror_live_head_bound_verdict_bytes_chirho(&report_bytes_chirho).unwrap();
        let mut verdict_chirho: LedgerMirrorLiveHeadBoundVerdictChirho =
            serde_json::from_slice(&verdict_bytes_chirho).unwrap();
        verdict_chirho.writer_node_id_chirho = Some("f".repeat(64));
        let altered_chirho = serde_json::to_vec(&verdict_chirho).unwrap();
        assert_eq!(
            verify_ledger_mirror_live_head_bound_verdict_bytes_chirho(
                &report_bytes_chirho,
                &altered_chirho,
            )
            .unwrap_err(),
            LedgerMirrorLiveHeadBoundVerdictRefusalChirho::BindingRefusedChirho
        );
    }
}
