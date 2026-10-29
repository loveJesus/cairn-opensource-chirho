// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One-signature verified-prefix closure and bounded historical transfer pages.

use crate::family_chirho::LedgerMirrorRecordChirho;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const PREFIX_MANIFEST_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-verified-prefix-manifest-v1-chirho";
const PREFIX_MANIFEST_DOMAIN_V1_CHIRHO: &[u8] = b"ledger-mirror-verified-prefix-manifest-v1-chirho";
const PREFIX_PAGE_SCHEMA_V1_CHIRHO: &str = "ledger-mirror-verified-prefix-page-v1-chirho";
const PREFIX_PAGE_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"ledger-mirror-verified-prefix-page-v1-chirho";
const PREFIX_CHAIN_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"ledger-mirror-verified-prefix-dense-chain-v1-chirho";
pub(crate) const PREFIX_MANIFEST_MAX_BYTES_CHIRHO: usize = 32 * 1024;
pub(crate) const PREFIX_PAGE_MAX_BYTES_CHIRHO: usize = 640 * 1024;
pub(crate) const PREFIX_PAGE_MAX_RECORDS_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorVerifiedPrefixManifestChirho {
    schema_chirho: String,
    origin_leader_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    assignment_digest_chirho: String,
    assigned_node_ids_chirho: [String; 3],
    expected_term_chirho: u64,
    membership_view_digest_chirho: String,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: String,
    tail_epoch_chirho: u64,
    tail_hlc_physical_ms_chirho: u64,
    tail_hlc_logical_chirho: u32,
    record_count_chirho: u64,
    dense_chain_digest_chirho: String,
    manifest_digest_chirho: String,
    sig_hex_chirho: String,
}

pub(crate) struct LedgerMirrorVerifiedPrefixManifestInputChirho {
    pub origin_leader_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub assigned_node_ids_chirho: [String; 3],
    pub expected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: String,
    pub tail_epoch_chirho: u64,
    pub tail_hlc_physical_ms_chirho: u64,
    pub tail_hlc_logical_chirho: u32,
    pub record_count_chirho: u64,
    pub dense_chain_digest_chirho: String,
}

/// Every manifest field whose equality makes an older bootstrap head reusable.
/// The reuse check compares this complete binding against the verified current placement and, when
/// present, one binding substituted with its signed immediate predecessor assignment.
/// Current election term and membership-view digest are deliberately excluded: the server verifies
/// those against its live joined view before the follower store evaluates this historical binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LedgerMirrorPrefixReuseBindingChirho {
    pub manifest_schema_chirho: String,
    pub origin_leader_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub assigned_node_ids_chirho: [String; 3],
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: String,
    pub tail_epoch_chirho: u64,
    pub tail_hlc_physical_ms_chirho: u64,
    pub tail_hlc_logical_chirho: u32,
    pub record_count_chirho: u64,
    pub dense_chain_digest_chirho: String,
}

impl LedgerMirrorVerifiedPrefixManifestChirho {
    pub(crate) fn sign_chirho(
        input_chirho: LedgerMirrorVerifiedPrefixManifestInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut manifest_chirho = Self {
            schema_chirho: PREFIX_MANIFEST_SCHEMA_V1_CHIRHO.to_string(),
            origin_leader_node_id_chirho: input_chirho.origin_leader_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            assigned_node_ids_chirho: input_chirho.assigned_node_ids_chirho,
            expected_term_chirho: input_chirho.expected_term_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            tail_seq_chirho: input_chirho.tail_seq_chirho,
            tail_record_digest_chirho: input_chirho.tail_record_digest_chirho,
            tail_epoch_chirho: input_chirho.tail_epoch_chirho,
            tail_hlc_physical_ms_chirho: input_chirho.tail_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: input_chirho.tail_hlc_logical_chirho,
            record_count_chirho: input_chirho.record_count_chirho,
            dense_chain_digest_chirho: input_chirho.dense_chain_digest_chirho,
            manifest_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        manifest_chirho.validate_shape_chirho()?;
        let digest_chirho = manifest_chirho.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )?;
        if possession_chirho.key_id_chirho() != manifest_chirho.origin_leader_node_id_chirho {
            bail!("LedgerMirrorPrefixManifestSignerIdentityRefusedChirho");
        }
        manifest_chirho.manifest_digest_chirho = digest_chirho.to_hex().to_string();
        manifest_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(manifest_chirho)
    }

    pub(crate) fn decode_and_verify_chirho(bytes_chirho: &[u8]) -> Result<Self> {
        if bytes_chirho.len() > PREFIX_MANIFEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorPrefixManifestTooLargeChirho");
        }
        let manifest_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixManifestMalformedChirho"))?;
        if serde_json::to_vec(&manifest_chirho)? != bytes_chirho {
            bail!("LedgerMirrorPrefixManifestNonCanonicalChirho");
        }
        manifest_chirho.verify_chirho()?;
        Ok(manifest_chirho)
    }

    pub(crate) fn verify_chirho(&self) -> Result<()> {
        self.validate_shape_chirho()?;
        let digest_chirho = self.compute_digest_chirho()?;
        if self.manifest_digest_chirho != digest_chirho.to_hex().as_str()
            || !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
                &self.origin_leader_node_id_chirho,
                digest_chirho.as_bytes(),
                &self.sig_hex_chirho,
            )?
        {
            bail!("LedgerMirrorPrefixManifestSignatureRefusedChirho");
        }
        Ok(())
    }

    pub(crate) fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>> {
        self.verify_chirho()?;
        let bytes_chirho = serde_json::to_vec(self)?;
        if bytes_chirho.len() > PREFIX_MANIFEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorPrefixManifestTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        let assigned_chirho = self
            .assigned_node_ids_chirho
            .iter()
            .collect::<BTreeSet<_>>();
        if self.schema_chirho != PREFIX_MANIFEST_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.origin_leader_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || assigned_chirho.len() != 3
            || !assigned_chirho.contains(&self.origin_leader_node_id_chirho)
            || self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || self.expected_term_chirho == 0
            || !is_lower_hex_digest_chirho(&self.membership_view_digest_chirho)
            || self.cluster_id_chirho.is_empty()
            || self.cluster_id_chirho.len() > 256
            || !is_lower_hex_digest_chirho(&self.journal_genesis_digest_chirho)
            || self.tail_seq_chirho == 0
            || !is_lower_hex_digest_chirho(&self.tail_record_digest_chirho)
            || self.tail_epoch_chirho == 0
            || self.tail_hlc_physical_ms_chirho == 0
            || self.record_count_chirho != self.tail_seq_chirho
            || !is_lower_hex_digest_chirho(&self.dense_chain_digest_chirho)
            || (!self.manifest_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.manifest_digest_chirho))
            || (self.manifest_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            bail!("LedgerMirrorPrefixManifestShapeRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.manifest_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(PREFIX_MANIFEST_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub(crate) fn origin_leader_node_id_chirho(&self) -> &str {
        &self.origin_leader_node_id_chirho
    }
    pub(crate) fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }
    pub(crate) fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }
    pub(crate) fn assigned_node_ids_chirho(&self) -> &[String; 3] {
        &self.assigned_node_ids_chirho
    }
    pub(crate) fn expected_term_chirho(&self) -> u64 {
        self.expected_term_chirho
    }
    pub(crate) fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }
    pub(crate) fn cluster_id_chirho(&self) -> &str {
        &self.cluster_id_chirho
    }
    pub(crate) fn journal_genesis_digest_chirho(&self) -> &str {
        &self.journal_genesis_digest_chirho
    }
    pub(crate) fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }
    pub(crate) fn tail_record_digest_chirho(&self) -> &str {
        &self.tail_record_digest_chirho
    }
    pub(crate) fn tail_epoch_chirho(&self) -> u64 {
        self.tail_epoch_chirho
    }
    pub(crate) fn tail_hlc_physical_ms_chirho(&self) -> u64 {
        self.tail_hlc_physical_ms_chirho
    }
    pub(crate) fn tail_hlc_logical_chirho(&self) -> u32 {
        self.tail_hlc_logical_chirho
    }
    pub(crate) fn record_count_chirho(&self) -> u64 {
        self.record_count_chirho
    }
    pub(crate) fn dense_chain_digest_chirho(&self) -> &str {
        &self.dense_chain_digest_chirho
    }
    pub(crate) fn manifest_digest_chirho(&self) -> &str {
        &self.manifest_digest_chirho
    }

    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/item7-f1-mirror-recovery-adoption-chirho.md`.
    pub(crate) fn reuse_binding_chirho(&self) -> LedgerMirrorPrefixReuseBindingChirho {
        let Self {
            schema_chirho,
            origin_leader_node_id_chirho,
            consistency_group_digest_chirho,
            assignment_digest_chirho,
            assigned_node_ids_chirho,
            expected_term_chirho: _,
            membership_view_digest_chirho: _,
            cluster_id_chirho,
            journal_genesis_digest_chirho,
            tail_seq_chirho,
            tail_record_digest_chirho,
            tail_epoch_chirho,
            tail_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho,
            record_count_chirho,
            dense_chain_digest_chirho,
            manifest_digest_chirho: _,
            sig_hex_chirho: _,
        } = self;
        LedgerMirrorPrefixReuseBindingChirho {
            manifest_schema_chirho: schema_chirho.clone(),
            origin_leader_node_id_chirho: origin_leader_node_id_chirho.clone(),
            consistency_group_digest_chirho: consistency_group_digest_chirho.clone(),
            assignment_digest_chirho: assignment_digest_chirho.clone(),
            assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
            cluster_id_chirho: cluster_id_chirho.clone(),
            journal_genesis_digest_chirho: journal_genesis_digest_chirho.clone(),
            tail_seq_chirho: *tail_seq_chirho,
            tail_record_digest_chirho: tail_record_digest_chirho.clone(),
            tail_epoch_chirho: *tail_epoch_chirho,
            tail_hlc_physical_ms_chirho: *tail_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: *tail_hlc_logical_chirho,
            record_count_chirho: *record_count_chirho,
            dense_chain_digest_chirho: dense_chain_digest_chirho.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorVerifiedPrefixPageChirho {
    schema_chirho: String,
    manifest_digest_chirho: String,
    page_index_chirho: u64,
    records_newest_first_chirho: Vec<LedgerMirrorRecordChirho>,
    page_digest_chirho: String,
}

impl LedgerMirrorVerifiedPrefixPageChirho {
    pub(crate) fn new_chirho(
        manifest_digest_chirho: String,
        page_index_chirho: u64,
        records_newest_first_chirho: Vec<LedgerMirrorRecordChirho>,
    ) -> Result<Self> {
        let mut page_chirho = Self {
            schema_chirho: PREFIX_PAGE_SCHEMA_V1_CHIRHO.to_string(),
            manifest_digest_chirho,
            page_index_chirho,
            records_newest_first_chirho,
            page_digest_chirho: String::new(),
        };
        page_chirho.validate_shape_chirho()?;
        page_chirho.page_digest_chirho = page_chirho.compute_digest_chirho()?.to_hex().to_string();
        page_chirho.validate_shape_chirho()?;
        Ok(page_chirho)
    }

    pub(crate) fn decode_chirho(bytes_chirho: &[u8]) -> Result<Self> {
        if bytes_chirho.len() > PREFIX_PAGE_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorPrefixPageTooLargeChirho");
        }
        let page_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorPrefixPageMalformedChirho"))?;
        if serde_json::to_vec(&page_chirho)? != bytes_chirho {
            bail!("LedgerMirrorPrefixPageNonCanonicalChirho");
        }
        page_chirho.verify_chirho()?;
        Ok(page_chirho)
    }

    pub(crate) fn verify_chirho(&self) -> Result<()> {
        self.validate_shape_chirho()?;
        if self.page_digest_chirho != self.compute_digest_chirho()?.to_hex().as_str() {
            bail!("LedgerMirrorPrefixPageDigestRefusedChirho");
        }
        Ok(())
    }

    pub(crate) fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>> {
        self.verify_chirho()?;
        let bytes_chirho = serde_json::to_vec(self)?;
        if bytes_chirho.len() > PREFIX_PAGE_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorPrefixPageTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        if self.schema_chirho != PREFIX_PAGE_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.manifest_digest_chirho)
            || self.records_newest_first_chirho.is_empty()
            || self.records_newest_first_chirho.len() > PREFIX_PAGE_MAX_RECORDS_CHIRHO
            || (!self.page_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.page_digest_chirho))
        {
            bail!("LedgerMirrorPrefixPageShapeRefusedChirho");
        }
        for pair_chirho in self.records_newest_first_chirho.windows(2) {
            let newer_chirho = &pair_chirho[0];
            let older_chirho = &pair_chirho[1];
            if older_chirho.record_seq_chirho.checked_add(1) != Some(newer_chirho.record_seq_chirho)
                || newer_chirho.predecessor_digest_chirho != older_chirho.record_digest_chirho
            {
                bail!("LedgerMirrorPrefixPageContinuityRefusedChirho");
            }
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.page_digest_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(PREFIX_PAGE_DIGEST_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub(crate) fn manifest_digest_chirho(&self) -> &str {
        &self.manifest_digest_chirho
    }

    pub(crate) fn page_index_chirho(&self) -> u64 {
        self.page_index_chirho
    }

    pub(crate) fn records_newest_first_chirho(&self) -> &[LedgerMirrorRecordChirho] {
        &self.records_newest_first_chirho
    }
}

pub(crate) struct LedgerMirrorDenseChainHasherChirho {
    hasher_chirho: blake3::Hasher,
    count_chirho: u64,
}

impl LedgerMirrorDenseChainHasherChirho {
    pub(crate) fn new_chirho() -> Self {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(PREFIX_CHAIN_DIGEST_DOMAIN_V1_CHIRHO);
        Self {
            hasher_chirho,
            count_chirho: 0,
        }
    }

    pub(crate) fn update_chirho(&mut self, record_chirho: &LedgerMirrorRecordChirho) -> Result<()> {
        self.count_chirho = self
            .count_chirho
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixRecordCountExhaustedChirho"))?;
        self.hasher_chirho
            .update(&record_chirho.record_seq_chirho.to_le_bytes());
        self.hasher_chirho
            .update(record_chirho.record_digest_chirho.as_bytes());
        Ok(())
    }

    pub(crate) fn finish_chirho(self) -> (u64, String) {
        (
            self.count_chirho,
            self.hasher_chirho.finalize().to_hex().to_string(),
        )
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
