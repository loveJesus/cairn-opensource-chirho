// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fresh current-leader request for one holder's ordinary-election sink-term receipt.
//!
//! This request is domain-separated from recovery. It names the resident-minted challenge and exact
//! acknowledged tail; the receiver independently joins its current election and placement before it
//! signs any response.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const ORDINARY_TERM_REQUEST_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-ordinary-term-acceptance-request-v1-chirho";
const ORDINARY_TERM_REQUEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"ledger-mirror-ordinary-term-acceptance-request-v1-chirho";
pub(crate) const ORDINARY_TERM_REQUEST_MAX_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorOrdinaryTermAcceptanceRequestChirho {
    schema_chirho: String,
    challenge_nonce_hex_chirho: String,
    requester_node_id_chirho: String,
    target_node_id_chirho: String,
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
    request_digest_chirho: String,
    sig_hex_chirho: String,
}

pub(crate) struct LedgerMirrorOrdinaryTermAcceptanceRequestInputChirho {
    pub challenge_nonce_hex_chirho: String,
    pub requester_node_id_chirho: String,
    pub target_node_id_chirho: String,
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
}

impl LedgerMirrorOrdinaryTermAcceptanceRequestChirho {
    pub(crate) fn sign_chirho(
        input_chirho: LedgerMirrorOrdinaryTermAcceptanceRequestInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut request_chirho = Self {
            schema_chirho: ORDINARY_TERM_REQUEST_SCHEMA_V1_CHIRHO.to_owned(),
            challenge_nonce_hex_chirho: input_chirho.challenge_nonce_hex_chirho,
            requester_node_id_chirho: input_chirho.requester_node_id_chirho,
            target_node_id_chirho: input_chirho.target_node_id_chirho,
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
            request_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        request_chirho.validate_shape_chirho()?;
        let digest_chirho = request_chirho.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )?;
        if possession_chirho.key_id_chirho() != request_chirho.requester_node_id_chirho {
            bail!("LedgerMirrorOrdinaryTermRequestSignerIdentityRefusedChirho");
        }
        request_chirho.request_digest_chirho = digest_chirho.to_hex().to_string();
        request_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(request_chirho)
    }

    pub(crate) fn decode_and_verify_chirho(bytes_chirho: &[u8]) -> Result<Self> {
        if bytes_chirho.len() > ORDINARY_TERM_REQUEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorOrdinaryTermRequestTooLargeChirho");
        }
        let request_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorOrdinaryTermRequestMalformedChirho"))?;
        if serde_json::to_vec(&request_chirho)? != bytes_chirho {
            bail!("LedgerMirrorOrdinaryTermRequestNonCanonicalChirho");
        }
        request_chirho.validate_shape_chirho()?;
        let digest_chirho = request_chirho.compute_digest_chirho()?;
        if request_chirho.request_digest_chirho != digest_chirho.to_hex().as_str()
            || !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
                &request_chirho.requester_node_id_chirho,
                digest_chirho.as_bytes(),
                &request_chirho.sig_hex_chirho,
            )?
        {
            bail!("LedgerMirrorOrdinaryTermRequestSignatureRefusedChirho");
        }
        Ok(request_chirho)
    }

    pub(crate) fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>> {
        let bytes_chirho = serde_json::to_vec(self)?;
        if bytes_chirho.len() > ORDINARY_TERM_REQUEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorOrdinaryTermRequestTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        if self.schema_chirho != ORDINARY_TERM_REQUEST_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.challenge_nonce_hex_chirho)
            || !is_lower_hex_digest_chirho(&self.requester_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.target_node_id_chirho)
            || self.requester_node_id_chirho == self.target_node_id_chirho
            || !is_lower_hex_digest_chirho(&self.consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.journal_genesis_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.tail_record_digest_chirho)
            || self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || self
                .assigned_node_ids_chirho
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 3
            || !self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| node_id_chirho == &self.requester_node_id_chirho)
            || !self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| node_id_chirho == &self.target_node_id_chirho)
            || self.expected_term_chirho == 0
            || self.cluster_id_chirho.is_empty()
            || self.cluster_id_chirho.len() > 256
            || self.tail_seq_chirho == 0
            || self.tail_epoch_chirho == 0
            || self.tail_hlc_physical_ms_chirho == 0
            || (!self.request_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.request_digest_chirho))
            || (self.request_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            bail!("LedgerMirrorOrdinaryTermRequestShapeRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.request_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(ORDINARY_TERM_REQUEST_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub(crate) fn challenge_nonce_hex_chirho(&self) -> &str {
        &self.challenge_nonce_hex_chirho
    }

    pub(crate) fn requester_node_id_chirho(&self) -> &str {
        &self.requester_node_id_chirho
    }

    pub(crate) fn target_node_id_chirho(&self) -> &str {
        &self.target_node_id_chirho
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
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
