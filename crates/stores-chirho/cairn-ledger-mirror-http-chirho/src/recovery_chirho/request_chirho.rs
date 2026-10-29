// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only current-leader request for one holder's verified F1 recovery head.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const RECOVERY_HEAD_REQUEST_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-recovery-head-request-v1-chirho";
const RECOVERY_HEAD_REQUEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"ledger-mirror-recovery-head-request-v1-chirho";
pub(crate) const RECOVERY_HEAD_REQUEST_MAX_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorRecoveryHeadRequestChirho {
    schema_chirho: String,
    requester_node_id_chirho: String,
    target_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    assignment_digest_chirho: String,
    expected_term_chirho: u64,
    membership_view_digest_chirho: String,
    request_digest_chirho: String,
    sig_hex_chirho: String,
}

pub(crate) struct LedgerMirrorRecoveryHeadRequestInputChirho {
    pub requester_node_id_chirho: String,
    pub target_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub expected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
}

impl LedgerMirrorRecoveryHeadRequestChirho {
    pub(crate) fn sign_chirho(
        input_chirho: LedgerMirrorRecoveryHeadRequestInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut request_chirho = Self {
            schema_chirho: RECOVERY_HEAD_REQUEST_SCHEMA_V1_CHIRHO.to_string(),
            requester_node_id_chirho: input_chirho.requester_node_id_chirho,
            target_node_id_chirho: input_chirho.target_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            expected_term_chirho: input_chirho.expected_term_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
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
            bail!("LedgerMirrorRecoveryRequestSignerIdentityRefusedChirho");
        }
        request_chirho.request_digest_chirho = digest_chirho.to_hex().to_string();
        request_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(request_chirho)
    }

    pub(crate) fn decode_and_verify_chirho(bytes_chirho: &[u8]) -> Result<Self> {
        if bytes_chirho.len() > RECOVERY_HEAD_REQUEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorRecoveryRequestTooLargeChirho");
        }
        let request_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecoveryRequestMalformedChirho"))?;
        if serde_json::to_vec(&request_chirho)? != bytes_chirho {
            bail!("LedgerMirrorRecoveryRequestNonCanonicalChirho");
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
            bail!("LedgerMirrorRecoveryRequestSignatureRefusedChirho");
        }
        Ok(request_chirho)
    }

    pub(crate) fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>> {
        let bytes_chirho = serde_json::to_vec(self)?;
        if bytes_chirho.len() > RECOVERY_HEAD_REQUEST_MAX_BYTES_CHIRHO {
            bail!("LedgerMirrorRecoveryRequestTooLargeChirho");
        }
        Ok(bytes_chirho)
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        if self.schema_chirho != RECOVERY_HEAD_REQUEST_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.requester_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.target_node_id_chirho)
            || self.requester_node_id_chirho == self.target_node_id_chirho
            || !is_lower_hex_digest_chirho(&self.consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.membership_view_digest_chirho)
            || self.expected_term_chirho == 0
            || (!self.request_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.request_digest_chirho))
            || (self.request_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            bail!("LedgerMirrorRecoveryRequestShapeRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.request_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(RECOVERY_HEAD_REQUEST_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
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

    pub(crate) fn expected_term_chirho(&self) -> u64 {
        self.expected_term_chirho
    }

    pub(crate) fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
