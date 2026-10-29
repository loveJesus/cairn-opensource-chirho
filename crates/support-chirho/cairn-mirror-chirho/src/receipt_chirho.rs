// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! `MirrorReceiptChirho` — the receiver's signed durable-storage receipt. It records WHICH native
//! durable point the sealed closure reached (NATIVE_DURABILITY), never "bytes accepted", and carries
//! the 7.2a placeholder-custody status forward so a later serving gate (7.4) cannot treat placeholder
//! custody as real 7.2c-confirmed custody. Named `MirrorReceiptChirho` because `MirrorReportChirho` is
//! taken by the S3 object mirror.

use crate::digest_chirho::{
    update_digest_field_chirho, valid_lower_hex_chirho, validate_signature_hex_chirho,
    verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use serde::{Deserialize, Serialize};

pub const MIRROR_RECEIPT_SCHEMA_V1_CHIRHO: &str = "mirror-receipt-v1-chirho";
pub const MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO: usize = 64 * 1024;
const MIRROR_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-mirror-receipt-v1-chirho";

/// Which staged point a receipt attests. PREPARE stores + verifies the inert bytes; FINALIZE marks
/// them visible to recovery/serving after the leader's local commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirrorReceiptStageChirho {
    #[serde(rename = "prepared-chirho")]
    PreparedChirho,
    #[serde(rename = "finalized-chirho")]
    FinalizedChirho,
}

impl MirrorReceiptStageChirho {
    fn as_bytes_chirho(self) -> &'static [u8] {
        match self {
            Self::PreparedChirho => b"prepared-chirho",
            Self::FinalizedChirho => b"finalized-chirho",
        }
    }
}

/// The native durable point a mirror counted. There is deliberately no "bytes accepted" variant: a
/// mirror counts only after its closure member reaches an actual verified durable commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirrorDurableCommitClassChirho {
    /// F1: the exact canonical signed ledger record reached the follower's fsync-durable inert mirror
    /// namespace and its verified continuity high-water was durably advanced.
    #[serde(rename = "signed-ledger-record-native-durable-chirho")]
    SignedLedgerRecordNativeDurableChirho,
    /// F12: the sealed ciphertext reached a CAS verify-on-read durable point and the privacy record
    /// prefix was durably appended. Key custody remains a 7.2c PLACEHOLDER, recorded here so serving
    /// never treats it as real custody.
    #[serde(rename = "sealed-blob-native-durable-placeholder-custody-chirho")]
    SealedBlobNativeDurablePlaceholderCustodyChirho,
}

impl MirrorDurableCommitClassChirho {
    fn as_bytes_chirho(self) -> &'static [u8] {
        match self {
            Self::SignedLedgerRecordNativeDurableChirho => {
                b"signed-ledger-record-native-durable-chirho"
            }
            Self::SealedBlobNativeDurablePlaceholderCustodyChirho => {
                b"sealed-blob-native-durable-placeholder-custody-chirho"
            }
        }
    }
}

pub struct MirrorReceiptInputChirho {
    pub prepare_frame_digest_chirho: String,
    pub caller_idempotency_key_digest_chirho: String,
    pub responder_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub mirror_closure_id_chirho: String,
    pub actual_term_chirho: u64,
    pub stage_chirho: MirrorReceiptStageChirho,
    pub durable_commit_class_chirho: MirrorDurableCommitClassChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MirrorReceiptChirho {
    schema_chirho: String,
    prepare_frame_digest_chirho: String,
    caller_idempotency_key_digest_chirho: String,
    responder_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    mirror_closure_id_chirho: String,
    actual_term_chirho: u64,
    stage_chirho: MirrorReceiptStageChirho,
    durable_commit_class_chirho: MirrorDurableCommitClassChirho,
    receipt_digest_chirho: String,
    sig_hex_chirho: String,
}

/// A receipt whose bindings are validated and whose digest is computed but not yet signed.
pub struct PreparedMirrorReceiptChirho {
    receipt_chirho: MirrorReceiptChirho,
}

impl PreparedMirrorReceiptChirho {
    pub fn new_chirho(
        input_chirho: MirrorReceiptInputChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let mut receipt_chirho = MirrorReceiptChirho {
            schema_chirho: MIRROR_RECEIPT_SCHEMA_V1_CHIRHO.to_string(),
            prepare_frame_digest_chirho: input_chirho.prepare_frame_digest_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            responder_node_id_chirho: input_chirho.responder_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            mirror_closure_id_chirho: input_chirho.mirror_closure_id_chirho,
            actual_term_chirho: input_chirho.actual_term_chirho,
            stage_chirho: input_chirho.stage_chirho,
            durable_commit_class_chirho: input_chirho.durable_commit_class_chirho,
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_receipt_semantics_chirho(&receipt_chirho)?;
        receipt_chirho.receipt_digest_chirho = receipt_digest_hex_chirho(&receipt_chirho);
        Ok(Self { receipt_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        crate::digest_chirho::decode_hex_32_chirho(&self.receipt_chirho.receipt_digest_chirho)
            .expect("a prepared receipt always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<MirrorReceiptChirho, MirrorContractErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho,
        )?;
        self.receipt_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.receipt_chirho)
    }
}

impl MirrorReceiptChirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, MirrorContractErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorWireDecodeRefusedChirho,
                "mirror receipt could not be encoded exactly",
            )
        })?;
        if bytes_chirho.len() > MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorWireTooLargeChirho,
                "mirror receipt exceeds its fixed bound",
            ));
        }
        Ok(bytes_chirho)
    }

    pub fn prepare_frame_digest_chirho(&self) -> &str {
        &self.prepare_frame_digest_chirho
    }

    pub fn responder_node_id_chirho(&self) -> &str {
        &self.responder_node_id_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.mirror_closure_id_chirho
    }

    pub fn actual_term_chirho(&self) -> u64 {
        self.actual_term_chirho
    }

    pub fn stage_chirho(&self) -> MirrorReceiptStageChirho {
        self.stage_chirho
    }

    pub fn durable_commit_class_chirho(&self) -> MirrorDurableCommitClassChirho {
        self.durable_commit_class_chirho
    }
}

/// A receipt whose bindings, digest, and responder signature all verified.
pub struct VerifiedMirrorReceiptChirho {
    receipt_chirho: MirrorReceiptChirho,
}

impl VerifiedMirrorReceiptChirho {
    pub fn into_receipt_chirho(self) -> MirrorReceiptChirho {
        self.receipt_chirho
    }

    pub fn stage_chirho(&self) -> MirrorReceiptStageChirho {
        self.receipt_chirho.stage_chirho
    }

    pub fn durable_commit_class_chirho(&self) -> MirrorDurableCommitClassChirho {
        self.receipt_chirho.durable_commit_class_chirho
    }
}

#[allow(clippy::too_many_arguments)]
pub fn decode_and_verify_mirror_receipt_chirho(
    wire_bytes_chirho: &[u8],
    expected_prepare_frame_digest_chirho: &str,
    expected_caller_key_digest_chirho: &str,
    expected_group_digest_chirho: &str,
    expected_responder_node_id_chirho: &str,
    expected_mirror_closure_id_chirho: &str,
) -> Result<VerifiedMirrorReceiptChirho, MirrorContractErrorChirho> {
    if wire_bytes_chirho.len() > MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorWireTooLargeChirho,
            "mirror receipt exceeds its fixed bound",
        ));
    }
    let receipt_chirho: MirrorReceiptChirho = serde_json::from_slice(wire_bytes_chirho)
        .map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorWireDecodeRefusedChirho,
                "mirror receipt could not be decoded exactly",
            )
        })
        .map_err(MirrorContractErrorChirho::after_prepare_may_be_durable_chirho)?;
    validate_receipt_semantics_chirho(&receipt_chirho)
        .map_err(MirrorContractErrorChirho::after_prepare_may_be_durable_chirho)?;
    if receipt_chirho.prepare_frame_digest_chirho != expected_prepare_frame_digest_chirho
        || receipt_chirho.caller_idempotency_key_digest_chirho != expected_caller_key_digest_chirho
        || receipt_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || receipt_chirho.responder_node_id_chirho != expected_responder_node_id_chirho
        || receipt_chirho.mirror_closure_id_chirho != expected_mirror_closure_id_chirho
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho,
            "mirror receipt does not bind the expected prepare, caller key, group, responder, and closure id",
        )
        .after_prepare_may_be_durable_chirho());
    }
    let expected_digest_chirho = receipt_digest_hex_chirho(&receipt_chirho);
    if receipt_chirho.receipt_digest_chirho != expected_digest_chirho {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorReceiptDigestMismatchChirho,
            "mirror receipt digest does not bind its semantic fields",
        )
        .after_prepare_may_be_durable_chirho());
    }
    verify_node_signature_chirho(
        &receipt_chirho.responder_node_id_chirho,
        &receipt_chirho.receipt_digest_chirho,
        &receipt_chirho.sig_hex_chirho,
        MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho,
    )
    .map_err(MirrorContractErrorChirho::after_prepare_may_be_durable_chirho)?;
    Ok(VerifiedMirrorReceiptChirho { receipt_chirho })
}

fn validate_receipt_semantics_chirho(
    receipt_chirho: &MirrorReceiptChirho,
) -> Result<(), MirrorContractErrorChirho> {
    if receipt_chirho.schema_chirho != MIRROR_RECEIPT_SCHEMA_V1_CHIRHO {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorSchemaUnsupportedChirho,
            "mirror receipt schema is unsupported",
        ));
    }
    if !valid_lower_hex_chirho(
        &receipt_chirho.prepare_frame_digest_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &receipt_chirho.caller_idempotency_key_digest_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &receipt_chirho.consistency_group_digest_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &receipt_chirho.responder_node_id_chirho,
        NODE_ID_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &receipt_chirho.mirror_closure_id_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho,
            "mirror receipt identity bindings are not canonical hex",
        ));
    }
    if receipt_chirho.actual_term_chirho == 0 {
        return Err(MirrorContractErrorChirho::term_invalid_chirho());
    }
    if !receipt_chirho.receipt_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(
            &receipt_chirho.receipt_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorReceiptDigestMismatchChirho,
            "mirror receipt digest is not canonical hex",
        ));
    }
    if !receipt_chirho.sig_hex_chirho.is_empty() {
        validate_signature_hex_chirho(
            &receipt_chirho.sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorReceiptAuthenticationRefusedChirho,
        )?;
    }
    Ok(())
}

fn receipt_digest_hex_chirho(receipt_chirho: &MirrorReceiptChirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(MIRROR_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        receipt_chirho.schema_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"prepare-frame-digest-chirho",
        receipt_chirho.prepare_frame_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"caller-key-digest-chirho",
        receipt_chirho
            .caller_idempotency_key_digest_chirho
            .as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"responder-node-id-chirho",
        receipt_chirho.responder_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"group-digest-chirho",
        receipt_chirho.consistency_group_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"mirror-closure-id-chirho",
        receipt_chirho.mirror_closure_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"actual-term-chirho",
        &receipt_chirho.actual_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"stage-chirho",
        receipt_chirho.stage_chirho.as_bytes_chirho(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"durable-commit-class-chirho",
        receipt_chirho.durable_commit_class_chirho.as_bytes_chirho(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}
