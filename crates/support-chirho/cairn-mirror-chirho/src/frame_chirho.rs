// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The PREPARE and FINALIZE wire frames: bounded, per-node-key signed, with their OWN domain
//! constants so a mirror frame digest can never collide with a relay envelope digest. PREPARE carries
//! the inline sealed manifest (bounded by the reused 2 MiB body cap); FINALIZE names the exact PREPARE
//! it releases and the leader's local-commit binding. Neither frame grants mutation authority — the
//! receiver's inverted-leadership check (the `authority_chirho` module) decides that separately.

use crate::digest_chirho::{
    update_digest_field_chirho, valid_lower_hex_chirho, validate_signature_hex_chirho,
    verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::manifest_chirho::MirrorClosureManifestChirho;
use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_write_relay_chirho::{RelayRosterChirho, RELAY_BODY_MAX_BYTES_CHIRHO};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MIRROR_PREPARE_FRAME_SCHEMA_V1_CHIRHO: &str = "mirror-prepare-frame-v1-chirho";
pub const MIRROR_FINALIZE_FRAME_SCHEMA_V1_CHIRHO: &str = "mirror-finalize-frame-v1-chirho";
pub const MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO: usize = 3 * 1024 * 1024;

const MIRROR_PREPARE_FRAME_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-mirror-prepare-frame-v1-chirho";
const MIRROR_FINALIZE_FRAME_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-mirror-finalize-frame-v1-chirho";

fn update_lease_field_chirho(hasher_chirho: &mut blake3::Hasher, lease_chirho: Option<u64>) {
    match lease_chirho {
        Some(value_chirho) => {
            update_digest_field_chirho(hasher_chirho, b"lease-present-chirho", &[1]);
            update_digest_field_chirho(
                hasher_chirho,
                b"lease-remaining-millis-chirho",
                &value_chirho.to_le_bytes(),
            );
        }
        None => update_digest_field_chirho(hasher_chirho, b"lease-present-chirho", &[0]),
    }
}

// ---------------------------------------------------------------------------------------------------
// Inline sealed bytes (OQ-3: the sealed ciphertext travels inline, bounded by the reused 2 MiB cap).
// ---------------------------------------------------------------------------------------------------

/// One inline sealed ciphertext: its CAS address and the sealed bytes themselves. The bytes are
/// self-authenticating (their blake3 must equal the address the signed manifest already commits to),
/// so they need no separate digest binding — a swapped byte fails the content-address check, and a
/// missing or extra payload fails the set-equality check against the manifest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineSealedPayloadChirho {
    pub ciphertext_addr_chirho: HashChirho,
    #[serde(with = "base64_bytes_chirho")]
    pub ciphertext_bytes_chirho: Vec<u8>,
}

/// A verified (address, bytes) pair the holder may durably store: its blake3 matched its address and
/// its address is named by the signed manifest.
pub struct VerifiedSealedPayloadChirho<'frame_chirho> {
    pub ciphertext_addr_chirho: &'frame_chirho HashChirho,
    pub ciphertext_bytes_chirho: &'frame_chirho [u8],
}

pub struct PrepareMirrorClosureFrameInputChirho {
    pub origin_node_id_chirho: String,
    pub target_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub expected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub leader_lease_remaining_millis_chirho: Option<u64>,
    pub caller_idempotency_key_digest_chirho: String,
    pub manifest_chirho: MirrorClosureManifestChirho,
    pub inline_sealed_payloads_chirho: Vec<InlineSealedPayloadChirho>,
}

mod base64_bytes_chirho {
    use super::*;

    pub fn serialize<SerializerChirho>(
        bytes_chirho: &[u8],
        serializer_chirho: SerializerChirho,
    ) -> Result<SerializerChirho::Ok, SerializerChirho::Error>
    where
        SerializerChirho: serde::Serializer,
    {
        serializer_chirho.serialize_str(&STANDARD_NO_PAD.encode(bytes_chirho))
    }

    pub fn deserialize<'de, DeserializerChirho>(
        deserializer_chirho: DeserializerChirho,
    ) -> Result<Vec<u8>, DeserializerChirho::Error>
    where
        DeserializerChirho: serde::Deserializer<'de>,
    {
        let encoded_chirho = String::deserialize(deserializer_chirho)?;
        let bytes_chirho = STANDARD_NO_PAD
            .decode(&encoded_chirho)
            .map_err(serde::de::Error::custom)?;
        if STANDARD_NO_PAD.encode(&bytes_chirho) != encoded_chirho {
            return Err(serde::de::Error::custom(
                "mirror sealed payload base64 is not canonical",
            ));
        }
        Ok(bytes_chirho)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareMirrorClosureFrameV1Chirho {
    schema_chirho: String,
    origin_node_id_chirho: String,
    target_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    expected_term_chirho: u64,
    membership_view_digest_chirho: String,
    leader_lease_remaining_millis_chirho: Option<u64>,
    caller_idempotency_key_digest_chirho: String,
    mirror_closure_id_chirho: String,
    manifest_chirho: MirrorClosureManifestChirho,
    inline_sealed_payloads_chirho: Vec<InlineSealedPayloadChirho>,
    prepare_frame_digest_chirho: String,
    sig_hex_chirho: String,
}

/// A PREPARE frame whose fields are validated and whose digest is computed but not yet signed.
pub struct PreparedPrepareMirrorClosureFrameChirho {
    frame_chirho: PrepareMirrorClosureFrameV1Chirho,
}

impl PreparedPrepareMirrorClosureFrameChirho {
    pub fn new_chirho(
        input_chirho: PrepareMirrorClosureFrameInputChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let mut frame_chirho = PrepareMirrorClosureFrameV1Chirho {
            schema_chirho: MIRROR_PREPARE_FRAME_SCHEMA_V1_CHIRHO.to_string(),
            origin_node_id_chirho: input_chirho.origin_node_id_chirho,
            target_node_id_chirho: input_chirho.target_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            expected_term_chirho: input_chirho.expected_term_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            leader_lease_remaining_millis_chirho: input_chirho.leader_lease_remaining_millis_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            mirror_closure_id_chirho: input_chirho
                .manifest_chirho
                .mirror_closure_id_chirho()
                .to_string(),
            manifest_chirho: input_chirho.manifest_chirho,
            inline_sealed_payloads_chirho: input_chirho.inline_sealed_payloads_chirho,
            prepare_frame_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_prepare_semantics_chirho(&frame_chirho)?;
        frame_chirho.prepare_frame_digest_chirho = prepare_frame_digest_hex_chirho(&frame_chirho);
        Ok(Self { frame_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        crate::digest_chirho::decode_hex_32_chirho(&self.frame_chirho.prepare_frame_digest_chirho)
            .expect("a prepared frame always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<PrepareMirrorClosureFrameV1Chirho, MirrorContractErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
        )?;
        self.frame_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.frame_chirho)
    }
}

impl PrepareMirrorClosureFrameV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, MirrorContractErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| wire_decode_error_chirho())?;
        if bytes_chirho.len() > MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO {
            return Err(wire_too_large_error_chirho());
        }
        Ok(bytes_chirho)
    }

    pub fn prepare_frame_digest_chirho(&self) -> &str {
        &self.prepare_frame_digest_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.mirror_closure_id_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.target_node_id_chirho
    }

    pub fn origin_node_id_chirho(&self) -> &str {
        &self.origin_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.expected_term_chirho
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.leader_lease_remaining_millis_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.caller_idempotency_key_digest_chirho
    }

    pub fn manifest_chirho(&self) -> &MirrorClosureManifestChirho {
        &self.manifest_chirho
    }
}

/// A PREPARE frame whose origin is rostered, whose digest binds its fields, and whose leader signature
/// verifies. Its authority (is the origin actually the current leader?) is NOT yet decided.
pub struct AuthenticatedMirrorPrepareChirho {
    frame_chirho: PrepareMirrorClosureFrameV1Chirho,
}

impl AuthenticatedMirrorPrepareChirho {
    pub fn origin_node_id_chirho(&self) -> &str {
        &self.frame_chirho.origin_node_id_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.frame_chirho.target_node_id_chirho
    }

    /// Bind the frame to THIS receiver: the group matches, the target is this node, this node is
    /// rostered, and the frame's caller key + closure id agree with the sealed manifest.
    pub fn bind_destination_chirho(
        self,
        expected_group_digest_chirho: &str,
        expected_receiver_node_id_chirho: &str,
        roster_chirho: &RelayRosterChirho,
    ) -> Result<VerifiedMirrorPrepareChirho, MirrorContractErrorChirho> {
        if self.frame_chirho.consistency_group_digest_chirho != expected_group_digest_chirho {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorConsistencyGroupMismatchChirho,
                "mirror prepare group does not match the selected root",
            ));
        }
        if self.frame_chirho.target_node_id_chirho != expected_receiver_node_id_chirho
            || !roster_chirho.contains_chirho(expected_receiver_node_id_chirho)
        {
            return Err(MirrorContractErrorChirho::receiver_unrostered_chirho());
        }
        if self.frame_chirho.caller_idempotency_key_digest_chirho
            != self
                .frame_chirho
                .manifest_chirho
                .caller_idempotency_key_digest_chirho()
            || self.frame_chirho.mirror_closure_id_chirho
                != self.frame_chirho.manifest_chirho.mirror_closure_id_chirho()
            || self.frame_chirho.consistency_group_digest_chirho
                != self
                    .frame_chirho
                    .manifest_chirho
                    .consistency_group_digest_chirho()
        {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorManifestDigestMismatchChirho,
                "mirror prepare frame bindings disagree with the sealed manifest it carries",
            ));
        }
        Ok(VerifiedMirrorPrepareChirho {
            frame_chirho: self.frame_chirho,
        })
    }
}

/// A PREPARE frame bound to this receiver. Consumed by `authority_chirho` for the leadership decision.
pub struct VerifiedMirrorPrepareChirho {
    frame_chirho: PrepareMirrorClosureFrameV1Chirho,
}

impl VerifiedMirrorPrepareChirho {
    pub fn frame_chirho(&self) -> &PrepareMirrorClosureFrameV1Chirho {
        &self.frame_chirho
    }

    pub fn origin_node_id_chirho(&self) -> &str {
        &self.frame_chirho.origin_node_id_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.frame_chirho.target_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.frame_chirho.consistency_group_digest_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.frame_chirho.expected_term_chirho
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.frame_chirho.membership_view_digest_chirho
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.frame_chirho.leader_lease_remaining_millis_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.frame_chirho.caller_idempotency_key_digest_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.frame_chirho.mirror_closure_id_chirho
    }

    pub fn prepare_frame_digest_chirho(&self) -> &str {
        &self.frame_chirho.prepare_frame_digest_chirho
    }

    pub fn manifest_chirho(&self) -> &MirrorClosureManifestChirho {
        &self.frame_chirho.manifest_chirho
    }

    /// Verify the inline sealed bytes against the signed manifest BEFORE any durable count: every
    /// manifest member's ciphertext address must be carried by exactly one payload whose blake3 hash
    /// re-derives that exact address. A missing, extra, duplicate, or content-mismatched payload is
    /// `MirrorClosureUnverifiedChirho` — the mirror counts such a member ABSENT rather than durable.
    pub fn verify_inline_payloads_against_manifest_chirho(
        &self,
    ) -> Result<Vec<VerifiedSealedPayloadChirho<'_>>, MirrorContractErrorChirho> {
        let manifest_addrs_chirho: BTreeSet<&str> = self
            .frame_chirho
            .manifest_chirho
            .members_chirho()
            .iter()
            .filter_map(|member_chirho| member_chirho.ciphertext_addr_chirho())
            .map(|addr_chirho| addr_chirho.0.as_str())
            .collect();
        let mut seen_chirho: BTreeSet<&str> = BTreeSet::new();
        let mut verified_chirho =
            Vec::with_capacity(self.frame_chirho.inline_sealed_payloads_chirho.len());
        for payload_chirho in &self.frame_chirho.inline_sealed_payloads_chirho {
            let addr_chirho = payload_chirho.ciphertext_addr_chirho.0.as_str();
            let recomputed_chirho = blake3::hash(&payload_chirho.ciphertext_bytes_chirho)
                .to_hex()
                .to_string();
            if recomputed_chirho != addr_chirho
                || !manifest_addrs_chirho.contains(addr_chirho)
                || !seen_chirho.insert(addr_chirho)
            {
                return Err(MirrorContractErrorChirho::closure_unverified_chirho());
            }
            verified_chirho.push(VerifiedSealedPayloadChirho {
                ciphertext_addr_chirho: &payload_chirho.ciphertext_addr_chirho,
                ciphertext_bytes_chirho: &payload_chirho.ciphertext_bytes_chirho,
            });
        }
        if seen_chirho.len() != manifest_addrs_chirho.len() {
            // A manifest member has no matching inline payload => that member counts ABSENT.
            return Err(MirrorContractErrorChirho::closure_unverified_chirho());
        }
        Ok(verified_chirho)
    }
}

pub fn decode_and_authenticate_mirror_prepare_chirho(
    wire_bytes_chirho: &[u8],
    roster_chirho: &RelayRosterChirho,
) -> Result<AuthenticatedMirrorPrepareChirho, MirrorContractErrorChirho> {
    if wire_bytes_chirho.len() > MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO {
        return Err(wire_too_large_error_chirho());
    }
    let frame_chirho: PrepareMirrorClosureFrameV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| wire_decode_error_chirho())?;
    validate_prepare_semantics_chirho(&frame_chirho)?;
    frame_chirho.manifest_chirho.verify_received_chirho()?;
    if !roster_chirho.contains_chirho(&frame_chirho.origin_node_id_chirho) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorOriginUnrosteredChirho,
            "mirror prepare origin is not in the exact active roster",
        ));
    }
    let expected_digest_chirho = prepare_frame_digest_hex_chirho(&frame_chirho);
    if frame_chirho.prepare_frame_digest_chirho != expected_digest_chirho {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho,
            "mirror prepare digest does not bind its semantic fields",
        ));
    }
    verify_node_signature_chirho(
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.prepare_frame_digest_chirho,
        &frame_chirho.sig_hex_chirho,
        MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
    )?;
    Ok(AuthenticatedMirrorPrepareChirho { frame_chirho })
}

fn validate_prepare_semantics_chirho(
    frame_chirho: &PrepareMirrorClosureFrameV1Chirho,
) -> Result<(), MirrorContractErrorChirho> {
    if frame_chirho.schema_chirho != MIRROR_PREPARE_FRAME_SCHEMA_V1_CHIRHO {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorSchemaUnsupportedChirho,
            "mirror prepare schema is unsupported",
        ));
    }
    validate_common_frame_fields_chirho(
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.target_node_id_chirho,
        &frame_chirho.consistency_group_digest_chirho,
        frame_chirho.expected_term_chirho,
        &frame_chirho.membership_view_digest_chirho,
        &frame_chirho.caller_idempotency_key_digest_chirho,
        &frame_chirho.mirror_closure_id_chirho,
    )?;
    // The inline sealed bytes (OQ-3) are bounded by the reused 2 MiB body cap, summed across payloads.
    let mut inline_total_chirho = 0_usize;
    for payload_chirho in &frame_chirho.inline_sealed_payloads_chirho {
        if !valid_lower_hex_chirho(
            &payload_chirho.ciphertext_addr_chirho.0,
            DIGEST_HEX_BYTES_CHIRHO,
        ) {
            return Err(MirrorContractErrorChirho::new_chirho(
                MirrorRefusalIdentityChirho::MirrorSealedFamilyIncompleteChirho,
                "mirror prepare inline sealed payload address is not canonical hex",
            ));
        }
        inline_total_chirho =
            inline_total_chirho.saturating_add(payload_chirho.ciphertext_bytes_chirho.len());
    }
    if inline_total_chirho > RELAY_BODY_MAX_BYTES_CHIRHO {
        return Err(wire_too_large_error_chirho());
    }
    if !frame_chirho.prepare_frame_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(
            &frame_chirho.prepare_frame_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho,
            "mirror prepare digest is not canonical hex",
        ));
    }
    if !frame_chirho.sig_hex_chirho.is_empty() {
        validate_signature_hex_chirho(
            &frame_chirho.sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
        )?;
    }
    Ok(())
}

fn prepare_frame_digest_hex_chirho(frame_chirho: &PrepareMirrorClosureFrameV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(MIRROR_PREPARE_FRAME_DIGEST_DOMAIN_V1_CHIRHO);
    update_common_frame_digest_chirho(
        &mut hasher_chirho,
        &frame_chirho.schema_chirho,
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.target_node_id_chirho,
        &frame_chirho.consistency_group_digest_chirho,
        frame_chirho.expected_term_chirho,
        &frame_chirho.membership_view_digest_chirho,
        &frame_chirho.caller_idempotency_key_digest_chirho,
        &frame_chirho.mirror_closure_id_chirho,
    );
    update_lease_field_chirho(
        &mut hasher_chirho,
        frame_chirho.leader_lease_remaining_millis_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"manifest-digest-chirho",
        frame_chirho
            .manifest_chirho
            .manifest_digest_chirho()
            .as_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}

// ---------------------------------------------------------------------------------------------------
// FINALIZE
// ---------------------------------------------------------------------------------------------------

pub struct FinalizeMirrorReceiptFrameInputChirho {
    pub origin_node_id_chirho: String,
    pub target_node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub expected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub leader_lease_remaining_millis_chirho: Option<u64>,
    pub caller_idempotency_key_digest_chirho: String,
    pub mirror_closure_id_chirho: String,
    pub prepare_frame_digest_chirho: String,
    pub local_commit_binding_chirho: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeMirrorReceiptFrameV1Chirho {
    schema_chirho: String,
    origin_node_id_chirho: String,
    target_node_id_chirho: String,
    consistency_group_digest_chirho: String,
    expected_term_chirho: u64,
    membership_view_digest_chirho: String,
    leader_lease_remaining_millis_chirho: Option<u64>,
    caller_idempotency_key_digest_chirho: String,
    mirror_closure_id_chirho: String,
    prepare_frame_digest_chirho: String,
    local_commit_binding_chirho: String,
    finalize_frame_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedFinalizeMirrorReceiptFrameChirho {
    frame_chirho: FinalizeMirrorReceiptFrameV1Chirho,
}

impl PreparedFinalizeMirrorReceiptFrameChirho {
    pub fn new_chirho(
        input_chirho: FinalizeMirrorReceiptFrameInputChirho,
    ) -> Result<Self, MirrorContractErrorChirho> {
        let mut frame_chirho = FinalizeMirrorReceiptFrameV1Chirho {
            schema_chirho: MIRROR_FINALIZE_FRAME_SCHEMA_V1_CHIRHO.to_string(),
            origin_node_id_chirho: input_chirho.origin_node_id_chirho,
            target_node_id_chirho: input_chirho.target_node_id_chirho,
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            expected_term_chirho: input_chirho.expected_term_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            leader_lease_remaining_millis_chirho: input_chirho.leader_lease_remaining_millis_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            mirror_closure_id_chirho: input_chirho.mirror_closure_id_chirho,
            prepare_frame_digest_chirho: input_chirho.prepare_frame_digest_chirho,
            local_commit_binding_chirho: input_chirho.local_commit_binding_chirho,
            finalize_frame_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_finalize_semantics_chirho(&frame_chirho)?;
        frame_chirho.finalize_frame_digest_chirho = finalize_frame_digest_hex_chirho(&frame_chirho);
        Ok(Self { frame_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        crate::digest_chirho::decode_hex_32_chirho(&self.frame_chirho.finalize_frame_digest_chirho)
            .expect("a prepared finalize frame always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<FinalizeMirrorReceiptFrameV1Chirho, MirrorContractErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
        )?;
        self.frame_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.frame_chirho)
    }
}

impl FinalizeMirrorReceiptFrameV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, MirrorContractErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| wire_decode_error_chirho())?;
        if bytes_chirho.len() > MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO {
            return Err(wire_too_large_error_chirho());
        }
        Ok(bytes_chirho)
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.target_node_id_chirho
    }

    pub fn origin_node_id_chirho(&self) -> &str {
        &self.origin_node_id_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.expected_term_chirho
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.leader_lease_remaining_millis_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.caller_idempotency_key_digest_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.mirror_closure_id_chirho
    }

    pub fn prepare_frame_digest_chirho(&self) -> &str {
        &self.prepare_frame_digest_chirho
    }
}

pub struct VerifiedMirrorFinalizeChirho {
    frame_chirho: FinalizeMirrorReceiptFrameV1Chirho,
}

impl VerifiedMirrorFinalizeChirho {
    pub fn origin_node_id_chirho(&self) -> &str {
        &self.frame_chirho.origin_node_id_chirho
    }

    pub fn target_node_id_chirho(&self) -> &str {
        &self.frame_chirho.target_node_id_chirho
    }

    pub fn expected_term_chirho(&self) -> u64 {
        self.frame_chirho.expected_term_chirho
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.frame_chirho.membership_view_digest_chirho
    }

    pub fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.frame_chirho.leader_lease_remaining_millis_chirho
    }

    pub fn caller_idempotency_key_digest_chirho(&self) -> &str {
        &self.frame_chirho.caller_idempotency_key_digest_chirho
    }

    pub fn mirror_closure_id_chirho(&self) -> &str {
        &self.frame_chirho.mirror_closure_id_chirho
    }

    pub fn prepare_frame_digest_chirho(&self) -> &str {
        &self.frame_chirho.prepare_frame_digest_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.frame_chirho.consistency_group_digest_chirho
    }

    pub fn local_commit_binding_chirho(&self) -> &str {
        &self.frame_chirho.local_commit_binding_chirho
    }
}

pub fn decode_and_verify_mirror_finalize_chirho(
    wire_bytes_chirho: &[u8],
    expected_group_digest_chirho: &str,
    expected_receiver_node_id_chirho: &str,
    roster_chirho: &RelayRosterChirho,
) -> Result<VerifiedMirrorFinalizeChirho, MirrorContractErrorChirho> {
    if wire_bytes_chirho.len() > MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO {
        return Err(wire_too_large_error_chirho());
    }
    let frame_chirho: FinalizeMirrorReceiptFrameV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| wire_decode_error_chirho())?;
    validate_finalize_semantics_chirho(&frame_chirho)?;
    if !roster_chirho.contains_chirho(&frame_chirho.origin_node_id_chirho) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorOriginUnrosteredChirho,
            "mirror finalize origin is not in the exact active roster",
        ));
    }
    if frame_chirho.consistency_group_digest_chirho != expected_group_digest_chirho {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorConsistencyGroupMismatchChirho,
            "mirror finalize group does not match the selected root",
        ));
    }
    if frame_chirho.target_node_id_chirho != expected_receiver_node_id_chirho
        || !roster_chirho.contains_chirho(expected_receiver_node_id_chirho)
    {
        return Err(MirrorContractErrorChirho::receiver_unrostered_chirho());
    }
    let expected_digest_chirho = finalize_frame_digest_hex_chirho(&frame_chirho);
    if frame_chirho.finalize_frame_digest_chirho != expected_digest_chirho {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho,
            "mirror finalize digest does not bind its semantic fields",
        ));
    }
    verify_node_signature_chirho(
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.finalize_frame_digest_chirho,
        &frame_chirho.sig_hex_chirho,
        MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
    )?;
    Ok(VerifiedMirrorFinalizeChirho { frame_chirho })
}

fn validate_finalize_semantics_chirho(
    frame_chirho: &FinalizeMirrorReceiptFrameV1Chirho,
) -> Result<(), MirrorContractErrorChirho> {
    if frame_chirho.schema_chirho != MIRROR_FINALIZE_FRAME_SCHEMA_V1_CHIRHO {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorSchemaUnsupportedChirho,
            "mirror finalize schema is unsupported",
        ));
    }
    validate_common_frame_fields_chirho(
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.target_node_id_chirho,
        &frame_chirho.consistency_group_digest_chirho,
        frame_chirho.expected_term_chirho,
        &frame_chirho.membership_view_digest_chirho,
        &frame_chirho.caller_idempotency_key_digest_chirho,
        &frame_chirho.mirror_closure_id_chirho,
    )?;
    if !valid_lower_hex_chirho(
        &frame_chirho.prepare_frame_digest_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) || !valid_lower_hex_chirho(
        &frame_chirho.local_commit_binding_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho,
            "mirror finalize prepare-digest or local-commit binding is not canonical hex",
        ));
    }
    if !frame_chirho.finalize_frame_digest_chirho.is_empty()
        && !valid_lower_hex_chirho(
            &frame_chirho.finalize_frame_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorFrameDigestMismatchChirho,
            "mirror finalize digest is not canonical hex",
        ));
    }
    if !frame_chirho.sig_hex_chirho.is_empty() {
        validate_signature_hex_chirho(
            &frame_chirho.sig_hex_chirho,
            MirrorRefusalIdentityChirho::MirrorRequestSignatureInvalidChirho,
        )?;
    }
    Ok(())
}

fn finalize_frame_digest_hex_chirho(frame_chirho: &FinalizeMirrorReceiptFrameV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(MIRROR_FINALIZE_FRAME_DIGEST_DOMAIN_V1_CHIRHO);
    update_common_frame_digest_chirho(
        &mut hasher_chirho,
        &frame_chirho.schema_chirho,
        &frame_chirho.origin_node_id_chirho,
        &frame_chirho.target_node_id_chirho,
        &frame_chirho.consistency_group_digest_chirho,
        frame_chirho.expected_term_chirho,
        &frame_chirho.membership_view_digest_chirho,
        &frame_chirho.caller_idempotency_key_digest_chirho,
        &frame_chirho.mirror_closure_id_chirho,
    );
    update_lease_field_chirho(
        &mut hasher_chirho,
        frame_chirho.leader_lease_remaining_millis_chirho,
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"prepare-frame-digest-chirho",
        frame_chirho.prepare_frame_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"local-commit-binding-chirho",
        frame_chirho.local_commit_binding_chirho.as_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}

// ---------------------------------------------------------------------------------------------------
// Shared field validation + digest
// ---------------------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn validate_common_frame_fields_chirho(
    origin_node_id_chirho: &str,
    target_node_id_chirho: &str,
    consistency_group_digest_chirho: &str,
    expected_term_chirho: u64,
    membership_view_digest_chirho: &str,
    caller_idempotency_key_digest_chirho: &str,
    mirror_closure_id_chirho: &str,
) -> Result<(), MirrorContractErrorChirho> {
    if !valid_lower_hex_chirho(origin_node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
        || !valid_lower_hex_chirho(target_node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
    {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorOriginNodeInvalidChirho,
            "mirror frame node ids must be canonical public-key hex",
        ));
    }
    if !valid_lower_hex_chirho(consistency_group_digest_chirho, DIGEST_HEX_BYTES_CHIRHO) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorConsistencyGroupMismatchChirho,
            "mirror frame group digest is not canonical hex",
        ));
    }
    if expected_term_chirho == 0 {
        return Err(MirrorContractErrorChirho::term_invalid_chirho());
    }
    if !valid_lower_hex_chirho(membership_view_digest_chirho, DIGEST_HEX_BYTES_CHIRHO) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho,
            "mirror frame membership view digest is not canonical hex",
        ));
    }
    if !valid_lower_hex_chirho(
        caller_idempotency_key_digest_chirho,
        DIGEST_HEX_BYTES_CHIRHO,
    ) {
        return Err(MirrorContractErrorChirho::caller_key_missing_chirho());
    }
    if !valid_lower_hex_chirho(mirror_closure_id_chirho, DIGEST_HEX_BYTES_CHIRHO) {
        return Err(MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorManifestDigestMismatchChirho,
            "mirror frame closure id is not canonical hex",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_common_frame_digest_chirho(
    hasher_chirho: &mut blake3::Hasher,
    schema_chirho: &str,
    origin_node_id_chirho: &str,
    target_node_id_chirho: &str,
    consistency_group_digest_chirho: &str,
    expected_term_chirho: u64,
    membership_view_digest_chirho: &str,
    caller_idempotency_key_digest_chirho: &str,
    mirror_closure_id_chirho: &str,
) {
    update_digest_field_chirho(hasher_chirho, b"schema-chirho", schema_chirho.as_bytes());
    update_digest_field_chirho(
        hasher_chirho,
        b"origin-node-id-chirho",
        origin_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"target-node-id-chirho",
        target_node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"group-digest-chirho",
        consistency_group_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"expected-term-chirho",
        &expected_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"membership-view-digest-chirho",
        membership_view_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"caller-key-digest-chirho",
        caller_idempotency_key_digest_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        hasher_chirho,
        b"mirror-closure-id-chirho",
        mirror_closure_id_chirho.as_bytes(),
    );
}

fn wire_decode_error_chirho() -> MirrorContractErrorChirho {
    MirrorContractErrorChirho::new_chirho(
        MirrorRefusalIdentityChirho::MirrorWireDecodeRefusedChirho,
        "mirror frame wire envelope could not be decoded exactly",
    )
}

fn wire_too_large_error_chirho() -> MirrorContractErrorChirho {
    MirrorContractErrorChirho::new_chirho(
        MirrorRefusalIdentityChirho::MirrorWireTooLargeChirho,
        "mirror frame wire envelope exceeds its fixed bound",
    )
}
