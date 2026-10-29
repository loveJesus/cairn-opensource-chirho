// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader-signed attestation that a lost holder's media was destroyed, which closes that holder's share of an erasure it can no longer answer.
//!
//! It is the operator's statement, relayed and signed by the current leader, so it is only as true as
//! that statement; the command that asks for it must be operator-gated (B3). Two invariants keep it from
//! becoming a way around real erasure receipts (agy R-C5-5). First, a holder cannot be attested while
//! the placement still names it: the attestation carries the replacement placement's serving holders and
//! held observer, and refuses if the destroyed holder is among them; and verification, at USE time, also
//! refuses a holder the CALLER'S current view still places, so a signer cannot get past the first check by
//! declaring a replacement list of its own (agy #28783). Second, an erasure it closes reports
//! the distinct `ErasureConfirmedWithDecommissionedHolderAttestationChirho` status, naming the holder,
//! never the plain receipts-only status.

use crate::digest_chirho::{
    decode_hex_32_chirho, update_digest_field_chirho, valid_lower_hex_chirho,
    validate_signature_hex_chirho, verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO,
    NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use cairn_mirror_chirho::{
    verify_mirror_receiver_elected_leader_chirho, JoinedMirrorViewChirho,
    MirrorMembershipViewChirho,
};
use serde::{Deserialize, Serialize};

pub const DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO: &str =
    "holder-decommission-attestation-v1-chirho";
const DECOMMISSION_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-holder-decommission-attestation-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecommissionAttestationV1Chirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    decommissioned_holder_node_id_chirho: String,
    replacement_assignment_digest_chirho: String,
    replacement_view_digest_chirho: String,
    replacement_serving_holders_chirho: Vec<String>,
    replacement_held_observer_chirho: String,
    attested_by_node_id_chirho: String,
    elected_term_chirho: u64,
    attestation_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedDecommissionAttestationChirho {
    attestation_chirho: DecommissionAttestationV1Chirho,
}

impl PreparedDecommissionAttestationChirho {
    /// Prepare an attestation from the leader's own CURRENT joined view, which must already be the
    /// replacement placement: the destroyed holder may be neither a serving holder nor the held observer.
    pub fn new_chirho(
        joined_chirho: &JoinedMirrorViewChirho,
        attested_by_node_id_chirho: &str,
        decommissioned_holder_node_id_chirho: &str,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        verify_mirror_receiver_elected_leader_chirho(
            joined_chirho,
            attested_by_node_id_chirho,
            joined_chirho.term_chirho(),
        )
        .map_err(KeyCustodyErrorChirho::from_mirror_authority_chirho)?;
        let view_chirho = joined_chirho.view_chirho();
        if view_chirho.contains_chirho(decommissioned_holder_node_id_chirho) {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::DecommissionHolderStillPlacedChirho,
                "the current placement still names this holder",
            ));
        }
        let mut serving_chirho = view_chirho
            .holders_chirho()
            .iter()
            .map(|holder_chirho| holder_chirho.node_id_chirho().to_string())
            .collect::<Vec<_>>();
        serving_chirho.sort();
        let mut attestation_chirho = DecommissionAttestationV1Chirho {
            schema_chirho: DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: view_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            decommissioned_holder_node_id_chirho: decommissioned_holder_node_id_chirho.to_string(),
            replacement_assignment_digest_chirho: view_chirho
                .assignment_digest_chirho()
                .to_string(),
            replacement_view_digest_chirho: view_chirho.view_digest_chirho(),
            replacement_serving_holders_chirho: serving_chirho,
            replacement_held_observer_chirho: view_chirho
                .held_observer_chirho()
                .node_id_chirho()
                .to_string(),
            attested_by_node_id_chirho: attested_by_node_id_chirho.to_string(),
            elected_term_chirho: joined_chirho.term_chirho(),
            attestation_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_attestation_chirho(&attestation_chirho)?;
        attestation_chirho.attestation_digest_chirho =
            attestation_digest_hex_chirho(&attestation_chirho);
        Ok(Self { attestation_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.attestation_chirho.attestation_digest_chirho)
            .expect("a prepared attestation always carries its digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<DecommissionAttestationV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::DecommissionAttestationInvalidChirho,
        )?;
        self.attestation_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.attestation_chirho)
    }
}

impl DecommissionAttestationV1Chirho {
    /// Accept the attestation only if it is in form, the destroyed holder is outside both the replacement
    /// placement it names and the caller's CURRENT view, it is for the current view's group, its signer is
    /// one of the named placement's serving holders, and the signer signed it. Verify at the time of use,
    /// against the view the caller holds then.
    pub fn verify_chirho(
        &self,
        current_view_chirho: &MirrorMembershipViewChirho,
    ) -> Result<VerifiedDecommissionAttestationChirho, KeyCustodyErrorChirho> {
        validate_attestation_chirho(self)?;
        let invalid_chirho = KeyCustodyRefusalIdentityChirho::DecommissionAttestationInvalidChirho;
        if self.consistency_group_digest_chirho
            != current_view_chirho.consistency_group_digest_chirho()
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "the attestation is for another group",
            ));
        }
        if current_view_chirho.contains_chirho(&self.decommissioned_holder_node_id_chirho) {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::DecommissionHolderStillPlacedChirho,
                "the current placement still names this holder",
            ));
        }
        if self.attestation_digest_chirho != attestation_digest_hex_chirho(self) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the attestation digest does not bind its fields",
            ));
        }
        let digest_chirho = decode_hex_32_chirho(&self.attestation_digest_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "attestation digest is not 32 bytes"))?;
        verify_node_signature_chirho(
            &self.attested_by_node_id_chirho,
            &digest_chirho,
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedDecommissionAttestationChirho {
            attestation_chirho: self.clone(),
        })
    }
}

/// A destroyed-media attestation its leader signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDecommissionAttestationChirho {
    attestation_chirho: DecommissionAttestationV1Chirho,
}

impl VerifiedDecommissionAttestationChirho {
    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.attestation_chirho.consistency_group_digest_chirho
    }

    pub fn decommissioned_holder_node_id_chirho(&self) -> &str {
        &self.attestation_chirho.decommissioned_holder_node_id_chirho
    }

    pub fn attestation_digest_chirho(&self) -> &str {
        &self.attestation_chirho.attestation_digest_chirho
    }
}

fn validate_attestation_chirho(
    attestation_chirho: &DecommissionAttestationV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let holders_chirho = &attestation_chirho.replacement_serving_holders_chirho;
    let destroyed_chirho = &attestation_chirho.decommissioned_holder_node_id_chirho;
    let in_form_chirho = attestation_chirho.schema_chirho
        == DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO
        && [
            &attestation_chirho.consistency_group_digest_chirho,
            &attestation_chirho.replacement_assignment_digest_chirho,
            &attestation_chirho.replacement_view_digest_chirho,
        ]
        .iter()
        .all(|value_chirho| valid_lower_hex_chirho(value_chirho, DIGEST_HEX_BYTES_CHIRHO))
        && [
            destroyed_chirho,
            &attestation_chirho.replacement_held_observer_chirho,
            &attestation_chirho.attested_by_node_id_chirho,
        ]
        .iter()
        .all(|value_chirho| valid_lower_hex_chirho(value_chirho, NODE_ID_HEX_BYTES_CHIRHO))
        && holders_chirho.len() == 3
        && holders_chirho
            .iter()
            .all(|holder_chirho| valid_lower_hex_chirho(holder_chirho, NODE_ID_HEX_BYTES_CHIRHO))
        && holders_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0] < pair_chirho[1])
        && attestation_chirho.elected_term_chirho != 0
        && (attestation_chirho.attestation_digest_chirho.is_empty()
            || valid_lower_hex_chirho(
                &attestation_chirho.attestation_digest_chirho,
                DIGEST_HEX_BYTES_CHIRHO,
            ));
    if !in_form_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::DecommissionAttestationInvalidChirho,
            "attestation fields are not in form",
        ));
    }
    if holders_chirho.contains(destroyed_chirho)
        || &attestation_chirho.replacement_held_observer_chirho == destroyed_chirho
    {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::DecommissionHolderStillPlacedChirho,
            "the replacement placement still names the destroyed holder",
        ));
    }
    if !holders_chirho.contains(&attestation_chirho.attested_by_node_id_chirho) {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::DecommissionAttestationInvalidChirho,
            "the signer is not a serving holder of the replacement placement",
        ));
    }
    Ok(())
}

pub(crate) fn attestation_digest_hex_chirho(
    attestation_chirho: &DecommissionAttestationV1Chirho,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(DECOMMISSION_DIGEST_DOMAIN_V1_CHIRHO);
    for (label_chirho, value_chirho) in [
        (&b"schema-chirho"[..], &attestation_chirho.schema_chirho),
        (
            &b"consistency-group-chirho"[..],
            &attestation_chirho.consistency_group_digest_chirho,
        ),
        (
            &b"decommissioned-holder-chirho"[..],
            &attestation_chirho.decommissioned_holder_node_id_chirho,
        ),
        (
            &b"replacement-assignment-chirho"[..],
            &attestation_chirho.replacement_assignment_digest_chirho,
        ),
        (
            &b"replacement-view-chirho"[..],
            &attestation_chirho.replacement_view_digest_chirho,
        ),
        (
            &b"replacement-held-observer-chirho"[..],
            &attestation_chirho.replacement_held_observer_chirho,
        ),
        (
            &b"attested-by-chirho"[..],
            &attestation_chirho.attested_by_node_id_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    for holder_chirho in &attestation_chirho.replacement_serving_holders_chirho {
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"replacement-serving-holder-chirho",
            holder_chirho.as_bytes(),
        );
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"elected-term-chirho",
        &attestation_chirho.elected_term_chirho.to_le_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}
