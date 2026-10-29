// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader's signed erasure-propagation requirement and its binding to the root's erasure record: what one erasure owes the holders, and the verified succession that carries an unrecorded attempt's obligations.
//!
//! C5 B3-a2. A requirement is fixed under the root's erasure lock before any key is unlinked. Its digest
//! binds every field, and the leader signs it with its EXISTING node key. A binding ties one requirement to
//! the digest of the erasure record the root appended at the same seq. Both are verified on every load
//! against the reader's context: one consistency group, one tenant lineage, one issuer. A record from
//! another context refuses under its own identity, so an old issuer after adoption is never read as
//! tampering, and never accepted either. A successor carries an earlier unrecorded requirement only as a
//! verified superset: the same subject, an older seq, its exact digest, and no fewer key ids or holders and
//! no smaller bound. Design: `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`,
//! section 5a, items 1 to 10.

use crate::digest_chirho::{
    decode_hex_32_chirho, update_digest_field_chirho, update_key_ids_field_chirho,
    valid_key_id_list_chirho, valid_lower_hex_chirho, validate_signature_hex_chirho,
    verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::erasure_chirho::status_chirho::ErasureRequirementChirho;
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ERASURE_PROPAGATION_REQUIREMENT_SCHEMA_V1_CHIRHO: &str =
    "erasure-propagation-requirement-v1-chirho";
pub const ERASURE_PROPAGATION_BINDING_SCHEMA_V1_CHIRHO: &str =
    "erasure-propagation-binding-v1-chirho";
const REQUIREMENT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-erasure-propagation-requirement-v1-chirho";
const BINDING_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-erasure-propagation-binding-v1-chirho";
/// The most holders one requirement may name.
pub const ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO: usize = 64;
/// The most earlier requirements one requirement may carry: one fewer than a subject directory holds.
pub const ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO: usize = 63;
/// The longest lineage field, C2.1's `CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO`. This crate is pure and
/// cannot see the signer's constant, so the store's tests pin the two equal.
pub const ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO: usize = 256;

/// Whose propagation records a reader accepts: one group, one tenant lineage and one issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasurePropagationContextChirho {
    consistency_group_digest_chirho: String,
    tenant_id_chirho: String,
    genesis_instance_id_chirho: String,
    issuer_node_id_chirho: String,
}

impl ErasurePropagationContextChirho {
    pub fn new_chirho(
        consistency_group_digest_chirho: &str,
        tenant_id_chirho: &str,
        genesis_instance_id_chirho: &str,
        issuer_node_id_chirho: &str,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let in_form_chirho =
            valid_lower_hex_chirho(consistency_group_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
                && valid_lineage_field_chirho(tenant_id_chirho)
                && valid_lineage_field_chirho(genesis_instance_id_chirho)
                && valid_lower_hex_chirho(issuer_node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO);
        if !in_form_chirho {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasurePropagationContextInvalidChirho,
                "the propagation context is not in form",
            ));
        }
        Ok(Self {
            consistency_group_digest_chirho: consistency_group_digest_chirho.to_string(),
            tenant_id_chirho: tenant_id_chirho.to_string(),
            genesis_instance_id_chirho: genesis_instance_id_chirho.to_string(),
            issuer_node_id_chirho: issuer_node_id_chirho.to_string(),
        })
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn tenant_id_chirho(&self) -> &str {
        &self.tenant_id_chirho
    }

    pub fn genesis_instance_id_chirho(&self) -> &str {
        &self.genesis_instance_id_chirho
    }

    pub fn issuer_node_id_chirho(&self) -> &str {
        &self.issuer_node_id_chirho
    }
}

/// One earlier requirement a successor carries, by its seq and exact digest.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasurePropagationRefChirho {
    pub erasure_seq_chirho: u64,
    pub requirement_digest_chirho: String,
}

/// What the leader fixes for one erasure, before it is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasurePropagationRequirementInputChirho {
    pub subject_digest_chirho: String,
    pub erasure_seq_chirho: u64,
    /// Every blob of the subject below this seq is covered.
    pub erased_below_blob_seq_chirho: u64,
    pub key_ids_chirho: BTreeSet<String>,
    pub holders_chirho: BTreeSet<String>,
    pub succeeds_chirho: BTreeSet<ErasurePropagationRefChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasurePropagationRequirementV1Chirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    tenant_id_chirho: String,
    genesis_instance_id_chirho: String,
    subject_digest_chirho: String,
    erasure_seq_chirho: u64,
    erased_below_blob_seq_chirho: u64,
    key_ids_chirho: Vec<String>,
    holders_chirho: Vec<String>,
    succeeds_chirho: Vec<ErasurePropagationRefChirho>,
    issued_by_node_id_chirho: String,
    requirement_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedErasurePropagationRequirementChirho {
    requirement_chirho: ErasurePropagationRequirementV1Chirho,
}

impl PreparedErasurePropagationRequirementChirho {
    /// Fix and digest a requirement for the context's group, lineage and issuer. It refuses one out of form
    /// or over its bounds: no holder, too many holders, key ids or carried requirements, or a carried
    /// requirement that is not older.
    pub fn new_chirho(
        context_chirho: &ErasurePropagationContextChirho,
        input_chirho: ErasurePropagationRequirementInputChirho,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let mut requirement_chirho = ErasurePropagationRequirementV1Chirho {
            schema_chirho: ERASURE_PROPAGATION_REQUIREMENT_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: context_chirho.consistency_group_digest_chirho.clone(),
            tenant_id_chirho: context_chirho.tenant_id_chirho.clone(),
            genesis_instance_id_chirho: context_chirho.genesis_instance_id_chirho.clone(),
            subject_digest_chirho: input_chirho.subject_digest_chirho,
            erasure_seq_chirho: input_chirho.erasure_seq_chirho,
            erased_below_blob_seq_chirho: input_chirho.erased_below_blob_seq_chirho,
            key_ids_chirho: input_chirho.key_ids_chirho.into_iter().collect(),
            holders_chirho: input_chirho.holders_chirho.into_iter().collect(),
            succeeds_chirho: input_chirho.succeeds_chirho.into_iter().collect(),
            issued_by_node_id_chirho: context_chirho.issuer_node_id_chirho.clone(),
            requirement_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_requirement_chirho(&requirement_chirho)?;
        requirement_chirho.requirement_digest_chirho =
            requirement_digest_hex_chirho(&requirement_chirho);
        Ok(Self { requirement_chirho })
    }

    pub fn requirement_digest_chirho(&self) -> &str {
        &self.requirement_chirho.requirement_digest_chirho
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.requirement_chirho.requirement_digest_chirho)
            .expect("a prepared requirement always carries its digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ErasurePropagationRequirementV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho,
        )?;
        self.requirement_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.requirement_chirho)
    }
}

impl ErasurePropagationRequirementV1Chirho {
    /// Accept a stored requirement only if it is in form, for the reader's own context, bound by its
    /// digest, and signed by that context's issuer.
    pub fn verify_chirho(
        &self,
        context_chirho: &ErasurePropagationContextChirho,
    ) -> Result<VerifiedErasurePropagationRequirementChirho, KeyCustodyErrorChirho> {
        validate_requirement_chirho(self)?;
        if self.consistency_group_digest_chirho != context_chirho.consistency_group_digest_chirho
            || self.tenant_id_chirho != context_chirho.tenant_id_chirho
            || self.genesis_instance_id_chirho != context_chirho.genesis_instance_id_chirho
            || self.issued_by_node_id_chirho != context_chirho.issuer_node_id_chirho
        {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho,
                "the requirement is for another group, lineage or issuer",
            ));
        }
        let invalid_chirho =
            KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho;
        if self.requirement_digest_chirho != requirement_digest_hex_chirho(self) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the requirement digest does not bind its fields",
            ));
        }
        let digest_chirho = decode_hex_32_chirho(&self.requirement_digest_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "requirement digest is not 32 bytes"))?;
        verify_node_signature_chirho(
            &self.issued_by_node_id_chirho,
            &digest_chirho,
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedErasurePropagationRequirementChirho {
            requirement_chirho: self.clone(),
        })
    }
}

/// A requirement its issuer signed, for the reader's context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedErasurePropagationRequirementChirho {
    requirement_chirho: ErasurePropagationRequirementV1Chirho,
}

impl VerifiedErasurePropagationRequirementChirho {
    pub fn record_chirho(&self) -> &ErasurePropagationRequirementV1Chirho {
        &self.requirement_chirho
    }

    pub fn subject_digest_chirho(&self) -> &str {
        &self.requirement_chirho.subject_digest_chirho
    }

    pub fn erasure_seq_chirho(&self) -> u64 {
        self.requirement_chirho.erasure_seq_chirho
    }

    pub fn erased_below_blob_seq_chirho(&self) -> u64 {
        self.requirement_chirho.erased_below_blob_seq_chirho
    }

    pub fn key_ids_chirho(&self) -> &[String] {
        &self.requirement_chirho.key_ids_chirho
    }

    pub fn holders_chirho(&self) -> &[String] {
        &self.requirement_chirho.holders_chirho
    }

    pub fn succeeds_chirho(&self) -> &[ErasurePropagationRefChirho] {
        &self.requirement_chirho.succeeds_chirho
    }

    pub fn requirement_digest_chirho(&self) -> &str {
        &self.requirement_chirho.requirement_digest_chirho
    }

    /// How a successor names this requirement.
    pub fn reference_chirho(&self) -> ErasurePropagationRefChirho {
        ErasurePropagationRefChirho {
            erasure_seq_chirho: self.requirement_chirho.erasure_seq_chirho,
            requirement_digest_chirho: self.requirement_chirho.requirement_digest_chirho.clone(),
        }
    }

    /// The requirement `erasure_status_chirho` checks receipts and attestations against.
    pub fn status_requirement_chirho(
        &self,
    ) -> Result<ErasureRequirementChirho, KeyCustodyErrorChirho> {
        ErasureRequirementChirho::new_chirho(
            self.requirement_chirho
                .consistency_group_digest_chirho
                .clone(),
            self.requirement_chirho.subject_digest_chirho.clone(),
            self.requirement_chirho.erased_below_blob_seq_chirho,
            self.requirement_chirho
                .key_ids_chirho
                .iter()
                .cloned()
                .collect(),
            self.requirement_chirho
                .holders_chirho
                .iter()
                .cloned()
                .collect(),
        )
    }

    /// Whether this requirement carries `predecessor_chirho` exactly: it names the predecessor's seq and
    /// digest, the predecessor is older and of the same subject, group and lineage, and this requirement's
    /// key ids, holders and bound cover it.
    pub fn verify_carries_chirho(
        &self,
        predecessor_chirho: &Self,
    ) -> Result<(), KeyCustodyErrorChirho> {
        let invalid_chirho =
            KeyCustodyRefusalIdentityChirho::ErasurePropagationSuccessionInvalidChirho;
        let successor_chirho = &self.requirement_chirho;
        let carried_chirho = &predecessor_chirho.requirement_chirho;
        if !successor_chirho
            .succeeds_chirho
            .contains(&predecessor_chirho.reference_chirho())
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "the successor does not name this predecessor exactly",
            ));
        }
        if carried_chirho.subject_digest_chirho != successor_chirho.subject_digest_chirho
            || carried_chirho.consistency_group_digest_chirho
                != successor_chirho.consistency_group_digest_chirho
            || carried_chirho.tenant_id_chirho != successor_chirho.tenant_id_chirho
            || carried_chirho.genesis_instance_id_chirho
                != successor_chirho.genesis_instance_id_chirho
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "the predecessor is for another subject, group or lineage",
            ));
        }
        if carried_chirho.erasure_seq_chirho >= successor_chirho.erasure_seq_chirho {
            return Err(refuse_chirho(
                invalid_chirho,
                "the predecessor is not older",
            ));
        }
        if !covers_chirho(
            &successor_chirho.key_ids_chirho,
            &carried_chirho.key_ids_chirho,
        ) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the successor drops a key id of its predecessor",
            ));
        }
        if !covers_chirho(
            &successor_chirho.holders_chirho,
            &carried_chirho.holders_chirho,
        ) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the successor drops a holder of its predecessor",
            ));
        }
        if carried_chirho.erased_below_blob_seq_chirho
            > successor_chirho.erased_below_blob_seq_chirho
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "the successor's bound is below its predecessor's",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasurePropagationBindingV1Chirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    tenant_id_chirho: String,
    genesis_instance_id_chirho: String,
    subject_digest_chirho: String,
    erasure_seq_chirho: u64,
    requirement_digest_chirho: String,
    erasure_record_digest_chirho: String,
    issued_by_node_id_chirho: String,
    binding_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedErasurePropagationBindingChirho {
    binding_chirho: ErasurePropagationBindingV1Chirho,
}

impl PreparedErasurePropagationBindingChirho {
    /// Bind a verified requirement to the digest of the erasure record the root appended at its seq.
    pub fn new_chirho(
        context_chirho: &ErasurePropagationContextChirho,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
        erasure_record_digest_chirho: &str,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let record_chirho = &requirement_chirho.requirement_chirho;
        let mut binding_chirho = ErasurePropagationBindingV1Chirho {
            schema_chirho: ERASURE_PROPAGATION_BINDING_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: context_chirho.consistency_group_digest_chirho.clone(),
            tenant_id_chirho: context_chirho.tenant_id_chirho.clone(),
            genesis_instance_id_chirho: context_chirho.genesis_instance_id_chirho.clone(),
            subject_digest_chirho: record_chirho.subject_digest_chirho.clone(),
            erasure_seq_chirho: record_chirho.erasure_seq_chirho,
            requirement_digest_chirho: record_chirho.requirement_digest_chirho.clone(),
            erasure_record_digest_chirho: erasure_record_digest_chirho.to_string(),
            issued_by_node_id_chirho: context_chirho.issuer_node_id_chirho.clone(),
            binding_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_binding_chirho(&binding_chirho)?;
        if !binding_matches_requirement_chirho(&binding_chirho, requirement_chirho) {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho,
                "the requirement is for another group or lineage than this context",
            ));
        }
        binding_chirho.binding_digest_chirho = binding_digest_hex_chirho(&binding_chirho);
        Ok(Self { binding_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.binding_chirho.binding_digest_chirho)
            .expect("a prepared binding always carries its digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ErasurePropagationBindingV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::ErasurePropagationBindingInvalidChirho,
        )?;
        self.binding_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.binding_chirho)
    }
}

impl ErasurePropagationBindingV1Chirho {
    /// Accept a stored binding only if it is in form, for the reader's context, names exactly this
    /// verified requirement (its subject, seq and digest), is bound by its digest, and is signed by the
    /// context's issuer.
    pub fn verify_chirho(
        &self,
        context_chirho: &ErasurePropagationContextChirho,
        requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
    ) -> Result<VerifiedErasurePropagationBindingChirho, KeyCustodyErrorChirho> {
        validate_binding_chirho(self)?;
        if self.consistency_group_digest_chirho != context_chirho.consistency_group_digest_chirho
            || self.tenant_id_chirho != context_chirho.tenant_id_chirho
            || self.genesis_instance_id_chirho != context_chirho.genesis_instance_id_chirho
            || self.issued_by_node_id_chirho != context_chirho.issuer_node_id_chirho
        {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho,
                "the binding is for another group, lineage or issuer",
            ));
        }
        let invalid_chirho =
            KeyCustodyRefusalIdentityChirho::ErasurePropagationBindingInvalidChirho;
        if !binding_matches_requirement_chirho(self, requirement_chirho) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the binding names another requirement",
            ));
        }
        if self.binding_digest_chirho != binding_digest_hex_chirho(self) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the binding digest does not bind its fields",
            ));
        }
        let digest_chirho = decode_hex_32_chirho(&self.binding_digest_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "binding digest is not 32 bytes"))?;
        verify_node_signature_chirho(
            &self.issued_by_node_id_chirho,
            &digest_chirho,
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedErasurePropagationBindingChirho {
            binding_chirho: self.clone(),
        })
    }
}

/// A binding its issuer signed, for exactly one verified requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedErasurePropagationBindingChirho {
    binding_chirho: ErasurePropagationBindingV1Chirho,
}

impl VerifiedErasurePropagationBindingChirho {
    pub fn record_chirho(&self) -> &ErasurePropagationBindingV1Chirho {
        &self.binding_chirho
    }

    pub fn erasure_seq_chirho(&self) -> u64 {
        self.binding_chirho.erasure_seq_chirho
    }

    pub fn requirement_digest_chirho(&self) -> &str {
        &self.binding_chirho.requirement_digest_chirho
    }

    pub fn erasure_record_digest_chirho(&self) -> &str {
        &self.binding_chirho.erasure_record_digest_chirho
    }
}

fn valid_lineage_field_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO
        && !value_chirho.bytes().any(|byte_chirho| byte_chirho == 0)
}

fn valid_node_id_list_chirho(node_ids_chirho: &[String]) -> bool {
    node_ids_chirho
        .iter()
        .all(|node_id_chirho| valid_lower_hex_chirho(node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO))
        && node_ids_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0] < pair_chirho[1])
}

/// Whether every value of `smaller_chirho` is in `larger_chirho`; both are strictly ascending.
fn covers_chirho(larger_chirho: &[String], smaller_chirho: &[String]) -> bool {
    smaller_chirho
        .iter()
        .all(|value_chirho| larger_chirho.binary_search(value_chirho).is_ok())
}

fn validate_requirement_chirho(
    requirement_chirho: &ErasurePropagationRequirementV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let succeeds_chirho = &requirement_chirho.succeeds_chirho;
    let in_form_chirho = requirement_chirho.schema_chirho
        == ERASURE_PROPAGATION_REQUIREMENT_SCHEMA_V1_CHIRHO
        && valid_lower_hex_chirho(
            &requirement_chirho.consistency_group_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
        && valid_lineage_field_chirho(&requirement_chirho.tenant_id_chirho)
        && valid_lineage_field_chirho(&requirement_chirho.genesis_instance_id_chirho)
        && valid_lower_hex_chirho(
            &requirement_chirho.subject_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
        && valid_key_id_list_chirho(&requirement_chirho.key_ids_chirho)
        && !requirement_chirho.holders_chirho.is_empty()
        && requirement_chirho.holders_chirho.len() <= ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO
        && valid_node_id_list_chirho(&requirement_chirho.holders_chirho)
        && succeeds_chirho.len() <= ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO
        && succeeds_chirho.iter().all(|carried_chirho| {
            carried_chirho.erasure_seq_chirho < requirement_chirho.erasure_seq_chirho
                && valid_lower_hex_chirho(
                    &carried_chirho.requirement_digest_chirho,
                    DIGEST_HEX_BYTES_CHIRHO,
                )
        })
        && succeeds_chirho.windows(2).all(|pair_chirho| {
            pair_chirho[0].erasure_seq_chirho < pair_chirho[1].erasure_seq_chirho
        })
        && valid_lower_hex_chirho(
            &requirement_chirho.issued_by_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && (requirement_chirho.requirement_digest_chirho.is_empty()
            || valid_lower_hex_chirho(
                &requirement_chirho.requirement_digest_chirho,
                DIGEST_HEX_BYTES_CHIRHO,
            ));
    if !in_form_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho,
            "requirement fields are not in form or over their bounds",
        ));
    }
    Ok(())
}

fn validate_binding_chirho(
    binding_chirho: &ErasurePropagationBindingV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let in_form_chirho = binding_chirho.schema_chirho
        == ERASURE_PROPAGATION_BINDING_SCHEMA_V1_CHIRHO
        && [
            &binding_chirho.consistency_group_digest_chirho,
            &binding_chirho.subject_digest_chirho,
            &binding_chirho.requirement_digest_chirho,
            &binding_chirho.erasure_record_digest_chirho,
        ]
        .iter()
        .all(|value_chirho| valid_lower_hex_chirho(value_chirho, DIGEST_HEX_BYTES_CHIRHO))
        && valid_lineage_field_chirho(&binding_chirho.tenant_id_chirho)
        && valid_lineage_field_chirho(&binding_chirho.genesis_instance_id_chirho)
        && valid_lower_hex_chirho(
            &binding_chirho.issued_by_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && (binding_chirho.binding_digest_chirho.is_empty()
            || valid_lower_hex_chirho(
                &binding_chirho.binding_digest_chirho,
                DIGEST_HEX_BYTES_CHIRHO,
            ));
    if !in_form_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasurePropagationBindingInvalidChirho,
            "binding fields are not in form",
        ));
    }
    Ok(())
}

/// Whether a binding names exactly this requirement: its group, lineage, subject, seq and digest.
fn binding_matches_requirement_chirho(
    binding_chirho: &ErasurePropagationBindingV1Chirho,
    requirement_chirho: &VerifiedErasurePropagationRequirementChirho,
) -> bool {
    let record_chirho = &requirement_chirho.requirement_chirho;
    binding_chirho.consistency_group_digest_chirho == record_chirho.consistency_group_digest_chirho
        && binding_chirho.tenant_id_chirho == record_chirho.tenant_id_chirho
        && binding_chirho.genesis_instance_id_chirho == record_chirho.genesis_instance_id_chirho
        && binding_chirho.subject_digest_chirho == record_chirho.subject_digest_chirho
        && binding_chirho.erasure_seq_chirho == record_chirho.erasure_seq_chirho
        && binding_chirho.requirement_digest_chirho == record_chirho.requirement_digest_chirho
}

pub(crate) fn requirement_digest_hex_chirho(
    requirement_chirho: &ErasurePropagationRequirementV1Chirho,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(REQUIREMENT_DIGEST_DOMAIN_V1_CHIRHO);
    for (label_chirho, value_chirho) in [
        (&b"schema-chirho"[..], &requirement_chirho.schema_chirho),
        (
            &b"consistency-group-chirho"[..],
            &requirement_chirho.consistency_group_digest_chirho,
        ),
        (
            &b"tenant-id-chirho"[..],
            &requirement_chirho.tenant_id_chirho,
        ),
        (
            &b"genesis-instance-id-chirho"[..],
            &requirement_chirho.genesis_instance_id_chirho,
        ),
        (
            &b"subject-chirho"[..],
            &requirement_chirho.subject_digest_chirho,
        ),
        (
            &b"issued-by-chirho"[..],
            &requirement_chirho.issued_by_node_id_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"erasure-seq-chirho",
        &requirement_chirho.erasure_seq_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"erased-below-blob-seq-chirho",
        &requirement_chirho
            .erased_below_blob_seq_chirho
            .to_le_bytes(),
    );
    update_key_ids_field_chirho(
        &mut hasher_chirho,
        b"key-ids-chirho",
        requirement_chirho.key_ids_chirho.iter(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"holders-chirho",
        &(requirement_chirho.holders_chirho.len() as u64).to_le_bytes(),
    );
    for holder_chirho in &requirement_chirho.holders_chirho {
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"holder-chirho",
            holder_chirho.as_bytes(),
        );
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"succeeds-chirho",
        &(requirement_chirho.succeeds_chirho.len() as u64).to_le_bytes(),
    );
    for carried_chirho in &requirement_chirho.succeeds_chirho {
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"succeeds-seq-chirho",
            &carried_chirho.erasure_seq_chirho.to_le_bytes(),
        );
        update_digest_field_chirho(
            &mut hasher_chirho,
            b"succeeds-digest-chirho",
            carried_chirho.requirement_digest_chirho.as_bytes(),
        );
    }
    hasher_chirho.finalize().to_hex().to_string()
}

pub(crate) fn binding_digest_hex_chirho(
    binding_chirho: &ErasurePropagationBindingV1Chirho,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(BINDING_DIGEST_DOMAIN_V1_CHIRHO);
    for (label_chirho, value_chirho) in [
        (&b"schema-chirho"[..], &binding_chirho.schema_chirho),
        (
            &b"consistency-group-chirho"[..],
            &binding_chirho.consistency_group_digest_chirho,
        ),
        (&b"tenant-id-chirho"[..], &binding_chirho.tenant_id_chirho),
        (
            &b"genesis-instance-id-chirho"[..],
            &binding_chirho.genesis_instance_id_chirho,
        ),
        (
            &b"subject-chirho"[..],
            &binding_chirho.subject_digest_chirho,
        ),
        (
            &b"requirement-chirho"[..],
            &binding_chirho.requirement_digest_chirho,
        ),
        (
            &b"erasure-record-chirho"[..],
            &binding_chirho.erasure_record_digest_chirho,
        ),
        (
            &b"issued-by-chirho"[..],
            &binding_chirho.issued_by_node_id_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"erasure-seq-chirho",
        &binding_chirho.erasure_seq_chirho.to_le_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}
