// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Two-authority resident-writer adoption for an activated tenant migration.
//!
//! Destination authority chooses the target. Activation authority separately authorizes minting a
//! resident identity over that target's existing journal. The source then witnesses durable target
//! activation before it can issue the one-use warrant consumed here at target startup.
//! A pending identity resumes only after its device/inode binding proves it belongs to this same
//! target root, so it is this root's interrupted mint rather than a second adoption entry point.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

mod store_chirho;

pub use store_chirho::TenantMigrationWriterAdoptionConsumptionRefusalChirho;
pub(crate) use store_chirho::{
    consume_writer_adoption_warrant_chirho, publish_writer_adoption_warrant_chirho,
};
#[cfg(test)]
pub(super) use store_chirho::{
    install_writer_adoption_post_mint_test_hook_chirho,
    install_writer_adoption_post_prepared_test_hook_chirho,
    replace_writer_adoption_warrant_for_replay_test_chirho,
};

use super::runtime_actor_chirho::target_adoption_chirho::TargetAdoptionPostureChirho;
use crate::authority_chirho::PinnedLedgerActivationVerifierChirho;
use cairn_ledger_tenant_migration_durable_chirho::{
    TenantMigrationDestinationRecordChirho, TenantMigrationOperationAuthorityBindingChirho,
    VerifiedTenantMigrationDestinationChirho,
};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-intent-v1-chirho";
pub const TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-record-v1-chirho";
pub const TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-intent-digest-v1-chirho";
pub const TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-record-signature-v1-chirho";
pub const MAX_TENANT_MIGRATION_WRITER_ADOPTION_RECORD_BYTES_CHIRHO: usize = 16 * 1024;
const MAX_TENANT_MIGRATION_WRITER_ADOPTION_LABEL_BYTES_CHIRHO: usize = 4096;
const TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-operation-authority-envelope-v1-chirho";
const TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V2_CHIRHO: &str =
    "tenant-migration-operation-authority-envelope-v2-chirho";
#[cfg(test)]
const TEST_CAPACITY_ADMISSION_IDENTITY_CHIRHO: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Activation-authority statement for one target-root writer-identity adoption.
///
/// A term is deliberately absent. The source-fence and final-sink identities carry the durable
/// authority coordinates; a live election term is restart-volatile and would make a crash retry
/// require a new offline ceremony for no additional root binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationWriterAdoptionIntentChirho {
    pub schema_chirho: String,
    pub digest_domain_chirho: String,
    pub tenant_id_chirho: String,
    pub source_root_digest_chirho: String,
    pub target_root_digest_chirho: String,
    pub destination_intent_digest_chirho: String,
    pub destination_revision_chirho: u64,
    pub source_control_node_id_chirho: String,
    pub target_instance_node_id_chirho: String,
    pub storage_namespace_chirho: String,
    pub journal_path_chirho: String,
    pub cluster_id_chirho: String,
    pub opening_epoch_chirho: u64,
    /// Minted by the authoring command from OS randomness; never caller-supplied text.
    pub attempt_nonce_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationWriterAdoptionRecordChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: TenantMigrationWriterAdoptionIntentChirho,
    pub intent_digest_chirho: String,
    pub activation_principal_chirho: String,
    pub signature_hex_chirho: String,
}

/// Live coordinates that a signed writer-adoption intent must match exactly.
pub struct TenantMigrationWriterAdoptionExpectedChirho<'expected_chirho> {
    pub tenant_id_chirho: &'expected_chirho str,
    pub source_root_digest_chirho: &'expected_chirho str,
    pub target_root_digest_chirho: &'expected_chirho str,
    pub destination_intent_digest_chirho: &'expected_chirho str,
    pub destination_revision_chirho: u64,
    pub source_control_node_id_chirho: &'expected_chirho str,
    pub target_instance_node_id_chirho: &'expected_chirho str,
    pub storage_namespace_chirho: &'expected_chirho str,
    pub journal_path_chirho: &'expected_chirho str,
    pub cluster_id_chirho: &'expected_chirho str,
    pub opening_epoch_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTenantMigrationWriterAdoptionChirho {
    intent_digest_chirho: String,
    source_control_node_id_chirho: String,
    target_instance_node_id_chirho: String,
    target_root_digest_chirho: String,
}

impl VerifiedTenantMigrationWriterAdoptionChirho {
    pub fn intent_digest_chirho(&self) -> &str {
        &self.intent_digest_chirho
    }

    pub fn source_control_node_id_chirho(&self) -> &str {
        &self.source_control_node_id_chirho
    }

    pub fn target_instance_node_id_chirho(&self) -> &str {
        &self.target_instance_node_id_chirho
    }

    pub fn target_root_digest_chirho(&self) -> &str {
        &self.target_root_digest_chirho
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationWriterAdoptionRefusalChirho {
    SchemaChirho,
    DigestDomainChirho,
    SignatureDomainChirho,
    TenantIdentityChirho,
    SourceRootBindingChirho,
    TargetRootBindingChirho,
    DestinationIntentBindingChirho,
    DestinationRevisionBindingChirho,
    SourceControlNodeBindingChirho,
    TargetInstanceNodeBindingChirho,
    StorageNamespaceBindingChirho,
    JournalPathBindingChirho,
    ClusterBindingChirho,
    OpeningEpochBindingChirho,
    AttemptNonceShapeChirho,
    FieldShapeChirho,
    IntentDigestChirho,
    ActivationPrincipalChirho,
    SignatureChirho,
    EncodeChirho,
}

pub fn tenant_migration_writer_adoption_intent_digest_chirho(
    intent_chirho: &TenantMigrationWriterAdoptionIntentChirho,
) -> Result<String, TenantMigrationWriterAdoptionRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(intent_chirho)
        .map_err(|_error_chirho| TenantMigrationWriterAdoptionRefusalChirho::EncodeChirho)?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

pub fn unsigned_tenant_migration_writer_adoption_message_chirho(
    record_chirho: &TenantMigrationWriterAdoptionRecordChirho,
) -> String {
    format!(
        "{}:{}:{}",
        record_chirho.signature_domain_chirho,
        record_chirho.activation_principal_chirho,
        record_chirho.intent_digest_chirho
    )
}

pub fn verify_tenant_migration_writer_adoption_record_chirho(
    record_chirho: &TenantMigrationWriterAdoptionRecordChirho,
    verifier_chirho: &PinnedLedgerActivationVerifierChirho,
    expected_chirho: TenantMigrationWriterAdoptionExpectedChirho<'_>,
) -> Result<VerifiedTenantMigrationWriterAdoptionChirho, TenantMigrationWriterAdoptionRefusalChirho>
{
    if record_chirho.schema_chirho != TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO
        || record_chirho.intent_chirho.schema_chirho
            != TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO
    {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::SchemaChirho);
    }
    if record_chirho.intent_chirho.digest_domain_chirho
        != TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO
    {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::DigestDomainChirho);
    }
    if record_chirho.signature_domain_chirho
        != TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO
    {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::SignatureDomainChirho);
    }
    let intent_chirho = &record_chirho.intent_chirho;
    let comparisons_chirho = [
        (
            intent_chirho.tenant_id_chirho == expected_chirho.tenant_id_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::TenantIdentityChirho,
        ),
        (
            intent_chirho.source_root_digest_chirho == expected_chirho.source_root_digest_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::SourceRootBindingChirho,
        ),
        (
            intent_chirho.target_root_digest_chirho == expected_chirho.target_root_digest_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::TargetRootBindingChirho,
        ),
        (
            intent_chirho.destination_intent_digest_chirho
                == expected_chirho.destination_intent_digest_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::DestinationIntentBindingChirho,
        ),
        (
            intent_chirho.destination_revision_chirho
                == expected_chirho.destination_revision_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::DestinationRevisionBindingChirho,
        ),
        (
            intent_chirho.source_control_node_id_chirho
                == expected_chirho.source_control_node_id_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::SourceControlNodeBindingChirho,
        ),
        (
            intent_chirho.target_instance_node_id_chirho
                == expected_chirho.target_instance_node_id_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::TargetInstanceNodeBindingChirho,
        ),
        (
            intent_chirho.storage_namespace_chirho == expected_chirho.storage_namespace_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::StorageNamespaceBindingChirho,
        ),
        (
            intent_chirho.journal_path_chirho == expected_chirho.journal_path_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::JournalPathBindingChirho,
        ),
        (
            intent_chirho.cluster_id_chirho == expected_chirho.cluster_id_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::ClusterBindingChirho,
        ),
        (
            intent_chirho.opening_epoch_chirho == expected_chirho.opening_epoch_chirho,
            TenantMigrationWriterAdoptionRefusalChirho::OpeningEpochBindingChirho,
        ),
    ];
    for (matches_chirho, refusal_chirho) in comparisons_chirho {
        if !matches_chirho {
            return Err(refusal_chirho);
        }
    }
    if !is_lower_hex_digest_chirho(&intent_chirho.attempt_nonce_chirho) {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::AttemptNonceShapeChirho);
    }
    if ![
        &intent_chirho.source_root_digest_chirho,
        &intent_chirho.target_root_digest_chirho,
        &intent_chirho.destination_intent_digest_chirho,
        &intent_chirho.source_control_node_id_chirho,
        &intent_chirho.target_instance_node_id_chirho,
    ]
    .into_iter()
    .all(|value_chirho| is_lower_hex_digest_chirho(value_chirho))
        || !is_bounded_field_chirho(&intent_chirho.tenant_id_chirho)
        || !is_bounded_field_chirho(&intent_chirho.storage_namespace_chirho)
        || !is_bounded_field_chirho(&intent_chirho.journal_path_chirho)
        || !is_bounded_field_chirho(&intent_chirho.cluster_id_chirho)
    {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::FieldShapeChirho);
    }
    let intent_digest_chirho =
        tenant_migration_writer_adoption_intent_digest_chirho(intent_chirho)?;
    if record_chirho.intent_digest_chirho != intent_digest_chirho {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::IntentDigestChirho);
    }
    if record_chirho.activation_principal_chirho != verifier_chirho.principal_chirho() {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::ActivationPrincipalChirho);
    }
    let message_chirho = unsigned_tenant_migration_writer_adoption_message_chirho(record_chirho);
    if !verifier_chirho.verify_canonical_statement_chirho(
        &record_chirho.activation_principal_chirho,
        message_chirho.as_bytes(),
        &record_chirho.signature_hex_chirho,
    ) {
        return Err(TenantMigrationWriterAdoptionRefusalChirho::SignatureChirho);
    }
    Ok(VerifiedTenantMigrationWriterAdoptionChirho {
        intent_digest_chirho,
        source_control_node_id_chirho: intent_chirho.source_control_node_id_chirho.clone(),
        target_instance_node_id_chirho: intent_chirho.target_instance_node_id_chirho.clone(),
        target_root_digest_chirho: intent_chirho.target_root_digest_chirho.clone(),
    })
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn is_bounded_field_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= MAX_TENANT_MIGRATION_WRITER_ADOPTION_LABEL_BYTES_CHIRHO
        && !value_chirho.contains(['\0', '\n', '\r'])
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub(super) enum TenantMigrationTargetWriterPostureChirho {
    ExistingIdentityChirho {
        identity_digest_chirho: String,
    },
    AuthorizedAdoptionChirho {
        adoption_chirho: Box<TenantMigrationWriterAdoptionRecordChirho>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TenantMigrationOperationAuthorityEnvelopeChirho {
    schema_chirho: String,
    destination_chirho: TenantMigrationDestinationRecordChirho,
    target_writer_posture_chirho: TenantMigrationTargetWriterPostureChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capacity_admission_identity_chirho: Option<String>,
}

impl TenantMigrationOperationAuthorityEnvelopeChirho {
    pub(super) fn destination_chirho(&self) -> &TenantMigrationDestinationRecordChirho {
        &self.destination_chirho
    }

    pub(super) fn target_writer_posture_chirho(&self) -> &TenantMigrationTargetWriterPostureChirho {
        &self.target_writer_posture_chirho
    }

    pub(super) fn capacity_admission_identity_chirho(&self) -> Option<&str> {
        self.capacity_admission_identity_chirho.as_deref()
    }
}

pub(super) struct VerifiedTenantMigrationBeginAuthorityChirho {
    destination_chirho: TenantMigrationDestinationRecordChirho,
    target_writer_posture_chirho: TenantMigrationTargetWriterPostureChirho,
}

pub(super) struct TenantMigrationWriterAdoptionCoordinatesChirho<'coordinates_chirho> {
    pub source_control_node_id_chirho: &'coordinates_chirho str,
    pub storage_namespace_chirho: &'coordinates_chirho str,
    pub journal_path_chirho: &'coordinates_chirho str,
    pub cluster_id_chirho: &'coordinates_chirho str,
    pub opening_epoch_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationWriterAdoptionGateRefusalChirho {
    WriterAdoptionAuthorityRequiredChirho,
    WriterAdoptionAuthorityUnexpectedChirho,
    WriterAdoptionAuthorityUnavailableChirho,
    WriterAdoptionAuthorityChirho(TenantMigrationWriterAdoptionRefusalChirho),
    TargetInstanceKeyUnavailableChirho,
    OperationAuthorityMalformedChirho,
    ExistingIdentityChangedChirho,
    AdoptionIdentityIncompleteChirho,
    AdoptionIdentityAlreadyPresentChirho,
}

pub(super) fn verify_operation_authority_for_begin_chirho(
    destination_chirho: &TenantMigrationDestinationRecordChirho,
    verified_destination_chirho: &VerifiedTenantMigrationDestinationChirho,
    adoption_chirho: Option<&TenantMigrationWriterAdoptionRecordChirho>,
    activation_verifier_chirho: Option<&PinnedLedgerActivationVerifierChirho>,
    target_root_chirho: &Path,
    target_posture_chirho: &TargetAdoptionPostureChirho,
    coordinates_chirho: TenantMigrationWriterAdoptionCoordinatesChirho<'_>,
) -> Result<
    VerifiedTenantMigrationBeginAuthorityChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let target_writer_posture_chirho = match (target_posture_chirho, adoption_chirho) {
        (
            TargetAdoptionPostureChirho::IdentityBoundChirho {
                identity_digest_chirho,
            },
            None,
        ) => TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho {
            identity_digest_chirho: identity_digest_chirho.clone(),
        },
        (TargetAdoptionPostureChirho::IdentityBoundChirho { .. }, Some(_adoption_chirho)) => {
            return Err(
                TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnexpectedChirho,
            )
        }
        (TargetAdoptionPostureChirho::IdentityAbsentChirho, None) => {
            return Err(
                TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityRequiredChirho,
            )
        }
        (TargetAdoptionPostureChirho::IdentityAbsentChirho, Some(adoption_chirho)) => {
            let activation_verifier_chirho = activation_verifier_chirho.ok_or(
                TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnavailableChirho,
            )?;
            verify_adoption_against_destination_chirho(
                adoption_chirho,
                activation_verifier_chirho,
                target_root_chirho,
                verified_destination_chirho,
                &destination_chirho.intent_digest_chirho,
                coordinates_chirho,
            )?;
            TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho {
                adoption_chirho: Box::new(adoption_chirho.clone()),
            }
        }
        (TargetAdoptionPostureChirho::IdentityPendingChirho { .. }, _) => {
            return Err(
                TenantMigrationWriterAdoptionGateRefusalChirho::AdoptionIdentityIncompleteChirho,
            )
        }
    };
    Ok(VerifiedTenantMigrationBeginAuthorityChirho {
        destination_chirho: destination_chirho.clone(),
        target_writer_posture_chirho,
    })
}

pub(super) fn encode_verified_operation_authority_for_begin_chirho(
    verified_begin_chirho: VerifiedTenantMigrationBeginAuthorityChirho,
    capacity_admission_identity_chirho: &str,
) -> Result<
    TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    if !is_nonzero_lower_hex_digest_chirho(capacity_admission_identity_chirho) {
        return Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho,
        );
    }
    encode_operation_authority_chirho(TenantMigrationOperationAuthorityEnvelopeChirho {
        schema_chirho: TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V2_CHIRHO.to_owned(),
        destination_chirho: verified_begin_chirho.destination_chirho,
        target_writer_posture_chirho: verified_begin_chirho.target_writer_posture_chirho,
        capacity_admission_identity_chirho: Some(capacity_admission_identity_chirho.to_owned()),
    })
}

#[cfg(test)]
pub(super) fn operation_authority_for_begin_chirho(
    destination_chirho: &TenantMigrationDestinationRecordChirho,
    verified_destination_chirho: &VerifiedTenantMigrationDestinationChirho,
    adoption_chirho: Option<&TenantMigrationWriterAdoptionRecordChirho>,
    activation_verifier_chirho: Option<&PinnedLedgerActivationVerifierChirho>,
    target_root_chirho: &Path,
    target_posture_chirho: &TargetAdoptionPostureChirho,
    coordinates_chirho: TenantMigrationWriterAdoptionCoordinatesChirho<'_>,
) -> Result<
    TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let verified_begin_chirho = verify_operation_authority_for_begin_chirho(
        destination_chirho,
        verified_destination_chirho,
        adoption_chirho,
        activation_verifier_chirho,
        target_root_chirho,
        target_posture_chirho,
        coordinates_chirho,
    )?;
    encode_verified_operation_authority_for_begin_chirho(
        verified_begin_chirho,
        TEST_CAPACITY_ADMISSION_IDENTITY_CHIRHO,
    )
}

pub(super) fn parse_operation_authority_chirho(
    binding_chirho: &TenantMigrationOperationAuthorityBindingChirho,
) -> Result<
    TenantMigrationOperationAuthorityEnvelopeChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let envelope_chirho: TenantMigrationOperationAuthorityEnvelopeChirho = serde_json::from_str(
        binding_chirho.canonical_payload_chirho(),
    )
    .map_err(|_error_chirho| {
        TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho
    })?;
    let schema_and_capacity_identity_match_chirho = match envelope_chirho.schema_chirho.as_str() {
        TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V1_CHIRHO => {
            envelope_chirho.capacity_admission_identity_chirho.is_none()
        }
        TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V2_CHIRHO => envelope_chirho
            .capacity_admission_identity_chirho
            .as_deref()
            .is_some_and(is_nonzero_lower_hex_digest_chirho),
        _ => false,
    };
    if !schema_and_capacity_identity_match_chirho
        || canonical_json_chirho(&envelope_chirho).ok().as_deref()
            != Some(binding_chirho.canonical_payload_chirho())
    {
        return Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho,
        );
    }
    Ok(envelope_chirho)
}

#[cfg(test)]
pub(super) fn legacy_v1_operation_authority_for_test_chirho(
    binding_chirho: &TenantMigrationOperationAuthorityBindingChirho,
) -> Result<
    TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let mut envelope_chirho = parse_operation_authority_chirho(binding_chirho)?;
    envelope_chirho.schema_chirho =
        TENANT_MIGRATION_OPERATION_AUTHORITY_ENVELOPE_SCHEMA_V1_CHIRHO.to_owned();
    envelope_chirho.capacity_admission_identity_chirho = None;
    encode_operation_authority_chirho(envelope_chirho)
}

#[cfg(test)]
pub(super) fn malformed_v2_operation_authority_without_capacity_for_test_chirho(
    binding_chirho: &TenantMigrationOperationAuthorityBindingChirho,
) -> Result<
    TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let mut envelope_chirho = parse_operation_authority_chirho(binding_chirho)?;
    envelope_chirho.capacity_admission_identity_chirho = None;
    encode_operation_authority_chirho(envelope_chirho)
}

pub(super) fn verify_recovered_operation_authority_chirho(
    envelope_chirho: &TenantMigrationOperationAuthorityEnvelopeChirho,
    verified_destination_chirho: &VerifiedTenantMigrationDestinationChirho,
    activation_verifier_chirho: Option<&PinnedLedgerActivationVerifierChirho>,
    target_root_chirho: &Path,
    target_posture_chirho: &TargetAdoptionPostureChirho,
    coordinates_chirho: TenantMigrationWriterAdoptionCoordinatesChirho<'_>,
) -> Result<(), TenantMigrationWriterAdoptionGateRefusalChirho> {
    match (
        envelope_chirho.target_writer_posture_chirho(),
        target_posture_chirho,
    ) {
        (
            TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho {
                identity_digest_chirho: expected_identity_digest_chirho,
            },
            TargetAdoptionPostureChirho::IdentityBoundChirho {
                identity_digest_chirho: observed_identity_digest_chirho,
            },
        ) if expected_identity_digest_chirho == observed_identity_digest_chirho => Ok(()),
        (
            TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho { .. },
            TargetAdoptionPostureChirho::IdentityAbsentChirho,
        )
        | (
            TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho { .. },
            TargetAdoptionPostureChirho::IdentityPendingChirho { .. },
        )
        | (
            TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho { .. },
            TargetAdoptionPostureChirho::IdentityBoundChirho { .. },
        ) => Err(TenantMigrationWriterAdoptionGateRefusalChirho::ExistingIdentityChangedChirho),
        (
            TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho { adoption_chirho },
            TargetAdoptionPostureChirho::IdentityAbsentChirho,
        ) => {
            let activation_verifier_chirho = activation_verifier_chirho.ok_or(
                TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnavailableChirho,
            )?;
            verify_adoption_against_destination_chirho(
                adoption_chirho,
                activation_verifier_chirho,
                target_root_chirho,
                verified_destination_chirho,
                &envelope_chirho.destination_chirho.intent_digest_chirho,
                coordinates_chirho,
            )?;
            Ok(())
        }
        (
            TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho { .. },
            TargetAdoptionPostureChirho::IdentityPendingChirho { .. },
        ) => Err(TenantMigrationWriterAdoptionGateRefusalChirho::AdoptionIdentityIncompleteChirho),
        (
            TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho { .. },
            TargetAdoptionPostureChirho::IdentityBoundChirho { .. },
        ) => Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::AdoptionIdentityAlreadyPresentChirho,
        ),
    }
}

fn verify_adoption_against_destination_chirho(
    adoption_chirho: &TenantMigrationWriterAdoptionRecordChirho,
    activation_verifier_chirho: &PinnedLedgerActivationVerifierChirho,
    target_root_chirho: &Path,
    destination_chirho: &VerifiedTenantMigrationDestinationChirho,
    destination_intent_digest_chirho: &str,
    coordinates_chirho: TenantMigrationWriterAdoptionCoordinatesChirho<'_>,
) -> Result<
    VerifiedTenantMigrationWriterAdoptionChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let target_instance_node_id_chirho = existing_keypair_pubkey_hex_chirho(target_root_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionGateRefusalChirho::TargetInstanceKeyUnavailableChirho
        })?;
    verify_tenant_migration_writer_adoption_record_chirho(
        adoption_chirho,
        activation_verifier_chirho,
        TenantMigrationWriterAdoptionExpectedChirho {
            tenant_id_chirho: destination_chirho.tenant_id_chirho(),
            source_root_digest_chirho: destination_chirho.source_root_digest_chirho(),
            target_root_digest_chirho: destination_chirho.destination_root_digest_chirho(),
            destination_intent_digest_chirho,
            destination_revision_chirho: destination_chirho.revision_chirho(),
            source_control_node_id_chirho: coordinates_chirho.source_control_node_id_chirho,
            target_instance_node_id_chirho: &target_instance_node_id_chirho,
            storage_namespace_chirho: coordinates_chirho.storage_namespace_chirho,
            journal_path_chirho: coordinates_chirho.journal_path_chirho,
            cluster_id_chirho: coordinates_chirho.cluster_id_chirho,
            opening_epoch_chirho: coordinates_chirho.opening_epoch_chirho,
        },
    )
    .map_err(TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityChirho)
}

fn encode_operation_authority_chirho(
    envelope_chirho: TenantMigrationOperationAuthorityEnvelopeChirho,
) -> Result<
    TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
> {
    let canonical_payload_chirho =
        canonical_json_chirho(&envelope_chirho).map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho
        })?;
    TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(
        canonical_payload_chirho,
    )
    .map_err(|_refusal_chirho| {
        TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho
    })
}

fn canonical_json_chirho<TChirho: Serialize>(
    value_chirho: &TChirho,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&serde_json::to_value(value_chirho)?)
}

fn is_nonzero_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    is_lower_hex_digest_chirho(value_chirho)
        && value_chirho.bytes().any(|byte_chirho| byte_chirho != b'0')
}
