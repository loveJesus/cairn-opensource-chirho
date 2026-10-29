// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Source-witnessed writer-adoption warrant and target-local one-use consumption.

use super::super::birth_chirho::ResidentLedgerBirthPermitChirho;
use super::super::runtime_actor_chirho::target_adoption_chirho::{
    inspect_target_adoption_posture_chirho, TargetAdoptionPostureChirho,
    TargetAdoptionRefusalChirho,
};
use super::super::{
    ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityRefusalChirho,
    ResidentLedgerLocalPortsChirho,
};
use super::{
    parse_operation_authority_chirho, verify_adoption_against_destination_chirho,
    TenantMigrationTargetWriterPostureChirho, TenantMigrationWriterAdoptionCoordinatesChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho,
};
use crate::authority_chirho::PinnedLedgerActivationVerifierChirho;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
use cairn_ledger_tenant_migration_durable_chirho::{
    verify_tenant_migration_destination_record_chirho, ActiveTenantMigrationChirho,
    TenantMigrationControlSignerPortChirho, TenantMigrationDestinationAuthorityPortChirho,
    TenantMigrationDestinationRefusalChirho, TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationPhaseChirho,
};
use cairn_signer_chirho::signer_chirho::{
    existing_keypair_pubkey_hex_chirho, sign_with_existing_key_possession_chirho,
    verify_with_pubkey_chirho,
};
use cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(test)]
std::thread_local! {
    static WRITER_ADOPTION_POST_PREPARED_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static WRITER_ADOPTION_POST_MINT_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn install_writer_adoption_post_prepared_test_hook_chirho(
    hook_chirho: impl FnOnce() + 'static,
) {
    WRITER_ADOPTION_POST_PREPARED_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
pub(crate) fn install_writer_adoption_post_mint_test_hook_chirho(
    hook_chirho: impl FnOnce() + 'static,
) {
    WRITER_ADOPTION_POST_MINT_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
pub(crate) fn replace_writer_adoption_warrant_for_replay_test_chirho(
    target_root_chirho: &Path,
    source_signer_chirho: &dyn TenantMigrationControlSignerPortChirho,
) {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(target_root_chirho)
        .expect("open target storage");
    let path_chirho = StoragePathChirho::new_chirho(WRITER_ADOPTION_WARRANT_PATH_CHIRHO);
    let bytes_chirho = read_bounded_chirho(
        &storage_chirho,
        &path_chirho,
        MAX_WRITER_ADOPTION_WARRANT_BYTES_CHIRHO,
    )
    .expect("read the source warrant")
    .expect("source warrant exists");
    let mut warrant_chirho: TenantMigrationWriterAdoptionWarrantChirho =
        parse_canonical_chirho(&bytes_chirho).expect("parse the source warrant");
    warrant_chirho.body_chirho.attempt_digest_chirho = "f".repeat(64);
    let message_chirho = signed_message_chirho(
        WRITER_ADOPTION_WARRANT_DOMAIN_V1_CHIRHO,
        &warrant_chirho.body_chirho,
    )
    .expect("encode the replay warrant message");
    warrant_chirho.source_signature_hex_chirho = source_signer_chirho
        .sign_chirho(&message_chirho)
        .expect("sign the replay warrant");
    storage_chirho
        .atomic_write_chirho(
            &path_chirho,
            &canonical_bytes_chirho(&warrant_chirho).expect("encode the replay warrant"),
        )
        .expect("persist the replay warrant");
}

#[cfg(test)]
fn run_writer_adoption_post_prepared_test_hook_chirho() {
    WRITER_ADOPTION_POST_PREPARED_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        if let Some(hook_chirho) = slot_chirho.borrow_mut().take() {
            hook_chirho();
        }
    });
}

#[cfg(test)]
fn run_writer_adoption_post_mint_test_hook_chirho() {
    WRITER_ADOPTION_POST_MINT_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        if let Some(hook_chirho) = slot_chirho.borrow_mut().take() {
            hook_chirho();
        }
    });
}

const WRITER_ADOPTION_WARRANT_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-warrant-v1-chirho";
const WRITER_ADOPTION_WARRANT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-warrant-signature-v1-chirho";
const WRITER_ADOPTION_CONSUMPTION_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-consumption-v1-chirho";
const WRITER_ADOPTION_CONSUMPTION_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-writer-adoption-consumption-signature-v1-chirho";
const WRITER_ADOPTION_WARRANT_PATH_CHIRHO: &str =
    "resident-writer-chirho/migration-adoption-warrant-chirho.json";
const WRITER_ADOPTION_CONSUMPTION_PATH_CHIRHO: &str =
    "resident-writer-chirho/migration-adoption-consumption-chirho.json";
const MAX_WRITER_ADOPTION_WARRANT_BYTES_CHIRHO: u64 = 48 * 1024;
const MAX_WRITER_ADOPTION_CONSUMPTION_BYTES_CHIRHO: u64 = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantMigrationWriterAdoptionWarrantBodyChirho {
    operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
    attempt_digest_chirho: String,
    activation_checkpoint_ref_chirho: String,
    activation_transition_seq_chirho: u64,
    fence_identity_digest_chirho: String,
    source_control_node_id_chirho: String,
    target_instance_node_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantMigrationWriterAdoptionWarrantChirho {
    schema_chirho: String,
    signature_domain_chirho: String,
    body_chirho: TenantMigrationWriterAdoptionWarrantBodyChirho,
    source_signature_hex_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
enum TenantMigrationWriterAdoptionConsumptionStateChirho {
    PreparedChirho,
    CompletedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantMigrationWriterAdoptionConsumptionBodyChirho {
    state_chirho: TenantMigrationWriterAdoptionConsumptionStateChirho,
    warrant_digest_chirho: String,
    attempt_digest_chirho: String,
    target_root_digest_chirho: String,
    target_instance_node_id_chirho: String,
    resident_identity_digest_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantMigrationWriterAdoptionConsumptionChirho {
    schema_chirho: String,
    signature_domain_chirho: String,
    body_chirho: TenantMigrationWriterAdoptionConsumptionBodyChirho,
    target_signature_hex_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationWriterAdoptionConsumptionRefusalChirho {
    WarrantUnavailableChirho,
    WarrantOversizedChirho,
    WarrantMalformedChirho,
    WarrantSignatureChirho,
    WarrantSourceNodeChirho,
    WarrantTargetNodeChirho,
    WarrantCheckpointChirho,
    WarrantAlreadyConsumedChirho,
    ConsumptionOversizedChirho,
    ConsumptionMalformedChirho,
    ConsumptionSignatureChirho,
    ConsumptionStateChirho,
    DestinationAuthorityUnavailableChirho,
    DestinationAuthorityChirho(TenantMigrationDestinationRefusalChirho),
    WriterAdoptionAuthorityChirho(TenantMigrationWriterAdoptionGateRefusalChirho),
    TargetIdentityChirho(TargetAdoptionRefusalChirho),
    TargetRootChirho,
    TargetInstanceKeyChirho,
    TargetIdentityChangedChirho,
    ResidentMintChirho(ResidentLedgerAuthorityRefusalChirho),
    StorageChirho,
}

pub(crate) fn publish_writer_adoption_warrant_chirho(
    target_root_chirho: &Path,
    active_chirho: &ActiveTenantMigrationChirho,
    source_signer_chirho: &dyn TenantMigrationControlSignerPortChirho,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    if active_chirho.phase_chirho()
        != TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantCheckpointChirho);
    }
    let operation_authority_chirho = active_chirho.operation_authority_chirho().clone();
    let envelope_chirho = parse_operation_authority_chirho(&operation_authority_chirho).map_err(
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::WriterAdoptionAuthorityChirho,
    )?;
    let adoption_chirho = match envelope_chirho.target_writer_posture_chirho() {
        TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho { .. } => return Ok(()),
        TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho { adoption_chirho } => {
            adoption_chirho
        }
    };
    let source_control_node_id_chirho = source_signer_chirho.key_id_chirho();
    if active_chirho.checkpoint_chirho().source_node_chirho != source_control_node_id_chirho
        || adoption_chirho.intent_chirho.source_control_node_id_chirho
            != source_control_node_id_chirho
    {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantSourceNodeChirho);
    }
    let fence_identity_digest_chirho = active_chirho
        .checkpoint_chirho()
        .fence_identity_digest_chirho
        .clone()
        .ok_or(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantCheckpointChirho)?;
    let body_chirho = TenantMigrationWriterAdoptionWarrantBodyChirho {
        operation_authority_chirho,
        attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
        activation_checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho().to_owned(),
        activation_transition_seq_chirho: active_chirho.checkpoint_chirho().transition_seq_chirho,
        fence_identity_digest_chirho,
        source_control_node_id_chirho,
        target_instance_node_id_chirho: adoption_chirho
            .intent_chirho
            .target_instance_node_id_chirho
            .clone(),
    };
    let message_chirho =
        signed_message_chirho(WRITER_ADOPTION_WARRANT_DOMAIN_V1_CHIRHO, &body_chirho)?;
    let warrant_chirho = TenantMigrationWriterAdoptionWarrantChirho {
        schema_chirho: WRITER_ADOPTION_WARRANT_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: WRITER_ADOPTION_WARRANT_DOMAIN_V1_CHIRHO.to_owned(),
        body_chirho,
        source_signature_hex_chirho: source_signer_chirho.sign_chirho(&message_chirho).map_err(
            |_error_chirho| {
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantSignatureChirho
            },
        )?,
    };
    let bytes_chirho = canonical_bytes_chirho(&warrant_chirho)?;
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(target_root_chirho).map_err(
        |_error_chirho| TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho,
    )?;
    create_or_compare_chirho(
        &storage_chirho,
        &StoragePathChirho::new_chirho(WRITER_ADOPTION_WARRANT_PATH_CHIRHO),
        &bytes_chirho,
        MAX_WRITER_ADOPTION_WARRANT_BYTES_CHIRHO,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one exact target-root adoption coordinate and its two verifier-only authorities"
)]
pub(crate) fn consume_writer_adoption_warrant_chirho<'ports_chirho>(
    canonical_root_chirho: &Path,
    identity_storage_namespace_chirho: &Path,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    opening_epoch_chirho: u64,
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
    activation_verifier_chirho: Option<&PinnedLedgerActivationVerifierChirho>,
    destination_authority_chirho: Option<&dyn TenantMigrationDestinationAuthorityPortChirho>,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(canonical_root_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
        })?;
    let warrant_path_chirho = StoragePathChirho::new_chirho(WRITER_ADOPTION_WARRANT_PATH_CHIRHO);
    let warrant_bytes_chirho = read_bounded_chirho(
        &storage_chirho,
        &warrant_path_chirho,
        MAX_WRITER_ADOPTION_WARRANT_BYTES_CHIRHO,
    )?
    .ok_or(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantUnavailableChirho)?;
    let warrant_chirho: TenantMigrationWriterAdoptionWarrantChirho =
        parse_canonical_chirho(&warrant_bytes_chirho).map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho
        })?;
    if warrant_chirho.schema_chirho != WRITER_ADOPTION_WARRANT_SCHEMA_V1_CHIRHO
        || warrant_chirho.signature_domain_chirho != WRITER_ADOPTION_WARRANT_DOMAIN_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&warrant_chirho.body_chirho.attempt_digest_chirho)
        || !is_lower_hex_digest_chirho(&warrant_chirho.body_chirho.activation_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&warrant_chirho.body_chirho.fence_identity_digest_chirho)
        || warrant_chirho.body_chirho.activation_transition_seq_chirho == 0
    {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho);
    }
    let reconstructed_authority_chirho =
        TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(
            warrant_chirho
                .body_chirho
                .operation_authority_chirho
                .canonical_payload_chirho()
                .to_owned(),
        )
        .map_err(|_refusal_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho
        })?;
    if reconstructed_authority_chirho != warrant_chirho.body_chirho.operation_authority_chirho {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho);
    }
    let envelope_chirho = parse_operation_authority_chirho(&reconstructed_authority_chirho)
        .map_err(
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::WriterAdoptionAuthorityChirho,
        )?;
    let adoption_chirho = match envelope_chirho.target_writer_posture_chirho() {
        TenantMigrationTargetWriterPostureChirho::ExistingIdentityChirho { .. } => {
            return Err(
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho,
            )
        }
        TenantMigrationTargetWriterPostureChirho::AuthorizedAdoptionChirho { adoption_chirho } => {
            adoption_chirho
        }
    };
    let target_root_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(
        canonical_root_chirho,
    )
    .map_err(|_refusal_chirho| {
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetRootChirho
    })?;
    let target_root_digest_chirho = target_root_chirho
        .binding_identity_digest_hex_chirho()
        .map_err(|_refusal_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetRootChirho
        })?;
    let target_instance_node_id_chirho = existing_keypair_pubkey_hex_chirho(canonical_root_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetInstanceKeyChirho
        })?;
    if target_instance_node_id_chirho != warrant_chirho.body_chirho.target_instance_node_id_chirho {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantTargetNodeChirho);
    }
    let destination_authority_chirho = destination_authority_chirho.ok_or(
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::DestinationAuthorityUnavailableChirho,
    )?;
    let destination_chirho = envelope_chirho.destination_chirho();
    let verified_destination_chirho = verify_tenant_migration_destination_record_chirho(
        destination_chirho,
        destination_authority_chirho,
        target_root_chirho.tenant_id_chirho(),
        &destination_chirho.intent_chirho.source_root_digest_chirho,
        &target_root_digest_chirho,
    )
    .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::DestinationAuthorityChirho)?;
    let activation_verifier_chirho = activation_verifier_chirho.ok_or(
        TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnavailableChirho,
    )
    .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WriterAdoptionAuthorityChirho)?;
    let verified_adoption_chirho = verify_adoption_against_destination_chirho(
        adoption_chirho,
        activation_verifier_chirho,
        canonical_root_chirho,
        &verified_destination_chirho,
        &destination_chirho.intent_digest_chirho,
        TenantMigrationWriterAdoptionCoordinatesChirho {
            source_control_node_id_chirho: &warrant_chirho
                .body_chirho
                .source_control_node_id_chirho,
            storage_namespace_chirho: identity_storage_namespace_chirho
                .strip_prefix(canonical_root_chirho)
                .ok()
                .and_then(Path::to_str)
                .ok_or(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho,
                )?,
            journal_path_chirho: journal_path_chirho.key_chirho(),
            cluster_id_chirho: &cluster_id_chirho.0,
            opening_epoch_chirho,
        },
    )
    .map_err(
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::WriterAdoptionAuthorityChirho,
    )?;
    if verified_adoption_chirho.source_control_node_id_chirho()
        != warrant_chirho.body_chirho.source_control_node_id_chirho
        || verified_adoption_chirho.intent_digest_chirho() != adoption_chirho.intent_digest_chirho
        || verified_adoption_chirho.target_instance_node_id_chirho()
            != target_instance_node_id_chirho
        || verified_adoption_chirho.target_root_digest_chirho() != target_root_digest_chirho
    {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho);
    }
    let warrant_message_chirho = signed_message_chirho(
        &warrant_chirho.signature_domain_chirho,
        &warrant_chirho.body_chirho,
    )?;
    if !verify_with_pubkey_chirho(
        &warrant_chirho.body_chirho.source_control_node_id_chirho,
        warrant_message_chirho.as_bytes(),
        &warrant_chirho.source_signature_hex_chirho,
    )
    .map_err(|_error_chirho| {
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantSignatureChirho
    })? {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantSignatureChirho);
    }
    let warrant_digest_chirho = blake3::hash(&warrant_bytes_chirho).to_hex().to_string();
    consume_once_chirho(
        canonical_root_chirho,
        identity_storage_namespace_chirho,
        journal_path_chirho,
        cluster_id_chirho,
        opening_epoch_chirho,
        ports_chirho,
        local_authority_chirho,
        &storage_chirho,
        &warrant_chirho,
        &warrant_digest_chirho,
        &target_root_digest_chirho,
        &target_instance_node_id_chirho,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one persisted target consumption and the exact resident birth coordinate it seals"
)]
fn consume_once_chirho<'ports_chirho>(
    canonical_root_chirho: &Path,
    identity_storage_namespace_chirho: &Path,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    opening_epoch_chirho: u64,
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
    storage_chirho: &FsLedgerStorageChirho,
    warrant_chirho: &TenantMigrationWriterAdoptionWarrantChirho,
    warrant_digest_chirho: &str,
    target_root_digest_chirho: &str,
    target_instance_node_id_chirho: &str,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let consumption_path_chirho =
        StoragePathChirho::new_chirho(WRITER_ADOPTION_CONSUMPTION_PATH_CHIRHO);
    let existing_chirho = read_bounded_chirho(
        storage_chirho,
        &consumption_path_chirho,
        MAX_WRITER_ADOPTION_CONSUMPTION_BYTES_CHIRHO,
    )?;
    let (consumption_chirho, _prepared_persisted_now_chirho) = match existing_chirho {
        Some(bytes_chirho) => (
            parse_and_verify_consumption_chirho(
                &bytes_chirho,
                warrant_chirho,
                warrant_digest_chirho,
                target_root_digest_chirho,
                target_instance_node_id_chirho,
            )?,
            false,
        ),
        None => {
            match inspect_target_adoption_posture_chirho(canonical_root_chirho) {
                Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho) => {}
                Ok(TargetAdoptionPostureChirho::IdentityBoundChirho { .. }) => {
                    return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantAlreadyConsumedChirho)
                }
                Ok(TargetAdoptionPostureChirho::IdentityPendingChirho { .. }) => {
                    return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionStateChirho)
                }
                Err(refusal_chirho) => {
                    return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChirho(refusal_chirho))
                }
            }
            let prepared_chirho = signed_consumption_chirho(
                canonical_root_chirho,
                TenantMigrationWriterAdoptionConsumptionBodyChirho {
                    state_chirho:
                        TenantMigrationWriterAdoptionConsumptionStateChirho::PreparedChirho,
                    warrant_digest_chirho: warrant_digest_chirho.to_owned(),
                    attempt_digest_chirho: warrant_chirho.body_chirho.attempt_digest_chirho.clone(),
                    target_root_digest_chirho: target_root_digest_chirho.to_owned(),
                    target_instance_node_id_chirho: target_instance_node_id_chirho.to_owned(),
                    resident_identity_digest_chirho: None,
                },
            )?;
            let prepared_bytes_chirho = canonical_bytes_chirho(&prepared_chirho)?;
            match storage_chirho
                .create_durable_chirho(&consumption_path_chirho, &prepared_bytes_chirho)
                .map_err(|_error_chirho| {
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
                })? {
                CreateDurableOutcomeChirho::CreatedChirho => (prepared_chirho, true),
                CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                    let raced_bytes_chirho = read_bounded_chirho(
                        storage_chirho,
                        &consumption_path_chirho,
                        MAX_WRITER_ADOPTION_CONSUMPTION_BYTES_CHIRHO,
                    )?
                    .ok_or(TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionMalformedChirho)?;
                    (
                        parse_and_verify_consumption_chirho(
                            &raced_bytes_chirho,
                            warrant_chirho,
                            warrant_digest_chirho,
                            target_root_digest_chirho,
                            target_instance_node_id_chirho,
                        )?,
                        false,
                    )
                }
            }
        }
    };
    #[cfg(test)]
    if _prepared_persisted_now_chirho {
        run_writer_adoption_post_prepared_test_hook_chirho();
    }
    match consumption_chirho.body_chirho.state_chirho {
        TenantMigrationWriterAdoptionConsumptionStateChirho::CompletedChirho => {
            let expected_identity_digest_chirho = consumption_chirho
                .body_chirho
                .resident_identity_digest_chirho
                .as_deref()
                .ok_or(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionStateChirho,
                )?;
            let observed_identity_digest_chirho = verify_existing_adopted_identity_chirho(
                canonical_root_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                opening_epoch_chirho,
                ports_chirho,
                local_authority_chirho,
            )?;
            return if observed_identity_digest_chirho == expected_identity_digest_chirho {
                Ok(())
            } else {
                Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChangedChirho)
            };
        }
        TenantMigrationWriterAdoptionConsumptionStateChirho::PreparedChirho => {
            if consumption_chirho
                .body_chirho
                .resident_identity_digest_chirho
                .is_some()
            {
                return Err(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionStateChirho,
                );
            }
        }
    }
    let resident_identity_digest_chirho =
        match inspect_target_adoption_posture_chirho(canonical_root_chirho) {
            Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho) => mint_adopted_identity_chirho(
                canonical_root_chirho,
                identity_storage_namespace_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                opening_epoch_chirho,
                ports_chirho,
                local_authority_chirho,
            )?,
            Ok(TargetAdoptionPostureChirho::IdentityPendingChirho { .. }) => {
                mint_adopted_identity_chirho(
                    canonical_root_chirho,
                    identity_storage_namespace_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    opening_epoch_chirho,
                    ports_chirho,
                    local_authority_chirho,
                )?
            }
            Ok(TargetAdoptionPostureChirho::IdentityBoundChirho {
                identity_digest_chirho: _identity_digest_chirho,
            }) => verify_existing_adopted_identity_chirho(
                canonical_root_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                opening_epoch_chirho,
                ports_chirho,
                local_authority_chirho,
            )?,
            Err(refusal_chirho) => {
                return Err(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChirho(
                        refusal_chirho,
                    ),
                )
            }
        };
    #[cfg(test)]
    run_writer_adoption_post_mint_test_hook_chirho();
    let completed_chirho = signed_consumption_chirho(
        canonical_root_chirho,
        TenantMigrationWriterAdoptionConsumptionBodyChirho {
            state_chirho: TenantMigrationWriterAdoptionConsumptionStateChirho::CompletedChirho,
            warrant_digest_chirho: warrant_digest_chirho.to_owned(),
            attempt_digest_chirho: warrant_chirho.body_chirho.attempt_digest_chirho.clone(),
            target_root_digest_chirho: target_root_digest_chirho.to_owned(),
            target_instance_node_id_chirho: target_instance_node_id_chirho.to_owned(),
            resident_identity_digest_chirho: Some(resident_identity_digest_chirho.clone()),
        },
    )?;
    storage_chirho
        .atomic_write_chirho(
            &consumption_path_chirho,
            &canonical_bytes_chirho(&completed_chirho)?,
        )
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
        })?;
    require_bound_identity_chirho(canonical_root_chirho, &resident_identity_digest_chirho)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the sealed resident-birth permit requires this exact coordinate"
)]
fn mint_adopted_identity_chirho<'ports_chirho>(
    canonical_root_chirho: &Path,
    identity_storage_namespace_chirho: &Path,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    opening_epoch_chirho: u64,
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
) -> Result<String, TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let adopted_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
        ResidentLedgerBirthPermitChirho::for_reviewed_adoption_chirho(
            canonical_root_chirho.to_path_buf(),
            identity_storage_namespace_chirho.to_path_buf(),
            journal_path_chirho.clone(),
            cluster_id_chirho.clone(),
            opening_epoch_chirho,
        ),
        ports_chirho,
        local_authority_chirho,
    )
    .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::ResidentMintChirho)?;
    drop(adopted_chirho);
    match inspect_target_adoption_posture_chirho(canonical_root_chirho)
        .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChirho)?
    {
        TargetAdoptionPostureChirho::IdentityBoundChirho {
            identity_digest_chirho,
        } => Ok(identity_digest_chirho),
        TargetAdoptionPostureChirho::IdentityAbsentChirho
        | TargetAdoptionPostureChirho::IdentityPendingChirho { .. } => {
            Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChangedChirho)
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "recovery must re-open the exact resident coordinate before completing consumption"
)]
fn verify_existing_adopted_identity_chirho<'ports_chirho>(
    canonical_root_chirho: &Path,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    opening_epoch_chirho: u64,
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
) -> Result<String, TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
        canonical_root_chirho,
        ports_chirho,
        journal_path_chirho.clone(),
        cluster_id_chirho.clone(),
        opening_epoch_chirho,
        local_authority_chirho,
    )
    .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::ResidentMintChirho)?;
    drop(resident_chirho);
    match inspect_target_adoption_posture_chirho(canonical_root_chirho)
        .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChirho)?
    {
        TargetAdoptionPostureChirho::IdentityBoundChirho {
            identity_digest_chirho,
        } => Ok(identity_digest_chirho),
        TargetAdoptionPostureChirho::IdentityAbsentChirho
        | TargetAdoptionPostureChirho::IdentityPendingChirho { .. } => {
            Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChangedChirho)
        }
    }
}

fn parse_and_verify_consumption_chirho(
    bytes_chirho: &[u8],
    warrant_chirho: &TenantMigrationWriterAdoptionWarrantChirho,
    warrant_digest_chirho: &str,
    target_root_digest_chirho: &str,
    target_instance_node_id_chirho: &str,
) -> Result<
    TenantMigrationWriterAdoptionConsumptionChirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
> {
    let consumption_chirho: TenantMigrationWriterAdoptionConsumptionChirho =
        parse_canonical_chirho(bytes_chirho).map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionMalformedChirho
        })?;
    if consumption_chirho.schema_chirho != WRITER_ADOPTION_CONSUMPTION_SCHEMA_V1_CHIRHO
        || consumption_chirho.signature_domain_chirho
            != WRITER_ADOPTION_CONSUMPTION_DOMAIN_V1_CHIRHO
        || consumption_chirho.body_chirho.warrant_digest_chirho != warrant_digest_chirho
        || consumption_chirho.body_chirho.attempt_digest_chirho
            != warrant_chirho.body_chirho.attempt_digest_chirho
        || consumption_chirho.body_chirho.target_root_digest_chirho != target_root_digest_chirho
        || consumption_chirho
            .body_chirho
            .target_instance_node_id_chirho
            != target_instance_node_id_chirho
    {
        return Err(
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantAlreadyConsumedChirho,
        );
    }
    let message_chirho = signed_message_chirho(
        &consumption_chirho.signature_domain_chirho,
        &consumption_chirho.body_chirho,
    )?;
    if !verify_with_pubkey_chirho(
        target_instance_node_id_chirho,
        message_chirho.as_bytes(),
        &consumption_chirho.target_signature_hex_chirho,
    )
    .map_err(|_error_chirho| {
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionSignatureChirho
    })? {
        return Err(
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionSignatureChirho,
        );
    }
    if consumption_chirho.body_chirho.state_chirho
        == TenantMigrationWriterAdoptionConsumptionStateChirho::CompletedChirho
        && consumption_chirho
            .body_chirho
            .resident_identity_digest_chirho
            .is_none()
    {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionStateChirho);
    }
    Ok(consumption_chirho)
}

fn signed_consumption_chirho(
    canonical_root_chirho: &Path,
    body_chirho: TenantMigrationWriterAdoptionConsumptionBodyChirho,
) -> Result<
    TenantMigrationWriterAdoptionConsumptionChirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
> {
    let message_chirho =
        signed_message_chirho(WRITER_ADOPTION_CONSUMPTION_DOMAIN_V1_CHIRHO, &body_chirho)?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(canonical_root_chirho, message_chirho.as_bytes())
            .map_err(|_error_chirho| {
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionSignatureChirho
            })?;
    if possession_chirho.key_id_chirho() != body_chirho.target_instance_node_id_chirho {
        return Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantTargetNodeChirho);
    }
    Ok(TenantMigrationWriterAdoptionConsumptionChirho {
        schema_chirho: WRITER_ADOPTION_CONSUMPTION_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: WRITER_ADOPTION_CONSUMPTION_DOMAIN_V1_CHIRHO.to_owned(),
        body_chirho,
        target_signature_hex_chirho: possession_chirho.into_signature_hex_chirho(),
    })
}

fn require_bound_identity_chirho(
    canonical_root_chirho: &Path,
    expected_digest_chirho: &str,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    match inspect_target_adoption_posture_chirho(canonical_root_chirho)
        .map_err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChirho)?
    {
        TargetAdoptionPostureChirho::IdentityBoundChirho {
            identity_digest_chirho,
        } if identity_digest_chirho == expected_digest_chirho => Ok(()),
        TargetAdoptionPostureChirho::IdentityAbsentChirho
        | TargetAdoptionPostureChirho::IdentityPendingChirho { .. }
        | TargetAdoptionPostureChirho::IdentityBoundChirho { .. } => {
            Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::TargetIdentityChangedChirho)
        }
    }
}

fn create_or_compare_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: u64,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
        })? {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(storage_chirho, path_chirho, maximum_chirho)?
                .ok_or(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantUnavailableChirho,
                )?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantAlreadyConsumedChirho)
            }
        }
    }
}

fn read_bounded_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: u64,
) -> Result<Option<Vec<u8>>, TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let Some(length_chirho) =
        storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_error_chirho| {
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
            })?
    else {
        return Ok(None);
    };
    if length_chirho > maximum_chirho {
        return Err(
            if path_chirho.key_chirho() == WRITER_ADOPTION_WARRANT_PATH_CHIRHO {
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantOversizedChirho
            } else {
                TenantMigrationWriterAdoptionConsumptionRefusalChirho::ConsumptionOversizedChirho
            },
        );
    }
    storage_chirho
        .read_exact_range_chirho(path_chirho, 0, length_chirho)
        .map(Some)
        .map_err(|_error_chirho| {
            TenantMigrationWriterAdoptionConsumptionRefusalChirho::StorageChirho
        })
}

fn canonical_bytes_chirho(
    value_chirho: &impl Serialize,
) -> Result<Vec<u8>, TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    serde_json::to_vec(value_chirho).map_err(|_error_chirho| {
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho
    })
}

fn parse_canonical_chirho<T: for<'de_chirho> Deserialize<'de_chirho> + Serialize>(
    bytes_chirho: &[u8],
) -> Result<T, ()> {
    let value_chirho: T = serde_json::from_slice(bytes_chirho).map_err(|_error_chirho| ())?;
    if serde_json::to_vec(&value_chirho).map_err(|_error_chirho| ())? != bytes_chirho {
        return Err(());
    }
    Ok(value_chirho)
}

fn signed_message_chirho(
    domain_chirho: &str,
    body_chirho: &impl Serialize,
) -> Result<String, TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    let body_chirho = serde_json::to_string(body_chirho).map_err(|_error_chirho| {
        TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantMalformedChirho
    })?;
    Ok(format!("{domain_chirho}:{body_chirho}"))
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
