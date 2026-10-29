// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::authority_chirho::PinnedLedgerActivationVerifierChirho;
use crate::reconciliation_chirho::{ExistingNodeGd7SignerChirho, Gd7WinnerHandoffStoreChirho};
use crate::resident_authority_chirho::runtime_actor_chirho::admitting_test_capacity_composition_chirho;
use crate::resident_authority_chirho::writer_adoption_chirho::{
    operation_authority_for_begin_chirho, TenantMigrationWriterAdoptionCoordinatesChirho,
    TenantMigrationWriterAdoptionExpectedChirho,
};
use crate::tests_chirho::{
    resident_mint_request_chirho, warm_single_node_elector_chirho,
    with_bound_resident_fixture_chirho,
};
use crate::{
    FsLedgerStorageChirho, ResidentLedgerAppendPermitChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerLocalPortsChirho,
};
use cairn_config_chirho::config_chirho::LedgerHostActivationPinConfigChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_tenant_migration_chirho::{
    TenantLedgerVerificationViewsChirho, VerifiedTenantMigrationRootChirho,
};
use cairn_ledger_tenant_migration_durable_chirho::{
    verify_tenant_migration_destination_record_chirho, TenantMigrationControlSignerPortChirho,
    TenantMigrationDestinationAuthorityPortChirho, TenantMigrationPhaseChirho,
    TenantMigrationStoreChirho,
};
use cairn_signer_chirho::signer_chirho::pubkey_hex_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use ed25519_dalek::{Signer, SigningKey};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::writer_adoption_chirho::{
    consume_writer_adoption_warrant_chirho, install_writer_adoption_post_mint_test_hook_chirho,
    install_writer_adoption_post_prepared_test_hook_chirho,
    legacy_v1_operation_authority_for_test_chirho,
    malformed_v2_operation_authority_without_capacity_for_test_chirho,
    parse_operation_authority_chirho, replace_writer_adoption_warrant_for_replay_test_chirho,
    tenant_migration_writer_adoption_intent_digest_chirho,
    unsigned_tenant_migration_writer_adoption_message_chirho,
    verify_tenant_migration_writer_adoption_record_chirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho, TenantMigrationWriterAdoptionIntentChirho,
    TenantMigrationWriterAdoptionRecordChirho, TenantMigrationWriterAdoptionRefusalChirho,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO,
};
use super::append_barrier_chirho::ResidentAppendBarrierRuntimeChirho;
use super::target_adoption_chirho::{
    inspect_target_adoption_posture_chirho, TargetAdoptionPostureChirho,
};
use super::tenant_migration_operation_chirho::{
    destination_record_for_roots_chirho, AcceptingDestinationAuthorityChirho,
    ResidentTenantMigrationOperationCommandChirho, ResidentTenantMigrationOperationOutcomeChirho,
    ResidentTenantMigrationOperationRuntimeChirho,
};
use super::{seed_migration_reference_chirho, stage_migration_target_surfaces_chirho};

const TEST_STORAGE_NAMESPACE_CHIRHO: &str = "ledger-namespace-chirho";
const TEST_JOURNAL_PATH_CHIRHO: &str = "journals/resident-authority-chirho.jsonl";
const TEST_CLUSTER_ID_CHIRHO: &str = "resident-authority-cluster-chirho";
const TEST_ACTIVATION_PRINCIPAL_CHIRHO: &str = "migration-activation-authority-chirho";

fn temp_platform_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-writer-adoption-{label_chirho}-{nanos_chirho}-{counter_chirho}-chirho"
    ))
}

fn copy_tree_chirho(source_chirho: &Path, target_chirho: &Path) {
    let metadata_chirho =
        std::fs::symlink_metadata(source_chirho).expect("stat the source fixture surface");
    if metadata_chirho.is_dir() {
        std::fs::create_dir_all(target_chirho).expect("create the target fixture directory");
        for entry_chirho in
            std::fs::read_dir(source_chirho).expect("read the source fixture directory")
        {
            let entry_chirho = entry_chirho.expect("read a source fixture entry");
            copy_tree_chirho(
                &entry_chirho.path(),
                &target_chirho.join(entry_chirho.file_name()),
            );
        }
    } else if metadata_chirho.is_file() {
        std::fs::copy(source_chirho, target_chirho).expect("copy the fixture file");
    }
}

fn hex_lower_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn activation_verifier_chirho(signing_chirho: &SigningKey) -> PinnedLedgerActivationVerifierChirho {
    PinnedLedgerActivationVerifierChirho::from_config_chirho(&LedgerHostActivationPinConfigChirho {
        principal_chirho: TEST_ACTIVATION_PRINCIPAL_CHIRHO.to_owned(),
        verifying_key_hex_chirho: hex_lower_chirho(signing_chirho.verifying_key().as_bytes()),
    })
    .expect("construct the independent activation verifier")
}

fn adoption_record_chirho(
    source_root_chirho: &Path,
    target_root_chirho: &Path,
    destination_chirho: &cairn_ledger_tenant_migration_durable_chirho::TenantMigrationDestinationRecordChirho,
    source_control_node_id_chirho: &str,
    target_instance_node_id_chirho: &str,
    signing_chirho: &SigningKey,
) -> TenantMigrationWriterAdoptionRecordChirho {
    let source_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(source_root_chirho)
        .expect("open the source root");
    let target_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(target_root_chirho)
        .expect("open the target root");
    let intent_chirho = TenantMigrationWriterAdoptionIntentChirho {
        schema_chirho: TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: source_chirho.tenant_id_chirho().to_owned(),
        source_root_digest_chirho: source_chirho
            .binding_identity_digest_hex_chirho()
            .expect("derive the source root digest"),
        target_root_digest_chirho: target_chirho
            .binding_identity_digest_hex_chirho()
            .expect("derive the target root digest"),
        destination_intent_digest_chirho: destination_chirho.intent_digest_chirho.clone(),
        destination_revision_chirho: destination_chirho.intent_chirho.revision_chirho,
        source_control_node_id_chirho: source_control_node_id_chirho.to_owned(),
        target_instance_node_id_chirho: target_instance_node_id_chirho.to_owned(),
        storage_namespace_chirho: TEST_STORAGE_NAMESPACE_CHIRHO.to_owned(),
        journal_path_chirho: TEST_JOURNAL_PATH_CHIRHO.to_owned(),
        cluster_id_chirho: TEST_CLUSTER_ID_CHIRHO.to_owned(),
        opening_epoch_chirho: 0,
        attempt_nonce_chirho: "a5".repeat(32),
    };
    let intent_digest_chirho =
        tenant_migration_writer_adoption_intent_digest_chirho(&intent_chirho)
            .expect("derive adoption intent digest");
    let mut record_chirho = TenantMigrationWriterAdoptionRecordChirho {
        schema_chirho: TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO
            .to_owned(),
        intent_chirho,
        intent_digest_chirho,
        activation_principal_chirho: TEST_ACTIVATION_PRINCIPAL_CHIRHO.to_owned(),
        signature_hex_chirho: String::new(),
    };
    let message_chirho = unsigned_tenant_migration_writer_adoption_message_chirho(&record_chirho);
    record_chirho.signature_hex_chirho =
        hex_lower_chirho(&signing_chirho.sign(message_chirho.as_bytes()).to_bytes());
    record_chirho
}

fn with_activated_writer_adoption_fixture_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &Path,
        ResidentLedgerLocalPortsChirho<'_>,
        LocalAppendAuthorityHandleChirho,
        &PinnedLedgerActivationVerifierChirho,
        &dyn TenantMigrationDestinationAuthorityPortChirho,
        &dyn TenantMigrationControlSignerPortChirho,
    ),
) {
    with_bound_resident_fixture_chirho(
        label_chirho,
        |source_root_chirho,
         source_group_chirho,
         source_node_chirho,
         source_ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            seed_migration_reference_chirho(source_root_chirho);
            let source_elector_chirho =
                warm_single_node_elector_chirho(source_node_chirho, source_group_chirho);
            let source_authority_chirho =
                source_elector_chirho.local_append_authority_handle_chirho();
            let source_control_chirho = source_authority_chirho.handoff_control_handle_chirho();
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                source_root_chirho,
                source_ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                source_authority_chirho.clone(),
            )
            .expect("open the source resident for the migration fixture");
            let control_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(source_root_chirho)
                    .expect("open the source migration-control storage");
            let control_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
                source_root_chirho,
                source_node_chirho,
            )
            .expect("open the source migration-control signer");
            let group_digest_chirho =
                consistency_group_digest_chirho(source_group_chirho).expect("digest the group");
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                group_digest_chirho.clone(),
                source_node_chirho.0.clone(),
            )
            .expect("open the empty winner-handoff store");
            let migration_store_chirho = TenantMigrationStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                group_digest_chirho,
                source_node_chirho.0.clone(),
            )
            .expect("open the migration store");
            let (mut append_barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &source_control_chirho,
                    &resident_chirho,
                    &source_authority_chirho,
                )
                .expect("restore the source append barrier");

            let target_platform_chirho = temp_platform_root_chirho(label_chirho);
            std::fs::create_dir_all(&target_platform_chirho)
                .expect("create the target platform root");
            let target_root_chirho = prepare_tenant_root_chirho(
                &target_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .expect("prepare the migration target root")
            .canonicalize()
            .expect("canonicalize the migration target root");
            stage_migration_target_surfaces_chirho(source_root_chirho, &target_root_chirho);
            copy_tree_chirho(
                &source_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
                &target_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
            );
            let target_instance_node_id_chirho =
                pubkey_hex_chirho(&target_root_chirho).expect("mint the target instance key");
            let destination_chirho =
                destination_record_for_roots_chirho(source_root_chirho, &target_root_chirho);
            let activation_signer_chirho = SigningKey::from_bytes(&[91; 32]);
            let activation_verifier_chirho = activation_verifier_chirho(&activation_signer_chirho);
            let writer_adoption_chirho = adoption_record_chirho(
                source_root_chirho,
                &target_root_chirho,
                &destination_chirho,
                &control_signer_chirho.key_id_chirho(),
                &target_instance_node_id_chirho,
                &activation_signer_chirho,
            );
            let mut runtime_chirho = ResidentTenantMigrationOperationRuntimeChirho::new_chirho(
                source_root_chirho,
                source_ports_chirho.storage_chirho,
                TEST_STORAGE_NAMESPACE_CHIRHO,
                TenantLedgerVerificationViewsChirho {
                    signer_chirho: source_ports_chirho.signer_chirho,
                    clock_chirho: source_ports_chirho.clock_chirho,
                    membership_chirho: source_ports_chirho.membership_chirho,
                    kind_registry_chirho: source_ports_chirho.kind_registry_chirho,
                    authority_chirho: source_ports_chirho.authority_chirho,
                },
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                migration_store_chirho,
                source_control_chirho.clone(),
                Some(&AcceptingDestinationAuthorityChirho),
                Some(admitting_test_capacity_composition_chirho()),
                None,
                Some(&activation_verifier_chirho),
                &control_signer_chirho,
                0,
            )
            .expect("bind the migration operation runtime");
            let begin_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_chirho),
                        writer_adoption_chirho: Some(Box::new(writer_adoption_chirho)),
                    },
                    &mut append_barrier_chirho,
                )
                .expect("begin the co-signed source fence");
            assert!(matches!(
                begin_chirho,
                ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(_)
            ));
            let warrant_path_chirho = target_root_chirho
                .join("resident-writer-chirho/migration-adoption-warrant-chirho.json");
            assert!(
                !warrant_path_chirho.exists(),
                "a source fence is not yet authority to issue an adoption warrant"
            );
            let activated_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect("activate the target and publish the source warrant");
            assert!(matches!(
                activated_chirho,
                ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(
                    ref status_chirho
                ) if status_chirho.phase_chirho
                    == TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
            ));
            let first_warrant_chirho =
                std::fs::read(&warrant_path_chirho).expect("read the activated source warrant");
            let recovered_activation_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect("recover the already-activated target");
            assert!(matches!(
                recovered_activation_chirho,
                ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(_)
            ));
            assert_eq!(
                std::fs::read(&warrant_path_chirho).expect("read the recovered source warrant"),
                first_warrant_chirho,
                "activation recovery must not issue a second warrant"
            );

            let target_storage_root_chirho = target_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO);
            let target_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(&target_storage_root_chirho)
                    .expect("open the activated target ledger storage");
            let target_group_chirho = consistency_group_for_root_chirho(&target_root_chirho)
                .expect("derive the target group");
            assert_eq!(&target_group_chirho, source_group_chirho);
            let target_elector_chirho = warm_single_node_elector_chirho(
                &cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho(
                    target_instance_node_id_chirho,
                ),
                &target_group_chirho,
            );
            let target_ports_chirho = ResidentLedgerLocalPortsChirho {
                storage_chirho: &target_storage_chirho,
                signer_chirho: source_ports_chirho.signer_chirho,
                clock_chirho: source_ports_chirho.clock_chirho,
                membership_chirho: source_ports_chirho.membership_chirho,
                kind_registry_chirho: source_ports_chirho.kind_registry_chirho,
                authority_chirho: source_ports_chirho.authority_chirho,
            };
            action_chirho(
                &target_root_chirho,
                target_ports_chirho,
                target_elector_chirho.local_append_authority_handle_chirho(),
                &activation_verifier_chirho,
                &AcceptingDestinationAuthorityChirho,
                &control_signer_chirho,
            );

            drop(runtime_chirho);
            drop(resident_chirho);
            drop(target_elector_chirho);
            drop(source_elector_chirho);
            std::fs::remove_dir_all(target_platform_chirho)
                .expect("remove the target fixture root");
        },
    );
}

fn consume_fixture_warrant_chirho(
    target_root_chirho: &Path,
    target_ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
    target_authority_chirho: LocalAppendAuthorityHandleChirho,
    activation_verifier_chirho: &PinnedLedgerActivationVerifierChirho,
    destination_authority_chirho: &dyn TenantMigrationDestinationAuthorityPortChirho,
) -> Result<(), TenantMigrationWriterAdoptionConsumptionRefusalChirho> {
    consume_writer_adoption_warrant_chirho(
        target_root_chirho,
        &target_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
        &StoragePathChirho::new_chirho(TEST_JOURNAL_PATH_CHIRHO),
        &ClusterIdChirho(TEST_CLUSTER_ID_CHIRHO.to_owned()),
        0,
        target_ports_chirho,
        target_authority_chirho,
        Some(activation_verifier_chirho),
        Some(destination_authority_chirho),
    )
}

#[test]
fn two_authorities_and_exact_target_binding_are_independently_required_chirho() {
    let platform_chirho = temp_platform_root_chirho("authority-halves");
    std::fs::create_dir_all(&platform_chirho).unwrap();
    let source_root_chirho =
        prepare_tenant_root_chirho(&platform_chirho, "writer-adoption-tenant-chirho").unwrap();
    let target_platform_chirho = temp_platform_root_chirho("authority-target");
    std::fs::create_dir_all(&target_platform_chirho).unwrap();
    let target_root_chirho =
        prepare_tenant_root_chirho(&target_platform_chirho, "writer-adoption-tenant-chirho")
            .unwrap();
    let source_node_chirho = pubkey_hex_chirho(&source_root_chirho).unwrap();
    let target_node_chirho = pubkey_hex_chirho(&target_root_chirho).unwrap();
    let destination_chirho =
        destination_record_for_roots_chirho(&source_root_chirho, &target_root_chirho);
    let verified_destination_chirho = verify_tenant_migration_destination_record_chirho(
        &destination_chirho,
        &AcceptingDestinationAuthorityChirho,
        "writer-adoption-tenant-chirho",
        &destination_chirho.intent_chirho.source_root_digest_chirho,
        &destination_chirho
            .intent_chirho
            .destination_root_digest_chirho,
    )
    .unwrap();
    let signing_chirho = SigningKey::from_bytes(&[91; 32]);
    let verifier_chirho = activation_verifier_chirho(&signing_chirho);
    let adoption_chirho = adoption_record_chirho(
        &source_root_chirho,
        &target_root_chirho,
        &destination_chirho,
        &source_node_chirho,
        &target_node_chirho,
        &signing_chirho,
    );
    let posture_chirho = inspect_target_adoption_posture_chirho(&target_root_chirho).unwrap();
    assert_eq!(
        posture_chirho,
        TargetAdoptionPostureChirho::IdentityAbsentChirho
    );
    let coordinates_chirho = || TenantMigrationWriterAdoptionCoordinatesChirho {
        source_control_node_id_chirho: &source_node_chirho,
        storage_namespace_chirho: TEST_STORAGE_NAMESPACE_CHIRHO,
        journal_path_chirho: TEST_JOURNAL_PATH_CHIRHO,
        cluster_id_chirho: TEST_CLUSTER_ID_CHIRHO,
        opening_epoch_chirho: 0,
    };

    assert_eq!(
        operation_authority_for_begin_chirho(
            &destination_chirho,
            &verified_destination_chirho,
            None,
            Some(&verifier_chirho),
            &target_root_chirho,
            &posture_chirho,
            coordinates_chirho(),
        ),
        Err(TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityRequiredChirho)
    );
    assert_eq!(
        operation_authority_for_begin_chirho(
            &destination_chirho,
            &verified_destination_chirho,
            Some(&adoption_chirho),
            None,
            &target_root_chirho,
            &posture_chirho,
            coordinates_chirho(),
        ),
        Err(TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnavailableChirho)
    );
    let v2_authority_chirho = operation_authority_for_begin_chirho(
        &destination_chirho,
        &verified_destination_chirho,
        Some(&adoption_chirho),
        Some(&verifier_chirho),
        &target_root_chirho,
        &posture_chirho,
        coordinates_chirho(),
    )
    .expect("both independent authorities admit the exact target");
    let v2_envelope_chirho = parse_operation_authority_chirho(&v2_authority_chirho)
        .expect("new begins encode a canonical v2 authority envelope");
    assert_eq!(
        v2_envelope_chirho.capacity_admission_identity_chirho(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    let legacy_v1_chirho =
        legacy_v1_operation_authority_for_test_chirho(&v2_authority_chirho).unwrap();
    assert_eq!(
        parse_operation_authority_chirho(&legacy_v1_chirho)
            .expect("completed legacy adoption records remain parseable")
            .capacity_admission_identity_chirho(),
        None
    );
    let malformed_v2_chirho =
        malformed_v2_operation_authority_without_capacity_for_test_chirho(&v2_authority_chirho)
            .unwrap();
    assert_eq!(
        parse_operation_authority_chirho(&malformed_v2_chirho),
        Err(TenantMigrationWriterAdoptionGateRefusalChirho::OperationAuthorityMalformedChirho),
        "v2 may never omit its capacity/load identity"
    );

    let mut wrong_intent_digest_adoption_chirho = adoption_chirho.clone();
    wrong_intent_digest_adoption_chirho.intent_digest_chirho = "00".repeat(32);
    assert_ne!(
        wrong_intent_digest_adoption_chirho.intent_digest_chirho,
        adoption_chirho.intent_digest_chirho
    );
    let intent_digest_refusal_chirho = operation_authority_for_begin_chirho(
        &destination_chirho,
        &verified_destination_chirho,
        Some(&wrong_intent_digest_adoption_chirho),
        Some(&verifier_chirho),
        &target_root_chirho,
        &posture_chirho,
        coordinates_chirho(),
    );
    assert_eq!(
        intent_digest_refusal_chirho,
        Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityChirho(
                TenantMigrationWriterAdoptionRefusalChirho::IntentDigestChirho,
            ),
        ),
        "the stored digest is recomputed from the carried intent before signature credit"
    );
    assert_ne!(
        intent_digest_refusal_chirho,
        Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityChirho(
                TenantMigrationWriterAdoptionRefusalChirho::SignatureChirho,
            ),
        ),
        "a digest mismatch must not pass by reaching the later signature refusal"
    );

    let wrong_signing_chirho = SigningKey::from_bytes(&[92; 32]);
    let wrong_authority_adoption_chirho = adoption_record_chirho(
        &source_root_chirho,
        &target_root_chirho,
        &destination_chirho,
        &source_node_chirho,
        &target_node_chirho,
        &wrong_signing_chirho,
    );
    assert_eq!(
        operation_authority_for_begin_chirho(
            &destination_chirho,
            &verified_destination_chirho,
            Some(&wrong_authority_adoption_chirho),
            Some(&verifier_chirho),
            &target_root_chirho,
            &posture_chirho,
            coordinates_chirho(),
        ),
        Err(
            TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityChirho(
                TenantMigrationWriterAdoptionRefusalChirho::SignatureChirho,
            ),
        ),
        "a well-shaped record signed by another valid key must reach the resident gate's exact \
         activation-authority signature refusal"
    );

    let wrong_target_platform_chirho = temp_platform_root_chirho("wrong-target");
    std::fs::create_dir_all(&wrong_target_platform_chirho).unwrap();
    let wrong_target_root_chirho = prepare_tenant_root_chirho(
        &wrong_target_platform_chirho,
        "writer-adoption-tenant-chirho",
    )
    .unwrap();
    let wrong_target_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&wrong_target_root_chirho).unwrap();
    let refusal_chirho = verify_tenant_migration_writer_adoption_record_chirho(
        &adoption_chirho,
        &verifier_chirho,
        TenantMigrationWriterAdoptionExpectedChirho {
            tenant_id_chirho: "writer-adoption-tenant-chirho",
            source_root_digest_chirho: &destination_chirho.intent_chirho.source_root_digest_chirho,
            target_root_digest_chirho: &wrong_target_chirho
                .binding_identity_digest_hex_chirho()
                .unwrap(),
            destination_intent_digest_chirho: &destination_chirho.intent_digest_chirho,
            destination_revision_chirho: destination_chirho.intent_chirho.revision_chirho,
            source_control_node_id_chirho: &source_node_chirho,
            target_instance_node_id_chirho: &target_node_chirho,
            storage_namespace_chirho: TEST_STORAGE_NAMESPACE_CHIRHO,
            journal_path_chirho: TEST_JOURNAL_PATH_CHIRHO,
            cluster_id_chirho: TEST_CLUSTER_ID_CHIRHO,
            opening_epoch_chirho: 0,
        },
    );
    assert_eq!(
        refusal_chirho,
        Err(TenantMigrationWriterAdoptionRefusalChirho::TargetRootBindingChirho)
    );

    std::fs::remove_dir_all(platform_chirho).unwrap();
    std::fs::remove_dir_all(target_platform_chirho).unwrap();
    std::fs::remove_dir_all(wrong_target_platform_chirho).unwrap();
}

#[test]
fn activated_source_warrant_mints_once_and_reopens_exactly_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "source-warrant-happy",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         _source_signer_chirho| {
            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho.clone(),
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("consume the source-witnessed adoption warrant");
            let first_identity_chirho =
                match inspect_target_adoption_posture_chirho(target_root_chirho)
                    .expect("inspect the first adopted identity")
                {
                    TargetAdoptionPostureChirho::IdentityBoundChirho {
                        identity_digest_chirho,
                    } => identity_digest_chirho,
                    posture_chirho => panic!("expected a bound identity, got {posture_chirho:?}"),
                };
            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho.clone(),
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("retry the completed consumption idempotently");
            assert_eq!(
                inspect_target_adoption_posture_chirho(target_root_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityBoundChirho {
                    identity_digest_chirho: first_identity_chirho,
                })
            );
            let mut adopted_resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    target_root_chirho,
                    target_ports_chirho,
                    StoragePathChirho::new_chirho(TEST_JOURNAL_PATH_CHIRHO),
                    ClusterIdChirho(TEST_CLUSTER_ID_CHIRHO.to_owned()),
                    0,
                    target_authority_chirho,
                )
                .expect("the capacity-admitted adopted target reopens as the resident writer");
            let append_receipt_chirho = adopted_resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(7, "capacity-admitted-target-write-chirho"),
                )
                .expect("the capacity-admitted adopted target accepts a resident append");
            assert!(
                append_receipt_chirho.append_chirho.seq_chirho > 0,
                "the positive control must produce a durable append receipt, not only reopen"
            );
        },
    );
}

#[test]
fn completed_consumption_refuses_a_different_valid_source_warrant_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "different-warrant-replay",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         source_signer_chirho| {
            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho.clone(),
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("complete the first warrant consumption");
            let first_identity_chirho = inspect_target_adoption_posture_chirho(target_root_chirho)
                .expect("inspect the first adopted identity");
            replace_writer_adoption_warrant_for_replay_test_chirho(
                target_root_chirho,
                source_signer_chirho,
            );
            assert_eq!(
                consume_fixture_warrant_chirho(
                    target_root_chirho,
                    target_ports_chirho,
                    target_authority_chirho,
                    activation_verifier_chirho,
                    destination_authority_chirho,
                ),
                Err(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantAlreadyConsumedChirho,
                ),
                "a distinct valid source warrant must not reuse a target-local nullifier"
            );
            assert_eq!(
                inspect_target_adoption_posture_chirho(target_root_chirho)
                    .expect("inspect identity after replay refusal"),
                first_identity_chirho
            );
        },
    );
}

#[test]
fn target_consumer_requires_each_authority_and_names_the_missing_half_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "target-authority-halves",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         _source_signer_chirho| {
            let destination_only_chirho = consume_writer_adoption_warrant_chirho(
                target_root_chirho,
                &target_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
                &StoragePathChirho::new_chirho(TEST_JOURNAL_PATH_CHIRHO),
                &ClusterIdChirho(TEST_CLUSTER_ID_CHIRHO.to_owned()),
                0,
                target_ports_chirho,
                target_authority_chirho.clone(),
                None,
                Some(destination_authority_chirho),
            );
            assert_eq!(
                destination_only_chirho,
                Err(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::WriterAdoptionAuthorityChirho(
                        TenantMigrationWriterAdoptionGateRefusalChirho::WriterAdoptionAuthorityUnavailableChirho,
                    ),
                )
            );
            let activation_only_chirho = consume_writer_adoption_warrant_chirho(
                target_root_chirho,
                &target_root_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
                &StoragePathChirho::new_chirho(TEST_JOURNAL_PATH_CHIRHO),
                &ClusterIdChirho(TEST_CLUSTER_ID_CHIRHO.to_owned()),
                0,
                target_ports_chirho,
                target_authority_chirho.clone(),
                Some(activation_verifier_chirho),
                None,
            );
            assert_eq!(
                activation_only_chirho,
                Err(
                    TenantMigrationWriterAdoptionConsumptionRefusalChirho::DestinationAuthorityUnavailableChirho,
                )
            );
            assert_eq!(
                inspect_target_adoption_posture_chirho(target_root_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho),
                "neither one-authority refusal may persist consumption or mint identity"
            );
            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho,
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("both authorities cross the same target boundary");
        },
    );
}

#[test]
fn source_warrant_for_one_target_refuses_on_another_target_before_mint_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "wrong-target-warrant",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         _source_signer_chirho| {
            let other_platform_chirho = temp_platform_root_chirho("warrant-replay-target");
            std::fs::create_dir_all(&other_platform_chirho)
                .expect("create the other target platform root");
            let other_target_chirho = prepare_tenant_root_chirho(
                &other_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .expect("prepare the other target")
            .canonicalize()
            .expect("canonicalize the other target");
            let _other_instance_chirho =
                pubkey_hex_chirho(&other_target_chirho).expect("mint the other target key");
            let other_warrant_chirho = other_target_chirho
                .join("resident-writer-chirho/migration-adoption-warrant-chirho.json");
            std::fs::create_dir_all(
                other_warrant_chirho
                    .parent()
                    .expect("the warrant has a target parent"),
            )
            .expect("create the other target writer directory");
            std::fs::copy(
                target_root_chirho
                    .join("resident-writer-chirho/migration-adoption-warrant-chirho.json"),
                &other_warrant_chirho,
            )
            .expect("replay the source warrant onto another target");
            let refusal_chirho = consume_writer_adoption_warrant_chirho(
                &other_target_chirho,
                &other_target_chirho.join(TEST_STORAGE_NAMESPACE_CHIRHO),
                &StoragePathChirho::new_chirho(TEST_JOURNAL_PATH_CHIRHO),
                &ClusterIdChirho(TEST_CLUSTER_ID_CHIRHO.to_owned()),
                0,
                target_ports_chirho,
                target_authority_chirho.clone(),
                Some(activation_verifier_chirho),
                Some(destination_authority_chirho),
            );
            assert_eq!(
                refusal_chirho,
                Err(TenantMigrationWriterAdoptionConsumptionRefusalChirho::WarrantTargetNodeChirho,),
                "the replay must name the target-node binding, not a later storage or mint failure"
            );
            assert_eq!(
                inspect_target_adoption_posture_chirho(&other_target_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho)
            );
            assert!(!other_target_chirho
                .join("resident-writer-chirho/migration-adoption-consumption-chirho.json")
                .exists());

            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho,
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("the same warrant remains valid on its exact target");
            std::fs::remove_dir_all(other_platform_chirho)
                .expect("remove the other target fixture");
        },
    );
}

#[test]
fn crash_after_durable_prepared_retries_from_absence_without_skipping_mint_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "crash-after-prepared",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         _source_signer_chirho| {
            install_writer_adoption_post_prepared_test_hook_chirho(|| {
                panic!("injected crash after durable adoption preparation")
            });
            let crashed_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _result_chirho = consume_fixture_warrant_chirho(
                    target_root_chirho,
                    target_ports_chirho,
                    target_authority_chirho.clone(),
                    activation_verifier_chirho,
                    destination_authority_chirho,
                );
            }));
            assert!(crashed_chirho.is_err());
            assert_eq!(
                inspect_target_adoption_posture_chirho(target_root_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityAbsentChirho),
                "the persisted attempt must precede the first identity byte"
            );
            let prepared_chirho = std::fs::read_to_string(
                target_root_chirho
                    .join("resident-writer-chirho/migration-adoption-consumption-chirho.json"),
            )
            .expect("read the durable prepared consumption");
            assert!(prepared_chirho.contains("\"state_chirho\":\"prepared_chirho\""));
            assert!(!prepared_chirho.contains("completed_chirho"));

            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho,
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("retry from the durable prepared state");
            assert!(matches!(
                inspect_target_adoption_posture_chirho(target_root_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityBoundChirho { .. })
            ));
        },
    );
}

#[test]
fn crash_after_mint_reuses_exact_identity_and_only_completes_consumption_chirho() {
    with_activated_writer_adoption_fixture_chirho(
        "crash-after-mint",
        |target_root_chirho,
         target_ports_chirho,
         target_authority_chirho,
         activation_verifier_chirho,
         destination_authority_chirho,
         _source_signer_chirho| {
            install_writer_adoption_post_mint_test_hook_chirho(|| {
                panic!("injected crash after writer identity mint")
            });
            let crashed_chirho = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _result_chirho = consume_fixture_warrant_chirho(
                    target_root_chirho,
                    target_ports_chirho,
                    target_authority_chirho.clone(),
                    activation_verifier_chirho,
                    destination_authority_chirho,
                );
            }));
            assert!(crashed_chirho.is_err());
            let minted_identity_chirho =
                match inspect_target_adoption_posture_chirho(target_root_chirho)
                    .expect("inspect the minted identity after the crash")
                {
                    TargetAdoptionPostureChirho::IdentityBoundChirho {
                        identity_digest_chirho,
                    } => identity_digest_chirho,
                    posture_chirho => {
                        panic!("expected the minted identity, got {posture_chirho:?}")
                    }
                };
            let prepared_chirho = std::fs::read_to_string(
                target_root_chirho
                    .join("resident-writer-chirho/migration-adoption-consumption-chirho.json"),
            )
            .expect("read the still-prepared consumption");
            assert!(prepared_chirho.contains("\"state_chirho\":\"prepared_chirho\""));

            consume_fixture_warrant_chirho(
                target_root_chirho,
                target_ports_chirho,
                target_authority_chirho,
                activation_verifier_chirho,
                destination_authority_chirho,
            )
            .expect("recover the exact minted identity and complete the consumption");
            assert_eq!(
                inspect_target_adoption_posture_chirho(target_root_chirho),
                Ok(TargetAdoptionPostureChirho::IdentityBoundChirho {
                    identity_digest_chirho: minted_identity_chirho,
                }),
                "retry must not mint a second identity"
            );
            let completed_chirho = std::fs::read_to_string(
                target_root_chirho
                    .join("resident-writer-chirho/migration-adoption-consumption-chirho.json"),
            )
            .expect("read the completed consumption");
            assert!(completed_chirho.contains("\"state_chirho\":\"completed_chirho\""));
        },
    );
}
