// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::{
    authority_registry_chirho, hex_bytes_chirho, provision_signers_chirho, temp_root_chirho,
};
use crate::elected_authority_chirho::{
    install_resident_post_verification_test_hook_chirho, ElectedLedgerAuthorityRefusalChirho,
    ElectedLedgerHostJournalChirho, ElectedLedgerLocalPortsChirho,
};
use crate::resident_authority_chirho::sink_term_lifecycle_chirho::{
    create_or_recover_resident_sink_term_cell_at_term_for_test_chirho,
    VerifiedResidentSinkTermCellAtBirthChirho,
};
use crate::resident_ledger_identity_chirho::{
    canonical_bound_identity_chirho, canonical_pending_identity_chirho,
    verify_bound_identity_chirho, verify_pending_identity_chirho,
    ResidentLedgerBoundIdentityVerificationRefusalChirho, ResidentLedgerCoordinateSourceChirho,
    RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
};
use crate::storage_chirho::StableLedgerNamespaceSnapshotChirho;
use crate::{
    FsLedgerStorageChirho, HostLedgerSignersChirho, PlatformPolicyMintAuthorityChirho,
    StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{LedgerClockPortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, AssetKindIdChirho, ClusterIdChirho};
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_head_chirho::resident_writer_chirho::{
    inspect_resident_writer_identity_chirho, reserve_resident_writer_chirho,
    resident_writer_identity_path_chirho, ResidentWriterBindingChirho,
    ResidentWriterReservationOutcomeChirho, MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, ConsistencyGroupIdChirho, WRITER_FENCE_LOCK_CHIRHO,
};
use ed25519_dalek::SigningKey;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

struct FixedIdentityClockChirho(u64);

impl LedgerClockPortChirho for FixedIdentityClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.0
    }
}

fn assert_resident_identity_refusal_chirho(error_chirho: &anyhow::Error, needle_chirho: &str) {
    let ElectedLedgerAuthorityRefusalChirho::ResidentIdentityRefusedChirho { detail_chirho } =
        error_chirho
            .downcast_ref::<ElectedLedgerAuthorityRefusalChirho>()
            .expect("resident identity refusal must retain its typed host cause")
    else {
        panic!("operation must fail through the resident identity boundary");
    };
    assert!(detail_chirho.contains(needle_chirho), "{detail_chirho}");
}

fn provision_instance_key_chirho(root_chirho: &Path, seed_chirho: u8) -> NodeIdChirho {
    fs::create_dir_all(root_chirho).unwrap();
    let signing_key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    fs::write(
        root_chirho.join("signing-key-chirho.bin"),
        signing_key_chirho.to_bytes(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root_chirho.join("signing-key-chirho.bin"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let public_key_chirho = hex_bytes_chirho(signing_key_chirho.verifying_key().as_bytes());
    fs::write(root_chirho.join("pubkey-chirho.hex"), &public_key_chirho).unwrap();
    NodeIdChirho(public_key_chirho)
}

fn prepare_identity_coordinate_chirho(
    label_chirho: &str,
) -> (
    PathBuf,
    PathBuf,
    ConsistencyGroupIdChirho,
    FsLedgerStorageChirho,
    StoragePathChirho,
    ClusterIdChirho,
    NodeIdChirho,
) {
    let platform_root_chirho = temp_root_chirho(label_chirho);
    fs::create_dir_all(&platform_root_chirho).unwrap();
    let tenant_root_chirho =
        prepare_tenant_root_chirho(&platform_root_chirho, "resident-identity-tenant-chirho")
            .unwrap();
    let group_chirho = consistency_group_for_root_chirho(&tenant_root_chirho).unwrap();
    let local_node_chirho = provision_instance_key_chirho(&tenant_root_chirho, 0x71);
    let storage_root_chirho = tenant_root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    (
        platform_root_chirho,
        tenant_root_chirho,
        group_chirho,
        storage_chirho,
        StoragePathChirho::new_chirho("journals/resident-identity-chirho.jsonl"),
        ClusterIdChirho("resident-identity-cluster-chirho".to_owned()),
        local_node_chirho,
    )
}

fn coordinate_source_chirho<'source_chirho>(
    root_chirho: &'source_chirho Path,
    namespace_snapshots_chirho: (
        &'source_chirho StableLedgerNamespaceSnapshotChirho,
        &'source_chirho StableLedgerNamespaceSnapshotChirho,
    ),
    group_chirho: &'source_chirho ConsistencyGroupIdChirho,
    storage_chirho: &'source_chirho FsLedgerStorageChirho,
    journal_path_chirho: &'source_chirho StoragePathChirho,
    cluster_id_chirho: &'source_chirho ClusterIdChirho,
    local_node_chirho: &'source_chirho NodeIdChirho,
) -> ResidentLedgerCoordinateSourceChirho<'source_chirho> {
    ResidentLedgerCoordinateSourceChirho {
        root_chirho,
        authority_root_snapshot_chirho: namespace_snapshots_chirho.0,
        group_chirho,
        storage_chirho,
        storage_snapshot_chirho: namespace_snapshots_chirho.1,
        identity_storage_namespace_chirho: storage_chirho.namespace_root_chirho(),
        journal_path_chirho,
        cluster_id_chirho,
        opening_epoch_chirho: 0,
        local_node_chirho,
    }
}

fn sink_term_cell_birth_proof_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    reservation_outcome_chirho: ResidentWriterReservationOutcomeChirho,
) -> VerifiedResidentSinkTermCellAtBirthChirho {
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let writer_lock_path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut writer_lock_chirho = authority_storage_chirho
        .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
        .unwrap();
    let writer_lock_guard_chirho = writer_lock_chirho.try_acquire_chirho().unwrap();
    create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
        group_chirho,
        0,
        &writer_lock_guard_chirho,
        reservation_outcome_chirho,
    )
    .unwrap()
}

#[test]
fn signed_pending_and_bound_identities_are_canonical_bounded_and_path_redacted_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-canonical",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
            );
            let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_one_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_chirho).unwrap();
            let pending_two_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_chirho).unwrap();
            assert_eq!(pending_one_chirho, pending_two_chirho);
            assert!(pending_one_chirho.len() < MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO);
            assert!(!String::from_utf8_lossy(&pending_one_chirho)
                .contains(root_chirho.to_str().unwrap()));
            assert!(!String::from_utf8_lossy(&pending_one_chirho).contains(
                ports_chirho
                    .storage_chirho
                    .namespace_root_chirho()
                    .to_str()
                    .unwrap()
            ));
            let verified_pending_chirho =
                verify_pending_identity_chirho(&pending_one_chirho, source_chirho).unwrap();
            assert_eq!(
                verified_pending_chirho.prepared_genesis_digest_chirho(),
                prepared_chirho.digest_chirho()
            );

            let genesis_chirho = prepared_chirho.digest_chirho().clone();
            let bound_one_chirho = canonical_bound_identity_chirho(
                source_chirho,
                prepared_chirho.canonical_line_chirho(),
                &genesis_chirho,
                sink_term_cell_birth_proof_chirho(
                    root_chirho,
                    group_chirho,
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                ),
            )
            .unwrap();
            let bound_two_chirho = canonical_bound_identity_chirho(
                source_chirho,
                prepared_chirho.canonical_line_chirho(),
                &genesis_chirho,
                sink_term_cell_birth_proof_chirho(
                    root_chirho,
                    group_chirho,
                    ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho,
                ),
            )
            .unwrap();
            assert_eq!(bound_one_chirho, bound_two_chirho);
            assert_eq!(
                verify_bound_identity_chirho(&bound_one_chirho, source_chirho)
                    .unwrap()
                    .verified_genesis_digest_chirho(),
                &genesis_chirho
            );
            let bound_without_birth_term_chirho =
                String::from_utf8(bound_one_chirho.clone()).unwrap();
            let signed_birth_term_field_chirho = ",\"sink_term_fence_birth_term_chirho\":0";
            assert_eq!(
                bound_without_birth_term_chirho
                    .matches(signed_birth_term_field_chirho)
                    .count(),
                1,
                "the tamper control must remove exactly one signed birth-term field"
            );
            let unsigned_omission_chirho =
                bound_without_birth_term_chirho.replacen(signed_birth_term_field_chirho, "", 1);
            let unsigned_omission_error_chirho =
                verify_bound_identity_chirho(unsigned_omission_chirho.as_bytes(), source_chirho)
                    .err()
                    .expect(
                        "removing the signed birth-term field without resigning must be refused",
                    );
            assert!(
                unsigned_omission_error_chirho
                    .downcast_ref::<ResidentLedgerBoundIdentityVerificationRefusalChirho>()
                    .is_none(),
                "an unsigned omission must not receive the typed signed-omission refusal"
            );
            assert!(
                unsigned_omission_error_chirho
                    .to_string()
                    .contains("ResidentLedgerIdentitySignatureInvalidChirho"),
                "a canonical identity tampered after signing must fail signature verification: {unsigned_omission_error_chirho}"
            );
            assert!(String::from_utf8(pending_one_chirho)
                .unwrap()
                .starts_with(
                    "{\"schema_chirho\":\"resident-ledger-pending-identity-v4-chirho\",\"state_chirho\":\"pending_chirho\",\"coordinate_chirho\":{\"canonical_root_digest_chirho\":"
                ));
            assert!(String::from_utf8(bound_one_chirho)
                .unwrap()
                .starts_with(
                    "{\"schema_chirho\":\"resident-ledger-bound-identity-v4-chirho\",\"state_chirho\":\"bound_chirho\",\"coordinate_chirho\":{\"canonical_root_digest_chirho\":"
                ));
        },
    );
}

#[test]
fn identity_parser_refuses_noncanonical_unknown_tampered_and_wrong_node_forms_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-refusals",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
            );
            let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_chirho).unwrap();

            let mut whitespace_chirho = pending_chirho.clone();
            whitespace_chirho.push(b' ');
            assert!(
                verify_pending_identity_chirho(&whitespace_chirho, source_chirho)
                    .err()
                    .expect("noncanonical pending identity must be refused")
                    .to_string()
                    .contains("ResidentLedgerIdentityNonCanonicalChirho")
            );

            let mut unknown_chirho = b"{\"unknown_chirho\":1,".to_vec();
            unknown_chirho.extend_from_slice(&pending_chirho[1..]);
            assert!(verify_pending_identity_chirho(&unknown_chirho, source_chirho).is_err());

            let signature_anchor_chirho = b"\"sig_chirho\":\"";
            let signature_offset_chirho = pending_chirho
                .windows(signature_anchor_chirho.len())
                .position(|window_chirho| window_chirho == signature_anchor_chirho)
                .unwrap()
                + signature_anchor_chirho.len();
            let mut tampered_chirho = pending_chirho.clone();
            tampered_chirho[signature_offset_chirho] =
                if tampered_chirho[signature_offset_chirho] == b'a' {
                    b'b'
                } else {
                    b'a'
                };
            assert!(
                verify_pending_identity_chirho(&tampered_chirho, source_chirho)
                    .err()
                    .expect("tampered pending identity must be refused")
                    .to_string()
                    .contains("ResidentLedgerIdentitySignatureInvalidChirho")
            );

            let wrong_node_chirho = NodeIdChirho("11".repeat(32));
            let wrong_source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                &wrong_node_chirho,
            );
            assert!(
                verify_pending_identity_chirho(&pending_chirho, wrong_source_chirho)
                    .err()
                    .expect("wrong-node pending identity must be refused")
                    .to_string()
                    .contains("ResidentLedgerIdentitySignerNodeMismatchChirho")
            );
        },
    );
}

fn with_resident_host_fixture_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &Path,
        &StableLedgerNamespaceSnapshotChirho,
        &ConsistencyGroupIdChirho,
        ElectedLedgerLocalPortsChirho<'_>,
        &StableLedgerNamespaceSnapshotChirho,
        &StoragePathChirho,
        &ClusterIdChirho,
        &NodeIdChirho,
    ),
) {
    let (
        platform_root_chirho,
        tenant_root_chirho,
        group_chirho,
        storage_chirho,
        journal_path_chirho,
        cluster_id_chirho,
        local_node_chirho,
    ) = prepare_identity_coordinate_chirho(label_chirho);
    let refs_chirho = provision_signers_chirho(&tenant_root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&tenant_root_chirho, &refs_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let account_chirho = AccountIdChirho {
        owner_chirho: "resident-identity-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    let membership_chirho = StaticClusterMembershipChirho::new_chirho(0, [account_chirho])
        .unwrap()
        .elected_view_chirho();
    let registry_chirho = authority_registry_chirho();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let ports_chirho = ElectedLedgerLocalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signers_chirho.journal_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let authority_root_snapshot_chirho =
        StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&tenant_root_chirho).unwrap();
    let storage_snapshot_chirho = StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(
        storage_chirho.namespace_root_chirho(),
    )
    .unwrap();
    action_chirho(
        &tenant_root_chirho,
        &authority_root_snapshot_chirho,
        &group_chirho,
        ports_chirho,
        &storage_snapshot_chirho,
        &journal_path_chirho,
        &cluster_id_chirho,
        &local_node_chirho,
    );
    fs::remove_dir_all(platform_root_chirho).unwrap();
}

fn raw_journal_ports_chirho<'ports_chirho>(
    ports_chirho: ElectedLedgerLocalPortsChirho<'ports_chirho>,
) -> JournalPortsChirho<'ports_chirho> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

#[test]
fn existing_journal_without_prior_pending_refuses_without_creating_identity_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-no-adopt",
        |root_chirho,
         _authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         _storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            drop(
                LedgerJournalChirho::create_chirho(
                    raw_journal_ports_chirho(ports_chirho),
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                )
                .unwrap(),
            );
            let error_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("an unowned existing journal must be refused");
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(
                    &ElectedLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho
                )
            );
            assert!(!resident_writer_identity_path_chirho(root_chirho)
                .unwrap()
                .exists());
        },
    );
}

#[test]
fn exact_pending_crash_recovery_binds_and_retains_lifetime_exclusion_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-crash-recovery",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
            );
            let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_identity_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_genesis_chirho).unwrap();
            let pending_binding_chirho = ResidentWriterBindingChirho {
                root_chirho,
                identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
                canonical_identity_chirho: &pending_identity_chirho,
            };
            let (provisioning_chirho, outcome_chirho) =
                reserve_resident_writer_chirho(&pending_binding_chirho).unwrap();
            assert_eq!(
                outcome_chirho,
                ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
            );
            drop(
                LedgerJournalChirho::create_prepared_chirho(
                    raw_journal_ports_chirho(ports_chirho),
                    journal_path_chirho.clone(),
                    prepared_genesis_chirho,
                )
                .unwrap(),
            );
            drop(provisioning_chirho);

            let first_host_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .unwrap();
            let inspection_chirho = inspect_resident_writer_identity_chirho(root_chirho).unwrap();
            let verified_chirho = verify_bound_identity_chirho(
                inspection_chirho.canonical_identity_chirho(),
                source_chirho,
            )
            .unwrap();
            assert_eq!(
                verified_chirho.verified_genesis_digest_chirho(),
                first_host_chirho
                    .journal_ref_chirho()
                    .genesis_digest_chirho()
            );

            let overlap_error_chirho = ElectedLedgerHostJournalChirho::open_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho,
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("a second resident host must be refused");
            assert_resident_identity_refusal_chirho(
                &overlap_error_chirho,
                "ResidentWriterAlreadyHeldChirho",
            );
            drop(first_host_chirho);

            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            let journal_before_refusals_chirho = fs::read(&journal_file_chirho).unwrap();
            let alternate_cluster_chirho =
                ClusterIdChirho("alternate-resident-cluster-chirho".to_owned());
            let alternate_cluster_error_chirho = ElectedLedgerHostJournalChirho::open_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                &alternate_cluster_chirho,
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("an alternate cluster identity must be refused");
            assert_resident_identity_refusal_chirho(
                &alternate_cluster_error_chirho,
                "ResidentLedgerIdentityCoordinateMismatchChirho",
            );
            let alternate_path_chirho =
                StoragePathChirho::new_chirho("journals/alternate-resident-chirho.jsonl");
            let alternate_path_error_chirho = ElectedLedgerHostJournalChirho::open_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                alternate_path_chirho,
                cluster_id_chirho,
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("an alternate journal path identity must be refused");
            assert_resident_identity_refusal_chirho(
                &alternate_path_error_chirho,
                "ResidentLedgerIdentityCoordinateMismatchChirho",
            );
            assert_eq!(
                fs::read(&journal_file_chirho).unwrap(),
                journal_before_refusals_chirho,
                "coordinate refusal must happen before journal recovery or mutation"
            );

            let reopened_chirho = ElectedLedgerHostJournalChirho::open_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho,
                0,
                local_node_chirho.clone(),
            )
            .unwrap();
            assert_eq!(reopened_chirho.journal_ref_chirho().tail_seq_chirho(), 0);
        },
    );
}

#[test]
fn pending_identity_never_adopts_a_different_pristine_genesis_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-genesis-collision",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
            );
            let committed_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_identity_chirho =
                canonical_pending_identity_chirho(source_chirho, &committed_genesis_chirho)
                    .unwrap();
            let pending_binding_chirho = ResidentWriterBindingChirho {
                root_chirho,
                identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
                canonical_identity_chirho: &pending_identity_chirho,
            };
            let (provisioning_chirho, _outcome_chirho) =
                reserve_resident_writer_chirho(&pending_binding_chirho).unwrap();
            drop(provisioning_chirho);

            let foreign_clock_chirho = FixedIdentityClockChirho(1);
            let foreign_ports_chirho = JournalPortsChirho {
                storage_chirho: ports_chirho.storage_chirho,
                signer_chirho: ports_chirho.signer_chirho,
                clock_chirho: &foreign_clock_chirho,
                membership_chirho: ports_chirho.membership_chirho,
                kind_registry_chirho: ports_chirho.kind_registry_chirho,
                authority_chirho: ports_chirho.authority_chirho,
            };
            let foreign_journal_chirho = LedgerJournalChirho::create_chirho(
                foreign_ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            assert_ne!(
                foreign_journal_chirho.genesis_digest_chirho(),
                committed_genesis_chirho.digest_chirho()
            );
            drop(foreign_journal_chirho);
            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            let foreign_bytes_chirho = fs::read(&journal_file_chirho).unwrap();

            let error_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("a different pristine genesis must never be adopted");
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(&ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho)
            );
            assert_eq!(fs::read(journal_file_chirho).unwrap(), foreign_bytes_chirho);
            let inspection_chirho = inspect_resident_writer_identity_chirho(root_chirho).unwrap();
            verify_pending_identity_chirho(
                inspection_chirho.canonical_identity_chirho(),
                source_chirho,
            )
            .unwrap();
        },
    );
}

#[test]
fn pending_identity_requires_exact_pristine_genesis_file_bytes_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-exact-genesis-bytes",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let source_chirho = coordinate_source_chirho(
                root_chirho,
                (authority_root_snapshot_chirho, storage_snapshot_chirho),
                group_chirho,
                ports_chirho.storage_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                local_node_chirho,
            );
            let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_identity_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_genesis_chirho).unwrap();
            let pending_binding_chirho = ResidentWriterBindingChirho {
                root_chirho,
                identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
                canonical_identity_chirho: &pending_identity_chirho,
            };
            let (provisioning_chirho, _outcome_chirho) =
                reserve_resident_writer_chirho(&pending_binding_chirho).unwrap();
            drop(provisioning_chirho);

            let journal_chirho = LedgerJournalChirho::create_prepared_chirho(
                raw_journal_ports_chirho(ports_chirho),
                journal_path_chirho.clone(),
                prepared_genesis_chirho,
            )
            .unwrap();
            drop(journal_chirho);
            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            let mut file_chirho = fs::OpenOptions::new()
                .append(true)
                .open(&journal_file_chirho)
                .unwrap();
            file_chirho.write_all(b" \n").unwrap();
            file_chirho.sync_all().unwrap();
            drop(file_chirho);
            let nonexact_bytes_chirho = fs::read(&journal_file_chirho).unwrap();

            let error_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("semantic genesis equivalence must not substitute for exact file bytes");
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(&ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho)
            );
            assert_eq!(
                fs::read(journal_file_chirho).unwrap(),
                nonexact_bytes_chirho
            );
        },
    );
}

#[test]
fn pending_identity_refuses_a_post_verification_journal_change_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-post-verification-change",
        |root_chirho,
         authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                raw_journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                0,
            )
            .unwrap();
            let pending_identity_chirho = canonical_pending_identity_chirho(
                coordinate_source_chirho(
                    root_chirho,
                    (authority_root_snapshot_chirho, storage_snapshot_chirho),
                    group_chirho,
                    ports_chirho.storage_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    local_node_chirho,
                ),
                &prepared_genesis_chirho,
            )
            .unwrap();
            let pending_binding_chirho = ResidentWriterBindingChirho {
                root_chirho,
                identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
                canonical_identity_chirho: &pending_identity_chirho,
            };
            let (provisioning_chirho, _outcome_chirho) =
                reserve_resident_writer_chirho(&pending_binding_chirho).unwrap();
            drop(provisioning_chirho);

            drop(
                LedgerJournalChirho::create_prepared_chirho(
                    raw_journal_ports_chirho(ports_chirho),
                    journal_path_chirho.clone(),
                    prepared_genesis_chirho,
                )
                .unwrap(),
            );
            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            let pristine_bytes_chirho = fs::read(&journal_file_chirho).unwrap();
            let mutation_path_chirho = journal_file_chirho.clone();
            install_resident_post_verification_test_hook_chirho(move || {
                let mut file_chirho = fs::OpenOptions::new()
                    .append(true)
                    .open(mutation_path_chirho)
                    .unwrap();
                file_chirho.write_all(b" \n").unwrap();
                file_chirho.sync_all().unwrap();
            });

            let error_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("a journal change after verification must be refused");
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(&ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho)
            );
            let mut changed_bytes_chirho = pristine_bytes_chirho;
            changed_bytes_chirho.extend_from_slice(b" \n");
            assert_eq!(fs::read(journal_file_chirho).unwrap(), changed_bytes_chirho);
            let inspection_chirho = inspect_resident_writer_identity_chirho(root_chirho).unwrap();
            assert_eq!(
                inspection_chirho.canonical_identity_chirho(),
                pending_identity_chirho
            );
            verify_pending_identity_chirho(
                inspection_chirho.canonical_identity_chirho(),
                coordinate_source_chirho(
                    root_chirho,
                    (authority_root_snapshot_chirho, storage_snapshot_chirho),
                    group_chirho,
                    ports_chirho.storage_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    local_node_chirho,
                ),
            )
            .unwrap();
        },
    );
}

#[test]
fn bound_reopen_requires_current_private_key_possession_before_journal_read_chirho() {
    with_resident_host_fixture_chirho(
        "resident-identity-private-possession",
        |root_chirho,
         _authority_root_snapshot_chirho,
         group_chirho,
         ports_chirho,
         _storage_snapshot_chirho,
         journal_path_chirho,
         cluster_id_chirho,
         local_node_chirho| {
            let host_chirho = ElectedLedgerHostJournalChirho::create_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                local_node_chirho.clone(),
            )
            .unwrap();
            drop(host_chirho);
            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            let journal_before_chirho = fs::read(&journal_file_chirho).unwrap();
            fs::write(root_chirho.join("signing-key-chirho.bin"), [0x19; 32]).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    root_chirho.join("signing-key-chirho.bin"),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }

            let error_chirho = ElectedLedgerHostJournalChirho::open_chirho(
                root_chirho,
                group_chirho.clone(),
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho,
                0,
                local_node_chirho.clone(),
            )
            .err()
            .expect("Bound reopen must prove possession of the persisted identity key");
            assert_resident_identity_refusal_chirho(
                &error_chirho,
                "existing signing key pair does not agree",
            );
            assert_eq!(
                fs::read(journal_file_chirho).unwrap(),
                journal_before_chirho
            );
        },
    );
}
