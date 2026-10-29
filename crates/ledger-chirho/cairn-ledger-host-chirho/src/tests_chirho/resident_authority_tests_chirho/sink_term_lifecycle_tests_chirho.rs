// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{
    warm_single_node_elector_chirho, with_bound_resident_fixture_chirho,
    with_unbound_resident_fixture_chirho,
};
use crate::reconciliation_chirho::sink_term_fence_chirho::{
    advance_accepted_winner_term_chirho, read_sink_term_fence_chirho,
    sink_term_fence_storage_key_chirho, SinkTermFenceStateChirho,
};
use crate::resident_authority_chirho::sink_term_lifecycle_chirho::create_or_recover_resident_sink_term_cell_at_term_for_test_chirho;
use crate::resident_authority_chirho::{
    install_resident_birth_post_genesis_test_hook_chirho,
    install_resident_birth_post_sink_term_cell_test_hook_chirho,
};
use crate::resident_ledger_identity_chirho::{
    canonical_current_v4_bound_identity_without_birth_term_for_test_chirho,
    canonical_legacy_v3_bound_identity_for_test_chirho,
    canonical_legacy_v3_pending_identity_for_test_chirho, canonical_pending_identity_chirho,
    verify_pending_identity_chirho, ResidentLedgerCoordinateSourceChirho,
    RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO, RESIDENT_LEDGER_LEGACY_V3_IDENTITY_KIND_CHIRHO,
};
use crate::{
    FsLedgerStorageChirho, HostLedgerStorageRefusalChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerBirthPermitChirho,
    ResidentLedgerLocalPortsChirho, ResidentSinkTermCellRefusalChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::resident_writer_chirho::{
    reserve_resident_writer_in_custody_chirho,
    try_inspect_resident_writer_identity_in_custody_chirho, ResidentWriterBindingChirho,
    ResidentWriterReservationOutcomeChirho, ResidentWriterRootCustodyChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho, WRITER_FENCE_LOCK_CHIRHO,
};
use std::cell::Cell;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::rc::Rc;

fn resident_identity_exists_chirho(
    root_chirho: &Path,
    authority_storage_chirho: &FsLedgerStorageChirho,
) -> bool {
    let custody_chirho = ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
        root_chirho,
        authority_storage_chirho
            .clone_namespace_root_descriptor_chirho()
            .unwrap(),
    )
    .unwrap();
    try_inspect_resident_writer_identity_in_custody_chirho(&custody_chirho)
        .unwrap()
        .is_some()
}

fn read_resident_sink_term_cell_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Option<SinkTermFenceStateChirho> {
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
    under_resident_writer_lock_chirho(root_chirho, |writer_lock_guard_chirho| {
        read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
    })
    .unwrap()
}

pub(super) fn under_resident_writer_lock_chirho<OutputChirho>(
    root_chirho: &Path,
    action_chirho: impl FnOnce(
        &crate::storage_chirho::StableLedgerExclusiveLockGuardChirho<'_>,
    ) -> OutputChirho,
) -> OutputChirho {
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut handle_chirho = storage_chirho
        .provision_exclusive_lock_handle_chirho(&path_chirho)
        .unwrap();
    let guard_chirho = handle_chirho.try_acquire_chirho().unwrap();
    action_chirho(&guard_chirho)
}

fn raw_journal_ports_chirho(
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
) -> JournalPortsChirho<'_> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

#[derive(Clone, Copy)]
enum BoundIdentityFixtureGenerationChirho {
    LegacyV3Chirho,
    CurrentV4MissingBirthTermChirho,
}

fn install_bound_identity_fixture_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    fixture_generation_chirho: BoundIdentityFixtureGenerationChirho,
) {
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let writer_lock_path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    drop(
        authority_storage_chirho
            .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
            .unwrap(),
    );
    let authority_snapshot_chirho = authority_storage_chirho
        .stable_namespace_snapshot_chirho()
        .unwrap();
    let storage_snapshot_chirho = ports_chirho
        .storage_chirho
        .stable_namespace_snapshot_chirho()
        .unwrap();
    let source_chirho = ResidentLedgerCoordinateSourceChirho {
        root_chirho,
        authority_root_snapshot_chirho: &authority_snapshot_chirho,
        group_chirho,
        storage_chirho: ports_chirho.storage_chirho,
        storage_snapshot_chirho: &storage_snapshot_chirho,
        identity_storage_namespace_chirho: ports_chirho.storage_chirho.namespace_root_chirho(),
        journal_path_chirho,
        cluster_id_chirho,
        opening_epoch_chirho: 0,
        local_node_chirho: node_chirho,
    };
    let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
        raw_journal_ports_chirho(ports_chirho),
        cluster_id_chirho.clone(),
        0,
    )
    .unwrap();
    let (pending_identity_chirho, identity_kind_chirho) = match fixture_generation_chirho {
        BoundIdentityFixtureGenerationChirho::LegacyV3Chirho => (
            canonical_legacy_v3_pending_identity_for_test_chirho(source_chirho, &prepared_chirho)
                .unwrap(),
            RESIDENT_LEDGER_LEGACY_V3_IDENTITY_KIND_CHIRHO,
        ),
        BoundIdentityFixtureGenerationChirho::CurrentV4MissingBirthTermChirho => (
            canonical_pending_identity_chirho(source_chirho, &prepared_chirho).unwrap(),
            RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
        ),
    };
    let pending_binding_chirho = ResidentWriterBindingChirho {
        root_chirho,
        identity_kind_chirho,
        canonical_identity_chirho: &pending_identity_chirho,
    };
    let custody_chirho = ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
        root_chirho,
        authority_storage_chirho
            .clone_namespace_root_descriptor_chirho()
            .unwrap(),
    )
    .unwrap();
    let (provisioning_chirho, outcome_chirho) =
        reserve_resident_writer_in_custody_chirho(&custody_chirho, &pending_binding_chirho)
            .unwrap();
    assert_eq!(
        outcome_chirho,
        ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
    );
    drop(
        LedgerJournalChirho::create_prepared_chirho(
            raw_journal_ports_chirho(ports_chirho),
            journal_path_chirho.clone(),
            prepared_chirho.clone(),
        )
        .unwrap(),
    );
    let bound_identity_chirho = match fixture_generation_chirho {
        BoundIdentityFixtureGenerationChirho::LegacyV3Chirho => {
            canonical_legacy_v3_bound_identity_for_test_chirho(
                source_chirho,
                prepared_chirho.canonical_line_chirho(),
                prepared_chirho.digest_chirho(),
            )
            .unwrap()
        }
        BoundIdentityFixtureGenerationChirho::CurrentV4MissingBirthTermChirho => {
            canonical_current_v4_bound_identity_without_birth_term_for_test_chirho(
                source_chirho,
                prepared_chirho.canonical_line_chirho(),
                prepared_chirho.digest_chirho(),
            )
            .unwrap()
        }
    };
    let bound_binding_chirho = ResidentWriterBindingChirho {
        root_chirho,
        identity_kind_chirho,
        canonical_identity_chirho: &bound_identity_chirho,
    };
    drop(
        provisioning_chirho
            .bind_resident_writer_chirho(&bound_binding_chirho)
            .unwrap(),
    );
}

fn warm_durable_single_node_elector_at_term_chirho(
    elector_root_chirho: &Path,
    node_chirho: &NodeIdChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    target_term_chirho: u64,
) -> RaftWriterElectorChirho {
    assert!(target_term_chirho > 0);
    let mut elector_chirho = if elector_root_chirho.exists() {
        RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
            elector_root_chirho.to_path_buf(),
            node_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap()
    } else {
        RaftWriterElectorChirho::new_durable_single_node_chirho(
            elector_root_chirho.to_path_buf(),
            node_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap()
    }
    .with_leadership_warmup_lease_chirho();

    loop {
        let before_chirho = elector_chirho.current_leadership_chirho();
        assert!(
            before_chirho.term_chirho < target_term_chirho || before_chirho.is_leader_chirho,
            "durable test elector must never begin beyond its requested term"
        );
        if before_chirho.is_leader_chirho && before_chirho.term_chirho == target_term_chirho {
            return elector_chirho;
        }
        elector_chirho.campaign_chirho().unwrap();
        for _tick_chirho in 0..10 {
            let _outbound_chirho = elector_chirho.tick_chirho();
        }
        let leadership_chirho = elector_chirho.current_leadership_chirho();
        assert!(leadership_chirho.is_leader_chirho);
        assert!(leadership_chirho.term_chirho <= target_term_chirho);
        if leadership_chirho.term_chirho == target_term_chirho {
            return elector_chirho;
        }
        drop(elector_chirho);
        elector_chirho = RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
            elector_root_chirho.to_path_buf(),
            node_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap()
        .with_leadership_warmup_lease_chirho();
    }
}

fn assert_exact_pending_residue_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
) {
    let authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
    let authority_snapshot_chirho = authority_storage_chirho
        .stable_namespace_snapshot_chirho()
        .unwrap();
    let storage_snapshot_chirho = ports_chirho
        .storage_chirho
        .stable_namespace_snapshot_chirho()
        .unwrap();
    let custody_chirho = ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
        root_chirho,
        authority_storage_chirho
            .clone_namespace_root_descriptor_chirho()
            .unwrap(),
    )
    .unwrap();
    let inspection_chirho = try_inspect_resident_writer_identity_in_custody_chirho(&custody_chirho)
        .unwrap()
        .expect("the crash injection must leave durable Pending identity bytes");
    assert_eq!(
        inspection_chirho.identity_kind_chirho(),
        RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO
    );
    let source_chirho = ResidentLedgerCoordinateSourceChirho {
        root_chirho,
        authority_root_snapshot_chirho: &authority_snapshot_chirho,
        group_chirho,
        storage_chirho: ports_chirho.storage_chirho,
        storage_snapshot_chirho: &storage_snapshot_chirho,
        identity_storage_namespace_chirho: ports_chirho.storage_chirho.namespace_root_chirho(),
        journal_path_chirho,
        cluster_id_chirho,
        opening_epoch_chirho: 0,
        local_node_chirho: node_chirho,
    };
    verify_pending_identity_chirho(inspection_chirho.canonical_identity_chirho(), source_chirho)
        .expect("the injected residue must be an exact signed Pending identity");
    assert!(
        ports_chirho
            .storage_chirho
            .read_all_chirho(journal_path_chirho)
            .unwrap()
            .is_some(),
        "the crash arm must reach the durable journal leg before retry"
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn fresh_birth_never_adopts_a_preexisting_sink_cell_on_retry_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-unowned-retry",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let authority_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let writer_lock_path_chirho = StoragePathChirho::new_chirho(
                named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO),
            );
            let mut writer_lock_chirho = authority_storage_chirho
                .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
                .unwrap();
            let writer_lock_guard_chirho = writer_lock_chirho.try_acquire_chirho().unwrap();
            create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                group_chirho,
                1,
                &writer_lock_guard_chirho,
                ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
            )
            .unwrap();
            drop(writer_lock_guard_chirho);
            drop(writer_lock_chirho);

            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let first_refusal_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("a fresh birth must refuse an unowned pre-existing sink cell");
            assert!(matches!(
                first_refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::UnownedResidueAtFreshBirthChirho {
                            existing_term_chirho: 1,
                        },
                }
            ));
            assert!(
                !resident_identity_exists_chirho(root_chirho, &authority_storage_chirho),
                "unowned-cell refusal must precede fresh Pending; if a future lifecycle changes this point, preserve the distinction between unowned residue and owned crash recovery"
            );
            assert!(
                ports_chirho
                    .storage_chirho
                    .read_all_chirho(journal_path_chirho)
                    .unwrap()
                    .is_none(),
                "unowned-cell refusal must precede journal creation"
            );

            let retry_refusal_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect(
                    "retry must not relabel the unowned cell as recovered merely because the first refusal left Pending",
                );
            assert!(matches!(
                retry_refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::UnownedResidueAtFreshBirthChirho {
                            existing_term_chirho: 1,
                        },
                }
            ), "both attempts must refuse the SAME unowned-residue reason; a different refusal would not prove retry cannot relabel the cell as owned, and acceptance would reintroduce the fail-open");
            assert!(
                !resident_identity_exists_chirho(root_chirho, &authority_storage_chirho),
                "retry must leave no identity residue"
            );
            assert!(
                ports_chirho
                    .storage_chirho
                    .read_all_chirho(journal_path_chirho)
                    .unwrap()
                    .is_none(),
                "retry must leave no journal residue"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn pending_before_cell_crash_retries_through_the_exact_pending_envelope_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-before-create-crash",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            install_resident_birth_post_genesis_test_hook_chirho(|| {
                panic!("InjectedResidentBirthAfterPendingBeforeSinkCellChirho")
            });
            let first_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let first_attempt_chirho = catch_unwind(AssertUnwindSafe(|| {
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    first_elector_chirho.local_append_authority_handle_chirho(),
                )
            }));
            assert!(
                first_attempt_chirho.is_err(),
                "the before-cell crash injection must apply before any retry claim"
            );
            assert_exact_pending_residue_chirho(
                root_chirho,
                group_chirho,
                node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
            );
            assert!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho).is_none(),
                "the first crash window must be durable Pending plus NO sink cell"
            );
            drop(first_elector_chirho);

            let retry_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let recovered_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    retry_elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("exact Pending retry must create the absent cell and finish Bound");
            assert_eq!(
                recovered_chirho
                    .probe_chirho()
                    .unwrap()
                    .published_raft_term_chirho,
                1
            );
            assert_eq!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho)
                    .expect("retry must create the birth cell")
                    .highest_accepted_winner_term_chirho,
                1
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn cell_before_bound_crash_reuses_the_owned_cell_on_exact_pending_retry_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-before-bound-crash",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            install_resident_birth_post_sink_term_cell_test_hook_chirho(|| {
                panic!("InjectedResidentBirthAfterSinkCellBeforeBoundChirho")
            });
            let first_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let first_attempt_chirho = catch_unwind(AssertUnwindSafe(|| {
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    first_elector_chirho.local_append_authority_handle_chirho(),
                )
            }));
            assert!(
                first_attempt_chirho.is_err(),
                "the after-cell crash injection must apply before any retry claim"
            );
            assert_exact_pending_residue_chirho(
                root_chirho,
                group_chirho,
                node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
            );
            assert_eq!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho)
                    .expect("the second crash window must leave its owned sink cell")
                    .highest_accepted_winner_term_chirho,
                1
            );
            drop(first_elector_chirho);

            let retry_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let recovered_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    ResidentLedgerBirthPermitChirho::for_test_chirho(
                        root_chirho,
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                    ),
                    ports_chirho,
                    retry_elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("exact Pending retry must reuse its owned cell and finish Bound");
            assert_eq!(
                recovered_chirho
                    .probe_chirho()
                    .unwrap()
                    .published_raft_term_chirho,
                1
            );
            assert_eq!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho)
                    .expect("owned cell must survive exact recovery")
                    .highest_accepted_winner_term_chirho,
                1
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn birth_retains_the_writer_lock_from_cell_write_through_bound_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-birth-lock-contention",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let hook_root_chirho = root_chirho.to_path_buf();
            let contention_observed_chirho = Rc::new(Cell::new(false));
            let hook_observed_chirho = Rc::clone(&contention_observed_chirho);
            install_resident_birth_post_sink_term_cell_test_hook_chirho(move || {
                let competing_storage_chirho =
                    FsLedgerStorageChirho::open_existing_chirho(&hook_root_chirho).unwrap();
                let writer_lock_path_chirho = StoragePathChirho::new_chirho(
                    named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO),
                );
                let mut competing_handle_chirho = competing_storage_chirho
                    .open_existing_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
                    .unwrap();
                let busy_chirho = competing_handle_chirho
                    .try_acquire_chirho()
                    .expect_err(
                        "a separately opened handle must contend while birth carries the cell into Bound",
                    );
                assert_eq!(
                    busy_chirho.downcast_ref::<HostLedgerStorageRefusalChirho>(),
                    Some(&HostLedgerStorageRefusalChirho::ExclusiveLockBusyChirho)
                );
                hook_observed_chirho.set(true);
            });
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let resident_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                ResidentLedgerBirthPermitChirho::for_test_chirho(
                    root_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                ),
                ports_chirho,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .expect("birth must complete after the competing lock is refused");
            assert!(
                contention_observed_chirho.get(),
                "the contention injection must run inside the cell-before-Bound window"
            );
            assert_eq!(
                resident_chirho
                    .probe_chirho()
                    .unwrap()
                    .published_raft_term_chirho,
                1
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn legacy_missing_legacy_planted_and_current_missing_cells_refuse_distinctly_chirho() {
    let mut legacy_missing_message_chirho = String::new();
    let mut legacy_planted_message_chirho = String::new();
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-legacy-neighbors",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            install_bound_identity_fixture_chirho(
                root_chirho,
                group_chirho,
                node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                BoundIdentityFixtureGenerationChirho::LegacyV3Chirho,
            );
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let missing_refusal_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("a fully verified legacy v3 Bound identity without a cell must refuse");
            assert!(matches!(
                missing_refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho: ResidentSinkTermCellRefusalChirho::LegacyBoundCellMissingChirho,
                }
            ));
            legacy_missing_message_chirho = missing_refusal_chirho.to_string();

            under_resident_writer_lock_chirho(root_chirho, |writer_lock_guard_chirho| {
                create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                    group_chirho,
                    1,
                    writer_lock_guard_chirho,
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                )
                .unwrap();
            });
            let planted_refusal_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("a planted cell must never grandfather a legacy v3 Bound identity");
            assert!(matches!(
                planted_refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::LegacyBoundIdentityGenerationChirho,
                }
            ));
            legacy_planted_message_chirho = planted_refusal_chirho.to_string();
        },
    );

    let mut current_missing_message_chirho = String::new();
    with_bound_resident_fixture_chirho(
        "resident-sink-cell-current-missing",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let cell_key_chirho = sink_term_fence_storage_key_chirho(&group_digest_chirho).unwrap();
            fs::remove_file(root_chirho.join(cell_key_chirho)).unwrap();
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let current_refusal_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("a current v4 Bound identity must require its birth cell");
            assert!(matches!(
                current_refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::CurrentBoundCellMissingChirho {
                            current_term_chirho: 1,
                        },
                }
            ));
            current_missing_message_chirho = current_refusal_chirho.to_string();
            assert!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho).is_none(),
                "Bound reopen must never recreate a missing current-generation cell"
            );
        },
    );

    let mut current_missing_proof_message_chirho = String::new();
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-current-missing-proof",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            install_bound_identity_fixture_chirho(
                root_chirho,
                group_chirho,
                node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
                BoundIdentityFixtureGenerationChirho::CurrentV4MissingBirthTermChirho,
            );
            under_resident_writer_lock_chirho(root_chirho, |writer_lock_guard_chirho| {
                create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                    group_chirho,
                    1,
                    writer_lock_guard_chirho,
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                )
                .unwrap();
            });
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let refusal_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .err()
            .expect("a signed v4 Bound identity without its birth term must fail closed");
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho: ResidentSinkTermCellRefusalChirho::CurrentBoundIdentityMissingSignedBirthTermChirho,
                },
                "an absent Option must produce the exact named refusal even when a valid cell exists; it must never skip the floor"
            );
            current_missing_proof_message_chirho = refusal_chirho.to_string();
        },
    );

    assert_ne!(legacy_missing_message_chirho, legacy_planted_message_chirho);
    assert_ne!(
        legacy_missing_message_chirho,
        current_missing_message_chirho
    );
    assert_ne!(
        legacy_planted_message_chirho,
        current_missing_message_chirho
    );
    assert_ne!(
        current_missing_proof_message_chirho,
        current_missing_message_chirho
    );
    assert_ne!(
        current_missing_proof_message_chirho,
        legacy_missing_message_chirho
    );
    assert_ne!(
        current_missing_proof_message_chirho,
        legacy_planted_message_chirho
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn current_bound_reopen_refuses_cell_rollback_below_its_signed_birth_term_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-signed-birth-floor",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_root_chirho = root_chirho.join("signed-birth-floor-elector-chirho");
            let birth_elector_chirho = warm_durable_single_node_elector_at_term_chirho(
                &elector_root_chirho,
                node_chirho,
                group_chirho,
                7,
            );
            let resident_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                ResidentLedgerBirthPermitChirho::for_test_chirho(
                    root_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                ),
                ports_chirho,
                birth_elector_chirho.local_append_authority_handle_chirho(),
            )
            .expect("the production birth path must sign and persist the T7 floor");
            assert_eq!(
                resident_chirho
                    .probe_chirho()
                    .unwrap()
                    .published_raft_term_chirho,
                7
            );
            drop(resident_chirho);
            drop(birth_elector_chirho);

            let current_elector_chirho = warm_durable_single_node_elector_at_term_chirho(
                &elector_root_chirho,
                node_chirho,
                group_chirho,
                8,
            );
            let legitimate_reopen_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    current_elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect(
                    "the signed T7 birth floor must not manufacture a refusal when live authority is T8",
                );
            assert_eq!(
                legitimate_reopen_chirho
                    .probe_chirho()
                    .unwrap()
                    .published_raft_term_chirho,
                8
            );
            drop(legitimate_reopen_chirho);

            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let authority_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let mut rolled_back_chirho =
                under_resident_writer_lock_chirho(root_chirho, |guard_chirho| {
                    read_sink_term_fence_chirho(guard_chirho, &group_digest_chirho)
                })
                .unwrap()
                .expect("birth must leave the exact production cell before the rollback plant");
            assert_eq!(rolled_back_chirho.highest_accepted_winner_term_chirho, 7);
            rolled_back_chirho.highest_accepted_winner_term_chirho = 5;
            let cell_path_chirho = StoragePathChirho::new_chirho(
                sink_term_fence_storage_key_chirho(&group_digest_chirho).unwrap(),
            );
            authority_storage_chirho
                .atomic_write_chirho(
                    &cell_path_chirho,
                    &serde_json::to_vec(&rolled_back_chirho).unwrap(),
                )
                .unwrap();
            assert_eq!(
                under_resident_writer_lock_chirho(root_chirho, |guard_chirho| {
                    read_sink_term_fence_chirho(guard_chirho, &group_digest_chirho)
                })
                .unwrap()
                .unwrap()
                .highest_accepted_winner_term_chirho,
                5,
                "the hostile plant must apply as a canonical, production-keyed T5 cell before open"
            );

            let refusal_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                current_elector_chirho.local_append_authority_handle_chirho(),
            )
            .err()
            .expect("T5 must not reopen a coordinate whose signed birth floor is T7");
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::CurrentBoundCellBelowSignedBirthTermChirho {
                            accepted_term_chirho: 5,
                            signed_birth_term_chirho: 7,
                        },
                }
            );
            assert!(!matches!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::CurrentBoundCellMissingChirho { .. }
                            | ResidentSinkTermCellRefusalChirho::CurrentBoundCellAheadOfAuthorityChirho { .. },
                }
            ));
            assert_eq!(
                under_resident_writer_lock_chirho(root_chirho, |guard_chirho| {
                    read_sink_term_fence_chirho(guard_chirho, &group_digest_chirho)
                })
                .unwrap()
                .unwrap()
                .highest_accepted_winner_term_chirho,
                5,
                "Bound reopen must refuse without repairing or rewriting hostile cell bytes"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn current_bound_reopen_refuses_a_cell_ahead_of_live_authority_without_rewrite_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-sink-cell-current-ahead",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            under_resident_writer_lock_chirho(root_chirho, |writer_lock_guard_chirho| {
                advance_accepted_winner_term_chirho(
                    writer_lock_guard_chirho,
                    &group_digest_chirho,
                    2,
                )
                .unwrap();
            });
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let refusal_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .err()
            .expect("a cell ahead of fresh local authority must refuse");
            assert!(matches!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho {
                    reason_chirho:
                        ResidentSinkTermCellRefusalChirho::CurrentBoundCellAheadOfAuthorityChirho {
                            accepted_term_chirho: 2,
                            current_term_chirho: 1,
                        },
                }
            ));
            assert_eq!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho)
                    .expect("ahead cell must remain present")
                    .highest_accepted_winner_term_chirho,
                2,
                "Bound reopen must never rewrite or lower the cell it verifies"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn recovered_pending_may_reuse_or_advance_but_fresh_outcomes_never_adopt_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-sink-cell-outcome-policy",
        |root_chirho,
         group_chirho,
         _node_chirho,
         _ports_chirho,
         _journal_path_chirho,
         _cluster_id_chirho| {
            under_resident_writer_lock_chirho(root_chirho, |writer_lock_guard_chirho| {
                create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                    group_chirho,
                    4,
                    writer_lock_guard_chirho,
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                )
                .unwrap();

                for fresh_outcome_chirho in [
                    ResidentWriterReservationOutcomeChirho::CreatedPendingChirho,
                    ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho,
                ] {
                    let refusal_chirho =
                        match create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                            group_chirho,
                            4,
                            writer_lock_guard_chirho,
                            fresh_outcome_chirho,
                        ) {
                            Ok(_proof_chirho) => panic!(
                                "a fresh reservation outcome must never adopt existing cell bytes"
                            ),
                            Err(refusal_chirho) => refusal_chirho,
                        };
                    assert_eq!(
                            refusal_chirho,
                            ResidentSinkTermCellRefusalChirho::UnownedResidueAtFreshBirthChirho {
                                existing_term_chirho: 4,
                            },
                            "both fresh reservation outcomes must reject existing bytes rather than infer ownership"
                        );
                }

                let advanced_chirho =
                    create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                        group_chirho,
                        5,
                        writer_lock_guard_chirho,
                        ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho,
                    )
                    .unwrap();
                assert_eq!(advanced_chirho.accepted_term_chirho(), 5);
                let reused_chirho =
                    create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                        group_chirho,
                        5,
                        writer_lock_guard_chirho,
                        ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho,
                    )
                    .unwrap();
                assert_eq!(reused_chirho.accepted_term_chirho(), 5);
                let ahead_refusal_chirho =
                    match create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                        group_chirho,
                        4,
                        writer_lock_guard_chirho,
                        ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho,
                    ) {
                        Ok(_proof_chirho) => {
                            panic!("recovered Pending must not accept a cell ahead of authority")
                        }
                        Err(refusal_chirho) => refusal_chirho,
                    };
                assert_eq!(
                    ahead_refusal_chirho,
                    ResidentSinkTermCellRefusalChirho::RecoveredCellAheadOfCurrentAuthorityChirho {
                        accepted_term_chirho: 5,
                        current_term_chirho: 4,
                    }
                );
            });
            assert_eq!(
                read_resident_sink_term_cell_chirho(root_chirho, group_chirho)
                    .unwrap()
                    .highest_accepted_winner_term_chirho,
                5
            );
        },
    );
}
