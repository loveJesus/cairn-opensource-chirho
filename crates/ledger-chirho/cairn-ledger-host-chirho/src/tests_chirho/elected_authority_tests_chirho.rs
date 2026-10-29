// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::{authority_registry_chirho, provision_signers_chirho, temp_root_chirho};
use crate::elected_authority_chirho::{
    ElectedLedgerAuthorityBridgeChirho, ElectedLedgerAuthorityRefusalChirho,
    ElectedLedgerHostJournalChirho, ElectedLedgerLocalPortsChirho,
};
use crate::{
    ElectedClusterMembershipChirho, FsLedgerStorageChirho, HostLedgerSignersChirho,
    PlatformPolicyMintAuthorityChirho, StaticClusterMembershipChirho, SystemLedgerClockChirho,
};
use cairn_ledger_log_chirho::admission_chirho::{MembershipStatusChirho, MembershipViewChirho};
use cairn_ledger_log_chirho::journal_chirho::{AppendLegRequestChirho, AppendRequestChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_signer_chirho::signer_chirho::pubkey_hex_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::{
    LeadershipChirho, NodeIdChirho, WriterElectorChirho,
};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, split_writer_epoch_chirho, writer_fence_path_chirho,
    CompositeWriterEpochRefusalChirho, ConsistencyGroupIdChirho,
};
use std::cell::RefCell;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

fn mint_request_chirho(
    account_chirho: &AccountIdChirho,
    amount_chirho: u64,
    idempotency_key_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho("11".repeat(32)),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: account_chirho.clone(),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("11".repeat(32))),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: idempotency_key_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn with_test_credit_journal_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &Path,
        &ConsistencyGroupIdChirho,
        &StaticClusterMembershipChirho,
        &ElectedClusterMembershipChirho,
        &NodeIdChirho,
        &mut ElectedLedgerHostJournalChirho<'_>,
        &AccountIdChirho,
    ),
) {
    let platform_root_chirho = temp_root_chirho(label_chirho);
    fs::create_dir_all(&platform_root_chirho).unwrap();
    let tenant_root_chirho =
        prepare_tenant_root_chirho(&platform_root_chirho, "test-credit-tenant-chirho").unwrap();
    let group_chirho = consistency_group_for_root_chirho(&tenant_root_chirho).unwrap();
    let local_node_chirho = NodeIdChirho(pubkey_hex_chirho(&tenant_root_chirho).unwrap());
    let refs_chirho = provision_signers_chirho(&tenant_root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&tenant_root_chirho, &refs_chirho).unwrap();
    let storage_root_chirho = tenant_root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let account_chirho = AccountIdChirho {
        owner_chirho: "test-credit-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    let static_membership_chirho =
        StaticClusterMembershipChirho::new_chirho(0, [account_chirho.clone()]).unwrap();
    let membership_chirho = static_membership_chirho.elected_view_chirho();
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
    let mut journal_chirho = ElectedLedgerHostJournalChirho::create_chirho(
        &tenant_root_chirho,
        group_chirho.clone(),
        ports_chirho,
        StoragePathChirho::new_chirho("journals/elected-test-credit-chirho.jsonl"),
        ClusterIdChirho("elected-test-credit-cluster-chirho".to_owned()),
        0,
        local_node_chirho.clone(),
    )
    .unwrap();

    action_chirho(
        &tenant_root_chirho,
        &group_chirho,
        &static_membership_chirho,
        &membership_chirho,
        &local_node_chirho,
        &mut journal_chirho,
        &account_chirho,
    );
    drop(journal_chirho);
    let _ = fs::remove_dir_all(platform_root_chirho);
}

#[test]
fn raft_leader_appends_at_exact_fence_and_reuses_one_durable_grant_chirho() {
    with_test_credit_journal_chirho(
        "elected-raft-append",
        |root_chirho,
         group_chirho,
         static_membership_chirho,
         membership_chirho,
         node_chirho,
         journal_chirho,
         account_chirho| {
            let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
                node_chirho.clone(),
                group_chirho.clone(),
            )
            .unwrap()
            .with_leadership_warmup_lease_chirho();
            elector_chirho.campaign_chirho().unwrap();
            for _tick_chirho in 0..10 {
                let _outbound_chirho = elector_chirho.tick_chirho();
            }
            let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
            assert!(leadership_chirho.is_leader_chirho);
            assert!(leadership_chirho.lease_valid_chirho);

            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let first_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    11,
                    "elected-mint-one-chirho",
                ))
                .unwrap();
            let fence_path_chirho = writer_fence_path_chirho(root_chirho, group_chirho).unwrap();
            let first_fence_bytes_chirho = fs::read(&fence_path_chirho).unwrap();
            let second_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    13,
                    "elected-mint-two-chirho",
                ))
                .unwrap();

            assert_eq!(first_chirho.fence_chirho, second_chirho.fence_chirho);
            assert_eq!(
                fs::read(&fence_path_chirho).unwrap(),
                first_fence_bytes_chirho
            );
            assert_eq!(first_chirho.append_chirho.seq_chirho, 1);
            assert_eq!(second_chirho.append_chirho.seq_chirho, 2);
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 2);
            assert_eq!(
                bridge_chirho.journal_chirho().current_epoch_chirho(),
                first_chirho.fence_chirho.epoch_chirho
            );
            assert_eq!(
                u64::from(
                    split_writer_epoch_chirho(first_chirho.fence_chirho.epoch_chirho)
                        .geo_term_chirho,
                ),
                leadership_chirho.term_chirho,
            );
            assert_eq!(
                membership_chirho.current_epoch_chirho(),
                first_chirho.fence_chirho.epoch_chirho,
            );
            assert!(membership_chirho.shares_roster_with_chirho(static_membership_chirho));
            assert_eq!(
                membership_chirho
                    .status_chirho(account_chirho, first_chirho.fence_chirho.epoch_chirho,),
                MembershipStatusChirho::MemberChirho,
            );
            assert_eq!(
                membership_chirho
                    .status_chirho(account_chirho, first_chirho.fence_chirho.epoch_chirho + 1,),
                MembershipStatusChirho::NonMemberChirho,
            );
            let head_chirho = bridge_chirho
                .journal_chirho()
                .head_state_chirho(account_chirho)
                .unwrap();
            assert_eq!(head_chirho.credits_total_chirho, 24);
            assert_eq!(head_chirho.debits_total_chirho, 0);
        },
    );
}

struct SequencedElectorChirho {
    node_chirho: NodeIdChirho,
    reads_chirho: AtomicUsize,
    first_chirho: LeadershipChirho,
    second_chirho: LeadershipChirho,
}

impl WriterElectorChirho for SequencedElectorChirho {
    fn leadership_chirho(&self, _group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        if self.reads_chirho.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_chirho.clone()
        } else {
            self.second_chirho.clone()
        }
    }

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_chirho
    }
}

struct MutableElectorChirho {
    node_chirho: NodeIdChirho,
    leadership_chirho: RefCell<LeadershipChirho>,
}

impl MutableElectorChirho {
    fn set_term_chirho(&self, term_chirho: u64) {
        self.leadership_chirho.replace(LeadershipChirho {
            is_leader_chirho: true,
            leader_id_chirho: Some(self.node_chirho.clone()),
            term_chirho,
            lease_valid_chirho: true,
        });
    }
}

impl WriterElectorChirho for MutableElectorChirho {
    fn leadership_chirho(&self, _group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        self.leadership_chirho.borrow().clone()
    }

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_chirho
    }
}

#[test]
fn restart_reissues_same_term_then_rolls_term_and_refuses_deposed_term_chirho() {
    let platform_root_chirho = temp_root_chirho("elected-restart-rollover");
    fs::create_dir_all(&platform_root_chirho).unwrap();
    let tenant_root_chirho =
        prepare_tenant_root_chirho(&platform_root_chirho, "restart-tenant-chirho").unwrap();
    let group_chirho = consistency_group_for_root_chirho(&tenant_root_chirho).unwrap();
    let refs_chirho = provision_signers_chirho(&tenant_root_chirho);
    let node_chirho = NodeIdChirho(pubkey_hex_chirho(&tenant_root_chirho).unwrap());
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&tenant_root_chirho, &refs_chirho).unwrap();
    let storage_root_chirho = tenant_root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let account_chirho = AccountIdChirho {
        owner_chirho: "restart-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    let static_membership_chirho =
        StaticClusterMembershipChirho::new_chirho(0, [account_chirho.clone()]).unwrap();
    let registry_chirho = authority_registry_chirho();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let path_chirho = StoragePathChirho::new_chirho("journals/restart-rollover-chirho.jsonl");
    let cluster_chirho = ClusterIdChirho("restart-rollover-cluster-chirho".to_owned());
    let elector_chirho = MutableElectorChirho {
        node_chirho: node_chirho.clone(),
        leadership_chirho: RefCell::new(LeadershipChirho {
            is_leader_chirho: true,
            leader_id_chirho: Some(node_chirho.clone()),
            term_chirho: 7,
            lease_valid_chirho: true,
        }),
    };

    let membership_one_chirho = static_membership_chirho.elected_view_chirho();
    let mut first_host_chirho = ElectedLedgerHostJournalChirho::create_chirho(
        &tenant_root_chirho,
        group_chirho.clone(),
        ElectedLedgerLocalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &signers_chirho.journal_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_one_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        },
        path_chirho.clone(),
        cluster_chirho.clone(),
        0,
        node_chirho.clone(),
    )
    .unwrap();
    let first_fence_chirho = {
        let mut bridge_chirho =
            ElectedLedgerAuthorityBridgeChirho::new_chirho(&mut first_host_chirho, &elector_chirho);
        bridge_chirho
            .append_chirho(mint_request_chirho(
                &account_chirho,
                3,
                "restart-first-chirho",
            ))
            .unwrap()
            .fence_chirho
    };
    drop(first_host_chirho);

    let membership_two_chirho = static_membership_chirho.elected_view_chirho();
    let mut reopened_host_chirho = ElectedLedgerHostJournalChirho::open_chirho(
        &tenant_root_chirho,
        group_chirho.clone(),
        ElectedLedgerLocalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &signers_chirho.journal_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_two_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        },
        path_chirho,
        &cluster_chirho,
        0,
        node_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        membership_two_chirho.current_epoch_chirho(),
        first_fence_chirho.epoch_chirho
    );
    let mut bridge_chirho =
        ElectedLedgerAuthorityBridgeChirho::new_chirho(&mut reopened_host_chirho, &elector_chirho);
    let restarted_chirho = bridge_chirho
        .append_chirho(mint_request_chirho(
            &account_chirho,
            5,
            "restart-second-chirho",
        ))
        .unwrap();
    assert_eq!(
        split_writer_epoch_chirho(restarted_chirho.fence_chirho.epoch_chirho).geo_term_chirho,
        7
    );
    assert!(restarted_chirho.fence_chirho.epoch_chirho > first_fence_chirho.epoch_chirho);

    elector_chirho.set_term_chirho(8);
    let rollover_chirho = bridge_chirho
        .append_chirho(mint_request_chirho(
            &account_chirho,
            7,
            "rollover-third-chirho",
        ))
        .unwrap();
    let rollover_parts_chirho =
        split_writer_epoch_chirho(rollover_chirho.fence_chirho.epoch_chirho);
    assert_eq!(rollover_parts_chirho.geo_term_chirho, 8);
    assert_eq!(rollover_parts_chirho.local_grant_seq_chirho, 0);
    let tail_before_deposed_chirho = bridge_chirho.journal_chirho().tail_seq_chirho();
    drop(bridge_chirho);

    elector_chirho.set_term_chirho(7);
    let mut deposed_bridge_chirho =
        ElectedLedgerAuthorityBridgeChirho::new_chirho(&mut reopened_host_chirho, &elector_chirho);
    let deposed_error_chirho = deposed_bridge_chirho
        .append_chirho(mint_request_chirho(
            &account_chirho,
            11,
            "deposed-fourth-chirho",
        ))
        .unwrap_err();
    assert_eq!(
        deposed_error_chirho.downcast_ref::<CompositeWriterEpochRefusalChirho>(),
        Some(&CompositeWriterEpochRefusalChirho::DeposedGeoTermChirho),
    );
    assert_eq!(
        deposed_bridge_chirho.journal_chirho().tail_seq_chirho(),
        tail_before_deposed_chirho
    );
    let _ = fs::remove_dir_all(platform_root_chirho);
}

#[test]
fn leadership_change_under_fence_refuses_before_journal_mutation_chirho() {
    with_test_credit_journal_chirho(
        "elected-leadership-change",
        |_root_chirho,
         _group_chirho,
         _static_membership_chirho,
         membership_chirho,
         node_chirho,
         journal_chirho,
         account_chirho| {
            let approved_chirho = LeadershipChirho {
                is_leader_chirho: true,
                leader_id_chirho: Some(node_chirho.clone()),
                term_chirho: 7,
                lease_valid_chirho: true,
            };
            let changed_chirho = LeadershipChirho {
                is_leader_chirho: false,
                leader_id_chirho: None,
                term_chirho: 8,
                lease_valid_chirho: false,
            };
            let elector_chirho = SequencedElectorChirho {
                node_chirho: node_chirho.clone(),
                reads_chirho: AtomicUsize::new(0),
                first_chirho: approved_chirho.clone(),
                second_chirho: changed_chirho.clone(),
            };
            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let error_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    17,
                    "leadership-change-chirho",
                ))
                .unwrap_err();
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(
                    &ElectedLedgerAuthorityRefusalChirho::LeadershipChangedChirho {
                        approved_chirho,
                        revalidated_chirho: changed_chirho,
                    }
                ),
            );
            assert!(bridge_chirho.active_fence_chirho().is_some());
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 0);
            assert_eq!(bridge_chirho.journal_chirho().current_epoch_chirho(), 0);
            assert_eq!(membership_chirho.current_epoch_chirho(), 0);
        },
    );
}

#[test]
fn invalid_initial_lease_refuses_before_fence_or_journal_mutation_chirho() {
    with_test_credit_journal_chirho(
        "elected-invalid-lease",
        |root_chirho,
         group_chirho,
         _static_membership_chirho,
         membership_chirho,
         node_chirho,
         journal_chirho,
         account_chirho| {
            let invalid_chirho = LeadershipChirho {
                is_leader_chirho: true,
                leader_id_chirho: Some(node_chirho.clone()),
                term_chirho: 5,
                lease_valid_chirho: false,
            };
            let elector_chirho = SequencedElectorChirho {
                node_chirho: node_chirho.clone(),
                reads_chirho: AtomicUsize::new(0),
                first_chirho: invalid_chirho.clone(),
                second_chirho: invalid_chirho,
            };
            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let error_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    23,
                    "invalid-lease-chirho",
                ))
                .unwrap_err();
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(&ElectedLedgerAuthorityRefusalChirho::LeaseInvalidChirho),
            );
            assert!(bridge_chirho.active_fence_chirho().is_none());
            assert!(!writer_fence_path_chirho(root_chirho, group_chirho)
                .unwrap()
                .exists());
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 0);
            assert_eq!(membership_chirho.current_epoch_chirho(), 0);
        },
    );
}

#[test]
fn elector_node_must_equal_the_resident_identity_key_before_fence_or_append_chirho() {
    with_test_credit_journal_chirho(
        "elected-resident-node-mismatch",
        |root_chirho,
         group_chirho,
         _static_membership_chirho,
         _membership_chirho,
         bound_node_chirho,
         journal_chirho,
         account_chirho| {
            let alternate_node_chirho = NodeIdChirho("11".repeat(32));
            assert_ne!(&alternate_node_chirho, bound_node_chirho);
            let elector_chirho = MutableElectorChirho {
                node_chirho: alternate_node_chirho.clone(),
                leadership_chirho: RefCell::new(LeadershipChirho {
                    is_leader_chirho: true,
                    leader_id_chirho: Some(alternate_node_chirho.clone()),
                    term_chirho: 5,
                    lease_valid_chirho: true,
                }),
            };
            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let error_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    29,
                    "resident-node-mismatch-chirho",
                ))
                .unwrap_err();
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(
                    &ElectedLedgerAuthorityRefusalChirho::ResidentNodeIdentityMismatchChirho {
                        bound_node_chirho: bound_node_chirho.clone(),
                        elector_node_chirho: alternate_node_chirho,
                    }
                )
            );
            assert!(!writer_fence_path_chirho(root_chirho, group_chirho)
                .unwrap()
                .exists());
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 0);
        },
    );
}

#[test]
fn journal_and_membership_ahead_of_fence_each_refuse_before_append_chirho() {
    with_test_credit_journal_chirho(
        "elected-journal-ahead",
        |_root_chirho,
         _group_chirho,
         _static_membership_chirho,
         _membership_chirho,
         node_chirho,
         journal_chirho,
         account_chirho| {
            let elector_chirho = MutableElectorChirho {
                node_chirho: node_chirho.clone(),
                leadership_chirho: RefCell::new(LeadershipChirho {
                    is_leader_chirho: true,
                    leader_id_chirho: Some(node_chirho.clone()),
                    term_chirho: 7,
                    lease_valid_chirho: true,
                }),
            };
            let first_fence_chirho = {
                let mut bridge_chirho =
                    ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
                bridge_chirho
                    .append_chirho(mint_request_chirho(
                        account_chirho,
                        2,
                        "journal-ahead-first-chirho",
                    ))
                    .unwrap()
                    .fence_chirho
            };
            journal_chirho
                .journal_mut_chirho()
                .advance_epoch_chirho(first_fence_chirho.epoch_chirho + 2)
                .unwrap();
            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let error_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    3,
                    "journal-ahead-second-chirho",
                ))
                .unwrap_err();
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(
                    &ElectedLedgerAuthorityRefusalChirho::JournalAheadOfFenceChirho {
                        journal_epoch_chirho: first_fence_chirho.epoch_chirho + 2,
                        fence_epoch_chirho: first_fence_chirho.epoch_chirho + 1,
                    }
                ),
            );
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 1);
        },
    );

    with_test_credit_journal_chirho(
        "elected-membership-ahead",
        |_root_chirho,
         _group_chirho,
         _static_membership_chirho,
         membership_chirho,
         node_chirho,
         journal_chirho,
         account_chirho| {
            let elector_chirho = MutableElectorChirho {
                node_chirho: node_chirho.clone(),
                leadership_chirho: RefCell::new(LeadershipChirho {
                    is_leader_chirho: true,
                    leader_id_chirho: Some(node_chirho.clone()),
                    term_chirho: 9,
                    lease_valid_chirho: true,
                }),
            };
            let first_fence_chirho = {
                let mut bridge_chirho =
                    ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
                bridge_chirho
                    .append_chirho(mint_request_chirho(
                        account_chirho,
                        2,
                        "membership-ahead-first-chirho",
                    ))
                    .unwrap()
                    .fence_chirho
            };
            membership_chirho
                .rebind_epoch_chirho(first_fence_chirho.epoch_chirho + 2)
                .unwrap();
            let mut bridge_chirho =
                ElectedLedgerAuthorityBridgeChirho::new_chirho(journal_chirho, &elector_chirho);
            let error_chirho = bridge_chirho
                .append_chirho(mint_request_chirho(
                    account_chirho,
                    3,
                    "membership-ahead-second-chirho",
                ))
                .unwrap_err();
            assert_eq!(
                error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
                Some(
                    &ElectedLedgerAuthorityRefusalChirho::MembershipAheadOfFenceChirho {
                        membership_epoch_chirho: first_fence_chirho.epoch_chirho + 2,
                        fence_epoch_chirho: first_fence_chirho.epoch_chirho + 1,
                    }
                ),
            );
            assert_eq!(bridge_chirho.journal_chirho().tail_seq_chirho(), 1);
        },
    );
}

#[test]
fn cross_root_storage_refuses_before_journal_creation_chirho() {
    let platform_a_chirho = temp_root_chirho("elected-cross-root-a");
    let platform_b_chirho = temp_root_chirho("elected-cross-root-b");
    fs::create_dir_all(&platform_a_chirho).unwrap();
    fs::create_dir_all(&platform_b_chirho).unwrap();
    let tenant_a_chirho =
        prepare_tenant_root_chirho(&platform_a_chirho, "tenant-a-chirho").unwrap();
    let tenant_b_chirho =
        prepare_tenant_root_chirho(&platform_b_chirho, "tenant-b-chirho").unwrap();
    let group_b_chirho = consistency_group_for_root_chirho(&tenant_b_chirho).unwrap();
    let refs_chirho = provision_signers_chirho(&tenant_a_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&tenant_a_chirho, &refs_chirho).unwrap();
    let storage_root_chirho = tenant_a_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = SystemLedgerClockChirho;
    let account_chirho = AccountIdChirho {
        owner_chirho: "cross-root-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    };
    let membership_chirho = StaticClusterMembershipChirho::new_chirho(0, [account_chirho])
        .unwrap()
        .elected_view_chirho();
    let registry_chirho = authority_registry_chirho();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let journal_relative_chirho = "journals/cross-root-chirho.jsonl";
    let error_chirho = ElectedLedgerHostJournalChirho::create_chirho(
        &tenant_b_chirho,
        group_b_chirho,
        ElectedLedgerLocalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: &signers_chirho.journal_chirho,
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        },
        StoragePathChirho::new_chirho(journal_relative_chirho),
        ClusterIdChirho("cross-root-cluster-chirho".to_owned()),
        0,
        NodeIdChirho("11".repeat(32)),
    )
    .err()
    .expect("cross-root host-journal binding must refuse");
    assert_eq!(
        error_chirho.downcast_ref::<ElectedLedgerAuthorityRefusalChirho>(),
        Some(&ElectedLedgerAuthorityRefusalChirho::StorageOutsideSelectedRootChirho),
    );
    assert!(!storage_root_chirho.join(journal_relative_chirho).exists());
    let _ = fs::remove_dir_all(platform_a_chirho);
    let _ = fs::remove_dir_all(platform_b_chirho);
}
