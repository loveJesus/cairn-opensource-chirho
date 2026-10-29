// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{
    authority_registry_chirho, hex_bytes_chirho, provision_signers_chirho, snapshot_files_chirho,
    temp_root_chirho,
};
use crate::reconciliation_chirho::{
    gd7_reconciliation_group_head_path_chirho, Gd7WinnerViewBundleStageOutcomeChirho,
};
use crate::resident_authority_chirho::install_resident_birth_post_genesis_test_hook_chirho;
use crate::{
    activate_reviewed_h3_chirho, canonical_resident_ledger_activation_statement_chirho,
    resident_ledger_activation_statement_chirho, ElectedClusterMembershipChirho,
    FsLedgerStorageChirho, HostLedgerSignersChirho, PinnedLedgerActivationVerifierChirho,
    PlatformPolicyMintAuthorityChirho, ResidentLedgerActivationAuthorizationChirho,
    ResidentLedgerActivationInputChirho, ResidentLedgerActivationStatementInputChirho,
    ResidentLedgerAppendPermitChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerBirthPermitChirho,
    ResidentLedgerClockChirho, ResidentLedgerLocalPortsChirho, ResidentLedgerMintIntentChirho,
    StaticClusterMembershipChirho,
};
use cairn_config_chirho::config_chirho::LedgerHostActivationPinConfigChirho;
use cairn_ledger_log_chirho::journal_chirho::{AppendLegRequestChirho, AppendRequestChirho};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho;
use cairn_signer_chirho::signer_chirho::pubkey_hex_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::resident_writer_chirho::resident_writer_identity_path_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, split_writer_epoch_chirho,
    writer_fence_path_chirho, ConsistencyGroupIdChirho, WRITER_FENCE_LOCK_CHIRHO,
};
use ed25519_dalek::{Signer, SigningKey};
use std::fs;
use std::io::Write;
use std::path::Path;

pub(crate) fn warm_single_node_elector_chirho(
    node_chirho: &NodeIdChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> RaftWriterElectorChirho {
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_chirho.clone(), group_chirho.clone())
            .unwrap()
            .with_leadership_warmup_lease_chirho();
    elector_chirho.campaign_chirho().unwrap();
    for _tick_chirho in 0..10 {
        let _outbound_chirho = elector_chirho.tick_chirho();
    }
    elector_chirho
}

fn resident_account_chirho() -> AccountIdChirho {
    AccountIdChirho {
        owner_chirho: "resident-authority-user-chirho".to_owned(),
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
    }
}

pub(crate) fn resident_mint_request_chirho(
    amount_chirho: u64,
    idempotency_key_chirho: &str,
) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho("11".repeat(32)),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: resident_account_chirho(),
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

fn signed_reviewed_activation_materials_chirho(
    root_chirho: &Path,
    final_storage_chirho: &Path,
    journal_path_chirho: &StoragePathChirho,
    cluster_id_chirho: &ClusterIdChirho,
    elected_node_chirho: &str,
    consistency_group_chirho: &ConsistencyGroupIdChirho,
    append_physical_ms_chirho: u64,
) -> (
    PinnedLedgerActivationVerifierChirho,
    ResidentLedgerMintIntentChirho,
    ResidentLedgerActivationAuthorizationChirho,
) {
    let signing_key_chirho = SigningKey::from_bytes(&[93; 32]);
    let activation_config_chirho = LedgerHostActivationPinConfigChirho {
        principal_chirho: "reviewed-root-binding-principal-chirho".to_owned(),
        verifying_key_hex_chirho: hex_bytes_chirho(signing_key_chirho.verifying_key().as_bytes()),
    };
    let verifier_chirho =
        PinnedLedgerActivationVerifierChirho::from_config_chirho(&activation_config_chirho)
            .unwrap();
    let plan_digest_chirho = "ac".repeat(32);
    let intent_chirho = ResidentLedgerMintIntentChirho {
        plan_digest_chirho: plan_digest_chirho.clone(),
        activation_principal_chirho: activation_config_chirho.principal_chirho.clone(),
        initial_owner_chirho: resident_account_chirho().owner_chirho,
        kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("11".repeat(32))),
        amount_chirho: 25,
        idempotency_key_chirho: format!(
            "regenesis-initial-mint-{}-chirho",
            &plan_digest_chirho[..24]
        ),
    };
    let statement_chirho =
        resident_ledger_activation_statement_chirho(ResidentLedgerActivationStatementInputChirho {
            root_chirho,
            identity_storage_namespace_chirho: final_storage_chirho,
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho: 0,
            append_physical_ms_chirho,
            elected_node_chirho,
            consistency_group_chirho,
            intent_chirho: intent_chirho.clone(),
        })
        .unwrap();
    let canonical_statement_chirho =
        canonical_resident_ledger_activation_statement_chirho(&statement_chirho).unwrap();
    let authorization_chirho = ResidentLedgerActivationAuthorizationChirho {
        principal_chirho: activation_config_chirho.principal_chirho,
        statement_chirho,
        signature_hex_chirho: hex_bytes_chirho(
            &signing_key_chirho
                .sign(&canonical_statement_chirho)
                .to_bytes(),
        ),
    };
    (verifier_chirho, intent_chirho, authorization_chirho)
}

pub(crate) fn with_unbound_resident_fixture_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &Path,
        &ConsistencyGroupIdChirho,
        &NodeIdChirho,
        ResidentLedgerLocalPortsChirho<'_>,
        &StoragePathChirho,
        &ClusterIdChirho,
    ),
) {
    let platform_root_chirho = temp_root_chirho(label_chirho);
    fs::create_dir_all(&platform_root_chirho).unwrap();
    let tenant_root_chirho =
        prepare_tenant_root_chirho(&platform_root_chirho, "resident-authority-tenant-chirho")
            .unwrap();
    let group_chirho = consistency_group_for_root_chirho(&tenant_root_chirho).unwrap();
    let local_node_chirho = NodeIdChirho(pubkey_hex_chirho(&tenant_root_chirho).unwrap());
    let refs_chirho = provision_signers_chirho(&tenant_root_chirho);
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&tenant_root_chirho, &refs_chirho).unwrap();
    let storage_root_chirho = tenant_root_chirho.join("ledger-namespace-chirho");
    fs::create_dir_all(&storage_root_chirho).unwrap();
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho).unwrap();
    let clock_chirho = ResidentLedgerClockChirho::reviewed_chirho(100);
    let account_chirho = resident_account_chirho();
    let static_membership_chirho =
        StaticClusterMembershipChirho::new_chirho(0, [account_chirho]).unwrap();
    let membership_chirho: ElectedClusterMembershipChirho =
        static_membership_chirho.elected_view_chirho();
    let registry_chirho = authority_registry_chirho();
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let resident_ports_chirho = ResidentLedgerLocalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signers_chirho.journal_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let journal_path_chirho =
        StoragePathChirho::new_chirho("journals/resident-authority-chirho.jsonl");
    let cluster_id_chirho = ClusterIdChirho("resident-authority-cluster-chirho".to_owned());
    action_chirho(
        &tenant_root_chirho,
        &group_chirho,
        &local_node_chirho,
        resident_ports_chirho,
        &journal_path_chirho,
        &cluster_id_chirho,
    );
    fs::remove_dir_all(platform_root_chirho).unwrap();
}

pub(crate) fn with_bound_resident_fixture_chirho(
    label_chirho: &str,
    action_chirho: impl FnOnce(
        &Path,
        &ConsistencyGroupIdChirho,
        &NodeIdChirho,
        ResidentLedgerLocalPortsChirho<'_>,
        &StoragePathChirho,
        &ClusterIdChirho,
    ),
) {
    with_unbound_resident_fixture_chirho(
        label_chirho,
        move |root_chirho,
              group_chirho,
              local_node_chirho,
              ports_chirho,
              journal_path_chirho,
              cluster_id_chirho| {
            let birth_elector_chirho =
                warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            let bound_host_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    ports_chirho,
                    birth_elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            assert_eq!(
                bound_host_chirho
                    .probe_chirho()
                    .unwrap()
                    .journal_tail_seq_chirho,
                0
            );
            drop(bound_host_chirho);
            drop(birth_elector_chirho);

            action_chirho(
                root_chirho,
                group_chirho,
                local_node_chirho,
                ports_chirho,
                journal_path_chirho,
                cluster_id_chirho,
            );
        },
    );
}

#[test]
fn reviewed_activation_refuses_amount_and_signature_tamper_before_journal_bytes_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-reviewed-activation",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let final_storage_chirho = root_chirho
                .canonicalize()
                .unwrap()
                .join("reviewed-final-parent-chirho")
                .join("ledger-namespace-chirho");
            let signing_key_chirho = SigningKey::from_bytes(&[91; 32]);
            let activation_config_chirho = LedgerHostActivationPinConfigChirho {
                principal_chirho: "reviewed-activation-principal-chirho".to_owned(),
                verifying_key_hex_chirho: hex_bytes_chirho(
                    signing_key_chirho.verifying_key().as_bytes(),
                ),
            };
            let verifier_chirho =
                PinnedLedgerActivationVerifierChirho::from_config_chirho(&activation_config_chirho)
                    .unwrap();
            let intent_chirho = ResidentLedgerMintIntentChirho {
                plan_digest_chirho: "aa".repeat(32),
                activation_principal_chirho: activation_config_chirho.principal_chirho.clone(),
                initial_owner_chirho: resident_account_chirho().owner_chirho,
                kind_id_chirho: AssetKindIdChirho("credits-chirho".to_owned()),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("11".repeat(32))),
                amount_chirho: 25,
                idempotency_key_chirho: format!(
                    "regenesis-initial-mint-{}-chirho",
                    &"aa".repeat(32)[..24]
                ),
            };
            let statement_chirho = resident_ledger_activation_statement_chirho(
                ResidentLedgerActivationStatementInputChirho {
                    root_chirho,
                    identity_storage_namespace_chirho: &final_storage_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    opening_epoch_chirho: 0,
                    append_physical_ms_chirho: 200,
                    elected_node_chirho: &local_authority_chirho.node_id_chirho().0,
                    consistency_group_chirho: local_authority_chirho.consistency_group_chirho(),
                    intent_chirho: intent_chirho.clone(),
                },
            )
            .unwrap();
            let canonical_statement_chirho =
                canonical_resident_ledger_activation_statement_chirho(&statement_chirho).unwrap();
            let signature_chirho = hex_bytes_chirho(
                &signing_key_chirho
                    .sign(&canonical_statement_chirho)
                    .to_bytes(),
            );
            let authorization_chirho = ResidentLedgerActivationAuthorizationChirho {
                principal_chirho: activation_config_chirho.principal_chirho.clone(),
                statement_chirho: statement_chirho.clone(),
                signature_hex_chirho: signature_chirho,
            };
            let before_chirho = snapshot_files_chirho(root_chirho);

            let mut amount_tamper_chirho = authorization_chirho.clone();
            amount_tamper_chirho
                .statement_chirho
                .intent_chirho
                .amount_chirho += 1;
            let amount_result_chirho =
                activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                    root_chirho,
                    identity_storage_namespace_chirho: &final_storage_chirho,
                    ports_chirho,
                    journal_path_chirho: journal_path_chirho.clone(),
                    cluster_id_chirho: cluster_id_chirho.clone(),
                    opening_epoch_chirho: 0,
                    append_physical_ms_chirho: 200,
                    local_authority_chirho: local_authority_chirho.clone(),
                    verifier_chirho: &verifier_chirho,
                    intent_chirho: intent_chirho.clone(),
                    authorization_chirho: amount_tamper_chirho,
                });
            assert_eq!(
                amount_result_chirho.unwrap_err(),
                ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho
            );
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);

            let mut signature_tamper_chirho = authorization_chirho.clone();
            // The signature is Ed25519 over a statement carrying the run-varying temp root, so its
            // leading hex digits differ every run. Forcing a FIXED "00" was therefore a no-op
            // roughly 1 run in 256 — the signature already began "00", nothing was tampered, the
            // activation legitimately succeeded, and the arm failed `unwrap_err()` on an `Ok`,
            // reading as a tamper-acceptance on an authority surface. Choose a prefix that cannot
            // equal the original, then assert the fixture actually changed the bytes.
            let tampered_prefix_chirho = if signature_tamper_chirho
                .signature_hex_chirho
                .starts_with("00")
            {
                "11"
            } else {
                "00"
            };
            signature_tamper_chirho
                .signature_hex_chirho
                .replace_range(0..2, tampered_prefix_chirho);
            assert_ne!(
                signature_tamper_chirho.signature_hex_chirho, authorization_chirho.signature_hex_chirho,
                "the signature fixture must actually tamper; an unchanged signature would make the \
                 refusal below untestable and the arm falsely red"
            );
            let signature_result_chirho =
                activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                    root_chirho,
                    identity_storage_namespace_chirho: &final_storage_chirho,
                    ports_chirho,
                    journal_path_chirho: journal_path_chirho.clone(),
                    cluster_id_chirho: cluster_id_chirho.clone(),
                    opening_epoch_chirho: 0,
                    append_physical_ms_chirho: 200,
                    local_authority_chirho: local_authority_chirho.clone(),
                    verifier_chirho: &verifier_chirho,
                    intent_chirho: intent_chirho.clone(),
                    authorization_chirho: signature_tamper_chirho,
                });
            assert_eq!(
                signature_result_chirho.unwrap_err(),
                ResidentLedgerAuthorityRefusalChirho::ActivationSignatureRefusedChirho
            );
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);

            let system_clock_chirho = ResidentLedgerClockChirho::system_chirho();
            let system_clock_ports_chirho = ResidentLedgerLocalPortsChirho {
                storage_chirho: ports_chirho.storage_chirho,
                signer_chirho: ports_chirho.signer_chirho,
                clock_chirho: &system_clock_chirho,
                membership_chirho: ports_chirho.membership_chirho,
                kind_registry_chirho: ports_chirho.kind_registry_chirho,
                authority_chirho: ports_chirho.authority_chirho,
            };
            let wrong_clock_result_chirho =
                activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                    root_chirho,
                    identity_storage_namespace_chirho: &final_storage_chirho,
                    ports_chirho: system_clock_ports_chirho,
                    journal_path_chirho: journal_path_chirho.clone(),
                    cluster_id_chirho: cluster_id_chirho.clone(),
                    opening_epoch_chirho: 0,
                    append_physical_ms_chirho: 200,
                    local_authority_chirho: local_authority_chirho.clone(),
                    verifier_chirho: &verifier_chirho,
                    intent_chirho: intent_chirho.clone(),
                    authorization_chirho: authorization_chirho.clone(),
                });
            assert_eq!(
                wrong_clock_result_chirho.unwrap_err(),
                ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho
            );
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);

            let receipt_chirho = activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                root_chirho,
                identity_storage_namespace_chirho: &final_storage_chirho,
                ports_chirho,
                journal_path_chirho: journal_path_chirho.clone(),
                cluster_id_chirho: cluster_id_chirho.clone(),
                opening_epoch_chirho: 0,
                append_physical_ms_chirho: 200,
                local_authority_chirho,
                verifier_chirho: &verifier_chirho,
                intent_chirho,
                authorization_chirho,
            })
            .unwrap();
            assert!(receipt_chirho.append_seq_chirho > 0);
            assert_ne!(snapshot_files_chirho(root_chirho), before_chirho);
        },
    );
}

#[test]
fn reviewed_resident_clock_refuses_regression_chirho() {
    let clock_chirho = ResidentLedgerClockChirho::reviewed_chirho(200);
    assert!(!clock_chirho.set_reviewed_chirho(199));
    assert!(clock_chirho.set_reviewed_chirho(200));
    assert!(clock_chirho.set_reviewed_chirho(201));
    assert!(!clock_chirho.set_reviewed_chirho(200));
}

#[test]
fn reviewed_activation_refuses_root_namespace_swap_before_append_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-reviewed-root-swap",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let final_storage_chirho = root_chirho
                .canonicalize()
                .unwrap()
                .join("reviewed-final-parent-chirho")
                .join("ledger-namespace-chirho");
            let (verifier_chirho, intent_chirho, authorization_chirho) =
                signed_reviewed_activation_materials_chirho(
                    root_chirho,
                    &final_storage_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &local_authority_chirho.node_id_chirho().0,
                    local_authority_chirho.consistency_group_chirho(),
                    220,
                );
            let before_chirho = snapshot_files_chirho(root_chirho);
            let parked_root_chirho = root_chirho
                .parent()
                .unwrap()
                .join("reviewed-root-swap-parked-chirho");
            let swap_source_chirho = root_chirho.to_path_buf();
            let swap_target_chirho = parked_root_chirho.clone();
            ResidentLedgerActivationInputChirho::install_post_authorization_test_hook_chirho(
                move || {
                    fs::rename(&swap_source_chirho, &swap_target_chirho).unwrap();
                    fs::create_dir(&swap_source_chirho).unwrap();
                },
            );

            let refusal_chirho = activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                root_chirho,
                identity_storage_namespace_chirho: &final_storage_chirho,
                ports_chirho,
                journal_path_chirho: journal_path_chirho.clone(),
                cluster_id_chirho: cluster_id_chirho.clone(),
                opening_epoch_chirho: 0,
                append_physical_ms_chirho: 220,
                local_authority_chirho,
                verifier_chirho: &verifier_chirho,
                intent_chirho,
                authorization_chirho,
            })
            .expect_err("a post-signature root namespace swap must fail before append");
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho
            );
            assert_eq!(snapshot_files_chirho(&parked_root_chirho), before_chirho);
            assert!(snapshot_files_chirho(root_chirho).is_empty());

            fs::remove_dir(root_chirho).unwrap();
            fs::rename(parked_root_chirho, root_chirho).unwrap();
        },
    );
}

#[test]
fn reviewed_activation_reopens_and_verifies_the_persisted_tail_digest_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-reviewed-persisted-tail",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let final_storage_chirho = root_chirho
                .canonicalize()
                .unwrap()
                .join("reviewed-final-parent-chirho")
                .join("ledger-namespace-chirho");
            let (verifier_chirho, intent_chirho, authorization_chirho) =
                signed_reviewed_activation_materials_chirho(
                    root_chirho,
                    &final_storage_chirho,
                    journal_path_chirho,
                    cluster_id_chirho,
                    &local_authority_chirho.node_id_chirho().0,
                    local_authority_chirho.consistency_group_chirho(),
                    230,
                );
            let journal_file_chirho = ports_chirho
                .storage_chirho
                .namespace_root_chirho()
                .join(journal_path_chirho.key_chirho());
            ResidentLedgerActivationInputChirho::install_post_append_test_hook_chirho(move || {
                let mut journal_chirho = fs::OpenOptions::new()
                    .append(true)
                    .open(&journal_file_chirho)
                    .unwrap();
                journal_chirho
                    .write_all(b"{\"torn-tail-chirho\":true}\n")
                    .unwrap();
                journal_chirho.sync_all().unwrap();
            });

            let refusal_chirho = activate_reviewed_h3_chirho(ResidentLedgerActivationInputChirho {
                root_chirho,
                identity_storage_namespace_chirho: &final_storage_chirho,
                ports_chirho,
                journal_path_chirho: journal_path_chirho.clone(),
                cluster_id_chirho: cluster_id_chirho.clone(),
                opening_epoch_chirho: 0,
                append_physical_ms_chirho: 230,
                local_authority_chirho,
                verifier_chirho: &verifier_chirho,
                intent_chirho,
                authorization_chirho,
            })
            .expect_err("persisted tail corruption must prevent an activation receipt");
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho
            );
        },
    );
}

#[test]
fn resident_identity_refuses_an_unreviewed_logical_storage_namespace_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-logical-namespace",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let reviewed_final_storage_chirho = root_chirho
                .canonicalize()
                .unwrap()
                .join("reviewed-final-parent-chirho")
                .join("ledger-namespace-chirho");
            let birth_elector_chirho =
                warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let birth_permit_chirho =
                ResidentLedgerBirthPermitChirho::for_test_with_identity_storage_chirho(
                    root_chirho,
                    reviewed_final_storage_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                );
            let resident_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                birth_permit_chirho,
                ports_chirho,
                birth_elector_chirho.local_append_authority_handle_chirho(),
            )
            .unwrap();
            drop(resident_chirho);
            drop(birth_elector_chirho);
            let before_chirho = snapshot_files_chirho(root_chirho);

            let reopen_elector_chirho =
                warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            let result_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                reopen_elector_chirho.local_append_authority_handle_chirho(),
            );
            assert!(matches!(
                result_chirho,
                Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityRefusedChirho { .. })
            ));
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);
        },
    );
}

#[test]
fn sealed_birth_retains_the_pending_to_bound_lifetime_lease_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-birth-lease",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            let resident_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                birth_permit_chirho,
                ports_chirho,
                local_authority_chirho.clone(),
            )
            .unwrap();
            let readiness_chirho = resident_chirho.probe_chirho().unwrap();
            assert_eq!(readiness_chirho.journal_tail_seq_chirho, 0);
            assert_eq!(readiness_chirho.journal_epoch_chirho, 0);

            let overlap_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    local_authority_chirho,
                )
                .err()
                .expect("the birth resident must retain lifetime exclusion");
            assert!(matches!(
                overlap_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::ResidentLeaseRefusedChirho { .. }
            ));
        },
    );
}

#[test]
fn sealed_birth_refuses_opening_epoch_drift_before_mutation_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-birth-epoch-drift",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let before_chirho = snapshot_files_chirho(root_chirho);
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                1,
            );
            let refusal_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                birth_permit_chirho,
                ports_chirho,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .err()
            .expect("opening epoch drift must refuse resident birth");
            assert!(matches!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::OpeningMembershipEpochMismatchChirho {
                    opening_epoch_chirho: 1,
                    membership_epoch_chirho: 0,
                }
            ));
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);
        },
    );
}

#[test]
fn sealed_birth_refuses_an_existing_journal_without_pending_identity_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-birth-orphan-journal",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let orphan_bytes_chirho = b"orphan-journal-chirho\n";
            ports_chirho
                .storage_chirho
                .create_durable_chirho(journal_path_chirho, orphan_bytes_chirho)
                .unwrap();
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            let refusal_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                birth_permit_chirho,
                ports_chirho,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .err()
            .expect("an orphan journal must refuse resident birth");
            assert!(matches!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho
            ));
            assert_eq!(
                ports_chirho
                    .storage_chirho
                    .read_all_chirho(journal_path_chirho)
                    .unwrap(),
                Some(orphan_bytes_chirho.to_vec())
            );
            assert!(!resident_writer_identity_path_chirho(root_chirho)
                .unwrap()
                .exists());
        },
    );
}

#[test]
fn sealed_birth_recovers_exact_pending_after_root_replacement_refusal_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-authority-birth-recovery",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            let moved_root_chirho = root_chirho
                .parent()
                .unwrap()
                .join("resident-authority-birth-recovery-moved-chirho");
            let hook_root_chirho = root_chirho.to_path_buf();
            let hook_moved_root_chirho = moved_root_chirho.clone();
            install_resident_birth_post_genesis_test_hook_chirho(move || {
                fs::rename(&hook_root_chirho, &hook_moved_root_chirho).unwrap();
                fs::create_dir(&hook_root_chirho).unwrap();
            });
            let first_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            let first_error_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    first_permit_chirho,
                    ports_chirho,
                    local_authority_chirho.clone(),
                )
                .err()
                .expect("root replacement must stop Pending-to-Bound birth");
            assert!(matches!(
                first_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::StableNamespaceRefusedChirho { .. }
            ));
            assert_eq!(fs::read_dir(root_chirho).unwrap().count(), 0);

            fs::remove_dir(root_chirho).unwrap();
            fs::rename(&moved_root_chirho, root_chirho).unwrap();
            let retry_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            let recovered_chirho =
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    retry_permit_chirho,
                    ports_chirho,
                    local_authority_chirho,
                )
                .unwrap();
            assert_eq!(
                recovered_chirho
                    .probe_chirho()
                    .unwrap()
                    .journal_tail_seq_chirho,
                0
            );
        },
    );
}

#[test]
fn bound_resident_open_and_probe_do_not_mutate_and_are_exact_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-ready",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let before_chirho = snapshot_files_chirho(root_chirho);
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .unwrap();
            let readiness_chirho = resident_chirho.probe_chirho().unwrap();

            assert_eq!(&readiness_chirho.consistency_group_chirho, group_chirho);
            assert_eq!(&readiness_chirho.local_node_chirho, node_chirho);
            assert_eq!(readiness_chirho.published_raft_term_chirho, 1);
            assert_eq!(readiness_chirho.journal_epoch_chirho, 0);
            assert_eq!(readiness_chirho.membership_epoch_chirho, 0);
            assert_eq!(readiness_chirho.journal_tail_seq_chirho, 0);
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);
        },
    );
}

#[test]
fn resident_open_refuses_unwarmed_and_dropped_electors_before_io_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-local-generation",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let before_chirho = snapshot_files_chirho(root_chirho);
            let unwarmed_chirho = RaftWriterElectorChirho::new_single_node_chirho(
                node_chirho.clone(),
                group_chirho.clone(),
            )
            .unwrap()
            .with_leadership_warmup_lease_chirho();
            let unwarmed_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    unwarmed_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("unwarmed elector must not open resident authority");
            assert_eq!(
                unwarmed_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho: LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho,
                }
            );

            let dropped_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let dropped_handle_chirho =
                dropped_elector_chirho.local_append_authority_handle_chirho();
            drop(dropped_elector_chirho);
            let dropped_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    dropped_handle_chirho,
                )
                .err()
                .expect("dropped elector must not retain resident authority");
            assert_eq!(
                dropped_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                    reason_chirho: LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho,
                }
            );
            assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);
        },
    );
}

#[test]
fn resident_open_refuses_wrong_group_and_overlapping_lifetime_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-exclusive",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let wrong_group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
                canonical_root_chirho: "/wrong-group-chirho".to_owned(),
            };
            let wrong_elector_chirho =
                warm_single_node_elector_chirho(node_chirho, &wrong_group_chirho);
            let wrong_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    wrong_elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("wrong consistency group must be refused");
            assert!(matches!(
                wrong_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::RootGroupMismatchChirho { .. }
            ));

            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                handle_chirho.clone(),
            )
            .unwrap();
            let before_overlap_chirho = snapshot_files_chirho(root_chirho);
            let overlap_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    handle_chirho.clone(),
                )
                .err()
                .expect("a second resident lifetime must be refused");
            assert!(matches!(
                overlap_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::ResidentLeaseRefusedChirho { .. }
            ));
            assert_eq!(snapshot_files_chirho(root_chirho), before_overlap_chirho);
            drop(resident_chirho);
            let reopened_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                handle_chirho,
            )
            .unwrap();
            reopened_chirho.probe_chirho().unwrap();
        },
    );
}

#[test]
fn resident_probe_refuses_replaced_storage_namespace_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-storage-replacement",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .unwrap();
            let storage_root_chirho = ports_chirho.storage_chirho.namespace_root_chirho();
            let parked_storage_chirho = root_chirho.join("ledger-namespace-parked-chirho");
            fs::rename(storage_root_chirho, &parked_storage_chirho).unwrap();
            fs::create_dir(storage_root_chirho).unwrap();

            let replacement_error_chirho = resident_chirho
                .probe_chirho()
                .expect_err("replacement storage directory must be refused");
            assert!(matches!(
                replacement_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::StableNamespaceRefusedChirho { .. }
            ));

            drop(resident_chirho);
            fs::remove_dir(storage_root_chirho).unwrap();
            fs::rename(parked_storage_chirho, storage_root_chirho).unwrap();
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn resident_preactivation_append_reuses_one_descriptor_owned_fence_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-append",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            let permit_chirho = ResidentLedgerAppendPermitChirho::for_test_chirho();
            let first_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(5, "resident-append-1-chirho"),
                )
                .unwrap();
            assert_eq!(first_chirho.append_chirho.seq_chirho, 1);
            assert_eq!(first_chirho.published_raft_term_chirho, 1);
            assert_eq!(
                split_writer_epoch_chirho(first_chirho.fence_chirho.epoch_chirho).geo_term_chirho,
                1
            );
            let fence_path_chirho = writer_fence_path_chirho(root_chirho, group_chirho).unwrap();
            let first_fence_bytes_chirho = fs::read(&fence_path_chirho).unwrap();

            let second_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(7, "resident-append-2-chirho"),
                )
                .unwrap();
            assert_eq!(second_chirho.append_chirho.seq_chirho, 2);
            assert_eq!(second_chirho.fence_chirho, first_chirho.fence_chirho);
            assert_eq!(
                fs::read(fence_path_chirho).unwrap(),
                first_fence_bytes_chirho
            );
            let readiness_chirho = resident_chirho.probe_chirho().unwrap();
            assert_eq!(readiness_chirho.journal_tail_seq_chirho, 2);
            assert_eq!(
                readiness_chirho.journal_epoch_chirho,
                first_chirho.fence_chirho.epoch_chirho
            );
            assert_eq!(
                readiness_chirho.membership_epoch_chirho,
                first_chirho.fence_chirho.epoch_chirho
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn failed_resident_append_retains_and_reuses_the_installed_fence_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-failed-append",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            let permit_chirho = ResidentLedgerAppendPermitChirho::for_test_chirho();
            let before_chirho = resident_chirho.probe_chirho().unwrap();
            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(0, "resident-refused-chirho"),
                )
                .unwrap_err();
            assert!(matches!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho { .. }
            ));
            let after_chirho = resident_chirho.probe_chirho().unwrap();
            assert_eq!(after_chirho.journal_tail_seq_chirho, 0);
            // A1 of the epoch-wedge brick, added 2026-08-17. This arm was ONE ASSERTION SHORT of
            // catching a production defect for as long as it has existed: it already held the exact
            // readiness the canary alignment check consumes, and asserted only the tail.
            //
            // PINNING CURRENT MEASURED BEHAVIOUR, NOT DESIRED BEHAVIOUR. A refused append leaves the
            // journal tail untouched (above) while the in-memory epoch HAS ALREADY ADVANCED, because
            // `append_with_current_fence_chirho` advances before the mutation is validated and the
            // advance is strictly monotone with no inverse. On the served path that divergence is what
            // wedges the writer, since the shadow-canary cut only moves on a successful append.
            //
            // MIGRATION PATH — what each future outcome MEANS, so whoever meets this red is not doing
            // archaeology:
            //   * If the `>` assertion FAILS because the epoch no longer advances on a refused append,
            //     that is the INTENDED FIX landing. Retarget this to `assert_eq!(after, before)` and
            //     keep the tail assertion; do not delete the arm.
            //   * If the tail assertion fails, a refused append is now writing a record, which is a
            //     far more serious regression than the one this arm documents.
            //   * If both hold, the defect is still present and this arm is doing its job.
            // NOTE this arm calls `append_preactivation_chirho` directly, so it never enters
            // `prepare_resident_mutation_chirho` and therefore does NOT itself observe the wedge. It
            // pins the DIVERGENCE that causes it; the end-to-end wedge needs the A2 fixture.
            assert!(
                after_chirho.journal_epoch_chirho > before_chirho.journal_epoch_chirho,
                "a refused append currently leaves the epoch advanced ({} -> {}) while the tail \
                 stays put; see the epoch-wedge brick",
                before_chirho.journal_epoch_chirho,
                after_chirho.journal_epoch_chirho
            );
            let fence_path_chirho = writer_fence_path_chirho(root_chirho, group_chirho).unwrap();
            let failed_fence_bytes_chirho = fs::read(&fence_path_chirho).unwrap();

            let accepted_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(3, "resident-retry-chirho"),
                )
                .unwrap();
            assert_eq!(accepted_chirho.append_chirho.seq_chirho, 1);
            assert_eq!(
                fs::read(fence_path_chirho).unwrap(),
                failed_fence_bytes_chirho,
                "retry must reuse the exact fence installed before the failed journal admission"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn resident_bundle_staging_uses_its_verified_journal_cut_and_heads_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-winner-view-bundle",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(3, "resident-view-bundle-source-chirho"),
                )
                .expect("append the resident source row");
            let readiness_chirho = resident_chirho.probe_chirho().expect("probe resident cut");

            let complete_chirho = resident_chirho
                .stage_next_gd7_winner_view_bundle_page_chirho(None)
                .expect("stage the resident journal's account-net view");
            let bundle_root_chirho = match complete_chirho {
                Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho { bundle_root_chirho } => {
                    bundle_root_chirho
                }
                Gd7WinnerViewBundleStageOutcomeChirho::ContinueChirho { .. } => {
                    panic!("one resident account must fit one bundle page")
                }
            };

            assert_eq!(bundle_root_chirho.root_chirho().page_count_chirho, 1);
            assert_eq!(bundle_root_chirho.root_chirho().row_count_chirho, 1);
            assert_eq!(
                bundle_root_chirho
                    .root_chirho()
                    .source_cut_chirho
                    .seq_chirho,
                readiness_chirho.journal_tail_seq_chirho
            );
            assert_eq!(
                bundle_root_chirho
                    .root_chirho()
                    .source_cut_chirho
                    .record_digest_chirho,
                readiness_chirho.journal_tail_digest_chirho.0
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn any_gd7_group_head_holds_the_final_resident_mutation_sink_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-gd7-hold",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            let authority_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let hold_path_chirho =
                gd7_reconciliation_group_head_path_chirho(&group_digest_chirho).unwrap();
            authority_storage_chirho
                .atomic_write_chirho(&hold_path_chirho, b"malformed-but-held")
                .unwrap();

            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(3, "resident-gd7-held-chirho"),
                )
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho
            );
            assert_eq!(
                resident_chirho
                    .probe_chirho()
                    .unwrap()
                    .journal_tail_seq_chirho,
                0,
                "the group hold refuses before any journal mutation"
            );
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn resident_append_refuses_missing_lock_and_root_replacement_before_mutation_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-root-replacement",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let lock_path_chirho = root_chirho.join(
                cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho(
                    WRITER_FENCE_LOCK_CHIRHO,
                ),
            );
            fs::remove_file(&lock_path_chirho).unwrap();
            let missing_elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let missing_error_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    missing_elector_chirho.local_append_authority_handle_chirho(),
                )
                .err()
                .expect("resident open must require a preprovisioned writer lock");
            assert!(matches!(
                missing_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho { .. }
            ));
            with_named_lock_chirho(
                root_chirho,
                WRITER_FENCE_LOCK_CHIRHO,
                || -> anyhow::Result<()> { Ok(()) },
            )
            .unwrap();

            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            let parked_root_chirho = root_chirho
                .parent()
                .unwrap()
                .join("resident-authority-parked-root-chirho");
            fs::rename(root_chirho, &parked_root_chirho).unwrap();
            fs::create_dir(root_chirho).unwrap();
            let replacement_storage_chirho =
                FsLedgerStorageChirho::open_existing_chirho(root_chirho).unwrap();
            let before_original_chirho = snapshot_files_chirho(&parked_root_chirho);
            let before_replacement_chirho = snapshot_files_chirho(root_chirho);
            let replacement_error_chirho = resident_chirho
                .append_preactivation_chirho(
                    &ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    resident_mint_request_chirho(1, "resident-replaced-root-chirho"),
                )
                .unwrap_err();
            assert!(matches!(
                replacement_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::StableNamespaceRefusedChirho { .. }
            ));
            assert_eq!(
                snapshot_files_chirho(root_chirho),
                before_replacement_chirho
            );
            assert_eq!(
                snapshot_files_chirho(&parked_root_chirho),
                before_original_chirho,
                "path replacement refusal must not mutate either the retained or replacement tree"
            );
            assert!(replacement_storage_chirho
                .read_all_chirho(journal_path_chirho)
                .unwrap()
                .is_none());
            drop(resident_chirho);
            fs::remove_dir(root_chirho).unwrap();
            fs::rename(parked_root_chirho, root_chirho).unwrap();
        },
    );
}

#[cfg(all(unix, not(target_os = "solaris")))]
#[test]
fn resident_append_never_ratchets_rolled_back_fence_state_forward_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-authority-fence-rollback",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .unwrap();
            let permit_chirho = ResidentLedgerAppendPermitChirho::for_test_chirho();
            resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(2, "resident-before-rollback-chirho"),
                )
                .unwrap();
            let fence_path_chirho = writer_fence_path_chirho(root_chirho, group_chirho).unwrap();
            fs::remove_file(&fence_path_chirho).unwrap();
            let journal_before_chirho = fs::read(
                ports_chirho
                    .storage_chirho
                    .namespace_root_chirho()
                    .join(journal_path_chirho.key_chirho()),
            )
            .unwrap();

            let rollback_error_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    resident_mint_request_chirho(2, "resident-after-rollback-chirho"),
                )
                .unwrap_err();
            assert!(matches!(
                rollback_error_chirho,
                ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho { .. }
            ));
            assert!(!fence_path_chirho.exists());
            assert_eq!(
                fs::read(
                    ports_chirho
                        .storage_chirho
                        .namespace_root_chirho()
                        .join(journal_path_chirho.key_chirho()),
                )
                .unwrap(),
                journal_before_chirho
            );
        },
    );
}

#[path = "resident_authority_tests_chirho/handoff_fence_tests_chirho.rs"]
mod handoff_fence_tests_chirho;
#[path = "resident_authority_tests_chirho/loss_witness_tests_chirho.rs"]
mod loss_witness_tests_chirho;

#[path = "resident_authority_tests_chirho/sink_term_lifecycle_tests_chirho.rs"]
mod sink_term_lifecycle_tests_chirho;

#[path = "resident_authority_tests_chirho/sink_term_revoke_tests_chirho.rs"]
mod sink_term_revoke_tests_chirho;

mod strand_fence_liveness_tests_chirho;
pub(crate) use strand_fence_liveness_tests_chirho::ElectorMeshChirho;
mod write_restoration_gate_tests_chirho;
mod write_restoration_tests_chirho;

#[path = "resident_authority_tests_chirho/deposed_reader_birth_term_pin_chirho.rs"]
mod deposed_reader_birth_term_pin_chirho;

mod post_cut_extension_traversal_tests_chirho;

/// A MIGRATED ROOT CAN BE OPENED, and an ordinary birth still cannot open one.
///
/// This is the mechanism CF8 clause 6 was missing. A migrated root carries the tenant's journal and
/// has NO resident writer identity — an identity binds a root's device and inode, so it cannot
/// travel — and birth was the only path that issues one, while requiring a pristine journal. The
/// result was a migration that completed and left a root nobody could open.
///
/// The two halves must both hold. Adoption has to WORK, or clause 6 is unreachable; and ordinary
/// birth has to keep refusing, or "an existing journal with no identity" becomes adoptable by any
/// caller, which is how a planted journal gets adopted.
#[test]
fn a_root_with_an_existing_journal_and_no_identity_is_adoptable_but_never_born_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-adoption-chirho",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(local_node_chirho, group_chirho);
            // Birth it once, the ordinary way: this is what produces the journal a migration copies.
            let born_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                ResidentLedgerBirthPermitChirho::for_test_chirho(
                    root_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                ),
                ports_chirho,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .expect("the ordinary birth must succeed, or this arm measures nothing");
            drop(born_chirho);

            // Now make it look like a migration target: the journal stays, the identity does not.
            // `resident-writer-chirho` is PROVEN DISPOSABLE precisely because it is bound to the
            // root it was born in, so a staged target legitimately has none.
            std::fs::remove_dir_all(root_chirho.join("resident-writer-chirho"))
                .expect("remove the identity the way a staged target lacks one");

            // HALF ONE: an ordinary birth must still refuse. If this ever succeeds, a journal
            // dropped into a directory becomes adoptable by anyone.
            let refusal_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
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
            .expect("an ordinary birth must refuse an existing journal with no identity");
            // TWO protections stand between an ordinary birth and this root, and either firing is
            // correct. On this fixture the SINK-TERM RESIDUE guard fires first — a fresh birth must
            // find no winner-term cell, and the born root left one — which is why the arm names both
            // rather than pinning the one that happens to come first. What must never happen is
            // SUCCESS: that would make any journal dropped into a directory adoptable by anyone.
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho
                        | ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho { .. }
                ),
                "an ordinary birth must refuse as one of its two protections, not incidentally: \
                 got {refusal_chirho:?}"
            );
            // DEFENCE IN DEPTH, found by a SURVIVING mutation. Disabling all three adoption gates
            // did not make this half fail: an ordinary birth still refused, because its genesis
            // branch prepares a FRESH genesis which then cannot match the existing journal's. So
            // there are three independent protections here, not two, and the arm only discriminates
            // against a mutation that flips the permit itself — which it does, by name.
            //
            // AND IT LEFT NOTHING BEHIND. This is the half that actually discriminates: widening
            // the refusal identity above to accept either protection also made it accept any
            // incidental refusal, and a mutation that let ordinary birth adopt still passed it.
            // Asserting the EFFECT is what catches that — a refused birth must not have minted the
            // identity, because minting it is precisely what adoption is for.
            assert!(
                !root_chirho
                    .join("resident-writer-chirho")
                    .join("resident-writer-identity.json")
                    .exists(),
                "a REFUSED ordinary birth must not have minted an identity — if it did, an existing \
                 journal with no identity is adoptable by any caller, which is the whole hazard"
            );

            // HALF TWO: adoption opens the same root. The genesis is the journal's own, re-verified
            // against the cluster, the opening epoch and the digest the journal reports.
            let adopted_chirho = ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                ResidentLedgerBirthPermitChirho::for_test_adoption_chirho(
                    root_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                ),
                ports_chirho,
                elector_chirho.local_append_authority_handle_chirho(),
            )
            .expect("a migrated root must be adoptable, or clause 6 has no mechanism at all");
            drop(adopted_chirho);

            // And it left a real identity behind, bound to THIS root — which is what the resident
            // open path will demand on the next start.
            assert!(
                root_chirho
                    .join("resident-writer-chirho")
                    .join("resident-writer-identity.json")
                    .exists(),
                "adoption must leave the identity the open path requires"
            );
        },
    );
}
