// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::super::bundle_chirho::Gd7WinnerViewBundlePageChirho;
use super::super::super::fork_baseline_tests_chirho::{
    with_fork_baseline_fixture_chirho, ForkBaselineTailBindingChirho, ForkBaselineTestContextChirho,
};
use super::super::super::*;
use super::super::tests_chirho::{fetch_next_chirho, stage_evidence_manifest_for_view_chirho};
use super::*;
use crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho;
use crate::resident_authority_chirho::{
    materialize_gd7_held_adoption_candidate_chirho, Gd7HeldAdoptionMaterializationPortsChirho,
    ResidentGd7HeldSealedPlanSnapshotChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    ExpectedLedgerGenesisChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerSignerPortChirho, LedgerStoragePortChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho, LegDeltaChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho, LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_ledger_read_model_chirho::{
    parse_canonical_account_net_projection_view_chirho, AccountNetProjectionRowChirho,
};
use cairn_ledger_sim_chirho::fault_chirho::FaultPlanChirho;
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, split_writer_epoch_chirho,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestReadOnlyBranchPrefixRecordChirho {
    record_digest_chirho: String,
    record_chirho: LedgerRecordChirho,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestReadOnlyBranchPrefixPageChirho {
    schema_chirho: String,
    transfer_identity_digest_chirho: String,
    page_index_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newer_page_ref_chirho: Option<String>,
    records_newest_first_chirho: Vec<TestReadOnlyBranchPrefixRecordChirho>,
    cumulative_record_count_chirho: u64,
}

#[test]
fn complete_held_artifacts_compose_to_the_exact_account_net_view_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let rows_chirho = expected_rows_chirho(&context_chirho);
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                rows_chirho.clone(),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho.clone(),
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );

            let proof_chirho = held_store_chirho
                .verify_account_net_composition_chirho()
                .expect("three complete artifact families compose exactly");
            let active_chirho = held_store_chirho
                .load_active_chirho()
                .expect("reload complete held evidence transfer")
                .expect("complete held evidence transfer remains present");
            assert_eq!(
                proof_chirho.evidence_checkpoint_ref_chirho(),
                active_chirho.checkpoint_ref_chirho
            );
            assert_eq!(
                proof_chirho.held_view_checkpoint_ref_chirho(),
                held_view_checkpoint_ref_chirho
            );
            assert_eq!(
                proof_chirho.winner_history_root_ref_chirho(),
                manifest_chirho.winner_history_root_object_digest_chirho
            );
            assert_eq!(
                proof_chirho.fork_baseline_root_ref_chirho(),
                manifest_chirho.fork_baseline_root_object_digest_chirho
            );
            assert_eq!(proof_chirho.applied_record_count_chirho(), 1);
            assert_eq!(
                proof_chirho.matched_row_count_chirho(),
                rows_chirho.len() as u64
            );
        },
    );
}

#[test]
fn exact_losing_prefix_and_winner_suffix_install_and_reopen_read_only_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let rows_chirho = expected_rows_chirho(&context_chirho);
            let held_view_checkpoint_ref_chirho =
                complete_view_transfer_chirho(&held_storage_chirho, &context_chirho, rows_chirho);
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );

            assert!(
                held_store_chirho
                    .load_active_read_only_branch_evidence_chirho()
                    .expect("inspect absent read-only branch head")
                    .is_none(),
                "a complete transfer does not itself install a branch"
            );
            let foreign_prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                JournalPortsChirho {
                    storage_chirho: context_chirho.journal_ports_chirho.storage_chirho,
                    signer_chirho: context_chirho.journal_ports_chirho.signer_chirho,
                    clock_chirho: context_chirho.journal_ports_chirho.clock_chirho,
                    membership_chirho: context_chirho.journal_ports_chirho.membership_chirho,
                    kind_registry_chirho: context_chirho.journal_ports_chirho.kind_registry_chirho,
                    authority_chirho: context_chirho.journal_ports_chirho.authority_chirho,
                },
                context_chirho.cluster_chirho.clone(),
                compose_writer_epoch_chirho(99, 0).unwrap(),
            )
            .expect("prepare a valid but foreign resident genesis commitment");
            let foreign_genesis_chirho =
                ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
                    foreign_prepared_genesis_chirho.canonical_line_chirho(),
                    foreign_prepared_genesis_chirho.digest_chirho().clone(),
                )
                .expect("bind the foreign canonical genesis");
            assert_eq!(
                held_store_chirho
                    .prepare_read_only_branch_evidence_chirho(
                        context_chirho.losing_journal_chirho,
                        &foreign_genesis_chirho,
                    )
                    .unwrap_err(),
                Gd7ReadOnlyBranchRefusalChirho::InvalidLosingTailChirho,
                "a foreign identity-derived genesis must refuse before immutable branch staging"
            );
            assert!(
                held_store_chirho
                    .load_active_read_only_branch_evidence_chirho()
                    .expect("inspect branch head after foreign-genesis refusal")
                    .is_none(),
                "a foreign identity commitment cannot publish a branch head"
            );
            let prepared_chirho = held_store_chirho
                .prepare_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("prepare exact losing prefix plus accepted winner suffix");
            assert!(
                held_store_chirho
                    .load_active_read_only_branch_evidence_chirho()
                    .expect("inspect branch head after immutable preparation")
                    .is_none(),
                "a crash after immutable preparation leaves no installed branch head"
            );

            let installed_chirho = held_store_chirho
                .install_prepared_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                    &prepared_chirho,
                )
                .expect("install reverified read-only branch evidence");
            assert_eq!(
                installed_chirho
                    .checkpoint_chirho
                    .prefix_record_count_chirho,
                2
            );
            assert_eq!(
                installed_chirho
                    .checkpoint_chirho
                    .winner_suffix_record_count_chirho,
                1
            );
            assert_eq!(
                installed_chirho
                    .checkpoint_chirho
                    .canonical_record_count_chirho,
                3
            );

            let reopened_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .expect("reopen held evidence store after installed-head publication");
            let reopened_proof_chirho = reopened_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .expect("reverify installed branch after restart")
                .expect("installed branch head remains present");
            assert_eq!(
                reopened_proof_chirho.checkpoint_ref_chirho(),
                prepared_chirho.checkpoint_ref_chirho()
            );
            assert_eq!(reopened_proof_chirho.canonical_record_count_chirho(), 3);

            let retried_chirho = reopened_store_chirho
                .install_prepared_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                    &prepared_chirho,
                )
                .expect("retry exact install idempotently");
            assert_eq!(retried_chirho, installed_chirho);
        },
    );
}

#[test]
fn exact_branch_materializes_an_ordinary_journal_and_accepted_projection_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let rows_chirho = expected_rows_chirho(&context_chirho);
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                rows_chirho.clone(),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let active_evidence_chirho = held_store_chirho
                .load_active_chirho()
                .expect("load complete evidence transfer")
                .expect("complete evidence transfer remains active");
            let active_branch_chirho = held_store_chirho
                .prepare_and_install_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("install exact read-only branch before materialization");
            let sealed_plan_chirho = sealed_plan_snapshot_for_context_chirho(&context_chirho);

            let prepared_chirho = materialize_gd7_held_adoption_candidate_chirho(
                &held_store_chirho,
                &sealed_plan_chirho,
                &active_evidence_chirho.checkpoint_ref_chirho,
                &active_branch_chirho.checkpoint_ref_chirho,
                Gd7HeldAdoptionMaterializationPortsChirho {
                    candidate_storage_chirho: &held_storage_chirho,
                    winner_ledger_verifier_chirho: context_chirho.winner_journal_signer_chirho,
                    clock_chirho: context_chirho.journal_ports_chirho.clock_chirho,
                    membership_chirho: context_chirho.journal_ports_chirho.membership_chirho,
                    kind_registry_chirho: context_chirho.journal_ports_chirho.kind_registry_chirho,
                    authority_chirho: context_chirho.journal_ports_chirho.authority_chirho,
                    cluster_id_chirho: context_chirho.cluster_chirho,
                },
            )
            .expect("materialize exact ordinary-journal adoption candidate");

            let journal_bytes_chirho = held_storage_chirho
                .read_all_chirho(prepared_chirho.candidate_journal_path_chirho())
                .expect("read materialized journal")
                .expect("materialized journal exists");
            let projection_bytes_chirho = held_storage_chirho
                .read_all_chirho(prepared_chirho.candidate_projection_path_chirho())
                .expect("read materialized projection")
                .expect("materialized projection exists");
            assert_eq!(
                journal_bytes_chirho.len(),
                3_460,
                "the three-record fixture pins its exact canonical journal length"
            );
            assert_eq!(prepared_chirho.candidate_record_count_chirho(), 3);
            assert_eq!(
                prepared_chirho.candidate_record_count_chirho(),
                context_chirho
                    .plan_checkpoint_chirho
                    .identity_chirho
                    .winner_journal_tail_chirho
                    .seq_chirho
            );
            assert_eq!(
                prepared_chirho.candidate_journal_byte_len_chirho(),
                journal_bytes_chirho.len() as u64,
                "the fixture records the exact one-time full-open byte cost"
            );
            assert_eq!(
                journal_bytes_chirho
                    .iter()
                    .filter(|byte_chirho| **byte_chirho == b'\n')
                    .count(),
                4
            );
            assert_eq!(
                prepared_chirho.candidate_projection_byte_len_chirho(),
                projection_bytes_chirho.len() as u64
            );
            assert_eq!(
                prepared_chirho.candidate_projection_row_count_chirho(),
                rows_chirho.len() as u64
            );
            assert_eq!(
                parse_canonical_account_net_projection_view_chirho(&projection_bytes_chirho)
                    .expect("parse exact canonical candidate projection")
                    .rows_chirho,
                rows_chirho
            );
            assert_eq!(
                held_store_chirho
                    .load_active_chirho()
                    .expect("reload unchanged evidence transfer")
                    .expect("evidence transfer stays present"),
                active_evidence_chirho,
                "Cut A materialization does not move the evidence head"
            );
        },
    );
}

#[test]
fn re_signed_account_row_count_only_checkpoint_refuses_stale_evidence_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let prepared_chirho = held_store_chirho
                .prepare_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("prepare exact read-only branch checkpoint");
            let installed_chirho = held_store_chirho
                .install_prepared_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                    &prepared_chirho,
                )
                .expect("install exact read-only branch checkpoint");
            held_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .expect("verify the untampered installed checkpoint")
                .expect("the untampered branch head remains installed");
            let original_checkpoint_chirho = installed_chirho.checkpoint_chirho;
            let mut changed_checkpoint_chirho = original_checkpoint_chirho.clone();
            changed_checkpoint_chirho.account_net_row_count_chirho = changed_checkpoint_chirho
                .account_net_row_count_chirho
                .checked_add(1)
                .expect("fixture row count remains bounded");
            sign_value_chirho(
                &mut changed_checkpoint_chirho,
                context_chirho.held_signer_chirho,
                |value_chirho| &mut value_chirho.sig_chirho,
            );
            assert_eq!(
                changed_checkpoint_chirho.account_net_row_count_chirho,
                original_checkpoint_chirho.account_net_row_count_chirho + 1,
                "the planted checkpoint changes the final bare count"
            );
            let mut normalized_checkpoint_chirho = changed_checkpoint_chirho.clone();
            normalized_checkpoint_chirho.account_net_row_count_chirho =
                original_checkpoint_chirho.account_net_row_count_chirho;
            normalized_checkpoint_chirho.sig_chirho = original_checkpoint_chirho.sig_chirho.clone();
            assert_eq!(
                normalized_checkpoint_chirho, original_checkpoint_chirho,
                "only account_net_row_count_chirho and its required signature may differ"
            );
            assert_ne!(
                changed_checkpoint_chirho.sig_chirho, original_checkpoint_chirho.sig_chirho,
                "the count-only mutation must carry a fresh valid signature"
            );
            persist_and_publish_read_only_branch_checkpoint_chirho(
                &held_storage_chirho,
                &manifest_chirho.transfer_identity_chirho,
                &changed_checkpoint_chirho,
                context_chirho.held_signer_chirho,
            );
            let refusal_chirho = held_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7ReadOnlyBranchRefusalChirho::StaleEvidenceChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("evidence changed"));
            assert!(!rendered_chirho.contains("signature"));
            assert!(!rendered_chirho.contains("checkpoint is invalid"));
        },
    );
}

#[test]
fn winner_signed_head_over_genuine_checkpoint_refuses_invalid_signature_chirho() {
    // Reviewer-chosen arm (claude2_chirho, #9679 / freeze #9682 target 4). Both frozen arms pin
    // INTEGRITY properties: digest-address binding and checkpoint completeness. This arm pins the
    // AUTHORITY property neither reaches: head verification must verify against the PINNED held
    // verifier port, never a verifier resolved from the head's own key_id_chirho field. The
    // fixture head violates ONLY who blessed it - schema, transfer-identity digest, checkpoint
    // ref, and key-id/signature self-consistency are all genuine, and the signature is VALID
    // under the winner key the head honestly names.
    // MIGRATION PATH: if this arm ever refuses WrongHeldSignerChirho instead of
    // InvalidSignatureChirho, the verifier is being RESOLVED from the head's self-declared key id
    // and only the trailing equality check is refusing - the attacker-controlled-field
    // architecture this arm exists to forbid. Restore the pinned verifier; do not retarget.
    with_fork_baseline_fixture_chirho(
        1,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let prepared_chirho = held_store_chirho
                .prepare_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("prepare exact read-only branch checkpoint");
            let installed_chirho = held_store_chirho
                .install_prepared_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                    &prepared_chirho,
                )
                .expect("install exact read-only branch checkpoint");
            held_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .expect("verify the untampered installed checkpoint")
                .expect("the untampered branch head remains installed");
            let original_checkpoint_chirho = installed_chirho.checkpoint_chirho;
            let checkpoint_bytes_chirho = canonical_json_chirho(&original_checkpoint_chirho)
                .expect("serialize the genuine installed checkpoint canonically");
            let mut winner_head_chirho = Gd7ReadOnlyBranchHeadChirho {
                schema_chirho: GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
                transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
                    &manifest_chirho.transfer_identity_chirho,
                )
                .expect("digest exact transfer identity"),
                active_checkpoint_ref_chirho: digest_bytes_chirho(&checkpoint_bytes_chirho),
                key_id_chirho: Gd7ReconciliationVerifierPortChirho::key_id_chirho(
                    context_chirho.winner_signer_chirho,
                ),
                sig_chirho: String::new(),
            };
            sign_value_chirho(
                &mut winner_head_chirho,
                context_chirho.winner_signer_chirho,
                |value_chirho| &mut value_chirho.sig_chirho,
            );
            assert_ne!(
                winner_head_chirho.key_id_chirho,
                Gd7ReconciliationVerifierPortChirho::key_id_chirho(
                    context_chirho.held_signer_chirho,
                ),
                "the planted head must be blessed by a principal other than the held signer"
            );
            held_storage_chirho
                .atomic_write_chirho(
                    &gd7_read_only_branch_head_path_chirho(
                        &manifest_chirho.transfer_identity_chirho,
                    )
                    .expect("derive exact branch-head path"),
                    &canonical_json_chirho(&winner_head_chirho)
                        .expect("serialize winner-signed head canonically"),
                )
                .expect("publish the winner-signed evidence-only test head");
            let refusal_chirho = held_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7ReadOnlyBranchRefusalChirho::InvalidSignatureChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("signature is invalid"));
            assert!(!rendered_chirho.contains("wrong held signer"));
            assert!(!rendered_chirho.contains("evidence changed"));
        },
    );
}

#[test]
fn held_signed_prefix_with_a_different_fork_record_refuses_before_install_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let prepared_chirho = held_store_chirho
                .prepare_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("prepare an exact branch before planting a seam mismatch");
            let installed_chirho = held_store_chirho
                .install_prepared_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                    &prepared_chirho,
                )
                .expect("install the exact control branch");

            let prefix_root_path_chirho = gd7_read_only_branch_prefix_root_path_chirho(
                &installed_chirho.checkpoint_chirho.prefix_root_ref_chirho,
            )
            .expect("derive exact prefix-root path");
            let prefix_root_bytes_chirho = held_storage_chirho
                .read_all_chirho(&prefix_root_path_chirho)
                .expect("read exact prefix root")
                .expect("exact prefix root exists");
            let mut prefix_root_chirho: Gd7ReadOnlyBranchPrefixRootChirho =
                serde_json::from_slice(&prefix_root_bytes_chirho).expect("parse exact prefix root");
            assert_eq!(prefix_root_chirho.page_count_chirho, 1);
            let original_page_ref_chirho = prefix_root_chirho
                .oldest_page_ref_chirho
                .clone()
                .expect("two-record prefix has one page");
            let page_path_chirho =
                gd7_read_only_branch_prefix_page_path_chirho(&original_page_ref_chirho)
                    .expect("derive exact prefix-page path");
            let page_bytes_chirho = held_storage_chirho
                .read_all_chirho(&page_path_chirho)
                .expect("read exact prefix page")
                .expect("exact prefix page exists");
            let mut page_chirho: TestReadOnlyBranchPrefixPageChirho =
                serde_json::from_slice(&page_bytes_chirho).expect("parse exact prefix page");
            let fork_record_chirho = page_chirho
                .records_newest_first_chirho
                .first_mut()
                .expect("prefix page contains the fork record");
            fork_record_chirho
                .record_chirho
                .idempotency_key_chirho
                .push_str("-equivocated-chirho");
            let signed_content_chirho =
                ledger_record_signed_content_line_chirho(&fork_record_chirho.record_chirho)
                    .expect("render changed fork record for a real signature");
            fork_record_chirho.record_chirho.sig_chirho = LedgerSignerPortChirho::sign_chirho(
                context_chirho.winner_journal_signer_chirho,
                &signed_content_chirho,
            )
            .expect("sign changed fork record with the real journal test signer");
            let changed_line_chirho =
                canonical_ledger_record_line_chirho(&fork_record_chirho.record_chirho)
                    .expect("render changed signed fork record");
            fork_record_chirho.record_digest_chirho =
                stored_line_digest_chirho(&changed_line_chirho).0;
            let changed_page_bytes_chirho =
                serde_json::to_vec(&page_chirho).expect("serialize changed canonical prefix page");
            let changed_page_ref_chirho = digest_bytes_chirho(&changed_page_bytes_chirho);
            assert!(matches!(
                held_storage_chirho
                    .create_durable_chirho(
                        &gd7_read_only_branch_prefix_page_path_chirho(&changed_page_ref_chirho)
                            .expect("derive changed page path"),
                        &changed_page_bytes_chirho,
                    )
                    .expect("persist changed immutable page"),
                CreateDurableOutcomeChirho::CreatedChirho
            ));

            prefix_root_chirho.oldest_page_ref_chirho = Some(changed_page_ref_chirho);
            sign_value_chirho(
                &mut prefix_root_chirho,
                context_chirho.held_signer_chirho,
                |value_chirho| &mut value_chirho.sig_chirho,
            );
            let changed_root_bytes_chirho =
                serde_json::to_vec(&prefix_root_chirho).expect("serialize changed signed root");
            let changed_root_ref_chirho = digest_bytes_chirho(&changed_root_bytes_chirho);
            assert!(matches!(
                held_storage_chirho
                    .create_durable_chirho(
                        &gd7_read_only_branch_prefix_root_path_chirho(&changed_root_ref_chirho)
                            .expect("derive changed root path"),
                        &changed_root_bytes_chirho,
                    )
                    .expect("persist changed signed root"),
                CreateDurableOutcomeChirho::CreatedChirho
            ));

            let mut changed_checkpoint_chirho = installed_chirho.checkpoint_chirho.clone();
            changed_checkpoint_chirho.prefix_root_ref_chirho = changed_root_ref_chirho;
            sign_value_chirho(
                &mut changed_checkpoint_chirho,
                context_chirho.held_signer_chirho,
                |value_chirho| &mut value_chirho.sig_chirho,
            );
            persist_and_publish_read_only_branch_checkpoint_chirho(
                &held_storage_chirho,
                &manifest_chirho.transfer_identity_chirho,
                &changed_checkpoint_chirho,
                context_chirho.held_signer_chirho,
            );

            let refusal_chirho = held_store_chirho
                .verify_active_read_only_branch_evidence_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7ReadOnlyBranchRefusalChirho::InvalidPrefixChainChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("prefix chain"));
            assert!(!rendered_chirho.contains("winner junction"));
        },
    );
}

#[test]
fn fully_signed_but_wrong_current_view_refuses_by_composition_identity_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let mut wrong_rows_chirho = expected_rows_chirho(&context_chirho);
            wrong_rows_chirho[0].account_net_chirho += 1;
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                wrong_rows_chirho,
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );

            let refusal_chirho = held_store_chirho
                .verify_account_net_composition_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7AccountNetCompositionRefusalChirho::CurrentViewMismatchChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("accepted winner view"));
            assert!(!rendered_chirho.contains("stored post"));
        },
    );
}

#[test]
fn receiving_transfer_refuses_before_account_net_composition_chirho() {
    with_fork_baseline_fixture_chirho(
        1,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let manifest_chirho =
                super::super::tests_chirho::stage_evidence_manifest_chirho(&context_chirho);
            let held_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .expect("open receiving held evidence transfer");
            let active_chirho = held_store_chirho
                .begin_chirho(&manifest_chirho)
                .expect("begin receiving held evidence transfer");
            assert_eq!(
                active_chirho.checkpoint_chirho.phase_chirho,
                Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
            );

            let refusal_chirho = held_store_chirho
                .verify_account_net_composition_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7AccountNetCompositionRefusalChirho::IncompleteEvidenceChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("incomplete"));
            assert!(!rendered_chirho.contains("changed"));
        },
    );
}

#[test]
fn independently_folded_record_refuses_a_false_carried_post_chirho() {
    let account_chirho = LogIdChirho::new_chirho(
        "gd7-composition-owner-chirho",
        "gd7-composition-kind-chirho",
    );
    let mut head_states_chirho = BTreeMap::new();
    let record_chirho = LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        seq_chirho: 1,
        prev_chirho: DigestChirho("1".repeat(64)),
        epoch_chirho: 1,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 1,
            logical_chirho: 0,
        },
        legs_chirho: vec![LedgerLegChirho {
            account_chirho,
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("2".repeat(64))),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: 2,
                debits_total_chirho: 0,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        }],
        op_chirho: LedgerOpChirho::CreditChirho,
        idempotency_key_chirho: "gd7-composition-post-mismatch-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
        anchor_chirho: None,
        sig_chirho: "test-signature-chirho".to_owned(),
        key_id_chirho: "3".repeat(64),
    };

    let refusal_chirho = apply_record_chirho(&mut head_states_chirho, &record_chirho).unwrap_err();
    assert_eq!(
        refusal_chirho,
        Gd7AccountNetCompositionRefusalChirho::StoredPostMismatchChirho
    );
    let rendered_chirho = refusal_chirho.to_string();
    assert!(rendered_chirho.contains("stored post"));
    assert!(!rendered_chirho.contains("accepted winner view"));
    assert!(head_states_chirho.is_empty());
}

#[test]
fn full_reconciliation_identity_equality_blocks_cross_term_splicing_chirho() {
    with_fork_baseline_fixture_chirho(
        1,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let manifest_chirho =
                super::super::tests_chirho::stage_evidence_manifest_chirho(&context_chirho);
            let mut foreign_chirho = manifest_chirho.clone();
            foreign_chirho
                .fork_baseline_root_chirho
                .identity_chirho
                .reconciliation_identity_chirho
                .winner_term_chirho += 1;

            assert_eq!(
                validate_exact_artifact_bindings_chirho(
                    &manifest_chirho.transfer_identity_chirho,
                    &foreign_chirho,
                )
                .unwrap_err(),
                Gd7AccountNetCompositionRefusalChirho::InvalidEvidenceBindingChirho,
                "full identity equality, not only fork/genesis fields, blocks a cross-term splice"
            );
        },
    );
}

#[test]
fn digest_addressed_root_substitution_refuses_before_cross_reconciliation_use_chirho() {
    with_fork_baseline_fixture_chirho(
        1,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            held_store_chirho
                .verify_account_net_composition_chirho()
                .expect("the retained genuine manifest and roots compose before substitution");

            let genuine_root_ref_chirho = manifest_chirho
                .fork_baseline_root_object_digest_chirho
                .clone();
            let mut foreign_reconciliation_chirho = manifest_chirho
                .fork_baseline_root_chirho
                .identity_chirho
                .reconciliation_identity_chirho
                .clone();
            let original_winner_epoch_chirho = split_writer_epoch_chirho(
                foreign_reconciliation_chirho
                    .winner_journal_tail_chirho
                    .epoch_chirho,
            );
            foreign_reconciliation_chirho.winner_term_chirho = foreign_reconciliation_chirho
                .winner_term_chirho
                .checked_add(1)
                .expect("fixture winner term remains bounded");
            foreign_reconciliation_chirho
                .winner_journal_tail_chirho
                .epoch_chirho = compose_writer_epoch_chirho(
                foreign_reconciliation_chirho.winner_term_chirho,
                u64::from(original_winner_epoch_chirho.local_grant_seq_chirho),
            )
            .expect("bind the foreign tail epoch to its different winner term");
            let foreign_identity_chirho = Gd7ForkBaselineIdentityChirho::new_chirho(
                foreign_reconciliation_chirho,
                manifest_chirho
                    .fork_baseline_root_chirho
                    .identity_chirho
                    .winner_handoff_attempt_digest_chirho
                    .clone(),
            )
            .expect("construct a different internally valid reconciliation identity");
            let mut foreign_root_chirho = manifest_chirho.fork_baseline_root_chirho.clone();
            foreign_root_chirho.identity_chirho = foreign_identity_chirho.clone();
            sign_value_chirho(
                &mut foreign_root_chirho,
                context_chirho.winner_signer_chirho,
                |value_chirho| &mut value_chirho.sig_chirho,
            );
            let foreign_root_bytes_chirho = canonical_json_chirho(&foreign_root_chirho)
                .expect("serialize foreign signed root canonically");
            let foreign_root_ref_chirho = digest_bytes_chirho(&foreign_root_bytes_chirho);
            assert_ne!(
                foreign_root_ref_chirho, genuine_root_ref_chirho,
                "the different reconciliation must produce a different object address"
            );
            assert_ne!(
                foreign_identity_chirho, manifest_chirho.fork_baseline_root_chirho.identity_chirho,
                "the substitution fixture must violate the exact reconciliation binding"
            );
            assert!(matches!(
                held_storage_chirho
                    .create_durable_chirho(
                        &gd7_fork_baseline_root_path_chirho(&foreign_root_ref_chirho)
                            .expect("derive foreign root's own path"),
                        &foreign_root_bytes_chirho,
                    )
                    .expect("persist foreign root at its own digest address"),
                CreateDurableOutcomeChirho::CreatedChirho
            ));
            let verified_foreign_chirho = load_verified_gd7_fork_baseline_root_chirho(
                &held_storage_chirho,
                &foreign_root_ref_chirho,
                &foreign_identity_chirho,
                context_chirho.winner_signer_chirho,
            )
            .expect("the separately signed foreign root is valid at its own address");
            assert_eq!(verified_foreign_chirho.root_chirho(), &foreign_root_chirho);

            held_storage_chirho
                .atomic_write_chirho(
                    &gd7_fork_baseline_root_path_chirho(&genuine_root_ref_chirho)
                        .expect("derive genuine manifest-pinned root path"),
                    &foreign_root_bytes_chirho,
                )
                .expect("substitute foreign bytes only at the digest-addressed read boundary");
            let refusal_chirho = held_store_chirho
                .verify_account_net_composition_chirho()
                .unwrap_err();
            assert_eq!(
                refusal_chirho,
                Gd7AccountNetCompositionRefusalChirho::ForkBaselineChirho(
                    Gd7ForkBaselineRefusalChirho::ObjectDigestMismatchChirho,
                )
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("digest mismatches its address"));
            assert!(!rendered_chirho.contains("identities do not match"));
            assert!(!rendered_chirho.contains("signature is invalid"));
        },
    );
}

pub(super) fn expected_rows_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
) -> Vec<AccountNetProjectionRowChirho> {
    context_chirho
        .winner_journal_chirho
        .head_states_chirho()
        .iter()
        .map(|(account_chirho, post_chirho)| {
            account_net_projection_row_chirho(account_chirho, post_chirho)
                .expect("real verified journal heads form canonical account-net rows")
        })
        .collect()
}

pub(super) fn sealed_plan_snapshot_for_context_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
) -> ResidentGd7HeldSealedPlanSnapshotChirho {
    let state_chirho = &context_chirho.plan_checkpoint_chirho.state_chirho;
    ResidentGd7HeldSealedPlanSnapshotChirho {
        reconciliation_identity_digest_chirho: gd7_reconciliation_identity_digest_chirho(
            &context_chirho.plan_checkpoint_chirho.identity_chirho,
        )
        .expect("digest fixture reconciliation identity"),
        checkpoint_ref_chirho: context_chirho.plan_checkpoint_ref_chirho.to_owned(),
        sealed_plan_ref_chirho: state_chirho
            .sealed_plan_ref_chirho
            .clone()
            .expect("fixture plan is sealed"),
        winner_fork_witness_object_digest_chirho: context_chirho
            .plan_checkpoint_chirho
            .winner_fork_witness_object_digest_chirho
            .clone(),
        winner_term_chirho: context_chirho
            .plan_checkpoint_chirho
            .identity_chirho
            .winner_term_chirho,
        plan_page_count_chirho: state_chirho.plan_page_count_chirho,
        manifest_record_count_chirho: state_chirho.manifest_record_count_chirho,
        effect_obligation_count_chirho: state_chirho.effect_obligation_count_chirho,
    }
}

pub(super) fn complete_view_transfer_chirho(
    held_storage_chirho: &SimStorageChirho,
    context_chirho: &ForkBaselineTestContextChirho<'_>,
    rows_chirho: Vec<AccountNetProjectionRowChirho>,
) -> String {
    let reconciliation_identity_chirho = &context_chirho.plan_checkpoint_chirho.identity_chirho;
    let identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: reconciliation_identity_chirho
            .consistency_group_digest_chirho
            .clone(),
        reconciliation_checkpoint_ref_chirho: context_chirho.plan_checkpoint_ref_chirho.to_owned(),
        winner_node_chirho: reconciliation_identity_chirho.winner_node_chirho.clone(),
        held_node_chirho: reconciliation_identity_chirho.held_node_chirho.clone(),
        winner_term_chirho: reconciliation_identity_chirho.winner_term_chirho,
    };
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        held_storage_chirho,
        context_chirho.held_signer_chirho,
        context_chirho.winner_signer_chirho,
        identity_chirho.clone(),
    )
    .expect("open held current-view transfer store");
    let initial_chirho = store_chirho
        .ensure_initialized_chirho()
        .expect("initialize held current-view transfer");
    let source_cut_chirho = reconciliation_identity_chirho
        .winner_journal_tail_chirho
        .clone();
    let page_chirho = Gd7WinnerViewBundlePageChirho {
        schema_chirho: "gd7-winner-view-bundle-page-v1-chirho".to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: reconciliation_identity_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        source_cut_chirho: source_cut_chirho.clone(),
        page_index_chirho: 0,
        higher_page_ref_chirho: None,
        rows_chirho,
        next_upper_exclusive_account_chirho: None,
        cumulative_page_count_chirho: 1,
        cumulative_row_count_chirho: 0,
    };
    let mut page_chirho = page_chirho;
    page_chirho.cumulative_row_count_chirho = page_chirho.rows_chirho.len() as u64;
    let page_bytes_chirho = canonical_json_chirho(&page_chirho).unwrap();
    let page_ref_chirho = digest_bytes_chirho(&page_bytes_chirho);
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: reconciliation_identity_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        source_cut_chirho: source_cut_chirho.clone(),
        lowest_page_ref_chirho: Some(page_ref_chirho.clone()),
        page_count_chirho: 1,
        row_count_chirho: page_chirho.rows_chirho.len() as u64,
    };
    let root_ref_chirho = digest_bytes_chirho(&canonical_json_chirho(&root_chirho).unwrap());
    let challenge_chirho = Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho: "4".repeat(64),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        expected_winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
        transfer_identity_digest_chirho: store_chirho.identity_digest_chirho().to_owned(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
    };
    let challenge_bytes_chirho = challenge_chirho.canonical_bytes_chirho().unwrap();
    let challenged_chirho = store_chirho
        .commit_challenge_issued_chirho(
            &initial_chirho.checkpoint_ref_chirho,
            0,
            root_ref_chirho.clone(),
            1,
            root_chirho.row_count_chirho,
            &challenge_bytes_chirho,
        )
        .expect("bind exact staged winner-view root");
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_chirho.digest_chirho().unwrap(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
        winner_process_generation_chirho: 17,
        winner_journal_genesis_digest_chirho: root_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        latest_verified_journal_cut_chirho: source_cut_chirho.clone(),
        view_bundle_root_chirho: root_ref_chirho.clone(),
        key_id_chirho: Gd7ReconciliationVerifierPortChirho::key_id_chirho(
            context_chirho.winner_signer_chirho,
        ),
        sig_chirho: String::new(),
    };
    sign_value_chirho(
        &mut evidence_chirho,
        context_chirho.winner_signer_chirho,
        |value_chirho| &mut value_chirho.sig_chirho,
    );
    let evidence_ref_chirho =
        digest_bytes_chirho(&canonical_json_chirho(&evidence_chirho).unwrap());
    let inspection_chirho = Gd7WinnerCurrentViewInspectionChirho {
        evidence_object_digest_chirho: evidence_ref_chirho.clone(),
        evidence_chirho,
        bundle_root_object_digest_chirho: root_ref_chirho.clone(),
        bundle_root_chirho: root_chirho,
    };
    let mut grant_chirho = Gd7WinnerViewPageGrantChirho {
        schema_chirho: GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
        winner_process_generation_chirho: 17,
        winner_evidence_object_digest_chirho: evidence_ref_chirho,
        bundle_root_object_digest_chirho: root_ref_chirho,
        source_cut_chirho,
        page_index_chirho: 0,
        page_object_digest_chirho: page_ref_chirho,
        key_id_chirho: Gd7ReconciliationVerifierPortChirho::key_id_chirho(
            context_chirho.winner_signer_chirho,
        ),
        sig_chirho: String::new(),
    };
    sign_value_chirho(
        &mut grant_chirho,
        context_chirho.winner_signer_chirho,
        |value_chirho| &mut value_chirho.sig_chirho,
    );
    let sealed_chirho = store_chirho
        .commit_sealed_chirho(
            &challenged_chirho.checkpoint_ref_chirho,
            inspection_chirho,
            Some(grant_chirho.clone()),
        )
        .expect("seal exact winner view");
    let complete_chirho = store_chirho
        .commit_received_page_chirho(
            &sealed_chirho.checkpoint_ref_chirho,
            grant_chirho,
            &page_bytes_chirho,
            None,
        )
        .expect("receive exact winner-view page");
    assert_eq!(
        complete_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldViewTransferPhaseChirho::CompleteChirho
    );
    complete_chirho.checkpoint_ref_chirho
}

pub(super) fn complete_evidence_transfer_chirho<'fixture_chirho>(
    held_storage_chirho: &'fixture_chirho SimStorageChirho,
    context_chirho: &'fixture_chirho ForkBaselineTestContextChirho<'fixture_chirho>,
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
) -> Gd7HeldEvidenceTransferStoreChirho<'fixture_chirho> {
    let store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
        held_storage_chirho,
        context_chirho.held_signer_chirho,
        context_chirho.winner_signer_chirho,
        context_chirho.winner_journal_signer_chirho,
        manifest_chirho.transfer_identity_chirho.clone(),
    )
    .expect("open held evidence transfer store");
    let mut active_chirho = store_chirho
        .begin_chirho(manifest_chirho)
        .expect("begin exact evidence transfer");
    while active_chirho.checkpoint_chirho.phase_chirho
        == Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
    {
        let transfer_chirho = fetch_next_chirho(context_chirho, manifest_chirho, &active_chirho);
        active_chirho = store_chirho
            .receive_page_chirho(&active_chirho.checkpoint_ref_chirho, &transfer_chirho)
            .expect("receive next exact evidence page");
    }
    assert_eq!(
        active_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
    );
    store_chirho
}

fn persist_and_publish_read_only_branch_checkpoint_chirho(
    storage_chirho: &SimStorageChirho,
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    checkpoint_chirho: &Gd7ReadOnlyBranchCheckpointChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) {
    let checkpoint_bytes_chirho =
        canonical_json_chirho(checkpoint_chirho).expect("serialize signed checkpoint canonically");
    let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
    assert!(matches!(
        storage_chirho
            .create_durable_chirho(
                &gd7_read_only_branch_checkpoint_path_chirho(&checkpoint_ref_chirho)
                    .expect("derive signed checkpoint path"),
                &checkpoint_bytes_chirho,
            )
            .expect("persist signed checkpoint"),
        CreateDurableOutcomeChirho::CreatedChirho
    ));
    let mut head_chirho = Gd7ReadOnlyBranchHeadChirho {
        schema_chirho: GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
        transfer_identity_digest_chirho: gd7_held_evidence_transfer_identity_digest_chirho(
            identity_chirho,
        )
        .expect("digest exact transfer identity"),
        active_checkpoint_ref_chirho: checkpoint_ref_chirho,
        key_id_chirho: Gd7ReconciliationVerifierPortChirho::key_id_chirho(held_signer_chirho),
        sig_chirho: String::new(),
    };
    sign_value_chirho(&mut head_chirho, held_signer_chirho, |value_chirho| {
        &mut value_chirho.sig_chirho
    });
    storage_chirho
        .atomic_write_chirho(
            &gd7_read_only_branch_head_path_chirho(identity_chirho)
                .expect("derive exact branch-head path"),
            &canonical_json_chirho(&head_chirho).expect("serialize signed head canonically"),
        )
        .expect("publish signed evidence-only test head");
}

fn sign_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &mut ValueChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) {
    signature_chirho(value_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(value_chirho).unwrap();
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho).unwrap();
    *signature_chirho(value_chirho) = signer_chirho.sign_chirho(unsigned_line_chirho).unwrap();
}
