// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{
    drive_campaign_chirho, drive_ticks_chirho, drive_transfer_chirho, fixture_chirho,
    request_chirho,
};
use crate::run_ledger_regenesis_chirho;
use cairn_config_chirho::config_chirho::load_config_chirho;
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalAuthorityRefusalIdentityChirho, EffectCommitJournalPortChirho,
    EffectCommitJournalPortErrorChirho, EffectCommitJournalViewPortChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, effect_intent_key_chirho, effect_intent_ref_chirho,
    sign_effect_intent_chirho, EffectIntentChirho, VerifiedEffectIntentChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_winner_handoff_head_path_chirho, generate_gd7_winner_current_view_challenge_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ExistingNodeGd7SignerChirho,
    Gd7HeldViewTransferIdentityChirho, Gd7HeldViewTransferPhaseChirho,
    Gd7HeldViewTransferStoreChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationCheckpointChirho, Gd7ReconciliationCheckpointStateChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationStoreRefusalChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerHandoffPhaseChirho,
    Gd7WinnerHandoffStoreRefusalChirho, Gd7WinnerWitnessReaderChirho, PinnedNodeGd7VerifierChirho,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, open_resident_effect_journal_handle_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho, FsLedgerStorageChirho,
    HostLedgerSignersChirho, ResidentGd7WinnerForkObservationRefusalChirho,
    ResidentGd7WinnerHandoffRefusalChirho, ResidentGd7WinnerViewStageInspectionChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::AttributionChirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, pubkey_hex_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use std::sync::Arc;

#[path = "resident_actor_tests_chirho/ordinary_term_acceptance_tests_chirho.rs"]
mod ordinary_term_acceptance_tests_chirho;

struct ExactOriginalCompensationViewChirho {
    original_effect_key_chirho: String,
}

impl CompensationAuthorizationViewChirho for ExactOriginalCompensationViewChirho {
    fn derive_chirho(
        &self,
        _candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            self.original_effect_key_chirho.clone(),
            self.original_effect_key_chirho.clone(),
            1,
            4,
            CompensationBreakerVerdictChirho::PermittedChirho,
        ))
    }
}

fn signed_plan_sealed_checkpoint_chirho(
    identity_chirho: Gd7ReconciliationIdentityChirho,
    winner_fork_witness_object_digest_chirho: String,
    held_signer_chirho: &ExistingNodeGd7SignerChirho,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let plan_ref_chirho = "3".repeat(64);
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho,
        winner_fork_witness_object_digest_chirho,
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 2,
            previous_checkpoint_ref_chirho: Some("1".repeat(64)),
            manifest_head_ref_chirho: Some("2".repeat(64)),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(plan_ref_chirho.clone()),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(plan_ref_chirho),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let unsigned_bytes_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode unsigned PlanSealed checkpoint");
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&unsigned_bytes_chirho)
                .expect("PlanSealed checkpoint is canonical UTF-8"),
        )
        .expect("sign PlanSealed checkpoint");
    let checkpoint_bytes_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode signed PlanSealed checkpoint");
    (
        blake3::hash(&checkpoint_bytes_chirho).to_hex().to_string(),
        checkpoint_chirho,
    )
}

#[test]
fn published_h3_ea_reopen_refuses_unaccepted_term_compensation_before_replay_recovery_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_config_chirho.signer_secrets_chirho)
            .unwrap();
    let signers_chirho = HostLedgerSignersChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &signer_refs_chirho,
    )
    .unwrap();
    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());

    let mut actor_chirho = open_resident_effect_journal_handle_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        None,
    )
    .expect("serving reopens the already published resident generation");
    let initial_cut_chirho = actor_chirho.effect_intent_cut_chirho().unwrap();
    let continuation_chirho = actor_chirho
        .current_continuation_chirho(&kind_id_chirho)
        .unwrap()
        .expect("the published kind has a verified continuation");
    let digest_chirho =
        |character_chirho: char| DigestChirho(character_chirho.to_string().repeat(64));
    let intent_chirho = sign_effect_intent_chirho(
        EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: initial_cut_chirho.clone(),
            contract_set_digest_chirho: digest_chirho('a'),
            door_chirho: serde_json::from_value(serde_json::json!({
                "effect_node_chirho": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "capability_fingerprint_chirho": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }))
            .unwrap(),
            reversion_contract_digest_chirho: digest_chirho('d'),
            request_ref_chirho: digest_chirho('e'),
            request_context_ref_chirho: digest_chirho('f'),
            evidence_refs_chirho: vec![digest_chirho('9')],
            resolved_price_chirho: AssetOpChirho {
                amount_chirho: 10,
                kind_id_chirho: kind_id_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: LogIdChirho::new_chirho(
                fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
                kind_id_chirho.clone(),
            ),
            effect_step_chirho: 1,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: fixture_chirho.plan_chirho.initial_owner_chirho.clone(),
            },
            original_effect_key_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        },
        signers_chirho.effect_intent_signer_chirho(),
    )
    .unwrap();
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let intent_line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();

    let first_receipt_chirho = actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .unwrap();
    assert_eq!(
        first_receipt_chirho.seq_chirho,
        initial_cut_chirho.tail_seq_chirho + 1,
        "one accepted mutation advances the resident journal exactly once"
    );

    let original_effect_key_chirho = effect_intent_key_chirho(&intent_chirho)
        .expect("the acknowledged forward intent has one canonical effect key");
    let mut compensation_intent_chirho = intent_chirho.clone();
    compensation_intent_chirho.journal_cut_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the compensation binds the post-forward cut");
    compensation_intent_chirho.request_ref_chirho = digest_chirho('4');
    compensation_intent_chirho.request_context_ref_chirho = digest_chirho('5');
    compensation_intent_chirho.evidence_refs_chirho = vec![digest_chirho('6')];
    compensation_intent_chirho.effect_step_chirho = 2;
    compensation_intent_chirho.original_effect_key_chirho =
        Some(original_effect_key_chirho.clone());
    compensation_intent_chirho.sig_chirho.clear();
    compensation_intent_chirho.key_id_chirho.clear();
    let compensation_intent_chirho = sign_effect_intent_chirho(
        compensation_intent_chirho,
        signers_chirho.effect_intent_signer_chirho(),
    )
    .expect("the compensation intent signs");
    let compensation_line_chirho = canonical_effect_intent_line_chirho(&compensation_intent_chirho)
        .expect("the compensation line is canonical");
    let compensation_authorization_chirho = match authorize_effect_compensation_chirho(
        &compensation_line_chirho,
        signers_chirho.effect_intent_signer_chirho(),
        &ExactOriginalCompensationViewChirho {
            original_effect_key_chirho,
        },
    )
    .expect("the exact original-effect authorization is derivable")
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorization_chirho) => {
            authorization_chirho
        }
        other_chirho => panic!(
            "the exact original-effect fixture must authorize before the actor mailbox: \
             {other_chirho:?}"
        ),
    };
    let cut_before_compensation_chirho = actor_chirho
        .effect_intent_cut_chirho()
        .expect("the refusal arm records the exact pre-compensation cut");
    let compensation_refusal_chirho = actor_chirho
        .append_compensation_hold_chirho(
            &compensation_line_chirho,
            &compensation_authorization_chirho,
        )
        .expect_err(
            "an E-A single-node reopen carries no independent acceptance evidence for its new \
             term, so its compensation hold must remain fenced",
        );
    let EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho {
        identity_chirho: compensation_refusal_identity_chirho,
        detail_chirho: compensation_refusal_detail_chirho,
    } = compensation_refusal_chirho
    else {
        panic!(
            "the present-but-behind sink cell without acceptance inputs must refuse by typed \
             authority identity, not as unavailable or committed-pending: \
             {compensation_refusal_chirho:?}"
        );
    };
    assert_eq!(
        compensation_refusal_identity_chirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
        "the missing ordinary-term source and placement binding must not collapse into a sink-term neighbour"
    );
    assert_ne!(
        compensation_refusal_identity_chirho,
        EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermUnseenWinnerChirho,
        "the old unseen-term identity would conceal that acceptance was never attempted"
    );
    assert_eq!(
        compensation_refusal_detail_chirho,
        "resident ordinary-election sink-term acceptance inputs are unavailable",
        "the fixed local detail must carry no path or caller-supplied bytes"
    );
    assert_eq!(
        actor_chirho
            .effect_intent_cut_chirho()
            .expect("the actor remains readable after the fenced hold"),
        cut_before_compensation_chirho,
        "the fenced compensation hold must append nothing"
    );

    let replay_receipt_chirho = actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .unwrap();
    assert_eq!(
        replay_receipt_chirho, first_receipt_chirho,
        "same-intent replay returns the original receipt without another append"
    );
    assert_eq!(
        actor_chirho
            .effect_intent_cut_chirho()
            .unwrap()
            .tail_seq_chirho,
        first_receipt_chirho.seq_chirho
    );
    let mut second_intent_chirho = intent_chirho.clone();
    second_intent_chirho.journal_cut_chirho = actor_chirho.effect_intent_cut_chirho().unwrap();
    second_intent_chirho.request_ref_chirho = digest_chirho('8');
    second_intent_chirho.request_context_ref_chirho = digest_chirho('7');
    second_intent_chirho.evidence_refs_chirho = vec![digest_chirho('6')];
    second_intent_chirho.effect_step_chirho = 2;
    second_intent_chirho.sig_chirho.clear();
    second_intent_chirho.key_id_chirho.clear();
    let second_intent_chirho = sign_effect_intent_chirho(
        second_intent_chirho,
        signers_chirho.effect_intent_signer_chirho(),
    )
    .unwrap();
    let second_line_chirho = canonical_effect_intent_line_chirho(&second_intent_chirho).unwrap();
    let second_receipt_chirho = actor_chirho
        .append_hold_chirho(&second_line_chirho)
        .unwrap();
    assert_eq!(
        second_receipt_chirho.seq_chirho,
        first_receipt_chirho.seq_chirho + 1,
        "a steady-term append moves the tail beyond exact-tail recovery"
    );
    drop(actor_chirho);

    let reopened_chirho = open_resident_effect_journal_handle_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        None,
    )
    .expect("restart verifies and recovers election, journal, and canary state");
    assert_eq!(
        reopened_chirho
            .effect_intent_cut_chirho()
            .unwrap()
            .tail_seq_chirho,
        second_receipt_chirho.seq_chirho,
        "restart must load the durable term-first index after the exact tail has moved on"
    );
    let recovered_chirho = reopened_chirho
        .receipt_by_intent_ref_chirho(&intent_ref_chirho)
        .unwrap()
        .expect("the verified resident view recovers the committed intent");
    assert_eq!(recovered_chirho.receipt_chirho, first_receipt_chirho);
    assert!(recovered_chirho.terminal_outcome_ref_chirho.is_none());
    drop(reopened_chirho);

    let node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&fixture_chirho.root_chirho).unwrap());
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let shared_elector_chirho = Arc::new(
        RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
            fixture_chirho
                .root_chirho
                .join(&ledger_config_chirho.monitor_evidence_namespace_chirho)
                .join("writer-election-chirho"),
            node_chirho,
            group_chirho,
        )
        .unwrap()
        .with_message_authentication_chirho(fixture_chirho.root_chirho.clone())
        .with_leadership_warmup_lease_chirho(),
    );
    let _campaign_chirho = shared_elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        let _messages_chirho = shared_elector_chirho.tick_chirho();
    }
    let shared_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        &shared_elector_chirho,
        None,
        None,
    )
    .expect("restart verifies journal/canary state around the exact externally ticked elector");
    let winner_evidence_chirho = shared_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive the restricted view from the one shared actor");
    assert_eq!(
        winner_evidence_chirho
            .probe_chirho()
            .unwrap()
            .journal_tail_seq_chirho,
        second_receipt_chirho.seq_chirho,
        "the restricted winner evidence facade shares the recovered journal cut"
    );

    drop(shared_actor_chirho);
    assert!(
        winner_evidence_chirho.probe_chirho().is_err(),
        "the restricted facade cannot keep the sole resident actor alive"
    );
    let shared_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        &shared_elector_chirho,
        None,
        None,
    )
    .expect("the sole actor lease releases before the exact shared elector is reopened");
    let winner_evidence_chirho = shared_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive another restricted view from the reopened sole actor");
    drop(shared_elector_chirho);
    assert!(
        winner_evidence_chirho.probe_chirho().is_err(),
        "the resident actor must not prolong or outlive the transport-owned elector"
    );
}

#[test]
fn shared_multinode_winner_facade_stages_seals_and_refuses_after_transfer_chirho() {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let ledger_config_chirho = load_config_chirho(&fixture_chirho.config_path_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("fixture config carries the ledger host");
    let canonical_root_chirho = fixture_chirho.root_chirho.canonicalize().unwrap();
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&ledger_config_chirho.signer_secrets_chirho)
            .unwrap();
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)
            .unwrap();
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho).unwrap();
    let local_node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&canonical_root_chirho).unwrap());
    let held_signing_root_chirho = canonical_root_chirho.join("gd7-held-signing-root-chirho");
    let held_node_chirho = NodeIdChirho(
        pubkey_hex_chirho(&held_signing_root_chirho)
            .expect("create one real held-node signing identity"),
    );
    let voters_chirho = vec![
        (1, local_node_chirho.clone()),
        (2, held_node_chirho.clone()),
        (3, NodeIdChirho("c".repeat(64))),
    ];
    let elector_root_chirho = canonical_root_chirho.join("gd7-winner-electors-chirho");
    let elector_dirs_chirho = (1..=3)
        .map(|raft_id_chirho| elector_root_chirho.join(format!("node-{raft_id_chirho}-chirho")))
        .collect::<Vec<_>>();
    let nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            Arc::new(
                RaftWriterElectorChirho::new_durable_cluster_node_chirho(
                    elector_dirs_chirho[(raft_id_chirho - 1) as usize].clone(),
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                )
                .unwrap()
                .with_leadership_warmup_lease_chirho(),
            )
        })
        .collect::<Vec<_>>();
    drive_campaign_chirho(&nodes_chirho, 0);
    drive_ticks_chirho(&nodes_chirho, 0, 10);
    let leadership_chirho = nodes_chirho[0].current_leadership_chirho();
    assert_eq!(
        leadership_chirho.leader_id_chirho.as_ref(),
        Some(&local_node_chirho)
    );
    assert!(leadership_chirho.is_leader_chirho);
    assert!(leadership_chirho.lease_valid_chirho);

    let shared_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        &nodes_chirho[0],
        None,
        None,
    )
    .expect("the one resident actor opens around the exact multi-node elector");
    let winner_evidence_chirho = shared_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive the restricted winner facade from the shared actor");
    let readiness_chirho = winner_evidence_chirho.probe_chirho().unwrap();
    let shared_journal_cut_chirho = shared_actor_chirho.effect_intent_cut_chirho().unwrap();
    assert_eq!(readiness_chirho.local_node_chirho, local_node_chirho);
    assert_eq!(
        readiness_chirho.published_raft_term_chirho,
        leadership_chirho.term_chirho
    );
    assert_eq!(
        readiness_chirho.journal_tail_seq_chirho, shared_journal_cut_chirho.tail_seq_chirho,
        "the neutral journal port and restricted winner facade share one resident actor"
    );

    let held_node_chirho = voters_chirho[1].1.clone();
    assert_eq!(
        winner_evidence_chirho
            .observe_deposed_fork_chirho(
                leadership_chirho.term_chirho + 1,
                held_node_chirho.clone(),
                readiness_chirho.genesis_digest_chirho.0.clone(),
                Gd7JournalTailCoordinateChirho {
                    epoch_chirho: readiness_chirho.journal_epoch_chirho,
                    seq_chirho: readiness_chirho.journal_tail_seq_chirho,
                    record_digest_chirho: readiness_chirho.journal_tail_digest_chirho.0.clone(),
                },
            )
            .unwrap_err(),
        ResidentGd7WinnerForkObservationRefusalChirho::InvalidHeldCoordinateChirho,
        "the actor rejects an old request coordinate before sealing next-term evidence"
    );
    let transfer_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho).unwrap();
    let winner_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(local_node_chirho.clone()).unwrap();
    let witness_reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &transfer_storage_chirho,
        &winner_verifier_chirho,
        signers_chirho.journal_signer_chirho(),
    );
    let first_record_index_chirho = witness_reader_chirho
        .load_winner_first_record_chirho(
            &consistency_group_digest_chirho(&group_chirho).unwrap(),
            &local_node_chirho.0,
            leadership_chirho.term_chirho,
            &readiness_chirho.genesis_digest_chirho.0,
        )
        .unwrap()
        .expect("resident startup persists the winner term-first index");
    let fork_anchor_chirho = first_record_index_chirho
        .index_chirho()
        .first_record_chirho
        .anchor_chirho
        .as_ref()
        .expect("winner term-first record binds the inherited fork");
    let observation_chirho = winner_evidence_chirho
        .observe_deposed_fork_chirho(
            leadership_chirho.term_chirho,
            held_node_chirho.clone(),
            readiness_chirho.genesis_digest_chirho.0.clone(),
            Gd7JournalTailCoordinateChirho {
                epoch_chirho: fork_anchor_chirho.inherited_epoch_chirho,
                seq_chirho: fork_anchor_chirho.inherited_seq_chirho + 1,
                record_digest_chirho: "b".repeat(64),
            },
        )
        .expect("the actor derives and signs the exact winner evidence for the frozen held tail");
    assert_eq!(
        observation_chirho.identity_chirho.winner_term_chirho,
        leadership_chirho.term_chirho
    );
    assert_eq!(
        observation_chirho.identity_chirho.fork_chirho.epoch_chirho,
        fork_anchor_chirho.inherited_epoch_chirho
    );
    assert_eq!(
        observation_chirho.winner_first_record_index_chirho,
        first_record_index_chirho.index_chirho().clone()
    );
    let held_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &held_signing_root_chirho,
        &held_node_chirho,
    )
    .expect("open the pre-provisioned held-node signing identity");
    let winner_fork_witness_object_digest_chirho = blake3::hash(
        &serde_json::to_vec(&observation_chirho.winner_fork_witness_chirho)
            .expect("encode the signed winner fork witness"),
    )
    .to_hex()
    .to_string();
    let (reconciliation_checkpoint_ref_chirho, reconciliation_checkpoint_chirho) =
        signed_plan_sealed_checkpoint_chirho(
            observation_chirho.identity_chirho.clone(),
            winner_fork_witness_object_digest_chirho,
            &held_signer_chirho,
        );
    let transfer_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &transfer_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        Gd7HeldViewTransferIdentityChirho {
            consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
                .unwrap(),
            reconciliation_checkpoint_ref_chirho: reconciliation_checkpoint_ref_chirho.clone(),
            winner_node_chirho: local_node_chirho.0.clone(),
            held_node_chirho: held_node_chirho.0.clone(),
            winner_term_chirho: leadership_chirho.term_chirho,
        },
    )
    .unwrap();
    let mut transfer_checkpoint_chirho = transfer_store_chirho.ensure_initialized_chirho().unwrap();
    let mut expected_stage_index_chirho = 0_u64;
    let ready_chirho = (0..16)
        .find_map(|_step_chirho| {
            let inspection_chirho = winner_evidence_chirho
                .stage_view_page_at_chirho(expected_stage_index_chirho)
                .expect("one indexed bounded winner-view page stages");
            assert_eq!(
                winner_evidence_chirho
                    .stage_view_page_at_chirho(expected_stage_index_chirho)
                    .expect("the immediately preceding stage retries idempotently"),
                inspection_chirho,
                "a network retry must not advance the projection twice"
            );
            match inspection_chirho {
                ResidentGd7WinnerViewStageInspectionChirho::AdvancedOnePageChirho => {
                    transfer_store_chirho
                        .commit_stage_advanced_chirho(
                            &transfer_checkpoint_chirho.checkpoint_ref_chirho,
                            expected_stage_index_chirho,
                        )
                        .expect("held checkpoint records exactly one staging advance");
                    transfer_checkpoint_chirho = transfer_store_chirho
                        .load_active_chirho()
                        .unwrap()
                        .expect("restart reloads the exact staging checkpoint");
                    expected_stage_index_chirho += 1;
                    None
                }
                ready_chirho @ ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
                    ..
                } => Some(ready_chirho),
            }
        })
        .expect("the small fixture projection completes within the fixed test bound");
    assert!(
        winner_evidence_chirho
            .stage_view_page_at_chirho(expected_stage_index_chirho + 2)
            .is_err(),
        "a skipped stage coordinate must fail closed"
    );
    let ResidentGd7WinnerViewStageInspectionChirho::ReadyChirho {
        bundle_root_object_digest_chirho,
        page_count_chirho,
        row_count_chirho,
        ..
    } = ready_chirho
    else {
        unreachable!("the bounded loop returns only the ready variant");
    };
    let issued_chirho = generate_gd7_winner_current_view_challenge_chirho(
        nodes_chirho[0].as_ref(),
        &group_chirho,
        &local_node_chirho,
        &held_node_chirho,
        transfer_store_chirho.identity_digest_chirho(),
    )
    .unwrap();
    let canonical_challenge_chirho = issued_chirho.canonical_bytes_chirho().unwrap();
    transfer_store_chirho
        .commit_challenge_issued_chirho(
            &transfer_checkpoint_chirho.checkpoint_ref_chirho,
            expected_stage_index_chirho,
            bundle_root_object_digest_chirho.clone(),
            page_count_chirho,
            row_count_chirho,
            &canonical_challenge_chirho,
        )
        .expect("the held challenge is durable before the winner sees it");
    transfer_checkpoint_chirho = transfer_store_chirho
        .load_active_chirho()
        .unwrap()
        .expect("restart reloads the exact issued challenge");
    let challenge_chirho =
        parse_canonical_gd7_winner_current_view_challenge_chirho(&canonical_challenge_chirho)
            .unwrap();
    let sealed_chirho = winner_evidence_chirho
        .seal_current_view_for_held_chirho(challenge_chirho, held_node_chirho.clone())
        .expect("the exact shared generation seals the view and its first held grant atomically");
    let inspection_chirho = sealed_chirho.inspection_chirho.clone();
    assert_eq!(
        inspection_chirho.bundle_root_object_digest_chirho,
        bundle_root_object_digest_chirho
    );
    assert_eq!(
        inspection_chirho.evidence_chirho.raft_term_chirho,
        leadership_chirho.term_chirho
    );

    let first_grant_chirho = sealed_chirho
        .first_page_grant_chirho
        .clone()
        .expect("the fixture current view contains at least one page");
    assert_eq!(first_grant_chirho.held_node_chirho, held_node_chirho.0);
    assert_eq!(
        first_grant_chirho.winner_evidence_object_digest_chirho,
        inspection_chirho.evidence_object_digest_chirho
    );
    assert!(
        winner_evidence_chirho
            .fetch_granted_page_chirho(voters_chirho[2].1.clone(), first_grant_chirho.clone())
            .is_err(),
        "another roster member cannot consume a recipient-bound grant"
    );
    transfer_store_chirho
        .commit_sealed_chirho(
            &transfer_checkpoint_chirho.checkpoint_ref_chirho,
            sealed_chirho.inspection_chirho,
            sealed_chirho.first_page_grant_chirho,
        )
        .expect("held checkpoint verifies and binds the winner seal");
    transfer_checkpoint_chirho = transfer_store_chirho
        .load_active_chirho()
        .unwrap()
        .expect("restart reloads the sealed first grant");
    let mut next_grant_chirho = Some(first_grant_chirho.clone());
    while let Some(grant_chirho) = next_grant_chirho {
        let transfer_chirho = winner_evidence_chirho
            .fetch_granted_page_chirho(held_node_chirho.clone(), grant_chirho.clone())
            .expect("the exact recipient fetches one granted immutable page");
        assert_eq!(transfer_chirho.grant_chirho, grant_chirho);
        assert!(!transfer_chirho.canonical_page_bytes_chirho.is_empty());
        next_grant_chirho = transfer_chirho.next_grant_chirho.clone();
        transfer_store_chirho
            .commit_received_page_chirho(
                &transfer_checkpoint_chirho.checkpoint_ref_chirho,
                transfer_chirho.grant_chirho,
                &transfer_chirho.canonical_page_bytes_chirho,
                transfer_chirho.next_grant_chirho,
            )
            .expect("held storage persists the page before moving its fixed head");
        transfer_checkpoint_chirho = transfer_store_chirho
            .load_active_chirho()
            .unwrap()
            .expect("restart reloads the exact next grant");
    }
    assert_eq!(
        transfer_checkpoint_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldViewTransferPhaseChirho::CompleteChirho
    );
    assert_eq!(
        transfer_checkpoint_chirho
            .checkpoint_chirho
            .received_page_count_chirho,
        page_count_chirho
    );
    assert_eq!(
        transfer_checkpoint_chirho
            .checkpoint_chirho
            .received_row_count_chirho,
        row_count_chirho
    );

    let fresh_handoff_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        nodes_chirho[0].as_ref(),
        &group_chirho,
        &local_node_chirho,
        &held_node_chirho,
        transfer_store_chirho.identity_digest_chirho(),
    )
    .expect("mint one fresh handoff challenge");
    let canonical_handoff_challenge_chirho = fresh_handoff_challenge_chirho
        .canonical_bytes_chirho()
        .expect("encode the fresh handoff challenge");
    let handoff_challenge_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(
        &canonical_handoff_challenge_chirho,
    )
    .expect("parse the winner-side handoff challenge");
    let handoff_chirho = shared_actor_chirho
        .gd7_winner_handoff_handle_chirho()
        .expect("derive the restricted handoff facade");
    let mut invalid_plan_checkpoint_chirho = reconciliation_checkpoint_chirho.clone();
    invalid_plan_checkpoint_chirho.sig_chirho = "invalid-signature-chirho".to_owned();
    assert_eq!(
        handoff_chirho
            .begin_chirho(
                transfer_store_chirho.identity_chirho().clone(),
                Box::new(invalid_plan_checkpoint_chirho),
                transfer_checkpoint_chirho.checkpoint_ref_chirho.clone(),
                Box::new(transfer_checkpoint_chirho.checkpoint_chirho.clone()),
                bundle_root_object_digest_chirho.clone(),
                parse_canonical_gd7_winner_current_view_challenge_chirho(
                    &canonical_handoff_challenge_chirho,
                )
                .expect("parse the exact challenge for the negative PlanSealed request"),
            )
            .expect_err("unverified PlanSealed content cannot activate a winner freeze"),
        ResidentGd7WinnerHandoffRefusalChirho::ReconciliationCheckpointChirho(
            Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho,
        )
    );
    assert_eq!(
        handoff_chirho
            .current_chirho()
            .expect("rejected PlanSealed content leaves no handoff attempt"),
        None
    );
    drop(
        nodes_chirho[0]
            .local_append_authority_handle_chirho()
            .try_acquire_chirho()
            .expect("PlanSealed verification fails before any handoff marker activates"),
    );
    let frozen_cut_chirho = shared_actor_chirho.effect_intent_cut_chirho().unwrap();
    let accepted_handoff_chirho = handoff_chirho
        .begin_chirho(
            transfer_store_chirho.identity_chirho().clone(),
            Box::new(reconciliation_checkpoint_chirho.clone()),
            transfer_checkpoint_chirho.checkpoint_ref_chirho.clone(),
            Box::new(transfer_checkpoint_chirho.checkpoint_chirho.clone()),
            bundle_root_object_digest_chirho.clone(),
            handoff_challenge_chirho,
        )
        .expect("the exact complete held chain freezes the accepted winner cut");
    assert_eq!(
        accepted_handoff_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho
    );
    assert_eq!(
        handoff_chirho
            .abort_chirho(accepted_handoff_chirho.attempt_digest_chirho.clone())
            .expect_err("the held-side facade cannot abort an Accepted freeze"),
        ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(
            Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
        )
    );
    assert_eq!(
        accepted_handoff_chirho
            .inspection_chirho
            .bundle_root_chirho
            .source_cut_chirho
            .seq_chirho,
        frozen_cut_chirho.tail_seq_chirho
    );
    let journal_path_chirho = canonical_root_chirho
        .join(&ledger_config_chirho.storage_namespace_chirho)
        .join(&ledger_config_chirho.journal_path_chirho);
    let frozen_journal_bytes_chirho =
        std::fs::read(&journal_path_chirho).expect("read the exact accepted winner journal bytes");

    drop(handoff_chirho);
    drop(winner_evidence_chirho);
    drop(shared_actor_chirho);
    drop(nodes_chirho);

    let fresh_nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            Arc::new(
                RaftWriterElectorChirho::open_existing_durable_cluster_node_chirho(
                    elector_dirs_chirho[(raft_id_chirho - 1) as usize].clone(),
                    group_chirho.clone(),
                    raft_id_chirho,
                    voters_chirho.clone(),
                )
                .unwrap()
                .with_leadership_warmup_lease_chirho(),
            )
        })
        .collect::<Vec<_>>();
    drive_campaign_chirho(&fresh_nodes_chirho, 0);
    drive_ticks_chirho(&fresh_nodes_chirho, 0, 10);
    assert_eq!(
        fresh_nodes_chirho[0]
            .current_leadership_chirho()
            .leader_id_chirho
            .as_ref(),
        Some(&local_node_chirho),
        "the durable restart re-elects the original winner node"
    );
    assert!(
        fresh_nodes_chirho[0]
            .current_leadership_chirho()
            .term_chirho
            > leadership_chirho.term_chirho,
        "a real durable-elector reopen advances beyond the historical accepted term"
    );
    let mut fresh_actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        &fresh_nodes_chirho[0],
        None,
        None,
    )
    .expect("fresh actor startup restores the durable winner handoff before serving");
    let fresh_handoff_chirho = fresh_actor_chirho
        .gd7_winner_handoff_handle_chirho()
        .expect("derive the handoff facade from the genuinely fresh actor");

    assert_eq!(
        fresh_handoff_chirho
            .current_chirho()
            .expect("fresh actor reads the restored durable handoff"),
        Some(accepted_handoff_chirho.clone()),
        "the exact Accepted status is restored before the first mutation command is served"
    );
    let fresh_winner_evidence_chirho = fresh_actor_chirho
        .gd7_winner_evidence_handle_chirho()
        .expect("derive the winner facade from the fresh actor");
    let fresh_readiness_chirho = fresh_winner_evidence_chirho
        .probe_chirho()
        .expect("Accepted freezes mutation without blocking the restricted winner probe");
    let accepted_source_cut_chirho = &accepted_handoff_chirho
        .inspection_chirho
        .bundle_root_chirho
        .source_cut_chirho;
    assert_eq!(
        fresh_readiness_chirho.journal_epoch_chirho,
        accepted_source_cut_chirho.epoch_chirho
    );
    assert_eq!(
        fresh_readiness_chirho.journal_tail_seq_chirho,
        accepted_source_cut_chirho.seq_chirho
    );
    assert_eq!(
        fresh_readiness_chirho.journal_tail_digest_chirho.0,
        accepted_source_cut_chirho.record_digest_chirho
    );
    assert_eq!(
        fresh_readiness_chirho.genesis_digest_chirho,
        frozen_cut_chirho.journal_genesis_digest_chirho,
        "the read-only probe observes the exact accepted winner journal"
    );
    let handoff_head_path_chirho = gd7_winner_handoff_head_path_chirho(
        &transfer_store_chirho
            .identity_chirho()
            .consistency_group_digest_chirho,
        &local_node_chirho.0,
    )
    .expect("derive the fixed winner-handoff head path");
    let handoff_head_file_chirho =
        canonical_root_chirho.join(handoff_head_path_chirho.key_chirho());
    let accepted_head_bytes_chirho = std::fs::read(&handoff_head_file_chirho)
        .expect("read the exact durable Accepted head before retry");
    let retried_handoff_chirho = fresh_handoff_chirho
        .begin_chirho(
            transfer_store_chirho.identity_chirho().clone(),
            Box::new(reconciliation_checkpoint_chirho.clone()),
            transfer_checkpoint_chirho.checkpoint_ref_chirho.clone(),
            Box::new(transfer_checkpoint_chirho.checkpoint_chirho.clone()),
            bundle_root_object_digest_chirho.clone(),
            parse_canonical_gd7_winner_current_view_challenge_chirho(
                &canonical_handoff_challenge_chirho,
            )
            .expect("reparse the exact accepted challenge for retry"),
        )
        .expect("an exact post-restart Begin retry is idempotent");
    assert_eq!(retried_handoff_chirho, accepted_handoff_chirho);
    assert_eq!(
        std::fs::read(&handoff_head_file_chirho)
            .expect("read the durable Accepted head after exact retry"),
        accepted_head_bytes_chirho,
        "an exact Begin retry creates no new durable head"
    );

    let alternate_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        fresh_nodes_chirho[0].as_ref(),
        &group_chirho,
        &local_node_chirho,
        &held_node_chirho,
        transfer_store_chirho.identity_digest_chirho(),
    )
    .expect("mint one distinct valid challenge for the active-attempt refusal");
    let alternate_challenge_bytes_chirho = alternate_challenge_chirho
        .canonical_bytes_chirho()
        .expect("encode the alternate valid challenge");
    assert_ne!(
        alternate_challenge_bytes_chirho, canonical_handoff_challenge_chirho,
        "the negative request must differ from the accepted attempt"
    );
    fresh_handoff_chirho
        .begin_chirho(
            transfer_store_chirho.identity_chirho().clone(),
            Box::new(reconciliation_checkpoint_chirho.clone()),
            transfer_checkpoint_chirho.checkpoint_ref_chirho.clone(),
            Box::new(transfer_checkpoint_chirho.checkpoint_chirho.clone()),
            bundle_root_object_digest_chirho.clone(),
            parse_canonical_gd7_winner_current_view_challenge_chirho(
                &alternate_challenge_bytes_chirho,
            )
            .expect("parse the alternate valid challenge"),
        )
        .expect_err("a different challenge cannot replace the active Accepted attempt");
    assert_eq!(
        fresh_handoff_chirho
            .current_chirho()
            .expect("read Accepted after the different-attempt refusal"),
        Some(accepted_handoff_chirho.clone())
    );
    assert_eq!(
        std::fs::read(&handoff_head_file_chirho)
            .expect("read the durable Accepted head after the different-attempt refusal"),
        accepted_head_bytes_chirho,
        "a refused different attempt cannot create a new durable head"
    );
    assert_eq!(
        fresh_actor_chirho
            .append_hold_chirho("{}")
            .expect_err("the first mutation command after restart remains frozen"),
        EffectCommitJournalPortErrorChirho::UnavailableChirho {
            detail_chirho: "resident ledger mutation is frozen by an active GD7 winner handoff"
                .to_owned(),
        }
    );
    assert_eq!(
        fresh_actor_chirho
            .append_terminal_chirho("{}", "{}")
            .expect_err("the terminal mutation command after restart remains frozen"),
        EffectCommitJournalPortErrorChirho::UnavailableChirho {
            detail_chirho: "resident ledger mutation is frozen by an active GD7 winner handoff"
                .to_owned(),
        }
    );
    fresh_actor_chirho
        .active_hold_intent_refs_chirho()
        .expect("Accepted leaves the active-intent read view available");
    fresh_actor_chirho
        .receipt_by_intent_ref_chirho(&DigestChirho("f".repeat(64)))
        .expect("Accepted leaves the receipt-by-intent read view available");
    assert_eq!(
        fresh_actor_chirho
            .effect_intent_cut_chirho()
            .expect("Accepted leaves the exact journal-cut read view available"),
        frozen_cut_chirho,
        "the refused post-restart append cannot move the accepted cut"
    );
    fresh_actor_chirho
        .current_continuation_chirho(&AssetKindIdChirho(
            fixture_chirho.plan_chirho.kind_id_chirho.clone(),
        ))
        .expect("Accepted leaves the current-continuation read view available");
    fresh_actor_chirho
        .verified_effect_receipt_inventory_chirho()
        .expect("Accepted leaves the verified-receipt inventory read view available");
    assert_eq!(
        std::fs::read(&journal_path_chirho)
            .expect("read the winner journal after the refused post-restart append"),
        frozen_journal_bytes_chirho,
        "fresh-elector restoration and the refused append leave journal bytes unchanged"
    );

    drive_transfer_chirho(&fresh_nodes_chirho, 0, 2);
    assert!(
        !fresh_nodes_chirho[0]
            .current_leadership_chirho()
            .is_leader_chirho
    );
    assert!(
        fresh_winner_evidence_chirho.probe_chirho().is_err(),
        "leadership transfer disables the restricted winner facade"
    );
    assert!(
        fresh_winner_evidence_chirho
            .stage_next_view_page_chirho()
            .is_err(),
        "a deposed process cannot stage another winner page"
    );
    assert!(
        fresh_winner_evidence_chirho
            .fetch_granted_page_chirho(held_node_chirho, first_grant_chirho)
            .is_err(),
        "a deposed process cannot serve a previously valid page grant"
    );
}
