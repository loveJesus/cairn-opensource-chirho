// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_log_chirho::append_mirror_chirho::{
    LedgerAppendMirrorCandidateChirho, LedgerAppendMirrorPortChirho,
    LedgerAppendMirrorPortErrorChirho, LedgerAppendMirrorTailChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
    LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
    LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
    LedgerMirrorOrdinaryTermAcceptanceReceiptChirho,
    LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho, LedgerMirrorPrefixSourceChirho,
    LedgerMirrorRecoveryCandidateChirho, LedgerMirrorRecoveryPortChirho,
    LedgerMirrorRecoveryPortErrorChirho, LedgerMirrorRuntimePortsChirho,
    RawCanonicalGroupIdDigestChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Default)]
struct RecordingAppendMirrorChirho {
    finalized_chirho: Mutex<Option<LedgerAppendMirrorCandidateChirho>>,
}

impl LedgerAppendMirrorPortChirho for RecordingAppendMirrorChirho {
    fn require_no_unreconciled_pending_append_chirho(
        &self,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn reconcile_before_append_chirho(
        &self,
        _local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn prepare_append_chirho(
        &self,
        _candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn finalize_append_chirho(
        &self,
        committed_candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        *self
            .finalized_chirho
            .lock()
            .map_err(|_| LedgerAppendMirrorPortErrorChirho::new_chirho("poisoned"))? =
            Some(committed_candidate_chirho.clone());
        Ok(())
    }
}

struct SignedHolderPairSourceChirho {
    append_mirror_chirho: Arc<RecordingAppendMirrorChirho>,
    leader_node_id_chirho: String,
    holder_node_ids_chirho: [String; 2],
    holder_roots_chirho: [PathBuf; 2],
    consistency_group_digest_chirho: String,
    term_chirho: u64,
    calls_chirho: AtomicUsize,
}

impl LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho for SignedHolderPairSourceChirho {
    fn read_ordinary_term_acceptance_receipts_chirho(
        &self,
        challenge_chirho: &LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<[Vec<u8>; 2], LedgerMirrorRecoveryPortErrorChirho> {
        self.calls_chirho.fetch_add(1, Ordering::SeqCst);
        let finalized_chirho = self
            .append_mirror_chirho
            .finalized_chirho
            .lock()
            .map_err(|_| LedgerMirrorRecoveryPortErrorChirho::new_chirho("poisoned"))?
            .clone()
            .ok_or_else(|| {
                LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                    "OrdinaryTermTestFinalizedTailUnavailableChirho",
                )
            })?;
        if finalized_chirho.record_seq_chirho() != local_tail_chirho.tail_seq_chirho()
            || finalized_chirho.record_digest_chirho()
                != local_tail_chirho.tail_record_digest_chirho()
            || finalized_chirho.record_epoch_chirho()
                != local_tail_chirho.tail_record_epoch_chirho()
            || finalized_chirho.record_hlc_chirho() != local_tail_chirho.tail_hlc_chirho()
            || finalized_chirho.cluster_id_chirho() != local_tail_chirho.cluster_id_chirho()
            || finalized_chirho.journal_genesis_digest_chirho()
                != local_tail_chirho.journal_genesis_digest_chirho()
        {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "OrdinaryTermTestTailNotFinalizedChirho",
            ));
        }
        let assignment_digest_chirho = "a".repeat(64);
        let membership_view_digest_chirho = "b".repeat(64);
        let assigned_node_ids_chirho = [
            self.leader_node_id_chirho.clone(),
            self.holder_node_ids_chirho[0].clone(),
            self.holder_node_ids_chirho[1].clone(),
        ];
        let sign_holder_chirho = |index_chirho: usize| {
            LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::sign_chirho(
                LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho {
                    challenge_nonce_hex_chirho: challenge_chirho.as_str_chirho().to_owned(),
                    current_consistency_group_digest_chirho: self
                        .consistency_group_digest_chirho
                        .clone(),
                    current_assignment_digest_chirho: assignment_digest_chirho.clone(),
                    current_assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                    current_leader_node_id_chirho: self.leader_node_id_chirho.clone(),
                    current_membership_view_digest_chirho: membership_view_digest_chirho.clone(),
                    current_term_chirho: self.term_chirho,
                    acknowledged_consistency_group_digest_chirho: self
                        .consistency_group_digest_chirho
                        .clone(),
                    acknowledged_assignment_digest_chirho: assignment_digest_chirho.clone(),
                    acknowledged_assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
                    acknowledged_leader_node_id_chirho: self.leader_node_id_chirho.clone(),
                    acknowledged_membership_view_digest_chirho: membership_view_digest_chirho
                        .clone(),
                    acknowledged_term_chirho: self.term_chirho,
                    holder_node_id_chirho: self.holder_node_ids_chirho[index_chirho].clone(),
                    cluster_id_chirho: local_tail_chirho.cluster_id_chirho().0.clone(),
                    journal_genesis_digest_chirho: local_tail_chirho
                        .journal_genesis_digest_chirho()
                        .0
                        .clone(),
                    tail_seq_chirho: local_tail_chirho.tail_seq_chirho(),
                    tail_record_digest_chirho: local_tail_chirho
                        .tail_record_digest_chirho()
                        .0
                        .clone(),
                    tail_epoch_chirho: local_tail_chirho.tail_record_epoch_chirho(),
                    tail_hlc_physical_ms_chirho: local_tail_chirho
                        .tail_hlc_chirho()
                        .physical_ms_chirho,
                    tail_hlc_logical_chirho: local_tail_chirho.tail_hlc_chirho().logical_chirho,
                },
                &self.holder_roots_chirho[index_chirho],
            )?
            .to_wire_bytes_chirho()
        };
        Ok([sign_holder_chirho(0)?, sign_holder_chirho(1)?])
    }
}

struct NoRecoveryCandidatePortChirho;

impl LedgerMirrorRecoveryPortChirho for NoRecoveryCandidatePortChirho {
    fn select_recovery_candidate_chirho(
        &self,
        _local_tail_chirho: &LedgerAppendMirrorTailChirho,
        _local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<Option<LedgerMirrorRecoveryCandidateChirho>, LedgerMirrorRecoveryPortErrorChirho>
    {
        Ok(None)
    }

    fn revalidate_recovery_authority_chirho(
        &self,
        _candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
            "NoRecoveryCandidateChirho",
        ))
    }

    fn read_recovery_record_chirho(
        &self,
        _candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        _seq_chirho: u64,
        _record_digest_chirho: &str,
    ) -> Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
            "NoRecoveryCandidateChirho",
        ))
    }

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        _source_tail_chirho: &LedgerAppendMirrorTailChirho,
        _source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        Ok(())
    }
}

#[test]
fn ordinary_election_two_holder_acceptance_advances_sink_before_compensation_chirho() {
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
    let node_chirho =
        NodeIdChirho(existing_keypair_pubkey_hex_chirho(&fixture_chirho.root_chirho).unwrap());
    let group_chirho = consistency_group_for_root_chirho(&fixture_chirho.root_chirho).unwrap();
    let shared_elector_chirho = Arc::new(
        RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
            fixture_chirho
                .root_chirho
                .join(&ledger_config_chirho.monitor_evidence_namespace_chirho)
                .join("writer-election-chirho"),
            node_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap()
        .with_message_authentication_chirho(fixture_chirho.root_chirho.clone())
        .with_leadership_warmup_lease_chirho(),
    );
    let _campaign_chirho = shared_elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        let _messages_chirho = shared_elector_chirho.tick_chirho();
    }
    let published_term_chirho = shared_elector_chirho
        .current_election_observation_chirho()
        .unwrap()
        .leadership_chirho()
        .term_chirho;
    assert_eq!(
        published_term_chirho, 2,
        "the arm reproduces H3 term 1 -> E-A term 2"
    );

    let first_holder_root_chirho = fixture_chirho
        .root_chirho
        .join("ordinary-term-first-holder-chirho");
    let second_holder_root_chirho = fixture_chirho
        .root_chirho
        .join("ordinary-term-second-holder-chirho");
    let holder_node_ids_chirho = [
        cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&first_holder_root_chirho).unwrap(),
        cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&second_holder_root_chirho).unwrap(),
    ];
    let placement_binding_chirho =
        LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho::new_chirho(
            "a".repeat(64),
            [
                node_chirho.0.clone(),
                holder_node_ids_chirho[0].clone(),
                holder_node_ids_chirho[1].clone(),
            ],
        )
        .unwrap();
    let raw_group_digest_chirho = RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
        &group_chirho.canonical_id_chirho(),
    );
    let append_mirror_chirho = Arc::new(RecordingAppendMirrorChirho::default());
    let ordinary_source_chirho = Arc::new(SignedHolderPairSourceChirho {
        append_mirror_chirho: Arc::clone(&append_mirror_chirho),
        leader_node_id_chirho: node_chirho.0.clone(),
        holder_node_ids_chirho,
        holder_roots_chirho: [first_holder_root_chirho, second_holder_root_chirho],
        consistency_group_digest_chirho: raw_group_digest_chirho.as_str_chirho().to_owned(),
        term_chirho: published_term_chirho,
        calls_chirho: AtomicUsize::new(0),
    });
    let mirror_runtime_chirho = LedgerMirrorRuntimePortsChirho::new_chirho(
        append_mirror_chirho,
        Arc::new(NoRecoveryCandidatePortChirho),
        ordinary_source_chirho.clone(),
        placement_binding_chirho,
    );
    let mut actor_chirho = open_resident_effect_journal_handle_with_shared_elector_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &ledger_config_chirho,
        &shared_elector_chirho,
        Some(mirror_runtime_chirho),
        None,
    )
    .expect("the term-2 Bound resident opens with its mirror runtime");

    let kind_id_chirho = AssetKindIdChirho(fixture_chirho.plan_chirho.kind_id_chirho.clone());
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
            journal_cut_chirho: initial_cut_chirho,
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
                kind_id_chirho,
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
    let intent_line_chirho = canonical_effect_intent_line_chirho(&intent_chirho).unwrap();
    let first_receipt_chirho = actor_chirho
        .append_hold_chirho(&intent_line_chirho)
        .unwrap();
    assert_eq!(
        ordinary_source_chirho.calls_chirho.load(Ordering::SeqCst),
        0
    );

    let original_effect_key_chirho = effect_intent_key_chirho(&intent_chirho).unwrap();
    let mut compensation_intent_chirho = intent_chirho.clone();
    compensation_intent_chirho.journal_cut_chirho =
        actor_chirho.effect_intent_cut_chirho().unwrap();
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
    .unwrap();
    let compensation_line_chirho =
        canonical_effect_intent_line_chirho(&compensation_intent_chirho).unwrap();
    let compensation_authorization_chirho = match authorize_effect_compensation_chirho(
        &compensation_line_chirho,
        signers_chirho.effect_intent_signer_chirho(),
        &ExactOriginalCompensationViewChirho {
            original_effect_key_chirho,
        },
    )
    .unwrap()
    {
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(authorization_chirho) => {
            authorization_chirho
        }
        other_chirho => panic!("compensation must authorize: {other_chirho:?}"),
    };
    let compensation_receipt_chirho = actor_chirho
        .append_compensation_hold_chirho(
            &compensation_line_chirho,
            &compensation_authorization_chirho,
        )
        .expect("the fresh exact two-holder proof advances the term-1 cell before compensation");
    assert_eq!(
        compensation_receipt_chirho.seq_chirho,
        first_receipt_chirho.seq_chirho + 1
    );
    assert_eq!(
        ordinary_source_chirho.calls_chirho.load(Ordering::SeqCst),
        1
    );

    let replay_receipt_chirho = actor_chirho
        .append_compensation_hold_chirho(
            &compensation_line_chirho,
            &compensation_authorization_chirho,
        )
        .expect("equal-term replay needs no second evidence read");
    assert_eq!(replay_receipt_chirho, compensation_receipt_chirho);
    assert_eq!(
        ordinary_source_chirho.calls_chirho.load(Ordering::SeqCst),
        1,
        "an already-current sink cell must not consult the receipt source"
    );
}
