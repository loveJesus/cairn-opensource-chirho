// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_mirror_chirho::{MirrorReceiptStageChirho, MirrorRefusalIdentityChirho};
use std::sync::Mutex;

struct PrepareFinalizeHttpFixtureChirho {
    _placement_fixture_chirho: PlacementFixtureChirho,
    _journal_root_chirho: tempfile::TempDir,
    _follower_store_root_chirho: tempfile::TempDir,
    follower_store_chirho: Arc<LedgerMirrorFollowerStoreChirho>,
    server_state_chirho: LedgerMirrorServerStateChirho,
    _server_chirho: RunningMirrorServerChirho,
    holder_chirho: HttpMirrorHolderChirho,
    refusal_lines_chirho: Arc<Mutex<Vec<String>>>,
    prepare_chirho: PrepareMirrorClosureFrameV1Chirho,
    record_chirho: LedgerMirrorRecordChirho,
}

fn start_prepare_finalize_fixture_chirho(
    receipt_refusal_stage_chirho: Option<MirrorReceiptStageChirho>,
    leader_lease_remaining_millis_chirho: Option<u64>,
) -> PrepareFinalizeHttpFixtureChirho {
    let placement_fixture_chirho = placement_fixture_chirho();
    let journal_root_chirho = tempfile::tempdir().expect("journal signer root");
    provision_node_chirho(journal_root_chirho.path());
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let follower_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let election_view_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        election_view_chirho.as_ref(),
    )
    .expect("join follower mirror view");
    let follower_store_root_chirho = tempfile::tempdir().expect("follower store root");
    let follower_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            follower_store_root_chirho.path(),
            follower_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_root_chirho.path()),
        )
        .expect("open follower store"),
    );
    let residency_chirho = MirrorResidencyPolicyChirho::allowed_domains_chirho(
        placement_fixture_chirho
            .placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    );
    let mut server_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        follower_chirho.node_id_chirho.clone(),
        follower_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        election_view_chirho,
        residency_chirho,
        Arc::clone(&follower_store_chirho),
    )
    .expect("compose follower server state");
    if let Some(stage_chirho) = receipt_refusal_stage_chirho {
        server_state_chirho = server_state_chirho.with_receipt_refusal_stage_chirho(stage_chirho);
    }
    let server_chirho = RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(
        server_state_chirho.clone(),
    ));
    let refusal_lines_chirho = Arc::new(Mutex::new(Vec::new()));
    let holder_chirho = HttpMirrorHolderChirho::new_chirho(
        follower_chirho.node_id_chirho.clone(),
        server_chirho.endpoint_chirho.clone(),
    )
    .with_refusal_log_capture_chirho(Arc::clone(&refusal_lines_chirho));
    let record_chirho = signed_record_chirho(journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
    let prepare_chirho = prepare_frame_with_lease_chirho(PrepareFrameFixtureInputChirho {
        leader_root_chirho: leader_chirho.root_chirho(),
        leader_node_id_chirho: &leader_chirho.node_id_chirho,
        target_node_id_chirho: &follower_chirho.node_id_chirho,
        term_chirho: TERM_CHIRHO,
        group_digest_chirho: joined_chirho
            .view_chirho()
            .consistency_group_digest_chirho(),
        view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
        record_chirho: record_chirho.clone(),
        leader_lease_remaining_millis_chirho,
    });

    PrepareFinalizeHttpFixtureChirho {
        _placement_fixture_chirho: placement_fixture_chirho,
        _journal_root_chirho: journal_root_chirho,
        _follower_store_root_chirho: follower_store_root_chirho,
        follower_store_chirho,
        server_state_chirho,
        _server_chirho: server_chirho,
        holder_chirho,
        refusal_lines_chirho,
        prepare_chirho,
        record_chirho,
    }
}

fn finalize_for_fixture_chirho(
    fixture_chirho: &PrepareFinalizeHttpFixtureChirho,
) -> cairn_mirror_chirho::FinalizeMirrorReceiptFrameV1Chirho {
    finalize_frame_chirho(
        fixture_chirho
            ._placement_fixture_chirho
            .serving_nodes_chirho[0]
            .root_chirho(),
        &fixture_chirho.prepare_chirho,
        fixture_chirho.record_chirho.record_digest_chirho.clone(),
    )
}

#[test]
fn exact_holder_authority_refusal_survives_real_http_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(None, None);
    let refusal_chirho = fixture_chirho
        .holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect_err("an absent signed lease must refuse before durable prepare");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorOutcomeAmbiguousChirho
    );
    assert!(fixture_chirho
        .follower_store_chirho
        .load_prepared_chirho()
        .expect("read prepared slot")
        .is_none());
}

#[test]
fn unknown_or_suffixed_holder_body_remains_ambiguous_and_leader_logged_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(None, Some(10_000));
    let router_chirho = axum::Router::new().route(
        LEDGER_MIRROR_PREPARE_PATH_CHIRHO,
        axum::routing::post(|| async {
            (
                axum::http::StatusCode::CONFLICT,
                "MirrorLeaseExpiredChirhoX",
            )
        }),
    );
    let server_chirho = RunningMirrorServerChirho::start_chirho(router_chirho);
    let refusal_lines_chirho = Arc::new(Mutex::new(Vec::new()));
    let holder_chirho = HttpMirrorHolderChirho::new_chirho(
        fixture_chirho
            .prepare_chirho
            .target_node_id_chirho()
            .to_string(),
        server_chirho.endpoint_chirho.clone(),
    )
    .with_refusal_log_capture_chirho(Arc::clone(&refusal_lines_chirho));
    let refusal_chirho = holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect_err("an unknown response body must never become a typed contract refusal");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorOutcomeAmbiguousChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho
    );
    assert_eq!(
        *refusal_lines_chirho
            .lock()
            .expect("read captured leader mirror refusal"),
        // The target node id is asserted from the fixture rather than spelled, so this arm pins that
        // the line names WHICH holder refused and cannot pass on a hardcoded string.
        vec![format!(
            "LedgerMirrorLeaderPrepareRefusalChirho:MirrorOutcomeAmbiguousChirho:target={}",
            fixture_chirho.prepare_chirho.target_node_id_chirho()
        )]
    );
}

#[test]
fn durable_prepare_without_receipt_is_named_positionally_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(
        Some(MirrorReceiptStageChirho::PreparedChirho),
        Some(10_000),
    );
    let refusal_chirho = fixture_chirho
        .holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect_err("the test fixture refuses only the post-store prepared receipt");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPrepareReceiptEvidencePendingChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPrepareStoreOutcomeAmbiguousChirho
    );
    assert!(fixture_chirho
        .follower_store_chirho
        .load_prepared_chirho()
        .expect("read durable prepared slot")
        .is_some());
}

#[test]
fn durable_finalize_without_receipt_is_named_committed_evidence_pending_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(
        Some(MirrorReceiptStageChirho::FinalizedChirho),
        Some(10_000),
    );
    fixture_chirho
        .holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect("prepare remains green before the forced finalized receipt refusal");
    let finalize_chirho = finalize_for_fixture_chirho(&fixture_chirho);
    let refusal_chirho = fixture_chirho
        .holder_chirho
        .finalize_chirho(&finalize_chirho)
        .expect_err("the test fixture refuses only the post-commit finalized receipt");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorFinalizeStoreOutcomeAmbiguousChirho
    );
    assert!(fixture_chirho
        .follower_store_chirho
        .load_prepared_chirho()
        .expect("read cleared prepared slot")
        .is_none());
    assert!(fixture_chirho
        .follower_store_chirho
        .load_high_water_chirho()
        .expect("read committed high-water")
        .is_some());
    assert_eq!(
        *fixture_chirho
            .refusal_lines_chirho
            .lock()
            .expect("read captured finalize refusal"),
        vec![
            format!(
                "LedgerMirrorLeaderFinalizeRefusalChirho:MirrorFinalizeCommittedEvidencePendingChirho:target={}",
                fixture_chirho._placement_fixture_chirho.serving_nodes_chirho[1].node_id_chirho
            )
                .to_string()
        ]
    );
}

#[test]
fn committed_finalize_refusal_marks_execution_as_may_have_happened_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(
        Some(MirrorReceiptStageChirho::FinalizedChirho),
        Some(10_000),
    );
    fixture_chirho
        .holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect("prepare remains green before the direct finalized receipt refusal");
    let finalize_chirho = finalize_for_fixture_chirho(&fixture_chirho);
    let refusal_chirho = finalize_result_for_test_chirho(
        &fixture_chirho.server_state_chirho,
        &finalize_chirho
            .to_wire_bytes_chirho()
            .expect("encode direct finalize request"),
    )
    .expect_err("the direct server result must preserve post-commit execution knowledge");
    let pre_store_knowledge_chirho = MirrorContractErrorChirho::new_chirho(
        MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho,
        "pre-store comparison",
    )
    .execution_knowledge_chirho();
    let post_store_knowledge_chirho = MirrorContractErrorChirho::new_chirho(
        MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho,
        "post-store comparison",
    )
    .after_prepare_may_be_durable_chirho()
    .execution_knowledge_chirho();
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorFinalizeCommittedEvidencePendingChirho
    );
    assert_eq!(
        refusal_chirho.execution_knowledge_chirho(),
        post_store_knowledge_chirho,
        "a committed high-water with missing receipt evidence must never report definitely-not-executed"
    );
    assert_ne!(
        refusal_chirho.execution_knowledge_chirho(),
        pre_store_knowledge_chirho
    );
    assert!(fixture_chirho
        .follower_store_chirho
        .load_high_water_chirho()
        .expect("read committed high-water")
        .is_some());
}

#[test]
fn absent_prepared_slot_is_distinct_from_unreadable_state_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(None, Some(10_000));
    let finalize_chirho = finalize_for_fixture_chirho(&fixture_chirho);
    let refusal_chirho = fixture_chirho
        .holder_chirho
        .finalize_chirho(&finalize_chirho)
        .expect_err("a fresh holder has neither a prepared slot nor a finalized high-water");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPreparedSlotUnavailableChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPreparedSlotUnreadableChirho
    );
}

#[test]
fn unreadable_prepared_slot_never_falls_through_as_absent_chirho() {
    let fixture_chirho = start_prepare_finalize_fixture_chirho(None, Some(10_000));
    fixture_chirho
        .holder_chirho
        .prepare_durably_chirho(&fixture_chirho.prepare_chirho)
        .expect("prepare a durable slot before corrupting its stored bytes");
    std::fs::write(
        fixture_chirho
            ._follower_store_root_chirho
            .path()
            .join("follower-f1-chirho/prepared-chirho.json"),
        b"{not-json-chirho",
    )
    .expect("plant unreadable prepared state");
    let finalize_chirho = finalize_for_fixture_chirho(&fixture_chirho);
    let refusal_chirho = fixture_chirho
        .holder_chirho
        .finalize_chirho(&finalize_chirho)
        .expect_err("unreadable state must refuse before any absent-slot replay");
    assert_eq!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPreparedSlotUnreadableChirho
    );
    assert_ne!(
        refusal_chirho.identity_chirho(),
        MirrorRefusalIdentityChirho::MirrorPreparedSlotUnavailableChirho
    );
}

// COVERAGE LIMIT, MEASURED RATHER THAN ASSUMED. These two arms pin the CLASSIFIER. They do NOT
// cover the server's `map_err` wiring in `prepare_chirho`'s caller: reverting that call site to its
// original catch-all leaves this suite green at its full count. So a regression that reintroduced
// the collapse would not be caught here, and this green must not be read as covering it.
// Closing it needs an HTTP-level arm driving a real continuity refusal through
// `prepare_durably_chirho`, which requires a record whose predecessor does not match the follower
// store; the fixture builds its record internally, so that is its own brick.
// If you add that arm, delete this note rather than leaving both.
#[test]
fn pre_durable_prepare_refusals_resolve_to_their_own_definitely_not_executed_identity_chirho() {
    // Each holder-store refusal raised before the prepared slot is written must reach the leader as
    // ITS OWN identity, and must keep the definitely-not-executed default. Before this, a single
    // catch-all reported all of them as in-doubt and erased the reason, so ~14 distinct causes
    // arrived as one token and a hosted window could not say which had fired.
    let expected_chirho = [
        (
            crate::store_chirho::FOLLOWER_CONTINUITY_REFUSED_CHIRHO,
            MirrorRefusalIdentityChirho::MirrorPrepareFollowerContinuityRefusedChirho,
        ),
        (
            crate::store_chirho::FOLLOWER_HIGH_WATER_MISSING_CHIRHO,
            MirrorRefusalIdentityChirho::MirrorPrepareFollowerHighWaterMissingChirho,
        ),
        (
            crate::store_chirho::FOLLOWER_GENESIS_CONTINUITY_REFUSED_CHIRHO,
            MirrorRefusalIdentityChirho::MirrorPrepareFollowerGenesisContinuityRefusedChirho,
        ),
        (
            crate::store_chirho::FINALIZED_PREPARE_REPLAY_BINDING_REFUSED_CHIRHO,
            MirrorRefusalIdentityChirho::MirrorPrepareFinalizedReplayBindingRefusedChirho,
        ),
    ];
    for (text_chirho, identity_chirho) in expected_chirho {
        let resolved_chirho = crate::store_chirho::prepare_pre_durable_identity_chirho(
            &anyhow::anyhow!("{}", text_chirho),
        );
        assert_eq!(
            resolved_chirho,
            Some(identity_chirho),
            "{text_chirho} must resolve to its own pre-durable identity"
        );
        // Compared against REFERENCE VALUES rather than a named enum: this crate does not depend on
        // the relay crate, and the two references make the claim sharper anyway -- the pre-durable
        // identity must match a plain refusal and must NOT match a may-be-durable one.
        let plain_chirho =
            cairn_mirror_chirho::MirrorContractErrorChirho::new_chirho(identity_chirho, "detail");
        let may_be_durable_chirho = cairn_mirror_chirho::MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorPrepareStoreOutcomeAmbiguousChirho,
            "detail",
        )
        .after_prepare_may_be_durable_chirho();
        assert_ne!(
            plain_chirho.execution_knowledge_chirho(),
            may_be_durable_chirho.execution_knowledge_chirho(),
            "{text_chirho} refuses before any durable write, so a retry must not treat it as in-doubt"
        );
    }
    // The population is derived from the shipped table rather than from this list, so a future
    // pre-durable refusal that nobody added here cannot pass by being forgotten.
    assert_eq!(
        crate::store_chirho::PREPARE_PRE_DURABLE_REFUSALS_CHIRHO.len(),
        expected_chirho.len(),
        "every shipped pre-durable refusal must be covered by this arm"
    );
}

#[test]
fn unclassified_prepare_store_error_stays_conservatively_in_doubt_chirho() {
    // THE SAFETY EDGE. Resolution must fail CLOSED: anything not proven pre-durable keeps the
    // ambiguous, may-have-executed report. A poisoned lock is the case that makes this necessary --
    // a previous holder may have panicked mid-write, so absence of a write cannot be proven -- and
    // it is deliberately absent from the pre-durable table even though it is raised in the same
    // function, above the same durable write.
    for text_chirho in [
        "LedgerMirrorFollowerStorePoisonedChirho",
        "some unrecognized io failure",
        "",
        // A near-miss on a real identity must not be accepted by a prefix or substring match.
        "LedgerMirrorFollowerContinuityRefusedChirhoX",
        "XLedgerMirrorFollowerContinuityRefusedChirho",
    ] {
        assert_eq!(
            crate::store_chirho::prepare_pre_durable_identity_chirho(&anyhow::anyhow!(
                "{}",
                text_chirho
            )),
            None,
            "{text_chirho:?} is not proven pre-durable and must keep the in-doubt report"
        );
    }
}
