// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::refusal_mapping_chirho::map_current_compensation_refusal_chirho;
use super::*;
use cairn_serve_runtime_chirho::LedgerConservationHeadEvidenceChirho;
use cairn_serve_runtime_chirho::{
    CurrentPostgresCompensationPreviewVerdictChirho, EffectTerminalDispositionChirho,
    LedgerHostPostgresEffectRefusalChirho, PostgresReversibleActivationErrorChirho,
    ReviewedCurrentPostgresCompensationRefusalChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho,
};
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;

static FIXTURE_ID_CHIRHO: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct FakeAuthorityStateChirho {
    execute_count_chirho: u64,
    replay_count_chirho: u64,
    current_loss_phases_chirho: Vec<ResidentTestkindLossWitnessPhaseChirho>,
    deposed_loss_phases_chirho: Vec<ResidentTestkindLossWitnessPhaseChirho>,
}

struct FakeAuthorityChirho {
    preview_chirho: CurrentPostgresCompensationPreviewChirho,
    execution_chirho: TestkindCompensationExecutionEvidenceChirho,
    conservation_chirho: LedgerConservationCycleRowChirho,
    state_chirho: Mutex<FakeAuthorityStateChirho>,
}

impl TestkindCf7OperatorAuthorityChirho for FakeAuthorityChirho {
    fn preview_chirho(
        &self,
        _app_chirho: &str,
        _owner_chirho: &str,
    ) -> std::result::Result<
        CurrentPostgresCompensationPreviewChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        Ok(self.preview_chirho.clone())
    }

    fn execute_chirho(
        &self,
        _app_chirho: &str,
        _owner_chirho: &str,
        reviewed_preview_chirho: &CurrentPostgresCompensationPreviewChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        if reviewed_preview_chirho != &self.preview_chirho {
            return Err(TestkindCf7OperatorRefusalChirho::ReviewedPreviewChangedChirho);
        }
        let mut state_chirho = self.state_chirho.lock().unwrap();
        state_chirho.execute_count_chirho += 1;
        Ok(self.execution_chirho.clone())
    }

    fn replay_chirho(
        &self,
        _app_chirho: &str,
        _owner_chirho: &str,
        expected_execution_chirho: &TestkindCompensationExecutionEvidenceChirho,
    ) -> std::result::Result<
        TestkindCompensationExecutionEvidenceChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        let mut state_chirho = self.state_chirho.lock().unwrap();
        if state_chirho.execute_count_chirho != 1 {
            return Err(TestkindCf7OperatorRefusalChirho::ReplayNotCompletedChirho);
        }
        if expected_execution_chirho != &self.execution_chirho {
            return Err(TestkindCf7OperatorRefusalChirho::ReplayExecutionChangedChirho);
        }
        state_chirho.replay_count_chirho += 1;
        Ok(self.execution_chirho.clone())
    }

    fn conservation_read_chirho(
        &self,
        expected_head_chirho: &TestkindLedgerHeadBindingChirho,
    ) -> std::result::Result<LedgerConservationCycleRowChirho, TestkindCf7OperatorRefusalChirho>
    {
        if expected_head_chirho != &self.execution_chirho.post_compensation_head_chirho {
            return Err(TestkindCf7OperatorRefusalChirho::ConservationHeadMismatchChirho);
        }
        verify_cf7_conservation_row_chirho(&self.conservation_chirho, expected_head_chirho)?;
        Ok(self.conservation_chirho.clone())
    }

    fn loss_witness_current_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        self.state_chirho
            .lock()
            .unwrap()
            .current_loss_phases_chirho
            .push(phase_chirho);
        Ok(ResidentTestkindLossWitnessOutcomeChirho::CommittedChirho {
            phase_chirho,
            commit_chirho: serde_json::from_value(serde_json::json!({
                "seq_chirho": 13,
                "record_digest_chirho": "aa".repeat(32),
                "physical_ms_chirho": 1_234,
                "logical_chirho": 0,
            }))
            .unwrap(),
        })
    }

    fn loss_witness_deposed_sink_chirho(
        &self,
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        TestkindCf7OperatorRefusalChirho,
    > {
        self.state_chirho
            .lock()
            .unwrap()
            .deposed_loss_phases_chirho
            .push(phase_chirho);
        Ok(ResidentTestkindLossWitnessOutcomeChirho::DeposedSinkRefusedChirho { phase_chirho })
    }
}

fn preview_fixture_chirho() -> CurrentPostgresCompensationPreviewChirho {
    serde_json::from_value(serde_json::json!({
        "schema_chirho": "current-postgres-compensation-preview-v1-chirho",
        "app_chirho": "credits-demo-chirho",
        "source_review_report_chirho": "11".repeat(32),
        "plan_digest_chirho": "22".repeat(32),
        "original_effect_key_chirho": "33".repeat(32),
        "intent_ref_chirho": "44".repeat(32),
        "terminal_outcome_ref_chirho": "55".repeat(32),
        "verdict_chirho": { "kind_chirho": "executable-chirho" }
    }))
    .unwrap()
}

fn execution_fixture_chirho() -> TestkindCompensationExecutionEvidenceChirho {
    let execution_chirho: CurrentPostgresCompensationExecutionChirho =
        serde_json::from_value(serde_json::json!({
            "schema_chirho": "current-postgres-compensation-execution-v1-chirho",
            "app_chirho": "credits-demo-chirho",
            "original_effect_key_chirho": "33".repeat(32),
            "compensation_intent_ref_chirho": "66".repeat(32),
            "terminal_outcome_ref_chirho": "77".repeat(32),
            "disposition_chirho": {
                "kind_chirho": "committed-chirho",
                "result_ref_chirho": "88".repeat(32)
            },
            "provider_restored_chirho": true
        }))
        .unwrap();
    assert!(matches!(
        execution_chirho.disposition_chirho,
        EffectTerminalDispositionChirho::CommittedChirho { .. }
    ));
    TestkindCompensationExecutionEvidenceChirho {
        execution_chirho,
        post_compensation_head_chirho: TestkindLedgerHeadBindingChirho {
            covered_record_count_chirho: 12,
            checkpoint_digest_chirho: "99".repeat(32),
        },
    }
}

fn conservation_fixture_chirho(
    head_chirho: &TestkindLedgerHeadBindingChirho,
) -> LedgerConservationCycleRowChirho {
    LedgerConservationCycleRowChirho {
        schema_chirho: "ledger-conservation-cycle-v1-chirho".to_owned(),
        configured_cadence_ms_chirho: 5_000,
        cycle_started_at_ms_chirho: 1_000,
        cycle_finished_at_ms_chirho: 1_001,
        outcome_chirho: LedgerConservationCycleOutcomeChirho::GreenChirho {
            head_chirho: LedgerConservationHeadEvidenceChirho {
                epoch_chirho: 1,
                checkpoint_digest_chirho: head_chirho.checkpoint_digest_chirho.clone(),
                covered_record_count_chirho: head_chirho.covered_record_count_chirho,
            },
            money_group_kind_scopes_checked_chirho: 1,
            domain_kind_rollups_checked_chirho: 1,
            global_supplies_checked_chirho: 1,
            work_items_checked_chirho: 1,
        },
    }
}

fn root_fixture_chirho(label_chirho: &str) -> PathBuf {
    let id_chirho = FIXTURE_ID_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = PathBuf::from(format!(
        "/tmp/cairn-r4b-{label_chirho}-{}-{id_chirho}-chirho",
        std::process::id()
    ));
    let _cleanup_chirho = fs::remove_dir_all(&root_chirho);
    fs::create_dir(&root_chirho).unwrap();
    root_chirho
}

fn start_operator_response_fixture_chirho(
    root_chirho: &Path,
    response_chirho: Option<Vec<u8>>,
    delay_chirho: Duration,
) -> JoinHandle<()> {
    let socket_path_chirho = testkind_cf7_operator_socket_path_chirho(root_chirho);
    fs::create_dir_all(socket_path_chirho.parent().unwrap()).unwrap();
    let listener_chirho = UnixListener::bind(&socket_path_chirho).unwrap();
    std::thread::spawn(move || {
        let (mut stream_chirho, _) = listener_chirho.accept().unwrap();
        let mut request_chirho = Vec::new();
        stream_chirho.read_to_end(&mut request_chirho).unwrap();
        assert!(!request_chirho.is_empty());
        std::thread::sleep(delay_chirho);
        if let Some(response_chirho) = response_chirho {
            let _write_result_chirho = stream_chirho.write_all(&response_chirho);
        }
    })
}

fn fake_authority_chirho() -> Arc<FakeAuthorityChirho> {
    let execution_chirho = execution_fixture_chirho();
    Arc::new(FakeAuthorityChirho {
        preview_chirho: preview_fixture_chirho(),
        conservation_chirho: conservation_fixture_chirho(
            &execution_chirho.post_compensation_head_chirho,
        ),
        execution_chirho,
        state_chirho: Mutex::new(FakeAuthorityStateChirho::default()),
    })
}

#[test]
fn operator_client_failures_carry_fixed_stage_contexts_chirho() {
    assert_eq!(
        TESTKIND_CF7_OPERATOR_CLIENT_RESPONSE_TIMEOUT_CHIRHO,
        Duration::from_secs(90)
    );
    let request_chirho = TestkindCf7OperatorRequestChirho::loss_witness_current_chirho(
        ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
    );

    let invalid_root_chirho = root_fixture_chirho("client-validation");
    let mut invalid_request_chirho = request_chirho.clone();
    invalid_request_chirho.schema_chirho = "wrong-schema-chirho".to_owned();
    let validation_error_chirho = send_testkind_cf7_operator_request_with_timeout_chirho(
        &invalid_root_chirho,
        &invalid_request_chirho,
        Duration::from_millis(10),
    )
    .unwrap_err();
    assert!(format!("{validation_error_chirho:?}")
        .contains("TestkindCf7OperatorClientRequestValidationRefusedChirho"));
    fs::remove_dir_all(invalid_root_chirho).unwrap();

    let missing_root_chirho = root_fixture_chirho("client-connect");
    let connect_error_chirho = send_testkind_cf7_operator_request_with_timeout_chirho(
        &missing_root_chirho,
        &request_chirho,
        Duration::from_millis(10),
    )
    .unwrap_err();
    assert!(format!("{connect_error_chirho:?}")
        .contains("TestkindCf7OperatorClientSocketConnectRefusedChirho"));
    fs::remove_dir_all(missing_root_chirho).unwrap();

    let timeout_root_chirho = root_fixture_chirho("client-timeout");
    let timeout_thread_chirho = start_operator_response_fixture_chirho(
        &timeout_root_chirho,
        Some(b"{}\n".to_vec()),
        Duration::from_millis(50),
    );
    let timeout_error_chirho = send_testkind_cf7_operator_request_with_timeout_chirho(
        &timeout_root_chirho,
        &request_chirho,
        Duration::from_millis(10),
    )
    .unwrap_err();
    assert!(format!("{timeout_error_chirho:?}")
        .contains("TestkindCf7OperatorClientResponseReadRefusedChirho"));
    timeout_thread_chirho.join().unwrap();
    fs::remove_dir_all(timeout_root_chirho).unwrap();

    let parse_root_chirho = root_fixture_chirho("client-parse");
    let parse_thread_chirho = start_operator_response_fixture_chirho(
        &parse_root_chirho,
        Some(b"{}\n".to_vec()),
        Duration::ZERO,
    );
    let parse_error_chirho = send_testkind_cf7_operator_request_with_timeout_chirho(
        &parse_root_chirho,
        &request_chirho,
        Duration::from_millis(100),
    )
    .unwrap_err();
    assert!(format!("{parse_error_chirho:?}")
        .contains("TestkindCf7OperatorClientResponseParseRefusedChirho"));
    parse_thread_chirho.join().unwrap();
    fs::remove_dir_all(parse_root_chirho).unwrap();
}

#[test]
fn unix_custody_and_all_six_verbs_are_one_live_control_path_chirho() {
    let root_chirho = root_fixture_chirho("roundtrip");
    let authority_chirho = fake_authority_chirho();
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let thread_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        authority_chirho.clone(),
        Arc::clone(&stop_chirho),
    )
    .unwrap();
    let socket_path_chirho = testkind_cf7_operator_socket_path_chirho(&root_chirho);
    assert_eq!(
        fs::metadata(&socket_path_chirho)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(socket_path_chirho.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    let preview_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::preview_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
        ),
    )
    .unwrap();
    let TestkindCf7OperatorOutcomeChirho::PreviewChirho { preview_chirho } =
        preview_response_chirho.outcome_chirho
    else {
        panic!("preview verb must return preview evidence")
    };
    assert_eq!(
        authority_chirho
            .state_chirho
            .lock()
            .unwrap()
            .execute_count_chirho,
        0,
        "the operator Preview selector must not reach the execute authority"
    );

    let mut wrong_preview_chirho = preview_chirho.clone();
    wrong_preview_chirho.plan_digest_chirho.0 = "aa".repeat(32);
    let wrong_execute_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::execute_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
            wrong_preview_chirho,
        ),
    )
    .unwrap();
    assert_eq!(
        wrong_execute_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::RefusedChirho {
            refusal_chirho: TestkindCf7OperatorRefusalChirho::ReviewedPreviewChangedChirho
        }
    );

    let premature_replay_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::replay_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
            execution_fixture_chirho(),
        ),
    )
    .unwrap();
    assert_eq!(
        premature_replay_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::RefusedChirho {
            refusal_chirho: TestkindCf7OperatorRefusalChirho::ReplayNotCompletedChirho
        }
    );

    let execute_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::execute_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
            preview_chirho,
        ),
    )
    .unwrap();
    let TestkindCf7OperatorOutcomeChirho::ExecutedChirho { evidence_chirho } =
        execute_response_chirho.outcome_chirho
    else {
        panic!("execute verb must return exact execution evidence")
    };

    let replay_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::replay_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
            evidence_chirho.clone(),
        ),
    )
    .unwrap();
    assert_eq!(
        replay_response_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::ReplayedChirho {
            evidence_chirho: evidence_chirho.clone()
        }
    );

    let conservation_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::conservation_read_chirho(
            evidence_chirho.post_compensation_head_chirho.clone(),
        ),
    )
    .unwrap();
    assert!(matches!(
        conservation_response_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::ConservationGreenChirho { .. }
    ));

    let current_loss_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::loss_witness_current_chirho(
            ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
        ),
    )
    .unwrap();
    assert!(matches!(
        current_loss_response_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::LossWitnessChirho {
            witness_chirho: ResidentTestkindLossWitnessOutcomeChirho::CommittedChirho {
                phase_chirho: ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                ..
            }
        }
    ));

    let deposed_loss_response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::loss_witness_deposed_sink_chirho(
            ResidentTestkindLossWitnessPhaseChirho::FailbackChirho,
        ),
    )
    .unwrap();
    assert_eq!(
        deposed_loss_response_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::LossWitnessChirho {
            witness_chirho: ResidentTestkindLossWitnessOutcomeChirho::DeposedSinkRefusedChirho {
                phase_chirho: ResidentTestkindLossWitnessPhaseChirho::FailbackChirho,
            },
        }
    );
    let state_chirho = authority_chirho.state_chirho.lock().unwrap();
    assert_eq!(state_chirho.execute_count_chirho, 1);
    assert_eq!(state_chirho.replay_count_chirho, 1);
    assert_eq!(
        state_chirho.current_loss_phases_chirho,
        [ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho]
    );
    assert_eq!(
        state_chirho.deposed_loss_phases_chirho,
        [ResidentTestkindLossWitnessPhaseChirho::FailbackChirho]
    );
    drop(state_chirho);

    stop_chirho.store(true, Ordering::Release);
    thread_chirho.join().unwrap().unwrap();
    assert!(!socket_path_chirho.exists());
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn green_by_empty_and_wrong_head_refuse_by_distinct_identity_chirho() {
    let expected_head_chirho = execution_fixture_chirho().post_compensation_head_chirho;
    for counter_index_chirho in 0..4 {
        let mut empty_chirho = conservation_fixture_chirho(&expected_head_chirho);
        if let LedgerConservationCycleOutcomeChirho::GreenChirho {
            money_group_kind_scopes_checked_chirho,
            domain_kind_rollups_checked_chirho,
            global_supplies_checked_chirho,
            work_items_checked_chirho,
            ..
        } = &mut empty_chirho.outcome_chirho
        {
            match counter_index_chirho {
                0 => *money_group_kind_scopes_checked_chirho = 0,
                1 => *domain_kind_rollups_checked_chirho = 0,
                2 => *global_supplies_checked_chirho = 0,
                3 => *work_items_checked_chirho = 0,
                _ => unreachable!(),
            }
        }
        assert_eq!(
            verify_cf7_conservation_row_chirho(&empty_chirho, &expected_head_chirho),
            Err(TestkindCf7OperatorRefusalChirho::ConservationEmptyChirho),
            "every checked population must independently reject green-by-emptiness"
        );
    }

    for head_field_index_chirho in 0..2 {
        let mut wrong_head_chirho = expected_head_chirho.clone();
        match head_field_index_chirho {
            0 => wrong_head_chirho.covered_record_count_chirho += 1,
            1 => wrong_head_chirho.checkpoint_digest_chirho = "aa".repeat(32),
            _ => unreachable!(),
        }
        assert_eq!(
            verify_cf7_conservation_row_chirho(
                &conservation_fixture_chirho(&expected_head_chirho),
                &wrong_head_chirho,
            ),
            Err(TestkindCf7OperatorRefusalChirho::ConservationHeadMismatchChirho),
            "both ledger-head coordinates must bind conservation evidence"
        );
    }
}

#[test]
fn preexisting_non_socket_path_is_refused_not_deleted_chirho() {
    let root_chirho = root_fixture_chirho("preexisting");
    let socket_path_chirho = testkind_cf7_operator_socket_path_chirho(&root_chirho);
    fs::create_dir(socket_path_chirho.parent().unwrap()).unwrap();
    fs::write(&socket_path_chirho, b"do-not-delete-chirho").unwrap();
    let result_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        fake_authority_chirho(),
        Arc::new(AtomicBool::new(false)),
    );
    let refusal_chirho = result_chirho.unwrap_err().to_string();
    assert!(refusal_chirho.contains("TestkindCf7OperatorPreexistingPathRefusedChirho"));
    assert_eq!(
        fs::read(&socket_path_chirho).unwrap(),
        b"do-not-delete-chirho"
    );
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_active_operator_socket_is_refused_not_unlinked_chirho() {
    let root_chirho = root_fixture_chirho("active");
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let thread_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        fake_authority_chirho(),
        Arc::clone(&stop_chirho),
    )
    .unwrap();
    let refusal_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        fake_authority_chirho(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap_err()
    .to_string();
    assert!(refusal_chirho.contains("TestkindCf7OperatorSocketAlreadyActiveChirho"));

    let response_chirho = send_testkind_cf7_operator_request_chirho(
        &root_chirho,
        &TestkindCf7OperatorRequestChirho::preview_chirho(
            "credits-demo-chirho".to_owned(),
            "user/0123456789abcdef".to_owned(),
        ),
    )
    .unwrap();
    assert!(matches!(
        response_chirho.outcome_chirho,
        TestkindCf7OperatorOutcomeChirho::PreviewChirho { .. }
    ));

    stop_chirho.store(true, Ordering::Release);
    thread_chirho.join().unwrap().unwrap();
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn shutdown_does_not_unlink_a_replacement_socket_chirho() {
    let root_chirho = root_fixture_chirho("replacement");
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let thread_chirho = start_testkind_cf7_operator_control_with_authority_chirho(
        &root_chirho,
        fake_authority_chirho(),
        Arc::clone(&stop_chirho),
    )
    .unwrap();
    let socket_path_chirho = testkind_cf7_operator_socket_path_chirho(&root_chirho);
    let original_identity_chirho = socket_identity_chirho(&socket_path_chirho).unwrap();
    fs::remove_file(&socket_path_chirho).unwrap();
    let replacement_listener_chirho = UnixListener::bind(&socket_path_chirho).unwrap();
    let replacement_identity_chirho = socket_identity_chirho(&socket_path_chirho).unwrap();
    assert_ne!(replacement_identity_chirho, original_identity_chirho);

    stop_chirho.store(true, Ordering::Release);
    thread_chirho.join().unwrap().unwrap();
    assert_eq!(
        socket_identity_chirho(&socket_path_chirho).unwrap(),
        replacement_identity_chirho,
        "the old server must clean up only the socket inode it bound"
    );

    drop(replacement_listener_chirho);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn fixture_preview_is_explicitly_executable_chirho() {
    assert!(matches!(
        preview_fixture_chirho().verdict_chirho,
        CurrentPostgresCompensationPreviewVerdictChirho::ExecutableChirho
    ));
}

#[test]
fn reviewed_runtime_refusals_preserve_fixed_operator_identity_chirho() {
    assert_eq!(
        map_reviewed_execution_refusal_chirho(anyhow::Error::new(
            ReviewedCurrentPostgresCompensationRefusalChirho::PreviewChangedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::ReviewedPreviewChangedChirho
    );
    assert_eq!(
        map_reviewed_execution_refusal_chirho(anyhow::Error::new(
            ReviewedCurrentPostgresCompensationRefusalChirho::PreviewNotExecutableChirho,
        )),
        TestkindCf7OperatorRefusalChirho::ReviewedPreviewNotExecutableChirho
    );
    assert_eq!(
        map_reviewed_replay_refusal_chirho(anyhow::Error::new(
            ReviewedCurrentPostgresCompensationRefusalChirho::ReplayNotCompletedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::ReplayNotCompletedChirho
    );
    assert_eq!(
        map_reviewed_replay_refusal_chirho(anyhow::Error::new(
            ReviewedCurrentPostgresCompensationRefusalChirho::ReplayExecutionChangedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::ReplayExecutionChangedChirho
    );
}

fn assert_fixed_current_compensation_refusal_chirho(
    error_chirho: anyhow::Error,
    expected_chirho: TestkindCf7OperatorRefusalChirho,
    expected_wire_chirho: &str,
) {
    let planted_private_detail_chirho = "/private/operator-identity-needle-chirho";
    let error_chirho = error_chirho.context(planted_private_detail_chirho);
    assert_eq!(
        map_current_compensation_refusal_chirho(&error_chirho),
        Some(expected_chirho.clone())
    );
    let wire_chirho = serde_json::to_string(&expected_chirho).unwrap();
    assert_eq!(
        wire_chirho,
        serde_json::json!(expected_wire_chirho).to_string()
    );
    assert!(
        !wire_chirho.contains(planted_private_detail_chirho),
        "the operator wire must serialize only the fixed unit identity"
    );
}

#[test]
fn current_undo_plan_refusals_preserve_fixed_operator_identity_chirho() {
    use VerifiedCurrentUndoPlanAuthorityErrorChirho as AuthorityRefusalChirho;

    let cases_chirho = [
        (
            AuthorityRefusalChirho::CurrentAppRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationCurrentAppRefusedChirho,
            "compensation-current-app-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CurrentPromotionRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationCurrentPromotionRefusedChirho,
            "compensation-current-promotion-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CurrentPlanRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationCurrentPlanRefusedChirho,
            "compensation-current-plan-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::NoEligiblePlanEffectChirho,
            TestkindCf7OperatorRefusalChirho::CompensationNoEligiblePlanEffectChirho,
            "compensation-no-eligible-plan-effect-chirho",
        ),
        (
            AuthorityRefusalChirho::MultipleEligiblePlanEffectsChirho,
            TestkindCf7OperatorRefusalChirho::CompensationMultipleEligiblePlanEffectsChirho,
            "compensation-multiple-eligible-plan-effects-chirho",
        ),
        (
            AuthorityRefusalChirho::StaleAuthorityChirho,
            TestkindCf7OperatorRefusalChirho::CompensationStaleAuthorityChirho,
            "compensation-stale-authority-chirho",
        ),
        (
            AuthorityRefusalChirho::NoEligibleJournalEffectChirho,
            TestkindCf7OperatorRefusalChirho::CompensationNoEligibleJournalEffectChirho,
            "compensation-no-eligible-journal-effect-chirho",
        ),
        (
            AuthorityRefusalChirho::MultipleEligibleJournalEffectsChirho,
            TestkindCf7OperatorRefusalChirho::CompensationMultipleEligibleJournalEffectsChirho,
            "compensation-multiple-eligible-journal-effects-chirho",
        ),
        (
            AuthorityRefusalChirho::OriginalEffectEvidenceRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationOriginalEffectEvidenceRefusedChirho,
            "compensation-original-effect-evidence-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::ProviderPreviewRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationProviderPreviewRefusedChirho,
            "compensation-provider-preview-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CurrentPriceRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationCurrentPriceRefusedChirho,
            "compensation-current-price-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::ExistingCompensationBindingRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExistingBindingRefusedChirho,
            "compensation-existing-binding-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationAuthorizationRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationAuthorizationRefusedChirho,
            "compensation-authorization-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationPendingManualChirho,
            TestkindCf7OperatorRefusalChirho::CompensationPendingManualChirho,
            "compensation-pending-manual-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationInDoubtChirho,
            TestkindCf7OperatorRefusalChirho::CompensationInDoubtChirho,
            "compensation-in-doubt-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationTerminalRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationTerminalRefusedChirho,
            "compensation-terminal-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho,
            "compensation-execution-sink-term-no-accepted-winner-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho,
            "compensation-execution-sink-term-stale-winner-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
            "compensation-execution-sink-term-unseen-winner-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho,
            "compensation-execution-ordinary-term-inputs-unavailable-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho,
            "compensation-execution-ordinary-term-acceptance-refused-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionCommittedEvidencePendingChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionCommittedEvidencePendingChirho,
            "compensation-execution-committed-evidence-pending-chirho",
        ),
        (
            AuthorityRefusalChirho::CompensationExecutionRefusedChirho,
            TestkindCf7OperatorRefusalChirho::CompensationExecutionRefusedChirho,
            "compensation-execution-refused-chirho",
        ),
    ];

    for (error_chirho, expected_chirho, expected_wire_chirho) in cases_chirho {
        assert_fixed_current_compensation_refusal_chirho(
            anyhow::Error::new(error_chirho),
            expected_chirho,
            expected_wire_chirho,
        );
    }
}

#[test]
fn host_postgres_refusals_preserve_fixed_operator_identity_chirho() {
    use LedgerHostPostgresEffectRefusalChirho as HostRefusalChirho;

    let cases_chirho = [
        (
            HostRefusalChirho::PostgresEffectConfigUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresEffectConfigUnavailableChirho,
            "postgres-effect-config-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ConnectionSecretUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresConnectionSecretUnavailableChirho,
            "postgres-connection-secret-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ConnectionOutsideLocalPhaseBChirho,
            TestkindCf7OperatorRefusalChirho::PostgresConnectionOutsideLocalPhaseBChirho,
            "postgres-connection-outside-local-phase-b-chirho",
        ),
        (
            HostRefusalChirho::ConnectionUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresConnectionUnavailableChirho,
            "postgres-connection-unavailable-chirho",
        ),
        (
            HostRefusalChirho::DatabaseSchemaUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresDatabaseSchemaUnavailableChirho,
            "postgres-database-schema-unavailable-chirho",
        ),
        (
            HostRefusalChirho::AdapterCustodyUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresAdapterCustodyUnavailableChirho,
            "postgres-adapter-custody-unavailable-chirho",
        ),
        (
            HostRefusalChirho::BillingKindUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresBillingKindUnavailableChirho,
            "postgres-billing-kind-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ProjectionRouteUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresProjectionRouteUnavailableChirho,
            "postgres-projection-route-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ProjectionFeedUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresProjectionFeedUnavailableChirho,
            "postgres-projection-feed-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ProviderLockUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresProviderLockUnavailableChirho,
            "postgres-provider-lock-unavailable-chirho",
        ),
        (
            HostRefusalChirho::BlockingDispatchUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresBlockingDispatchUnavailableChirho,
            "postgres-blocking-dispatch-unavailable-chirho",
        ),
        (
            HostRefusalChirho::ForeignRootChirho,
            TestkindCf7OperatorRefusalChirho::PostgresForeignRootChirho,
            "postgres-foreign-root-chirho",
        ),
    ];

    for (error_chirho, expected_chirho, expected_wire_chirho) in cases_chirho {
        assert_fixed_current_compensation_refusal_chirho(
            anyhow::Error::new(error_chirho),
            expected_chirho,
            expected_wire_chirho,
        );
    }
}

#[test]
fn postgres_activation_refusals_preserve_fixed_operator_identity_chirho() {
    let cases_chirho = [
        (
            PostgresReversibleActivationErrorChirho::ContractLawRefusedChirho {
                detail_chirho: "private detail must not cross the wire".to_owned(),
            },
            TestkindCf7OperatorRefusalChirho::PostgresContractLawRefusedChirho,
            "postgres-contract-law-refused-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::CompositionUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresCompositionUnavailableChirho,
            "postgres-composition-unavailable-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::VerifiedContextUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresVerifiedContextUnavailableChirho,
            "postgres-verified-context-unavailable-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::InvocationScopeUnavailableChirho,
            TestkindCf7OperatorRefusalChirho::PostgresInvocationScopeUnavailableChirho,
            "postgres-invocation-scope-unavailable-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho {
                detail_chirho: "private detail must not cross the wire".to_owned(),
            },
            TestkindCf7OperatorRefusalChirho::PostgresBootstrapRefusedChirho,
            "postgres-bootstrap-refused-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::CustodyUnavailableChirho {
                detail_chirho: "private detail must not cross the wire".to_owned(),
            },
            TestkindCf7OperatorRefusalChirho::PostgresCustodyUnavailableChirho,
            "postgres-custody-unavailable-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho {
                detail_chirho: "private detail must not cross the wire".to_owned(),
            },
            TestkindCf7OperatorRefusalChirho::PostgresMoneyPolicyRefusedChirho,
            "postgres-money-policy-refused-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::InvocationObligationConflictChirho,
            TestkindCf7OperatorRefusalChirho::PostgresInvocationObligationConflictChirho,
            "postgres-invocation-obligation-conflict-chirho",
        ),
        (
            PostgresReversibleActivationErrorChirho::InDoubtChirho {
                intent_ref_chirho: preview_fixture_chirho().intent_ref_chirho,
                hold_seq_chirho: 17,
            },
            TestkindCf7OperatorRefusalChirho::PostgresProviderOutcomeInDoubtChirho,
            "postgres-provider-outcome-in-doubt-chirho",
        ),
    ];

    for (error_chirho, expected_chirho, expected_wire_chirho) in cases_chirho {
        assert_fixed_current_compensation_refusal_chirho(
            anyhow::Error::new(error_chirho),
            expected_chirho,
            expected_wire_chirho,
        );
    }
}

#[test]
fn typed_refusals_cross_every_operator_verb_without_anyhow_text_chirho() {
    assert_eq!(
        map_preview_refusal_chirho(anyhow::Error::new(
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::CompensationCurrentPriceRefusedChirho
    );
    assert_eq!(
        map_reviewed_execution_refusal_chirho(anyhow::Error::new(
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::CompensationCurrentPriceRefusedChirho
    );
    assert_eq!(
        map_reviewed_replay_refusal_chirho(anyhow::Error::new(
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho,
        )),
        TestkindCf7OperatorRefusalChirho::CompensationCurrentPriceRefusedChirho
    );

    assert_eq!(
        map_preview_refusal_chirho(anyhow::anyhow!("private opaque preview detail")),
        TestkindCf7OperatorRefusalChirho::PreviewRefusedChirho
    );
    assert_eq!(
        map_reviewed_execution_refusal_chirho(anyhow::anyhow!("private opaque execute detail")),
        TestkindCf7OperatorRefusalChirho::ExecutionRefusedChirho
    );
    assert_eq!(
        map_reviewed_replay_refusal_chirho(anyhow::anyhow!("private opaque replay detail")),
        TestkindCf7OperatorRefusalChirho::ReplayRefusedChirho
    );
}

#[test]
fn an_authority_that_does_not_implement_activation_refuses_it_chirho() {
    // THE FAIL-CLOSED DEFAULT, measured rather than asserted in a doc comment. `FakeAuthorityChirho`
    // implements this trait and deliberately does NOT implement `migration_activate_target_chirho`,
    // so it inherits the default — which must REFUSE. That is the property that makes adding an
    // operation to this socket safe: an authority cannot be made to activate a tenant-root migration
    // by someone extending the wire.
    //
    // If this ever returns an outcome, the default stopped refusing and every non-implementing
    // adapter silently gained a money/authority capability.
    let authority_chirho = fake_authority_chirho();
    let request_chirho = TestkindCf7OperatorRequestChirho::migration_activate_target_chirho(
        "/an/absolute/target/root-chirho".to_owned(),
    );
    let mut bytes_chirho = serde_json::to_vec(&request_chirho).expect("encode");
    bytes_chirho.push(b'\n');

    let response_chirho = dispatch_wire_request_chirho(&bytes_chirho, authority_chirho.as_ref());
    match response_chirho.outcome_chirho {
        TestkindCf7OperatorOutcomeChirho::RefusedChirho { refusal_chirho } => {
            assert_eq!(
                refusal_chirho,
                TestkindCf7OperatorRefusalChirho::MigrationActivationRefusedChirho {
                    reason_chirho: "migration-activation-not-implemented-chirho".to_owned(),
                }
            );
        }
        other_chirho => panic!("a non-implementing authority must refuse, got {other_chirho:?}"),
    }
}

#[test]
fn a_malformed_target_root_path_refuses_before_reaching_the_authority_chirho() {
    // Shape hygiene runs at VALIDATION, before dispatch, so a malformed path never reaches an
    // authority at all. Relative and empty are both rejected; the identity is the token refusal the
    // other operand checks already use, so an operator sees one consistent answer for bad input.
    //
    // This is NOT the authorization — that is the verified-root open plus the namespace containment
    // check downstream. It only keeps obviously malformed input off an authority surface.
    let authority_chirho = fake_authority_chirho();
    for bad_chirho in ["", "relative/root-chirho", "\0/leading-nul-chirho"] {
        let request_chirho = TestkindCf7OperatorRequestChirho::migration_activate_target_chirho(
            bad_chirho.to_owned(),
        );
        let mut bytes_chirho = serde_json::to_vec(&request_chirho).expect("encode");
        bytes_chirho.push(b'\n');
        let response_chirho =
            dispatch_wire_request_chirho(&bytes_chirho, authority_chirho.as_ref());
        match response_chirho.outcome_chirho {
            TestkindCf7OperatorOutcomeChirho::RefusedChirho { refusal_chirho } => assert_eq!(
                refusal_chirho,
                TestkindCf7OperatorRefusalChirho::InvalidTokenChirho,
                "{bad_chirho:?} must refuse as an invalid token"
            ),
            other_chirho => panic!("{bad_chirho:?} must refuse, got {other_chirho:?}"),
        }
    }
}

#[path = "slow_client_tests_chirho.rs"]
mod slow_client_tests_chirho;
