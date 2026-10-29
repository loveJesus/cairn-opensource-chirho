// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::dag_chirho::refusal_chirho::{
    dag_execution_refusal_observation_chirho, DagExecutionAttemptOrdinalChirho,
    DagExecutionRefusalIdentityChirho,
};
use crate::model_chirho::{CapabilityChirho, EdgeChirho, NodeDefChirho, PortChirho};
use crate::provider_test_support_chirho::{
    current_effect_contract_set_chirho, llm_request_bytes_chirho,
};
use cairn_ledger_composition_chirho::{
    ComposedProjectionReadChirho, FollowerReadRefusalChirho, FollowerServeOutcomeChirho,
    ProjectionCostClassChirho, ProjectionReadOutcomeChirho, ProjectionWatermarkChirho,
    PublishedProjectionViewChirho,
};
use cairn_ledger_model_chirho::{ids_chirho::DigestChirho, record_chirho::HlcChirho};
use cairn_ledger_read_model_chirho::{
    VerifiedProjectionReadCutChirho, VerifiedProjectionSourceHeadChirho,
};
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use crate::effect_chirho::projection_read_chirho::{
    PublishedProjectionClassifierRefusalChirho, PublishedProjectionReadPortChirho,
    PublishedProjectionReadRequestChirho, PublishedProjectionReadResponseChirho,
    PublishedProjectionVerdictChirho,
};

/// The plaintext a sealed write landed under `key_chirho`. The F4 write door rests only a
/// `SealedStoreValueChirho` envelope, so an arm asking "did the write land these bytes?" unseals
/// the row rather than reading it raw.
fn sealed_row_plaintext_chirho(
    root_chirho: &Path,
    store_chirho: &crate::versioned_chirho::VersionedStoreChirho,
    key_chirho: &str,
) -> Vec<u8> {
    crate::store_seal_chirho::test_store_row_plaintext_chirho(root_chirho, store_chirho, key_chirho)
        .unwrap()
        .unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProjectionReadCallChirho {
    projection_name_chirho: String,
    requested_limit_chirho: u64,
    app_chirho: String,
    user_principal_chirho: String,
}

struct SequencedProjectionReadPortChirho {
    outcomes_chirho: Mutex<VecDeque<ComposedProjectionReadChirho>>,
    calls_chirho: Mutex<Vec<ProjectionReadCallChirho>>,
}

impl SequencedProjectionReadPortChirho {
    fn new_chirho(outcomes_chirho: Vec<ComposedProjectionReadChirho>) -> Self {
        Self {
            outcomes_chirho: Mutex::new(outcomes_chirho.into()),
            calls_chirho: Mutex::new(Vec::new()),
        }
    }

    fn calls_chirho(&self) -> Vec<ProjectionReadCallChirho> {
        self.calls_chirho.lock().unwrap().clone()
    }
}

impl PublishedProjectionReadPortChirho for SequencedProjectionReadPortChirho {
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> anyhow::Result<ComposedProjectionReadChirho> {
        self.calls_chirho
            .lock()
            .unwrap()
            .push(ProjectionReadCallChirho {
                projection_name_chirho: request_chirho.projection_name_chirho.to_string(),
                requested_limit_chirho: request_chirho.requested_limit_chirho,
                app_chirho: request_chirho.request_context_chirho.app_chirho.clone(),
                user_principal_chirho: request_chirho
                    .request_context_chirho
                    .user_principal_chirho
                    .clone(),
            });
        self.outcomes_chirho
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow!("projection-read test port exhausted"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MoneySurfaceFingerprintChirho {
    effect_files_chirho: usize,
    volatile_bytes_chirho: u64,
    billing_bytes_chirho: u64,
    legacy_ledger_bytes_chirho: u64,
}

pub(super) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-run-intent-test-{}-{n_chirho}",
        now_ms_chirho()
    ))
}

fn store_one_node_dag_chirho(root_chirho: &Path, wasm_chirho: &[u8]) -> HashChirho {
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wasm_chirho).unwrap();
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: "upcase_chirho".to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

pub(super) fn store_effect_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capability_chirho: CapabilityChirho,
) -> (NodeDefChirho, HashChirho) {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let effect_contract_set_chirho = matches!(
        &capability_chirho,
        CapabilityChirho::PaidEffectChirho { .. }
    )
    .then(current_effect_contract_set_chirho);
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, name_chirho.as_bytes()).unwrap(),
        entry_chirho: name_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![capability_chirho],
        effect_contract_set_chirho,
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    (node_chirho, node_hash_chirho)
}

fn store_query_dag_chirho(root_chirho: &Path, prefix_chirho: &str) -> HashChirho {
    let (_node_chirho, node_hash_chirho) = store_effect_node_chirho(
        root_chirho,
        "published_projection_query_chirho",
        CapabilityChirho::QueryChirho {
            prefix_chirho: prefix_chirho.to_string(),
            caller_chirho: "caller-string-grants-nothing-chirho".to_string(),
            max_rows_chirho: 25,
        },
    );
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn projection_request_bytes_chirho(prefix_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&crate::effect_chirho::ScopedQueryRequestChirho {
        prefix_chirho: prefix_chirho.to_string(),
        limit_chirho: Some(5),
    })
    .unwrap()
}

fn projection_view_chirho() -> PublishedProjectionViewChirho {
    PublishedProjectionViewChirho {
        descriptor_ref_chirho: DigestChirho("descriptor-digest-chirho".to_string()),
        watermark_chirho: ProjectionWatermarkChirho {
            source_family_id_chirho: "credits-family-chirho".to_string(),
            source_seq_chirho: 14,
            source_hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_725_000_000_000,
                logical_chirho: 2,
            },
            signed_prefix_digest_chirho: DigestChirho("prefix-digest-chirho".to_string()),
        },
        state_digest_chirho: DigestChirho("state-digest-chirho".to_string()),
    }
}

fn projection_cut_chirho() -> VerifiedProjectionReadCutChirho {
    let view_chirho = projection_view_chirho();
    VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.clone(),
        view_prefix_chirho: view_chirho.watermark_chirho.clone(),
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: view_chirho.watermark_chirho.source_family_id_chirho,
            source_seq_chirho: view_chirho.watermark_chirho.source_seq_chirho,
            source_hlc_chirho: view_chirho.watermark_chirho.source_hlc_chirho,
            signed_prefix_digest_chirho: view_chirho.watermark_chirho.signed_prefix_digest_chirho,
        },
    }
}

fn fresh_projection_read_chirho(balance_chirho: u64) -> ComposedProjectionReadChirho {
    ComposedProjectionReadChirho {
        view_bytes_chirho: Some(
            serde_json::to_vec(&serde_json::json!({"balance_chirho": balance_chirho})).unwrap(),
        ),
        verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
        outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
            ProjectionReadOutcomeChirho::fresh_from_verified_cut_chirho(
                &projection_cut_chirho(),
                projection_view_chirho(),
                0,
            ),
        ),
    }
}

fn refused_projection_read_chirho() -> ComposedProjectionReadChirho {
    ComposedProjectionReadChirho {
        view_bytes_chirho: None,
        verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
        outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
            ProjectionReadOutcomeChirho::RefusedChirho(
                FollowerReadRefusalChirho::StaleBeyondContractChirho {
                    lag_ms_chirho: 9,
                    max_lag_ms_chirho: 5,
                },
            ),
        ),
    }
}

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "user/projection-reader-chirho".to_string(),
        app_chirho: "projection-app-chirho".to_string(),
        owner_principal_chirho: "owner/projection-app-chirho".to_string(),
        client_id_chirho: "client/projection-app-chirho".to_string(),
        token_hash_chirho: "token/projection-app-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn verified_request_context_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
) -> RequestContextChirho {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let user_chirho = crate::identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
        "projection-resume-secret-chirho",
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        root_chirho,
        "projection-resume-app-chirho",
        dag_hash_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let client_chirho = crate::oauth_chirho::register_client_chirho(
        root_chirho,
        "projection-resume-app-chirho",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = crate::oauth_chirho::issue_scoped_token_chirho(
        root_chirho,
        &user_chirho.principal_chirho,
        "projection-resume-secret-chirho",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    RequestContextChirho {
        user_principal_chirho: user_chirho.principal_chirho,
        app_chirho: "projection-resume-app-chirho".to_string(),
        owner_principal_chirho: owner_chirho.principal_chirho,
        client_id_chirho: client_chirho.client_id_chirho,
        token_hash_chirho: token_chirho.record_chirho.token_hash_chirho,
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn path_bytes_chirho(path_chirho: &Path) -> u64 {
    std::fs::metadata(path_chirho)
        .map(|metadata_chirho| metadata_chirho.len())
        .unwrap_or(0)
}

fn money_surface_fingerprint_chirho(root_chirho: &Path) -> MoneySurfaceFingerprintChirho {
    MoneySurfaceFingerprintChirho {
        effect_files_chirho: std::fs::read_dir(root_chirho.join("effects-chirho"))
            .map(|entries_chirho| entries_chirho.count())
            .unwrap_or(0),
        volatile_bytes_chirho: path_bytes_chirho(
            &crate::effect_chirho::volatile_effect_records_path_chirho(root_chirho),
        ),
        billing_bytes_chirho: path_bytes_chirho(&root_chirho.join("billing-usage-chirho.jsonl")),
        legacy_ledger_bytes_chirho: path_bytes_chirho(&root_chirho.join("ledger-chirho.jsonl")),
    }
}

pub(super) fn append_intent_statuses_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    statuses_chirho: &[&'static str],
) -> RunIntentAdmissionChirho {
    let request_chirho = cas_chirho::add_chirho(root_chirho, input_chirho).unwrap();
    let scope_chirho = run_intent_scope_chirho(root_chirho, request_context_chirho).unwrap();
    let idempotency_context_hash_chirho =
        run_intent_context_hash_chirho(dag_hash_chirho, &request_chirho, &scope_chirho).unwrap();
    let run_chirho = run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap();
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho,
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho,
        request_private_subject_chirho: None,
        caller_idempotency_key_digest_chirho: None,
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    for &status_chirho in statuses_chirho {
        append_run_intent_record_chirho(
            root_chirho,
            &admission_chirho,
            RunIntentWriteStatusChirho::CraftedChirho(status_chirho),
            None,
        )
        .unwrap();
    }
    admission_chirho
}

fn write_records_chirho(root_chirho: &Path, records_chirho: &[RunIntentRecordChirho]) {
    let text_chirho = records_chirho
        .iter()
        .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        run_intent_records_path_chirho(root_chirho),
        format!("{text_chirho}\n"),
    )
    .unwrap();
}

fn cas_object_path_for_test_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

#[test]
fn run_intent_append_failure_prevents_execution_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    std::fs::create_dir_all(run_intent_records_path_chirho(&root_chirho)).unwrap();

    assert!(run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).is_err());
    assert!(!root_chirho.join("runs-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_request_stone_failure_prevents_journal_and_execution_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    let input_chirho = (0..1000)
        .map(|idx_chirho| format!("input-{idx_chirho}-chirho"))
        .find(|input_chirho| {
            let hash_chirho = cas_chirho::hash_chirho(input_chirho.as_bytes());
            !cas_object_path_for_test_chirho(&root_chirho, &hash_chirho)
                .parent()
                .unwrap()
                .exists()
        })
        .unwrap();
    let input_hash_chirho = cas_chirho::hash_chirho(input_chirho.as_bytes());
    let shard_chirho = cas_object_path_for_test_chirho(&root_chirho, &input_hash_chirho)
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::write(&shard_chirho, b"not a directory").unwrap();

    assert!(run_dag_with_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        input_chirho.as_bytes(),
        None
    )
    .is_err());
    assert!(!run_intent_records_path_chirho(&root_chirho).exists());
    assert!(!root_chirho.join("runs-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_records_success_transitions_and_request_stone_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    let report_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap();
    assert_eq!(report_chirho.payload_chirho, b"SAME");
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    assert_eq!(records_chirho[0].status_chirho, RUN_INTENT_PENDING_CHIRHO);
    assert_eq!(records_chirho[1].status_chirho, RUN_INTENT_RUNNING_CHIRHO);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_DONE_CHIRHO);
    assert_eq!(records_chirho[0].run_chirho, records_chirho[2].run_chirho);
    assert_eq!(
        cas_chirho::get_chirho(&root_chirho, &records_chirho[0].request_chirho).unwrap(),
        b"same"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_unfinished_pending_intent_runs_to_done_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"resume",
        None,
        &[RUN_INTENT_PENDING_CHIRHO],
    );

    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.resumed_chirho, 1);
    assert_eq!(report_chirho.failed_chirho, 0);
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        records_chirho
            .iter()
            .map(|record_chirho| record_chirho.status_chirho.as_str())
            .collect::<Vec<_>>(),
        vec![
            RUN_INTENT_PENDING_CHIRHO,
            RUN_INTENT_RUNNING_CHIRHO,
            RUN_INTENT_DONE_CHIRHO
        ]
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_replays_own_volatile_read_instead_of_live_store_chirho() {
    let root_chirho = tmp_root_chirho();
    {
        let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
            &root_chirho.join("versioned-chirho.redb"),
        )
        .unwrap();
        store_chirho.put_chirho("msg", b"first").unwrap();
    }
    let (read_node_chirho, read_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "read_resume_chirho",
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "msg".to_string(),
        },
    );
    let (_write_node_chirho, write_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "write_resume_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "sent".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![read_hash_chirho.clone(), write_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: read_hash_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: write_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();
    // A signed-in run, so the resume rebuilds its context and attributes the sealed write: since C5 2a a
    // context-free run that stores privately is not resumed (it fails closed and is retried).
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"",
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"").unwrap();
    let (read_result_chirho, read_cached_chirho) =
        crate::cache_chirho::run_effect_node_cached_with_context_chirho(
            &root_chirho,
            &read_node_chirho,
            &read_hash_chirho,
            &input_hash_chirho,
            &[],
            Some(&context_chirho),
        )
        .unwrap();
    assert!(!read_cached_chirho);
    assert_eq!(
        cas_chirho::get_chirho(
            &root_chirho,
            read_result_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap(),
        b"first"
    );
    {
        let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
            &root_chirho.join("versioned-chirho.redb"),
        )
        .unwrap();
        store_chirho.put_chirho("msg", b"second").unwrap();
    }

    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.resumed_chirho, 1);
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, &store_chirho, "sent"),
        b"first"
    );
    assert_eq!(
        crate::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_replays_logged_clock_instead_of_fresh_value_chirho() {
    let root_chirho = tmp_root_chirho();
    let (clock_node_chirho, clock_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "clock_resume_chirho",
        CapabilityChirho::ClockChirho,
    );
    let (_write_node_chirho, write_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "write_clock_resume_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "clock/out".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![clock_hash_chirho.clone(), write_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: clock_hash_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: write_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();
    // A signed-in run, so the resume rebuilds its context and attributes the sealed write: since C5 2a a
    // context-free run that stores privately is not resumed (it fails closed and is retried).
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"",
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"").unwrap();
    let (clock_result_chirho, clock_cached_chirho) =
        crate::cache_chirho::run_effect_node_cached_with_context_chirho(
            &root_chirho,
            &clock_node_chirho,
            &clock_hash_chirho,
            &input_hash_chirho,
            &[],
            Some(&context_chirho),
        )
        .unwrap();
    assert!(!clock_cached_chirho);
    let original_clock_chirho = cas_chirho::get_chirho(
        &root_chirho,
        clock_result_chirho.outputs_chirho.get("out").unwrap(),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.resumed_chirho, 1);
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, &store_chirho, "clock/out"),
        original_clock_chirho
    );
    assert!(crate::effect_chirho::load_effect_chirho(
        &root_chirho,
        &clock_result_chirho.run_chirho
    )
    .unwrap()
    .is_some());
    assert_eq!(
        crate::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_refuses_signed_scope_with_swapped_token_hash_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let user_chirho = crate::identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
        "tamper-secret-chirho",
    )
    .unwrap();
    let (_write_node_chirho, write_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "tamper_write_resume_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "tamper/out".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![write_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "tamperapp",
        dag_hash_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let client_chirho = crate::oauth_chirho::register_client_chirho(
        &root_chirho,
        "tamperapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = crate::oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "tamper-secret-chirho",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: user_chirho.principal_chirho,
        app_chirho: "tamperapp".to_string(),
        owner_principal_chirho: owner_chirho.principal_chirho,
        client_id_chirho: client_chirho.client_id_chirho,
        token_hash_chirho: token_chirho.record_chirho.token_hash_chirho,
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let request_chirho = cas_chirho::add_chirho(&root_chirho, b"should not write").unwrap();
    let mut scope_chirho = run_intent_scope_chirho(&root_chirho, Some(&context_chirho)).unwrap();
    scope_chirho.token_hash_chirho = Some("swapped-token-hash-chirho".to_string());
    let idempotency_context_hash_chirho =
        run_intent_context_hash_chirho(&dag_hash_chirho, &request_chirho, &scope_chirho).unwrap();
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho: run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap(),
        dag_chirho: dag_hash_chirho,
        request_chirho,
        request_private_subject_chirho: None,
        caller_idempotency_key_digest_chirho: None,
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    append_run_intent_record_chirho(
        &root_chirho,
        &admission_chirho,
        RunIntentWriteStatusChirho::PendingChirho,
        None,
    )
    .unwrap();
    append_run_intent_record_chirho(
        &root_chirho,
        &admission_chirho,
        RunIntentWriteStatusChirho::RunningChirho,
        None,
    )
    .unwrap();

    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.resumed_chirho, 0);
    assert_eq!(report_chirho.failed_chirho, 1);
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        records_chirho.last().unwrap().status_chirho,
        RUN_INTENT_FAILED_CHIRHO
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert!(store_chirho.get_chirho("tamper/out").unwrap().is_none());
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_legacy_paid_node_fails_without_billing_or_followup_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let user_chirho = crate::identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
        "resume-secret-chirho",
    )
    .unwrap();
    let (_charge_node_chirho, charge_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "charge_resume_chirho",
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "ignored-until-context-chirho".to_string(),
        },
    );
    let (_email_node_chirho, email_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "email_resume_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "email/out".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![charge_hash_chirho.clone(), email_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: charge_hash_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: email_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "recoverapp",
        dag_hash_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let client_chirho = crate::oauth_chirho::register_client_chirho(
        &root_chirho,
        "recoverapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = crate::oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "resume-secret-chirho",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let mut prices_chirho = std::collections::BTreeMap::new();
    prices_chirho.insert("llm_chirho".to_string(), 7);
    let (price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "recoverapp",
        &owner_chirho.principal_chirho,
        None,
        prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: user_chirho.principal_chirho.clone(),
        app_chirho: "recoverapp".to_string(),
        owner_principal_chirho: owner_chirho.principal_chirho.clone(),
        client_id_chirho: client_chirho.client_id_chirho,
        token_hash_chirho: token_chirho.record_chirho.token_hash_chirho,
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let request_chirho = llm_request_bytes_chirho("email body");
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.resumed_chirho, 0);
    assert_eq!(report_chirho.failed_chirho, 1);
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert!(store_chirho.get_chirho("email/out").unwrap().is_none());
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resume_after_prior_write_refuses_later_legacy_paid_door_chirho() {
    let root_chirho = tmp_root_chirho();
    let request_chirho = b"first write completed before crash".to_vec();
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let user_chirho = crate::identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::UserChirho,
        "second-charge-secret-chirho",
    )
    .unwrap();
    let (first_node_chirho, first_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "first_write_resume_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "resume/first".to_string(),
        },
    );
    let (_second_node_chirho, second_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "second_charge_resume_chirho",
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "ignored-until-context-chirho".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![first_hash_chirho.clone(), second_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: first_hash_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: second_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "secondchargeapp",
        dag_hash_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let client_chirho = crate::oauth_chirho::register_client_chirho(
        &root_chirho,
        "secondchargeapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = crate::oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "second-charge-secret-chirho",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let mut prices_chirho = std::collections::BTreeMap::new();
    prices_chirho.insert("llm_chirho".to_string(), 7);
    let (price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "secondchargeapp",
        &owner_chirho.principal_chirho,
        None,
        prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: user_chirho.principal_chirho.clone(),
        app_chirho: "secondchargeapp".to_string(),
        owner_principal_chirho: owner_chirho.principal_chirho,
        client_id_chirho: client_chirho.client_id_chirho,
        token_hash_chirho: token_chirho.record_chirho.token_hash_chirho,
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, &request_chirho).unwrap();
    let (first_result_chirho, first_cached_chirho) =
        crate::cache_chirho::run_effect_node_cached_with_context_chirho(
            &root_chirho,
            &first_node_chirho,
            &first_hash_chirho,
            &input_hash_chirho,
            &[],
            Some(&context_chirho),
        )
        .unwrap();
    assert!(!first_cached_chirho);
    assert_eq!(first_result_chirho.effects_chirho.len(), 1);

    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.resumed_chirho, 0);
    assert_eq!(report_chirho.failed_chirho, 1);
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, &store_chirho, "resume/first"),
        request_chirho
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_verifier_fails_closed_on_tamper_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap();
    let mut records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    records_chirho[0].status_chirho = RUN_INTENT_DONE_CHIRHO.to_string();
    write_records_chirho(&root_chirho, &records_chirho);

    assert!(verify_run_intent_records_chirho(&root_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_subject_scope_matches_without_raw_principals_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user@example.test".to_string(),
        app_chirho: "demo-app-chirho".to_string(),
        owner_principal_chirho: "owner@example.test".to_string(),
        client_id_chirho: "client-chirho".to_string(),
        token_hash_chirho: "token-hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    run_dag_with_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"same",
        Some(&context_chirho),
    )
    .unwrap();
    let log_chirho = std::fs::read_to_string(run_intent_records_path_chirho(&root_chirho)).unwrap();
    assert!(!log_chirho.contains("user@example.test"));
    assert!(!log_chirho.contains("owner@example.test"));
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    let owner_hashes_chirho =
        run_intent_subject_index_hashes_chirho(&root_chirho, "owner@example.test").unwrap();
    assert_eq!(
        run_intent_subject_matches_chirho(&records_chirho[0], &owner_hashes_chirho),
        vec!["scope_chirho.owner_principal_hash_chirho".to_string()]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_failure_keeps_pre_execution_records_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, b"not wasm");
    let first_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();
    let first_observation_chirho =
        crate::dag_chirho::refusal_chirho::dag_execution_refusal_observation_chirho(
            &first_error_chirho,
        );
    assert_eq!(
        first_observation_chirho.identity_chirho(),
        crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
    );
    assert_eq!(
        first_observation_chirho.attempt_ordinal_chirho(),
        crate::dag_chirho::refusal_chirho::DagExecutionAttemptOrdinalChirho::FirstChirho
    );
    assert_eq!(
        crate::dag_chirho::refusal_chirho::dag_execution_refusal_log_line_chirho(
            &first_error_chirho
        ),
        "CairnAppExecutionRefusalChirho:attempt_ordinal_chirho=first-chirho:identity_chirho=DagPreEffectRefusedChirho:knowledge_chirho=definitely-not-executed-chirho:prior_identity_chirho=none-chirho"
    );
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    assert_eq!(records_chirho[0].status_chirho, RUN_INTENT_PENDING_CHIRHO);
    assert_eq!(records_chirho[1].status_chirho, RUN_INTENT_RUNNING_CHIRHO);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_FAILED_CHIRHO);
    assert_eq!(
        records_chirho[2].error_kind_chirho.as_deref(),
        Some(
            crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
                .as_str_chirho()
        )
    );
    assert!(records_chirho[2].error_digest_chirho.is_some());

    let replay_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();
    let replay_observation_chirho =
        crate::dag_chirho::refusal_chirho::dag_execution_refusal_observation_chirho(
            &replay_error_chirho,
        );
    assert_eq!(
        replay_observation_chirho.identity_chirho(),
        crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::RunIntentPreviouslyFailedRefusedChirho
    );
    assert_eq!(
        replay_observation_chirho.prior_identity_chirho(),
        Some(
            crate::dag_chirho::refusal_chirho::DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho
        )
    );
    assert_eq!(
        replay_observation_chirho.attempt_ordinal_chirho(),
        crate::dag_chirho::refusal_chirho::DagExecutionAttemptOrdinalChirho::FailedReplayChirho
    );
    assert_ne!(
        replay_observation_chirho.identity_chirho(),
        replay_observation_chirho.prior_identity_chirho().unwrap()
    );
    assert_eq!(
        crate::dag_chirho::refusal_chirho::dag_execution_refusal_log_line_chirho(
            &replay_error_chirho
        ),
        "CairnAppExecutionRefusalChirho:attempt_ordinal_chirho=failed-replay-chirho:identity_chirho=RunIntentPreviouslyFailedRefusedChirho:knowledge_chirho=prior-attempt-failed-chirho:prior_identity_chirho=DagPreEffectRefusedChirho"
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn failed_replay_retains_the_first_post_effect_class_chirho() {
    let root_chirho = tmp_root_chirho();
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho
        .put_chirho("post-effect/replay", b"provider-returned-chirho")
        .unwrap();
    drop(store_chirho);
    let (effect_node_chirho, effect_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "post_effect_replay_chirho",
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "post-effect/replay".to_string(),
        },
    );
    let schema_chirho = effect_node_chirho.outputs_chirho[0].schema_chirho.clone();
    let pure_node_chirho = NodeDefChirho {
        name_chirho: "post_effect_replay_failure_chirho".to_string(),
        impl_wasm_chirho: HashChirho("missing-post-effect-wasm-chirho".to_string()),
        entry_chirho: "run_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let pure_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &pure_node_chirho).unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![effect_hash_chirho.clone(), pure_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: effect_hash_chirho,
                from_port_chirho: "out".to_string(),
                to_node_chirho: pure_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();

    let first_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();
    let first_chirho = dag_execution_refusal_observation_chirho(&first_error_chirho);
    assert_eq!(
        first_chirho.identity_chirho(),
        DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho
    );
    assert_eq!(
        first_chirho.attempt_ordinal_chirho(),
        DagExecutionAttemptOrdinalChirho::FirstChirho
    );

    let replay_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();
    let replay_chirho = dag_execution_refusal_observation_chirho(&replay_error_chirho);
    assert_eq!(
        replay_chirho.identity_chirho(),
        DagExecutionRefusalIdentityChirho::RunIntentPreviouslyFailedRefusedChirho
    );
    assert_eq!(
        replay_chirho.prior_identity_chirho(),
        Some(DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho)
    );
    assert_eq!(
        replay_chirho.attempt_ordinal_chirho(),
        DagExecutionAttemptOrdinalChirho::FailedReplayChirho
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn run_intent_scope_index_is_root_private_chirho() {
    let first_root_chirho = tmp_root_chirho();
    let second_root_chirho = tmp_root_chirho();
    let subject_chirho = "owner@example.test";
    let first_chirho =
        run_intent_subject_index_hashes_chirho(&first_root_chirho, subject_chirho).unwrap();
    let second_chirho =
        run_intent_subject_index_hashes_chirho(&second_root_chirho, subject_chirho).unwrap();
    assert_ne!(
        first_chirho.owner_principal_hash_chirho,
        second_chirho.owner_principal_hash_chirho
    );
    let _ = std::fs::remove_dir_all(&first_root_chirho);
    let _ = std::fs::remove_dir_all(&second_root_chirho);
}

#[test]
fn completed_projection_retry_refreshes_refused_to_fresh_without_rows_chirho() {
    let root_chirho = tmp_root_chirho();
    let projection_name_chirho = "credits-balance-chirho";
    let dag_hash_chirho = store_query_dag_chirho(&root_chirho, projection_name_chirho);
    let request_chirho = projection_request_bytes_chirho(projection_name_chirho);
    let context_chirho = request_context_chirho();
    let port_chirho = SequencedProjectionReadPortChirho::new_chirho(vec![
        refused_projection_read_chirho(),
        fresh_projection_read_chirho(7),
    ]);

    let refused_report_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        Some(&port_chirho),
    )
    .unwrap();
    let refused_response_chirho: PublishedProjectionReadResponseChirho =
        serde_json::from_slice(&refused_report_chirho.payload_chirho).unwrap();
    assert_eq!(
        refused_response_chirho.viewer_principal_chirho,
        context_chirho.user_principal_chirho
    );
    assert!(refused_response_chirho.view_chirho.is_none());
    assert!(matches!(
        refused_response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::ClassifierRefusedChirho {
            refusal_chirho: PublishedProjectionClassifierRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho: 9,
                max_lag_ms_chirho: 5,
            },
        }
    ));

    let fresh_report_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        Some(&port_chirho),
    )
    .unwrap();
    let fresh_response_chirho: PublishedProjectionReadResponseChirho =
        serde_json::from_slice(&fresh_report_chirho.payload_chirho).unwrap();
    assert_eq!(
        fresh_response_chirho.viewer_principal_chirho,
        context_chirho.user_principal_chirho
    );
    assert_eq!(
        fresh_response_chirho.view_chirho,
        Some(serde_json::json!({"balance_chirho": 7}))
    );
    assert!(matches!(
        fresh_response_chirho.outcome_chirho,
        PublishedProjectionVerdictChirho::FreshChirho {
            lag_ms_chirho: 0,
            ..
        }
    ));
    assert_ne!(
        refused_report_chirho.payload_hash_chirho,
        fresh_report_chirho.payload_hash_chirho
    );
    assert!(!refused_report_chirho.node_runs_chirho[0].cached_chirho);
    assert!(!fresh_report_chirho.node_runs_chirho[0].cached_chirho);

    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_DONE_CHIRHO);
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    assert_eq!(
        port_chirho.calls_chirho(),
        vec![
            ProjectionReadCallChirho {
                projection_name_chirho: projection_name_chirho.to_string(),
                requested_limit_chirho: 5,
                app_chirho: context_chirho.app_chirho.clone(),
                user_principal_chirho: context_chirho.user_principal_chirho.clone(),
            },
            ProjectionReadCallChirho {
                projection_name_chirho: projection_name_chirho.to_string(),
                requested_limit_chirho: 5,
                app_chirho: context_chirho.app_chirho.clone(),
                user_principal_chirho: context_chirho.user_principal_chirho.clone(),
            },
        ]
    );
    assert_eq!(
        money_surface_fingerprint_chirho(&root_chirho),
        MoneySurfaceFingerprintChirho {
            effect_files_chirho: 0,
            volatile_bytes_chirho: 0,
            billing_bytes_chirho: 0,
            legacy_ledger_bytes_chirho: 0,
        }
    );
    assert!(!root_chirho.join("runs-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn projection_response_viewer_comes_only_from_verified_context_chirho() {
    let root_chirho = tmp_root_chirho();
    let projection_name_chirho = "credits-balance-chirho";
    let dag_hash_chirho = store_query_dag_chirho(&root_chirho, projection_name_chirho);
    let request_chirho = serde_json::to_vec(&serde_json::json!({
        "prefix_chirho": projection_name_chirho,
        "limit_chirho": 5,
        "viewer_principal_chirho": "user/caller-spoof-chirho",
    }))
    .unwrap();
    let context_chirho = request_context_chirho();
    let port_chirho =
        SequencedProjectionReadPortChirho::new_chirho(vec![fresh_projection_read_chirho(7)]);

    let report_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        Some(&port_chirho),
    )
    .unwrap();
    let response_chirho: PublishedProjectionReadResponseChirho =
        serde_json::from_slice(&report_chirho.payload_chirho).unwrap();

    assert_eq!(
        response_chirho.viewer_principal_chirho,
        context_chirho.user_principal_chirho
    );
    assert_ne!(
        response_chirho.viewer_principal_chirho,
        "user/caller-spoof-chirho"
    );
    assert_eq!(
        port_chirho.calls_chirho()[0].user_principal_chirho,
        context_chirho.user_principal_chirho
    );

    let anonymous_error_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        None,
        Some(&port_chirho),
    )
    .unwrap_err();
    assert!(format!("{anonymous_error_chirho:#}").contains("requires matching UserIdentityChirho"));
    assert_eq!(port_chirho.calls_chirho().len(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn crash_resume_reenters_projection_port_without_money_or_observation_rows_chirho() {
    let root_chirho = tmp_root_chirho();
    let projection_name_chirho = "credits-balance-chirho";
    let dag_hash_chirho = store_query_dag_chirho(&root_chirho, projection_name_chirho);
    let request_chirho = projection_request_bytes_chirho(projection_name_chirho);
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let before_chirho = money_surface_fingerprint_chirho(&root_chirho);
    let port_chirho =
        SequencedProjectionReadPortChirho::new_chirho(vec![fresh_projection_read_chirho(11)]);

    let report_chirho =
        resume_unfinished_run_intents_with_projection_read_chirho(&root_chirho, Some(&port_chirho))
            .unwrap();

    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.resumed_chirho, 1);
    assert_eq!(report_chirho.failed_chirho, 0);
    assert_eq!(port_chirho.calls_chirho().len(), 1);
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_DONE_CHIRHO);
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    assert_eq!(
        money_surface_fingerprint_chirho(&root_chirho),
        before_chirho
    );
    assert!(!root_chirho.join("runs-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[path = "dag_version_pinning_tests_chirho.rs"]
mod dag_version_pinning_tests_chirho;
#[path = "retry_tests_chirho.rs"]
mod retry_tests_chirho;
#[path = "runtime_ports_tests_chirho.rs"]
mod runtime_ports_tests_chirho;

#[path = "aborted_reader_tests_chirho.rs"]
mod aborted_reader_tests_chirho;
#[path = "private_subject_pin_tests_chirho.rs"]
mod private_subject_pin_tests_chirho;
#[path = "request_stored_once_tests_chirho.rs"]
mod request_stored_once_tests_chirho;
