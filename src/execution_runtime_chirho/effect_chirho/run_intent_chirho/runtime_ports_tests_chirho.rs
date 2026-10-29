// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::effect_chirho::postgres_reversible_chirho::{
    PostgresReversibleActivationErrorChirho, PostgresReversibleExecutionChirho,
    PostgresReversibleRuntimePortChirho,
};
use crate::effect_chirho::DagEffectRuntimePortsChirho;
use cairn_undo_plan_chirho::contract_chirho::POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO;

const DESCRIPTOR_D_TERMINAL_CHIRHO: &[u8] = b"descriptor-d-terminal-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
struct PostgresRuntimeCallChirho {
    invocation_ref_chirho: HashChirho,
    run_chirho: HashChirho,
    request_bytes_chirho: Vec<u8>,
}

#[derive(Default)]
struct RecordingPostgresRuntimeChirho {
    calls_chirho: Vec<PostgresRuntimeCallChirho>,
}

impl PostgresReversibleRuntimePortChirho for RecordingPostgresRuntimeChirho {
    fn execute_chirho(
        &mut self,
        execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> anyhow::Result<Vec<u8>> {
        self.calls_chirho.push(PostgresRuntimeCallChirho {
            invocation_ref_chirho: execution_chirho.invocation_ref_chirho().clone(),
            run_chirho: execution_chirho.run_chirho().clone(),
            request_bytes_chirho: execution_chirho.request_bytes_chirho().to_vec(),
        });
        Ok(DESCRIPTOR_D_TERMINAL_CHIRHO.to_vec())
    }
}

fn store_projection_then_postgres_dag_chirho(root_chirho: &Path) -> HashChirho {
    let projection_name_chirho = "credits-balance-chirho";
    let (_query_node_chirho, query_hash_chirho) = store_effect_node_chirho(
        root_chirho,
        "runtime_ports_query_chirho",
        CapabilityChirho::QueryChirho {
            prefix_chirho: projection_name_chirho.to_owned(),
            caller_chirho: "caller-string-grants-nothing-chirho".to_owned(),
            max_rows_chirho: 25,
        },
    );
    let (_postgres_node_chirho, postgres_hash_chirho) = store_effect_node_chirho(
        root_chirho,
        "runtime_ports_postgres_chirho",
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_owned(),
            caller_chirho: "descriptor-d-runtime-ports-chirho".to_owned(),
        },
    );
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![query_hash_chirho.clone(), postgres_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: query_hash_chirho,
                from_port_chirho: "out".to_owned(),
                to_node_chirho: postgres_hash_chirho,
                to_port_chirho: "in".to_owned(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap()
}

fn runtime_ports_request_chirho() -> Vec<u8> {
    projection_request_bytes_chirho("credits-balance-chirho")
}

#[test]
fn one_runtime_bundle_reaches_fresh_and_completed_replay_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_projection_then_postgres_dag_chirho(&root_chirho);
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    let request_chirho = runtime_ports_request_chirho();
    let projection_port_chirho = SequencedProjectionReadPortChirho::new_chirho(vec![
        fresh_projection_read_chirho(750),
        fresh_projection_read_chirho(750),
    ]);
    let mut postgres_runtime_chirho = RecordingPostgresRuntimeChirho::default();

    let first_chirho = run_dag_with_intent_and_effect_runtime_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        DagEffectRuntimePortsChirho {
            projection_read_chirho: Some(&projection_port_chirho),
            postgres_reversible_chirho: Some(&mut postgres_runtime_chirho),
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
    .unwrap();
    let completed_replay_chirho = run_dag_with_intent_and_effect_runtime_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        DagEffectRuntimePortsChirho {
            projection_read_chirho: Some(&projection_port_chirho),
            postgres_reversible_chirho: Some(&mut postgres_runtime_chirho),
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
    .unwrap();

    assert_eq!(first_chirho.payload_chirho, DESCRIPTOR_D_TERMINAL_CHIRHO);
    assert_eq!(
        completed_replay_chirho.payload_chirho,
        first_chirho.payload_chirho
    );
    assert_eq!(projection_port_chirho.calls_chirho().len(), 2);
    assert_eq!(postgres_runtime_chirho.calls_chirho.len(), 2);
    assert_eq!(
        postgres_runtime_chirho.calls_chirho[0].invocation_ref_chirho,
        postgres_runtime_chirho.calls_chirho[1].invocation_ref_chirho
    );
    assert_eq!(
        postgres_runtime_chirho.calls_chirho[0].run_chirho,
        postgres_runtime_chirho.calls_chirho[1].run_chirho
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn one_runtime_bundle_reaches_private_input_execution_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_projection_then_postgres_dag_chirho(&root_chirho);
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    let request_chirho = runtime_ports_request_chirho();
    let projection_port_chirho =
        SequencedProjectionReadPortChirho::new_chirho(vec![fresh_projection_read_chirho(750)]);
    let mut postgres_runtime_chirho = RecordingPostgresRuntimeChirho::default();

    // An unkeyed private run carries the requesting user's own principal as its subject, as the served request-user
    // mode does: THE PIN refuses any other subject on an unkeyed run.
    let report_chirho = run_dag_with_private_input_intent_and_effect_runtime_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &context_chirho.user_principal_chirho,
        &request_chirho,
        Some(&context_chirho),
        DagEffectRuntimePortsChirho {
            projection_read_chirho: Some(&projection_port_chirho),
            postgres_reversible_chirho: Some(&mut postgres_runtime_chirho),
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
    .unwrap();

    assert_eq!(report_chirho.payload_chirho, DESCRIPTOR_D_TERMINAL_CHIRHO);
    assert_eq!(projection_port_chirho.calls_chirho().len(), 1);
    assert_eq!(postgres_runtime_chirho.calls_chirho.len(), 1);
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(
        records_chirho[0].request_private_subject_chirho.as_deref(),
        Some(context_chirho.user_principal_chirho.as_str())
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn one_runtime_bundle_reaches_unfinished_resume_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_projection_then_postgres_dag_chirho(&root_chirho);
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    let request_chirho = runtime_ports_request_chirho();
    let admission_chirho = append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        Some(&context_chirho),
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let projection_port_chirho =
        SequencedProjectionReadPortChirho::new_chirho(vec![fresh_projection_read_chirho(750)]);
    let mut postgres_runtime_chirho = RecordingPostgresRuntimeChirho::default();

    let report_chirho = resume_unfinished_run_intents_with_effect_runtime_chirho(
        &root_chirho,
        DagEffectRuntimePortsChirho {
            projection_read_chirho: Some(&projection_port_chirho),
            postgres_reversible_chirho: Some(&mut postgres_runtime_chirho),
            llm_served_chirho: None,
            private_attribution_chirho: None,
        },
    )
    .unwrap();

    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.resumed_chirho, 1);
    assert_eq!(report_chirho.failed_chirho, 0);
    assert_eq!(projection_port_chirho.calls_chirho().len(), 1);
    assert_eq!(postgres_runtime_chirho.calls_chirho.len(), 1);
    assert_eq!(
        postgres_runtime_chirho.calls_chirho[0].run_chirho,
        admission_chirho.run_chirho
    );
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_DONE_CHIRHO);
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn legacy_projection_only_entrypoint_keeps_descriptor_d_uncomposed_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_projection_then_postgres_dag_chirho(&root_chirho);
    let context_chirho = verified_request_context_chirho(&root_chirho, &dag_hash_chirho);
    let projection_port_chirho =
        SequencedProjectionReadPortChirho::new_chirho(vec![fresh_projection_read_chirho(750)]);

    let error_chirho = run_dag_with_intent_and_projection_read_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &runtime_ports_request_chirho(),
        Some(&context_chirho),
        Some(&projection_port_chirho),
    )
    .unwrap_err();

    assert!(matches!(
        error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::CompositionUnavailableChirho)
    ));
    assert_eq!(projection_port_chirho.calls_chirho().len(), 1);
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].status_chirho, RUN_INTENT_FAILED_CHIRHO);
    let _ = std::fs::remove_dir_all(root_chirho);
}
