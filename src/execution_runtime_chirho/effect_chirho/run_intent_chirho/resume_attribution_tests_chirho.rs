// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A resume never takes a declaration made at startup: a context-free unfinished run that stores privately fails closed and leaves no key, whatever ports startup passes.

use super::tests_chirho::{
    append_intent_statuses_chirho, store_effect_node_chirho, tmp_root_chirho,
};
use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho};
use crate::privacy_chirho::PrivateBlobAttributionChirho;

/// A one-node DAG whose WriteStore node seals its input, so any run of it stores privately.
fn sealing_dag_chirho(root_chirho: &Path) -> HashChirho {
    let (_node_chirho, write_hash_chirho) = store_effect_node_chirho(
        root_chirho,
        "write_resume_attribution_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "sent".to_string(),
        },
    );
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![write_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn key_files_chirho(root_chirho: &Path) -> usize {
    std::fs::read_dir(root_chirho.join("privacy-keys-chirho"))
        .map(|entries_chirho| entries_chirho.count())
        .unwrap_or(0)
}

#[test]
fn a_resumed_context_free_run_ignores_a_startup_declaration_and_stores_nothing_chirho() {
    let operator_chirho = PrivateBlobAttributionChirho::test_operator_chirho();
    let declared_ports_chirho = || crate::effect_chirho::DagEffectRuntimePortsChirho {
        private_attribution_chirho: Some(&operator_chirho),
        ..crate::effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho()
    };
    // Control: run directly with a declaration, this DAG does store privately, so the arm is not vacuous.
    let control_root_chirho = tmp_root_chirho();
    let control_dag_chirho = sealing_dag_chirho(&control_root_chirho);
    run_dag_with_intent_and_effect_runtime_chirho(
        &control_root_chirho,
        &control_dag_chirho,
        b"resume attribution body",
        None,
        declared_ports_chirho(),
    )
    .unwrap();
    assert!(
        key_files_chirho(&control_root_chirho) > 0,
        "the control stored nothing privately"
    );
    let _ = std::fs::remove_dir_all(control_root_chirho);

    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = sealing_dag_chirho(&root_chirho);
    append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"resume attribution body",
        None,
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let report_chirho = resume_unfinished_run_intents_with_effect_runtime_chirho(
        &root_chirho,
        declared_ports_chirho(),
    )
    .unwrap();
    assert_eq!(
        (report_chirho.resumed_chirho, report_chirho.failed_chirho),
        (0, 1),
        "a context-free run must not be resumed under a startup declaration"
    );
    assert_eq!(
        key_files_chirho(&root_chirho),
        0,
        "the refused resume made a key"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The operator entry the CLI's DAG commands use declares its reason, so a sealing DAG stores privately under no
/// account; the plain context-free entry declares nothing, so the same DAG refuses before any key.
#[test]
fn only_the_operator_entry_lets_a_context_free_dag_store_privately_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = sealing_dag_chirho(&root_chirho);
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    let error_chirho =
        dag_chirho::run_dag_chirho(&root_chirho, &dag_chirho, b"operator body").unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("MissingRunAttributionChirho"),
        "{error_chirho:#}"
    );
    assert_eq!(
        key_files_chirho(&root_chirho),
        0,
        "the refused run made a key"
    );
    dag_chirho::run_dag_as_operator_chirho(&root_chirho, &dag_chirho, b"operator body").unwrap();
    assert!(
        key_files_chirho(&root_chirho) > 0,
        "the operator run stored nothing privately"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
