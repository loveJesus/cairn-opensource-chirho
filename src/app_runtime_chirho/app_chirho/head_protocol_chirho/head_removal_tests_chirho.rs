// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::cas_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-app-head-removal-test-{nanos_chirho}-{n_chirho}"
    ))
}

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn fake_dag_chirho(root_chirho: &Path, label_chirho: &[u8]) -> HashChirho {
    let marker_chirho = cas_chirho::add_chirho(root_chirho, label_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn removal_evidence_chirho(root_chirho: &Path) -> Vec<serde_json::Value> {
    crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho)
        .unwrap()
}

#[test]
fn app_undeploy_records_signed_head_removal_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"head removal app");
    deploy_app_chirho(&root_chirho, "myapp", dag_chirho, &owner_chirho).unwrap();

    assert!(undeploy_app_chirho(&root_chirho, "myapp", &owner_chirho).unwrap());
    assert!(!undeploy_app_chirho(&root_chirho, "myapp", &owner_chirho).unwrap());
    let records_chirho = removal_evidence_chirho(&root_chirho);
    assert_eq!(records_chirho.len(), 2);
    assert_eq!(records_chirho[0]["kind_chirho"], "AppUndeployChirho");
    assert_eq!(records_chirho[0]["branch_chirho"], "app/myapp");
    assert_eq!(
        records_chirho[0]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO
    );
    assert_eq!(
        records_chirho[1]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO
    );
    assert_eq!(
        crate::head_removal_chirho::verify_head_removal_records_chirho(&root_chirho).unwrap(),
        1
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_undeploy_records_signed_head_removal_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"route app");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"route dag");
    deploy_app_chirho(&root_chirho, "myapp", app_dag_chirho, &owner_chirho).unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "lite",
        route_dag_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert!(undeploy_app_route_chirho(&root_chirho, "myapp", "lite", &owner_chirho).unwrap());
    let records_chirho = removal_evidence_chirho(&root_chirho);
    assert_eq!(records_chirho.len(), 2);
    assert_eq!(records_chirho[0]["kind_chirho"], "AppRouteUndeployChirho");
    assert_eq!(records_chirho[0]["branch_chirho"], "app-route/myapp/lite");
    assert_eq!(
        records_chirho[0]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO
    );
    assert_eq!(
        records_chirho[1]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_undeploy_failure_order_never_removes_without_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"failure order app");
    deploy_app_chirho(&root_chirho, "failureapp", dag_chirho, &owner_chirho).unwrap();

    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(
        undeploy_app_chirho(&root_chirho, "failureapp", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/failureapp"));
    assert!(removal_evidence_chirho(&root_chirho).is_empty());

    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(
        undeploy_app_chirho(&root_chirho, "failureapp", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/failureapp"));
    assert_eq!(
        crate::head_removal_chirho::verify_head_removal_records_chirho(&root_chirho).unwrap(),
        1
    );

    assert!(undeploy_app_chirho(&root_chirho, "failureapp", &owner_chirho).unwrap());
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/failureapp"));
    assert_eq!(removal_evidence_chirho(&root_chirho).len(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_undeploy_rejects_tampered_pending_head_removal_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"tampered pending app");
    deploy_app_chirho(&root_chirho, "tamperedpending", dag_chirho, &owner_chirho).unwrap();

    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(
        undeploy_app_chirho(&root_chirho, "tamperedpending", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    let mut records_chirho = removal_evidence_chirho(&root_chirho);
    records_chirho[0]["sig_chirho"] = serde_json::Value::String("00".repeat(64));
    std::fs::write(
        root_chirho.join("head-removals-chirho.jsonl"),
        format!("{}\n", serde_json::to_string(&records_chirho[0]).unwrap()),
    )
    .unwrap();

    let error_chirho = undeploy_app_chirho(&root_chirho, "tamperedpending", &owner_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("signature invalid"), "{error_chirho}");
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/tamperedpending"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_undeploy_error_after_remove_still_has_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"post remove failure app");
    deploy_app_chirho(&root_chirho, "postremoveapp", dag_chirho, &owner_chirho).unwrap();
    crate::head_removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        crate::head_removal_chirho::HeadRemovalStepChirho::AfterBranchRemoveChirho,
    );

    assert!(
        undeploy_app_chirho(&root_chirho, "postremoveapp", &owner_chirho)
            .unwrap_err()
            .to_string()
            .contains("injected head removal failure")
    );
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/postremoveapp"));
    assert_eq!(
        crate::head_removal_chirho::verify_head_removal_records_chirho(&root_chirho).unwrap(),
        1
    );
    assert!(!undeploy_app_chirho(&root_chirho, "postremoveapp", &owner_chirho).unwrap());
    assert_eq!(removal_evidence_chirho(&root_chirho).len(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}
