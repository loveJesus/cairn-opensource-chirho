// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_writer_head_chirho::writer_head_chirho::{
    self as writer_head_chirho, WriterFenceTokenChirho,
};

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn append_pending_app_deploy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    dag_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
) -> (AppRecordChirho, WriterFenceTokenChirho) {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        let record_chirho = app_head_transition_chirho::append_app_deploy_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            dag_chirho,
            AppActionChirho::DeployChirho,
            previous_chirho,
            fence_chirho,
        )?;
        Ok((record_chirho, fence_chirho.clone()))
    })
    .unwrap()
}

fn selected_dag_chirho(root_chirho: &Path, app_chirho: &str) -> HashChirho {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho).unwrap();
    resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)
        .unwrap()
        .dag_chirho
}

#[test]
fn app_ref_before_receipt_fails_closed_then_repairs_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"app receipt A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"app receipt B");
    deploy_app_chirho(
        &root_chirho,
        "receiptroute",
        dag_a_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let (pending_chirho, _) = append_pending_app_deploy_chirho(
        &root_chirho,
        "receiptroute",
        &owner_chirho,
        dag_b_chirho.clone(),
        Some(dag_a_chirho),
    );
    refs_chirho::set_branch_chirho(&root_chirho, "app/receiptroute", dag_b_chirho.clone()).unwrap();

    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let error_chirho =
        resolve_app_dag_chirho(&root_chirho, &refs_chirho, "receiptroute").unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .contains("no valid Applied receipt"),
        "{error_chirho}"
    );
    assert!(app_status_chirho(&root_chirho, "receiptroute").is_err());

    assert!(matches!(
        recover_app_head_chirho(&root_chirho, "receiptroute").unwrap(),
        Some(
            cairn_writer_head_chirho::head_transition_chirho::HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho
        )
    ));
    assert_eq!(
        selected_dag_chirho(&root_chirho, "receiptroute"),
        dag_b_chirho
    );
    assert_eq!(
        recover_app_head_chirho(&root_chirho, "receiptroute").unwrap(),
        None
    );
    assert_eq!(
        verified_app_records_chirho(&root_chirho).unwrap()[1],
        pending_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn first_pending_deploy_is_settled_before_undeploy_and_never_resurrects_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"first pending undeploy");
    append_pending_app_deploy_chirho(
        &root_chirho,
        "firstpending",
        &owner_chirho,
        dag_chirho.clone(),
        None,
    );
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/firstpending"));

    assert!(undeploy_app_chirho(&root_chirho, "firstpending", &owner_chirho).unwrap());
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/firstpending"));
    let removals_chirho =
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap();
    assert_eq!(removals_chirho.len(), 2);
    assert_eq!(removals_chirho[0]["from_chirho"], dag_chirho.0);
    assert_eq!(
        removals_chirho[0]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO
    );
    assert_eq!(
        removals_chirho[1]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO
    );
    assert_eq!(
        recover_app_head_chirho(&root_chirho, "firstpending").unwrap(),
        None
    );
    assert!(
        !app_status_chirho(&root_chirho, "firstpending")
            .unwrap()
            .active_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn existing_head_pending_deploy_is_settled_before_undeploy_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"existing pending A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"existing pending B");
    deploy_app_chirho(
        &root_chirho,
        "existingpending",
        dag_a_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    append_pending_app_deploy_chirho(
        &root_chirho,
        "existingpending",
        &owner_chirho,
        dag_b_chirho.clone(),
        Some(dag_a_chirho),
    );

    assert!(undeploy_app_chirho(&root_chirho, "existingpending", &owner_chirho).unwrap());
    let removals_chirho =
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap();
    assert_eq!(removals_chirho.len(), 2);
    assert_eq!(removals_chirho[0]["from_chirho"], dag_b_chirho.0);
    assert_eq!(
        removals_chirho[0]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO
    );
    assert_eq!(
        removals_chirho[1]["schema_chirho"],
        crate::head_removal_transition_chirho::HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO
    );
    assert_eq!(
        recover_app_head_chirho(&root_chirho, "existingpending").unwrap(),
        None
    );
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/existingpending"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_rollback_branches_from_verified_selected_head_without_resurrection_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"app branch A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"app branch B");
    let dag_c_chirho = fake_dag_chirho(&root_chirho, b"app branch C");
    deploy_app_chirho(
        &root_chirho,
        "rollbackapp",
        dag_a_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    deploy_app_chirho(&root_chirho, "rollbackapp", dag_b_chirho, &owner_chirho).unwrap();
    refs_chirho::rollback_chirho(&root_chirho, "app/rollbackapp", dag_a_chirho.clone()).unwrap();
    assert_eq!(
        recover_app_head_chirho(&root_chirho, "rollbackapp").unwrap(),
        None
    );
    let record_c_chirho = deploy_app_chirho(
        &root_chirho,
        "rollbackapp",
        dag_c_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    assert_eq!(record_c_chirho.previous_chirho, Some(dag_a_chirho));
    assert_eq!(
        selected_dag_chirho(&root_chirho, "rollbackapp"),
        dag_c_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_ref_outside_verified_history_cannot_resolve_or_seed_a_write_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"verified app A");
    let forged_chirho = fake_dag_chirho(&root_chirho, b"forged app ref");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"verified app B");
    deploy_app_chirho(&root_chirho, "forgedapp", dag_a_chirho, &owner_chirho).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/forgedapp", forged_chirho).unwrap();
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    assert!(resolve_app_dag_chirho(&root_chirho, &refs_chirho, "forgedapp").is_err());
    let before_chirho = verified_app_records_chirho(&root_chirho).unwrap().len();
    let error_chirho =
        deploy_app_chirho(&root_chirho, "forgedapp", dag_b_chirho, &owner_chirho).unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .contains("does not select verified signed deploy history"),
        "{error_chirho}"
    );
    assert_eq!(
        verified_app_records_chirho(&root_chirho).unwrap().len(),
        before_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn latest_undeploy_is_a_ceiling_and_recreate_starts_from_absent_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"undeploy ceiling A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"undeploy ceiling B");
    deploy_app_chirho(
        &root_chirho,
        "ceilingapp",
        dag_a_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    undeploy_app_chirho(&root_chirho, "ceilingapp", &owner_chirho).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/ceilingapp", dag_a_chirho).unwrap();
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    assert!(resolve_app_dag_chirho(&root_chirho, &refs_chirho, "ceilingapp").is_err());
    refs_chirho::remove_branch_chirho(&root_chirho, "app/ceilingapp").unwrap();
    let recreated_chirho =
        deploy_app_chirho(&root_chirho, "ceilingapp", dag_b_chirho, &owner_chirho).unwrap();
    assert_eq!(recreated_chirho.previous_chirho, None);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn different_app_pending_transitions_recover_independently_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"independent app A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"independent app B");
    append_pending_app_deploy_chirho(
        &root_chirho,
        "independenta",
        &owner_chirho,
        dag_a_chirho.clone(),
        None,
    );
    append_pending_app_deploy_chirho(
        &root_chirho,
        "independentb",
        &owner_chirho,
        dag_b_chirho.clone(),
        None,
    );
    recover_app_head_chirho(&root_chirho, "independenta")
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_dag_chirho(&root_chirho, "independenta"),
        dag_a_chirho
    );
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/independentb"));
    recover_app_head_chirho(&root_chirho, "independentb")
        .unwrap()
        .unwrap();
    assert_eq!(
        selected_dag_chirho(&root_chirho, "independentb"),
        dag_b_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn same_app_write_recovers_pending_transition_before_next_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"same app pending A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"same app pending B");
    append_pending_app_deploy_chirho(
        &root_chirho,
        "samepending",
        &owner_chirho,
        dag_a_chirho.clone(),
        None,
    );
    let next_chirho = deploy_app_chirho(
        &root_chirho,
        "samepending",
        dag_b_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    assert_eq!(next_chirho.seq_chirho, 1);
    assert_eq!(next_chirho.previous_chirho, Some(dag_a_chirho));
    assert_eq!(
        selected_dag_chirho(&root_chirho, "samepending"),
        dag_b_chirho
    );
    assert_eq!(verified_app_records_chirho(&root_chirho).unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn same_dag_deploy_returns_existing_applied_record_without_new_transition_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"same DAG idempotence");
    let first_chirho =
        deploy_app_chirho(&root_chirho, "sameappdag", dag_chirho, &owner_chirho).unwrap();
    let record_count_chirho = verified_app_records_chirho(&root_chirho).unwrap().len();
    let reflog_count_chirho = refs_chirho::reflog_chirho(&root_chirho).unwrap().len();

    let repeated_chirho = deploy_app_chirho(
        &root_chirho,
        "sameappdag",
        first_chirho.dag_chirho.clone().unwrap(),
        &owner_chirho,
    )
    .unwrap();

    assert_eq!(repeated_chirho, first_chirho);
    assert_eq!(
        verified_app_records_chirho(&root_chirho).unwrap().len(),
        record_count_chirho
    );
    assert_eq!(
        refs_chirho::reflog_chirho(&root_chirho).unwrap().len(),
        reflog_count_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn stale_app_preparer_cannot_complete_after_recovery_advances_fence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"stale app preparer");
    let (record_chirho, stale_fence_chirho) =
        append_pending_app_deploy_chirho(&root_chirho, "staleapp", &owner_chirho, dag_chirho, None);
    recover_app_head_chirho(&root_chirho, "staleapp")
        .unwrap()
        .unwrap();
    let prepared_chirho = app_head_transition_chirho::prepared_from_verified_app_record_chirho(
        &root_chirho,
        &record_chirho,
    )
    .unwrap();
    let error_chirho =
        cairn_writer_head_chirho::head_transition_chirho::complete_head_transition_unlocked_chirho(
            &root_chirho,
            &prepared_chirho,
            &stale_fence_chirho,
        )
        .unwrap_err();
    assert!(error_chirho
        .chain()
        .any(|cause_chirho| cause_chirho.to_string().contains("StaleWriterFenceChirho")));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
