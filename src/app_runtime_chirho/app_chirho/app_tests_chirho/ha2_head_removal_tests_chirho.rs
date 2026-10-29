// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_head_removal_chirho::{
    head_removal_chirho::{
        self as removal_chirho, HeadRemovalEvidenceInputChirho, HeadRemovalKindChirho,
        HeadRemovalStepChirho,
    },
    head_removal_transition_chirho as removal_transition_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho;

fn owner_chirho(root_chirho: &Path) -> String {
    identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho
}

fn removal_values_chirho(root_chirho: &Path) -> Vec<serde_json::Value> {
    removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho).unwrap()
}

fn prepared_for_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> removal_transition_chirho::PreparedHeadRemovalChirho {
    let record_chirho =
        removal_transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)
            .unwrap()
            .into_iter()
            .find(|record_chirho| record_chirho.app_chirho == app_chirho)
            .unwrap();
    let domain_chirho = verified_app_records_chirho(root_chirho).unwrap()
        [record_chirho.domain_seq_chirho as usize]
        .clone();
    removal_transition_chirho::bind_caller_verified_prepared_head_removal_chirho(
        root_chirho,
        &record_chirho,
        &serde_json::to_vec(&domain_chirho).unwrap(),
    )
    .unwrap()
}

#[test]
fn app_domain_only_removal_recovers_without_duplicate_domain_row_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"domain only removal");
    deploy_app_chirho(&root_chirho, "domainonly", dag_chirho, &owner_chirho).unwrap();
    removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(undeploy_app_chirho(&root_chirho, "domainonly", &owner_chirho).is_err());
    assert!(removal_values_chirho(&root_chirho).is_empty());
    assert_eq!(verified_app_records_chirho(&root_chirho).unwrap().len(), 2);

    assert!(recover_app_head_removal_chirho(&root_chirho, "domainonly")
        .unwrap()
        .is_some());
    assert_eq!(verified_app_records_chirho(&root_chirho).unwrap().len(), 2);
    assert_eq!(removal_values_chirho(&root_chirho).len(), 2);
    assert!(!refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/domainonly"));
}

#[test]
fn app_domain_only_removal_rejects_forged_raw_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"domain forged original");
    let forged_chirho = fake_dag_chirho(&root_chirho, b"domain forged head");
    deploy_app_chirho(&root_chirho, "domainforged", dag_chirho, &owner_chirho).unwrap();
    removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        HeadRemovalStepChirho::AfterDomainRecordChirho,
    );
    assert!(undeploy_app_chirho(&root_chirho, "domainforged", &owner_chirho).is_err());
    refs_chirho::set_branch_chirho(&root_chirho, "app/domainforged", forged_chirho.clone())
        .unwrap();

    let error_chirho = recover_app_head_removal_chirho(&root_chirho, "domainforged")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("not exact verified deploy history"));
    assert!(removal_values_chirho(&root_chirho).is_empty());
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app/domainforged"],
        forged_chirho
    );
}

#[test]
fn app_direct_undeploy_rejects_forged_raw_target_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"direct forged original");
    let forged_chirho = fake_dag_chirho(&root_chirho, b"direct forged head");
    deploy_app_chirho(&root_chirho, "forgedirect", dag_chirho, &owner_chirho).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/forgedirect", forged_chirho.clone()).unwrap();

    let error_chirho = undeploy_app_chirho(&root_chirho, "forgedirect", &owner_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("not exact verified deploy history"));
    assert!(removal_values_chirho(&root_chirho).is_empty());
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app/forgedirect"],
        forged_chirho
    );
    assert_eq!(
        verified_app_records_chirho(&root_chirho).unwrap().len(),
        1,
        "forged direct undeploy must not append a domain row"
    );
}

#[test]
fn positive_deploy_recovers_pending_removal_before_recreate_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"removal composition A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"removal composition B");
    deploy_app_chirho(&root_chirho, "removalcompose", dag_a_chirho, &owner_chirho).unwrap();
    removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(undeploy_app_chirho(&root_chirho, "removalcompose", &owner_chirho).is_err());

    let recreated_chirho = deploy_app_chirho(
        &root_chirho,
        "removalcompose",
        dag_b_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    assert!(recreated_chirho.previous_chirho.is_none());
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app/removalcompose"],
        dag_b_chirho
    );
    assert_eq!(removal_values_chirho(&root_chirho).len(), 2);
}

#[test]
fn applied_app_removal_never_stale_deletes_same_dag_recreate_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"same dag recreate");
    deploy_app_chirho(
        &root_chirho,
        "samedagrecreate",
        dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    assert!(undeploy_app_chirho(&root_chirho, "samedagrecreate", &owner_chirho).unwrap());
    let prepared_chirho = prepared_for_app_chirho(&root_chirho, "samedagrecreate");
    deploy_app_chirho(
        &root_chirho,
        "samedagrecreate",
        dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();

    assert_eq!(
        removal_transition_chirho::recover_head_removal_chirho(&root_chirho, &prepared_chirho,)
            .unwrap(),
        removal_transition_chirho::HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app/samedagrecreate"],
        dag_chirho
    );
}

#[test]
fn app_removal_absent_branch_repairs_applied_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"absent repair");
    deploy_app_chirho(&root_chirho, "absentrepair", dag_chirho, &owner_chirho).unwrap();
    removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(undeploy_app_chirho(&root_chirho, "absentrepair", &owner_chirho).is_err());
    refs_chirho::remove_branch_chirho(&root_chirho, "app/absentrepair").unwrap();

    assert!(
        recover_app_head_removal_chirho(&root_chirho, "absentrepair")
            .unwrap()
            .is_some()
    );
    assert_eq!(removal_values_chirho(&root_chirho).len(), 2);
    assert!(
        recover_app_head_removal_chirho(&root_chirho, "absentrepair")
            .unwrap()
            .is_none()
    );
    assert_eq!(removal_values_chirho(&root_chirho).len(), 2);
}

#[test]
fn app_removal_current_other_fails_closed_without_delete_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"removal diverged A");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"removal diverged B");
    deploy_app_chirho(
        &root_chirho,
        "removaldiverged",
        dag_a_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    deploy_app_chirho(
        &root_chirho,
        "removaldiverged",
        dag_b_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/removaldiverged", dag_a_chirho).unwrap();
    removal_chirho::set_head_removal_failpoint_chirho(
        &root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );
    assert!(undeploy_app_chirho(&root_chirho, "removaldiverged", &owner_chirho).is_err());
    refs_chirho::set_branch_chirho(&root_chirho, "app/removaldiverged", dag_b_chirho.clone())
        .unwrap();

    let error_chirho = recover_app_head_removal_chirho(&root_chirho, "removaldiverged")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("diverges from the current branch head"));
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho["app/removaldiverged"],
        dag_b_chirho
    );
    assert_eq!(removal_values_chirho(&root_chirho).len(), 1);
}

#[test]
fn different_app_pending_removals_recover_independently_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    for (app_chirho, marker_chirho) in [
        ("removalbrancha", b"removal branch A".as_slice()),
        ("removalbranchb", b"removal branch B".as_slice()),
    ] {
        let dag_chirho = fake_dag_chirho(&root_chirho, marker_chirho);
        deploy_app_chirho(&root_chirho, app_chirho, dag_chirho, &owner_chirho).unwrap();
        removal_chirho::set_head_removal_failpoint_chirho(
            &root_chirho,
            HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
        );
        assert!(undeploy_app_chirho(&root_chirho, app_chirho, &owner_chirho).is_err());
    }

    assert!(
        recover_app_head_removal_chirho(&root_chirho, "removalbrancha")
            .unwrap()
            .is_some()
    );
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/removalbranchb"));
    assert!(
        recover_app_head_removal_chirho(&root_chirho, "removalbranchb")
            .unwrap()
            .is_some()
    );
    assert_eq!(removal_values_chirho(&root_chirho).len(), 4);
}

#[test]
fn legacy_app_removal_recovers_without_v2_conversion_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = owner_chirho(&root_chirho);
    let dag_chirho = fake_dag_chirho(&root_chirho, b"legacy removal");
    deploy_app_chirho(
        &root_chirho,
        "legacyremoval",
        dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    writer_head_chirho::with_head_transition_scope_chirho(&root_chirho, |_fence_chirho| {
        let domain_chirho = append_app_record_unlocked_chirho(
            &root_chirho,
            "legacyremoval",
            &owner_chirho,
            None,
            AppActionChirho::UndeployChirho,
        )?;
        removal_chirho::append_head_removal_record_unlocked_chirho(
            &root_chirho,
            HeadRemovalEvidenceInputChirho {
                branch_chirho: "app/legacyremoval",
                from_chirho: &dag_chirho,
                kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                app_chirho: "legacyremoval",
                route_chirho: None,
                owner_principal_chirho: &owner_chirho,
                domain_log_chirho: "app-records-chirho.jsonl",
                domain_seq_chirho: domain_chirho.seq_chirho,
            },
        )?;
        Ok(())
    })
    .unwrap();

    assert!(
        recover_app_head_removal_chirho(&root_chirho, "legacyremoval")
            .unwrap()
            .is_some()
    );
    let values_chirho = removal_values_chirho(&root_chirho);
    assert_eq!(values_chirho.len(), 1);
    assert_eq!(
        values_chirho[0]["schema_chirho"],
        removal_chirho::HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO
    );
    assert!(
        removal_transition_chirho::root_signed_prepared_head_removal_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
}
