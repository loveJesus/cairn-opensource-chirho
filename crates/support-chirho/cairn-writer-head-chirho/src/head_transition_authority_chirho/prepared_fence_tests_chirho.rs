// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::tests_chirho::temp_root_chirho;
use super::*;
use crate::writer_head_chirho::{
    consistency_group_for_root_chirho, issue_elected_writer_fence_for_root_chirho,
    observe_prepared_fence_lower_bound_chirho,
};

#[test]
fn elected_control_recovery_scope_checks_its_actual_fence_group_chirho() {
    let root_chirho = temp_root_chirho("recovery-root-chirho");
    let other_root_chirho = temp_root_chirho("recovery-other-chirho");
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
    let prepared_chirho =
        observe_prepared_fence_lower_bound_chirho(&root_chirho, &group_chirho).unwrap();
    with_elected_head_transition_scope_chirho(
        &root_chirho,
        &group_chirho,
        2,
        None,
        |scope_chirho| scope_chirho.preflight_prepared_fence_chirho(&root_chirho, &prepared_chirho),
    )
    .into_result_chirho()
    .unwrap();
    let other_group_chirho = consistency_group_for_root_chirho(&other_root_chirho).unwrap();
    let error_chirho = with_elected_head_transition_scope_chirho(
        &other_root_chirho,
        &other_group_chirho,
        2,
        None,
        |scope_chirho| scope_chirho.preflight_prepared_fence_chirho(&root_chirho, &prepared_chirho),
    )
    .into_result_chirho()
    .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("HeadTransitionWrongGroupChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
    std::fs::remove_dir_all(other_root_chirho).unwrap();
}

#[test]
fn elected_control_recovery_preflight_keeps_the_observed_lower_bound_chirho() {
    let root_chirho = temp_root_chirho("recovery-lower-bound-chirho");
    let old_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 3).unwrap();
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
    let prepared_chirho =
        observe_prepared_fence_lower_bound_chirho(&root_chirho, &group_chirho).unwrap();
    let error_chirho =
        preflight_prepared_fence_commit_chirho(&root_chirho, &prepared_chirho, &old_fence_chirho)
            .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("HeadTransitionPreparedFenceEpochRegressionChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_recovery_preflight_rejects_a_no_longer_current_fence_chirho() {
    let root_chirho = temp_root_chirho("recovery-stale-fence-chirho");
    let old_fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
    let prepared_chirho =
        observe_prepared_fence_lower_bound_chirho(&root_chirho, &group_chirho).unwrap();
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 2).unwrap();
    let error_chirho =
        preflight_prepared_fence_commit_chirho(&root_chirho, &prepared_chirho, &old_fence_chirho)
            .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .starts_with("HeadTransitionApplierFenceNotCurrentChirho"),
        "{error_chirho:#}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}
