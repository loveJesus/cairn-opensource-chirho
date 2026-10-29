// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::tests_chirho::{deploy_owned_app_chirho, tmp_root_chirho};
use super::*;
use crate::elected_control_prepare_chirho::test_support_chirho::{
    rebind_root_chirho, rewrite_refs_chirho, snapshot_chirho, ControlAuthorityChirho,
};

fn setup_chirho() -> (PathBuf, String, ControlAuthorityChirho) {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
    let authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    (root_chirho, owner_chirho, authority_chirho)
}

fn steps_chirho() -> Vec<OnboardingStepChirho> {
    vec![parse_onboarding_step_spec_chirho("Start=Read the guide").unwrap()]
}

#[test]
fn elected_control_onboarding_commits_verified_guide_and_receipt_chirho() {
    let (root_chirho, owner_chirho, authority_chirho) = setup_chirho();
    let (hash_chirho, guide_chirho, record_chirho) =
        set_onboarding_guide_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &owner_chirho,
            "Guide",
            steps_chirho(),
            &authority_chirho,
        )
        .unwrap();
    assert!(authority_chirho.called_chirho.get());
    assert_eq!(record_chirho.guide_chirho, hash_chirho);
    let selected_chirho = current_onboarding_guide_chirho(&root_chirho, "geo-guide-chirho")
        .unwrap()
        .unwrap();
    assert_eq!(selected_chirho.0, hash_chirho);
    assert_eq!(selected_chirho.1.title_chirho, guide_chirho.title_chirho);
    let prepared_chirho =
        prepared_from_verified_onboarding_record_chirho(&root_chirho, &record_chirho).unwrap();
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 1);
    assert!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_deposed_authority_writes_nothing_chirho() {
    let (root_chirho, owner_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = set_onboarding_guide_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &owner_chirho,
        "Guide",
        steps_chirho(),
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "refusal changed durable bytes"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_stale_inputs_refuse_before_object_or_record_chirho() {
    let (root_chirho, owner_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.before_chirho = Some(rewrite_refs_chirho);
    let error_chirho = set_onboarding_guide_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &owner_chirho,
        "Guide",
        steps_chirho(),
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ElectedControlPreparedStateChangedChirho"
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 0);
    assert!(
        current_onboarding_guide_chirho(&root_chirho, "geo-guide-chirho")
            .unwrap()
            .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_wrong_owner_never_calls_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
    let other_owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = set_onboarding_guide_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &other_owner_chirho,
        "Guide",
        steps_chirho(),
        &authority_chirho,
    )
    .unwrap_err();
    assert!(
        error_chirho.to_string().contains("is owned by"),
        "{error_chirho:#}"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "owner refusal changed durable bytes"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_recovers_pending_record_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
    let (hash_chirho, record_chirho, prepared_chirho, _fence_chirho) =
        super::tests_chirho::append_pending_onboarding_v2_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &owner_chirho,
            "Pending guide",
        );
    let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = recover_onboarding_head_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    authority_chirho.refuse_chirho = false;
    assert_eq!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho),
    );
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "geo-guide-chirho").unwrap(),
        Some(hash_chirho)
    );
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert_eq!(
        verified_onboarding_records_chirho(&root_chirho).unwrap(),
        vec![record_chirho]
    );
    assert!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_recovery_never_repairs_before_authority_chirho() {
    use std::io::Write;
    let (root_chirho, _owner_chirho, mut authority_chirho) = setup_chirho();
    std::fs::OpenOptions::new()
        .append(true)
        .open(root_chirho.join("reflog-chirho.jsonl"))
        .unwrap()
        .write_all(b"{")
        .unwrap();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    assert!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .is_err()
    );
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "PREPARE repaired a torn reflog before authority"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_recovery_repairs_torn_receipt_after_authority_chirho() {
    use std::io::Write;
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
    let (hash_chirho, _record_chirho, prepared_chirho, _fence_chirho) =
        super::tests_chirho::append_pending_onboarding_v2_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &owner_chirho,
            "Pending guide",
        );
    let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
    std::fs::OpenOptions::new()
        .append(true)
        .open(root_chirho.join("reflog-chirho.jsonl"))
        .unwrap()
        .write_all(b"{")
        .unwrap();
    authority_chirho.refuse_chirho = true;
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = recover_onboarding_head_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(error_chirho.to_string(), "ElectedAuthorityDeposedChirho");
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    authority_chirho.refuse_chirho = false;
    assert_eq!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "geo-guide-chirho").unwrap(),
        Some(hash_chirho)
    );
    assert!(
        head_transition_chirho::verified_head_transition_receipt_chirho(
            &root_chirho,
            &prepared_chirho
        )
        .unwrap()
    );
    assert!(
        recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .unwrap()
        .is_none()
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_recovery_binds_root_even_without_pending_chirho() {
    for pending_chirho in [false, true] {
        let root_chirho = tmp_root_chirho();
        let owner_chirho = deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
        if pending_chirho {
            super::tests_chirho::append_pending_onboarding_v2_chirho(
                &root_chirho,
                "geo-guide-chirho",
                &owner_chirho,
                "Pending guide",
            );
        }
        let mut authority_chirho = ControlAuthorityChirho::new_chirho(&root_chirho);
        authority_chirho.before_chirho = Some(rebind_root_chirho);
        let before_chirho = snapshot_chirho(&root_chirho);
        let error_chirho = recover_onboarding_head_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &authority_chirho,
        )
        .unwrap_err();
        assert!(
            error_chirho
                .to_string()
                .contains("HeadTransitionWrongRootChirho"),
            "{error_chirho:#}"
        );
        assert!(snapshot_chirho(&root_chirho.with_extension("held-chirho")) == before_chirho);
        assert_eq!(
            std::fs::read(root_chirho.join("reflog-chirho.jsonl")).unwrap(),
            std::fs::read(
                root_chirho
                    .with_extension("held-chirho")
                    .join("reflog-chirho.jsonl")
            )
            .unwrap(),
        );
        std::fs::remove_dir_all(root_chirho.with_extension("held-chirho")).unwrap();
        std::fs::remove_dir_all(root_chirho).unwrap();
    }
}

#[test]
fn elected_control_onboarding_legacy_door_still_refuses_elected_root_chirho() {
    let (root_chirho, owner_chirho, _authority_chirho) = setup_chirho();
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = set_onboarding_guide_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &owner_chirho,
        "Guide",
        steps_chirho(),
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "GeoWriterAuthorityAlreadyActiveChirho"
    );
    assert!(
        snapshot_chirho(&root_chirho) == before_chirho,
        "legacy door changed elected root"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_missing_signer_is_not_recreated_chirho() {
    let (root_chirho, owner_chirho, authority_chirho) = setup_chirho();
    std::fs::remove_file(root_chirho.join("signing-key-chirho.bin")).unwrap();
    let before_chirho = snapshot_chirho(&root_chirho);
    let error_chirho = set_onboarding_guide_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &owner_chirho,
        "Guide",
        steps_chirho(),
        &authority_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ElectedControlExistingSignerUnavailableChirho"
    );
    assert!(!authority_chirho.called_chirho.get());
    assert!(snapshot_chirho(&root_chirho) == before_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_root_rebinding_refuses_publication_chirho() {
    let (root_chirho, owner_chirho, mut authority_chirho) = setup_chirho();
    authority_chirho.before_chirho = Some(rebind_root_chirho);
    let error_chirho = set_onboarding_guide_with_head_transition_authority_chirho(
        &root_chirho,
        "geo-guide-chirho",
        &owner_chirho,
        "Guide",
        steps_chirho(),
        &authority_chirho,
    )
    .unwrap_err();
    assert!(
        error_chirho
            .to_string()
            .contains("HeadTransitionWrongRootChirho"),
        "{error_chirho:#}"
    );
    assert!(!onboarding_records_path_chirho(&root_chirho).exists());
    assert!(!onboarding_records_path_chirho(&root_chirho.with_extension("held-chirho")).exists());
    std::fs::remove_dir_all(root_chirho.with_extension("held-chirho")).unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn elected_control_onboarding_local_root_keeps_local_behavior_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "geo-guide-chirho");
    let authority_chirho = ControlAuthorityChirho::refusing_chirho(&root_chirho);
    let (hash_chirho, _guide_chirho, _record_chirho) =
        set_onboarding_guide_with_head_transition_authority_chirho(
            &root_chirho,
            "geo-guide-chirho",
            &owner_chirho,
            "Guide",
            steps_chirho(),
            &authority_chirho,
        )
        .unwrap();
    assert!(!authority_chirho.called_chirho.get());
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "geo-guide-chirho").unwrap(),
        Some(hash_chirho)
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}
