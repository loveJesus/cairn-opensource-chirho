// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const APP_ROOT_CHIRHO: &str = "src/app_runtime_chirho/app_chirho.rs";
const APP_TRANSITION_CHIRHO: &str =
    "src/app_runtime_chirho/app_chirho/head_protocol_chirho/app_head_transition_chirho.rs";
const APP_REMOVAL_SERVICE_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/app_head_removal_chirho.rs";
const MODEL_RECORDS_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_control_plane_records_chirho.rs";
const MODEL_TRANSITION_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_head_transition_chirho.rs";
const MODEL_POLICY_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_policy_chirho.rs";
const SUBSCRIPTION_CONTROL_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/lib.rs";

fn production_file_chirho(path_chirho: &str) -> String {
    let text_chirho = std::fs::read_to_string(workspace_root_chirho().join(path_chirho)).unwrap();
    production_text_chirho(&text_chirho).to_string()
}

#[test]
fn app_root_v2_keeps_verify_recover_append_complete_order_chirho() {
    let root_chirho = production_file_chirho(APP_ROOT_CHIRHO);
    let transition_chirho = production_file_chirho(APP_TRANSITION_CHIRHO);
    for required_chirho in [
        "recover_app_head_unlocked_chirho(",
        "verified_app_records_chirho(",
        "app_previous_is_verified_chirho(",
        "append_app_deploy_record_unlocked_chirho(",
        "verified_record_at_seq_chirho(",
        "complete_verified_app_record_unlocked_chirho(",
    ] {
        assert!(
            root_chirho.contains(required_chirho),
            "app deploy must retain {required_chirho}"
        );
    }
    let recover_chirho = root_chirho
        .find("recover_app_head_unlocked_chirho(")
        .unwrap();
    let verify_chirho = root_chirho[recover_chirho..]
        .find("verified_app_records_chirho(")
        .unwrap()
        + recover_chirho;
    let append_chirho = root_chirho[verify_chirho..]
        .find("append_app_deploy_record_unlocked_chirho(")
        .unwrap()
        + verify_chirho;
    let complete_chirho = root_chirho[append_chirho..]
        .find("complete_verified_app_record_unlocked_chirho(")
        .unwrap()
        + append_chirho;
    assert!(recover_chirho < verify_chirho && verify_chirho < append_chirho);
    assert!(append_chirho < complete_chirho);
    for required_chirho in [
        "recover_jsonl_len_unlocked_chirho(",
        "bind_caller_verified_head_transition_chirho(",
        "verified_head_transition_receipt_chirho(",
        "pending_head_transition_index_unlocked_chirho(",
    ] {
        assert!(transition_chirho.contains(required_chirho));
    }
}

#[test]
fn app_raw_ref_and_direct_commit_surfaces_stay_narrow_chirho() {
    // The per-file raw-app-ref occurrence MAP freeze was demoted to the advisory structure report;
    // the no-raw-head-commit engine claim stays RED.
    assert!(
        production_source_lines_matching_chirho("refs_chirho::commit_head_chirho(")
            .into_iter()
            .all(|(file_chirho, _, _)| {
                file_chirho != APP_ROOT_CHIRHO && file_chirho != APP_TRANSITION_CHIRHO
            }),
        "app-root deploy surfaces must move heads through the signed transition protocol, not raw head commits"
    );
}

#[test]
fn app_deploy_uses_the_elected_dispatcher_and_remaining_local_scopes_are_allowlisted_chirho() {
    let root_chirho = production_file_chirho(APP_ROOT_CHIRHO);
    let deploy_start_chirho = root_chirho
        .find("fn deploy_app_with_review_label_chirho(")
        .expect("app deploy implementation exists");
    let deploy_end_chirho = root_chirho[deploy_start_chirho..]
        .find("fn deploy_app_local_unlocked_chirho(")
        .map(|offset_chirho| deploy_start_chirho + offset_chirho)
        .expect("local app deploy implementation follows dispatcher");
    let deploy_chirho = &root_chirho[deploy_start_chirho..deploy_end_chirho];
    assert!(
        deploy_chirho.contains("dispatch_head_transition_chirho("),
        "app Deploy must stay on the local/elected dispatcher"
    );
    assert!(
        !deploy_chirho.contains("with_head_transition_scope_chirho("),
        "app Deploy must not regress to the bare local-fence door"
    );

    let actual_chirho =
        production_source_lines_matching_chirho("with_head_transition_scope_chirho(")
            .into_iter()
            .fold(
                std::collections::BTreeMap::<String, usize>::new(),
                |mut counts_chirho, (file_chirho, _line_chirho, _text_chirho)| {
                    *counts_chirho.entry(file_chirho).or_default() += 1;
                    counts_chirho
                },
            );
    let expected_chirho = [
        (
            "crates/runtime-chirho/cairn-app-control-chirho/src/app_head_removal_chirho.rs",
            1,
        ),
        (
            "crates/runtime-chirho/cairn-app-control-chirho/src/app_route_head_removal_chirho.rs",
            1,
        ),
        (
            "crates/runtime-chirho/cairn-app-control-chirho/src/lib.rs",
            2,
        ),
        (
            "crates/support-chirho/cairn-head-removal-chirho/src/head_removal_transition_chirho.rs",
            1,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_authority_chirho.rs",
            1,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/head_transition_chirho.rs",
            1,
        ),
        (
            "crates/support-chirho/cairn-writer-head-chirho/src/writer_head_chirho.rs",
            1,
        ),
        (
            "src/app_runtime_chirho/app_chirho/head_protocol_chirho/app_head_transition_chirho.rs",
            1,
        ),
        ("src/app_runtime_chirho/app_chirho/app_route_chirho.rs", 1),
        ("src/app_runtime_chirho/app_chirho.rs", 1),
        // S3 converted the price-book door to the elected dispatcher, so one bare local-fence
        // scope became zero-plus-a-dispatch and the count drops 2 -> 1. The pin FOLLOWS the
        // improvement, the same way the F4 landing moved `object_path_chirho` 3 -> 2 once
        // `add_chirho` began publishing through the lifecycle.
        ("src/app_runtime_chirho/effect_pricing_chirho.rs", 1),
        ("src/edge_flows_chirho/onboarding_chirho.rs", 2),
        (
            "src/governance_flows_chirho/agent_authority_chirho/mod.rs",
            2,
        ),
    ]
    .into_iter()
    .map(|(file_chirho, count_chirho)| (file_chirho.to_string(), count_chirho))
    .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        actual_chirho, expected_chirho,
        "PARTIAL guard: a new bare local-fence door is review-blocking; convert it or add one explicit reviewed allowlist entry"
    );
}

#[test]
fn app_undeploy_recovers_positive_head_before_receipted_remove_chirho() {
    let root_chirho = production_file_chirho(APP_ROOT_CHIRHO);
    let undeploy_chirho = root_chirho.find("pub fn undeploy_app_chirho(").unwrap();
    let end_chirho = root_chirho[undeploy_chirho..]
        .find("pub fn recover_app_head_removal_chirho(")
        .map(|offset_chirho| undeploy_chirho + offset_chirho)
        .unwrap();
    let undeploy_body_chirho = &root_chirho[undeploy_chirho..end_chirho];
    let recover_chirho = undeploy_body_chirho
        .find("recover_app_head_unlocked_chirho(")
        .unwrap();
    let removal_scope_chirho = undeploy_body_chirho[recover_chirho..]
        .find("undeploy_app_head_unlocked_chirho(")
        .unwrap()
        + recover_chirho;
    assert!(recover_chirho < removal_scope_chirho);
    let service_chirho = production_file_chirho(APP_REMOVAL_SERVICE_CHIRHO);
    for required_chirho in [
        "append_signed_app_undeploy_record_unlocked_chirho(",
        "append_caller_verified_prepared_head_removal_unlocked_chirho(",
        "complete_head_removal_unlocked_chirho(",
        "require_applied_historical_app_head_chirho(",
    ] {
        assert!(
            service_chirho.contains(required_chirho),
            "app removal adoption must retain {required_chirho}"
        );
    }
    assert!(production_source_lines_matching_chirho("head_removal_bridge_chirho").is_empty());
}

#[test]
fn app_removal_service_uses_only_root_verified_authority_port_chirho() {
    let service_chirho = production_file_chirho(APP_REMOVAL_SERVICE_CHIRHO);
    for required_chirho in [
        "trait AppHeadRemovalAuthorityPortChirho",
        "port_chirho.verified_app_records_chirho(",
        "port_chirho.append_signed_app_undeploy_record_unlocked_chirho(",
        "port_chirho.require_applied_historical_app_head_chirho(",
        "bind_caller_verified_prepared_head_removal_chirho(",
    ] {
        assert!(service_chirho.contains(required_chirho));
    }
    for forbidden_chirho in [
        "load_app_records_chirho(",
        "sign_message_chirho(",
        "verify_with_pubkey_chirho(",
        "cairn_chirho::",
    ] {
        assert!(
            !service_chirho.contains(forbidden_chirho),
            "app removal service bypasses its verified port through {forbidden_chirho}"
        );
    }
    let impls_chirho =
        production_source_lines_matching_chirho("impl AppHeadRemovalAuthorityPortChirho for")
            .into_iter()
            .map(|(file_chirho, _, _)| file_chirho)
            .collect::<Vec<_>>();
    assert_eq!(impls_chirho, vec![APP_ROOT_CHIRHO.to_string()]);
}

#[test]
fn app_model_transition_modules_stay_pure_chirho() {
    for path_chirho in [
        MODEL_POLICY_CHIRHO,
        MODEL_RECORDS_CHIRHO,
        MODEL_TRANSITION_CHIRHO,
    ] {
        let text_chirho = production_file_chirho(path_chirho);
        for forbidden_chirho in [
            "std::fs",
            "PathBuf",
            "sign_message_chirho(",
            "verify_with_pubkey_chirho(",
            "refs_chirho::",
            "seqlog_chirho::",
            "writer_head_chirho::",
            "append_",
        ] {
            assert!(
                !text_chirho.contains(forbidden_chirho),
                "pure app model module {path_chirho} contains {forbidden_chirho}"
            );
        }
    }
}

#[test]
fn subscribe_uses_exact_receipt_gated_app_selection_chirho() {
    let text_chirho = production_file_chirho(SUBSCRIPTION_CONTROL_CHIRHO);
    assert!(text_chirho.contains("verified_selected_app_record_chirho("));
    assert!(
        !text_chirho.contains("verified_app_records_chirho("),
        "Subscribe must not independently select a plausible app row"
    );
}
