// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const APP_ROUTE_ROOT_CHIRHO: &str = "src/app_runtime_chirho/app_chirho/app_route_chirho.rs";
const ROUTE_TRANSITION_CHIRHO: &str = "crates/runtime-chirho/cairn-app-control-chirho/src/lib.rs";
const ROUTE_DEPLOY_EVIDENCE_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/elected_app_route_deploy_chirho.rs";
const ROUTE_DEPLOY_ELECTED_TESTS_CHIRHO: &str =
    "src/app_runtime_chirho/app_chirho/app_tests_chirho/elected_app_route_deploy_tests_chirho.rs";
const ROUTE_REMOVAL_CHIRHO: &str =
    "crates/runtime-chirho/cairn-app-control-chirho/src/app_route_head_removal_chirho.rs";
const MODEL_ROUTE_TRANSITION_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_route_head_transition_chirho.rs";
const MODEL_ROUTE_RECORDS_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_control_plane_records_chirho.rs";
const MODEL_PARAMS_POLICY_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_params_policy_chirho.rs";
const SUBSCRIPTION_CONTROL_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/lib.rs";

fn production_file_chirho(path_chirho: &str) -> String {
    let text_chirho = std::fs::read_to_string(workspace_root_chirho().join(path_chirho)).unwrap();
    production_text_chirho(&text_chirho).to_string()
}

#[test]
fn route_v2_keeps_state_verify_recover_append_complete_order_chirho() {
    let root_chirho = production_file_chirho(APP_ROUTE_ROOT_CHIRHO);
    let service_chirho = production_file_chirho(ROUTE_TRANSITION_CHIRHO);
    let evidence_chirho = production_file_chirho(ROUTE_DEPLOY_EVIDENCE_CHIRHO);
    let root_deploy_start_chirho = root_chirho
        .find("fn deploy_app_route_with_request_body_policy_and_authority_chirho(")
        .unwrap();
    let root_deploy_chirho = &root_chirho[root_deploy_start_chirho..];
    let validate_parent_chirho = root_deploy_chirho
        .find("validate_app_route_deploy_chirho(")
        .unwrap();
    let local_delegate_chirho = root_deploy_chirho
        .find("deploy_app_route_authority_chirho(")
        .unwrap();
    let elected_delegate_chirho = root_deploy_chirho
        .find("deploy_app_route_authority_with_head_transition_authority_chirho(")
        .unwrap();
    assert!(validate_parent_chirho < local_delegate_chirho);
    assert!(validate_parent_chirho < elected_delegate_chirho);

    let dispatcher_start_chirho = service_chirho
        .find("fn deploy_app_route_authority_inner_chirho<")
        .unwrap();
    let local_start_chirho = service_chirho
        .find("fn deploy_app_route_authority_local_unlocked_chirho<")
        .unwrap();
    let dispatcher_chirho = &service_chirho[dispatcher_start_chirho..local_start_chirho];
    assert!(dispatcher_chirho.contains("dispatch_head_transition_chirho("));
    assert!(!dispatcher_chirho.contains("with_head_transition_scope_chirho("));

    let local_end_chirho = service_chirho[local_start_chirho..]
        .find("pub fn verified_selected_app_route_record_chirho<")
        .map(|offset_chirho| local_start_chirho + offset_chirho)
        .unwrap();
    let local_chirho = &service_chirho[local_start_chirho..local_end_chirho];
    for required_chirho in [
        "recover_app_route_head_removal_unlocked_chirho(",
        "recover_app_route_head_unlocked_chirho(",
        "verified_app_route_records_chirho(",
        "app_route_previous_is_verified_chirho(",
        "store_app_route_authority_state_chirho(",
        "append_app_route_deploy_record_unlocked_chirho(",
        "verified_route_record_at_seq_chirho(",
        "complete_verified_app_route_record_unlocked_chirho(",
    ] {
        assert!(local_chirho.contains(required_chirho));
    }
    let removal_recover_chirho = local_chirho
        .find("recover_app_route_head_removal_unlocked_chirho(")
        .unwrap();
    let recover_chirho = local_chirho
        .find("recover_app_route_head_unlocked_chirho(")
        .unwrap();
    let verify_chirho = local_chirho[recover_chirho..]
        .find("verified_app_route_records_chirho(")
        .unwrap()
        + recover_chirho;
    let store_chirho = local_chirho[verify_chirho..]
        .find("store_app_route_authority_state_chirho(")
        .unwrap()
        + verify_chirho;
    let append_chirho = local_chirho[store_chirho..]
        .find("append_app_route_deploy_record_unlocked_chirho(")
        .unwrap()
        + store_chirho;
    let complete_chirho = local_chirho[append_chirho..]
        .find("complete_verified_app_route_record_unlocked_chirho(")
        .unwrap()
        + append_chirho;
    assert!(removal_recover_chirho < recover_chirho && recover_chirho < verify_chirho);
    assert!(verify_chirho < store_chirho);
    assert!(
        store_chirho < append_chirho && append_chirho < complete_chirho,
        "the LOCAL route era must keep recovery before verification and the new append; if local \
         recovery is retired, replace this arm with the migration that makes pending local rows \
         unreachable rather than weakening the ordering"
    );

    for forbidden_chirho in [
        "recover_app_route_head_unlocked_chirho(",
        "recover_app_route_head_removal_unlocked_chirho(",
    ] {
        assert!(
            !evidence_chirho.contains(forbidden_chirho),
            "the ELECTED route era must named-refuse pending recovery rather than mutate through \
             {forbidden_chirho}; a future elected retry-repair path belongs after authority \
             admission, never in read-only PREPARE"
        );
    }
    assert!(
        evidence_chirho.contains("refuse_pending_app_route_transition_chirho(")
            && evidence_chirho.contains("AppRouteDeployPendingHeadTransitionChirho"),
        "the ELECTED route era must retain the pending-transition refusal identity until a \
         post-authority recovery design replaces it"
    );
    let elected_tests_chirho = production_file_chirho(ROUTE_DEPLOY_ELECTED_TESTS_CHIRHO);
    let pending_test_start_chirho = elected_tests_chirho
        .find("fn pending_route_transition_named_refuses_without_prepare_recovery_chirho()")
        .unwrap();
    let pending_test_end_chirho = elected_tests_chirho[pending_test_start_chirho..]
        .find(
            "fn prior_route_tombstone_named_refuses_without_placeholder_settlement_proof_chirho()",
        )
        .map(|offset_chirho| pending_test_start_chirho + offset_chirho)
        .unwrap();
    let pending_test_chirho =
        &elected_tests_chirho[pending_test_start_chirho..pending_test_end_chirho];
    for required_chirho in [
        "let before_chirho = route_durable_counts_chirho(",
        "before_chirho.records_chirho > 0",
        "AppRouteDeployPendingHeadTransitionChirho",
        "!error_chirho.contains(\"AppRouteDeployHeadRemovalSettlementRequiredChirho\")",
        "route_durable_counts_chirho(&root_chirho, \"pendingrouteapp\", \"submit\")",
        "before_chirho,",
    ] {
        assert!(
            pending_test_chirho.contains(required_chirho),
            "the ELECTED pending-transition arm lost its non-vacuous pre-state/refusal proof: \
             {required_chirho}; preserve the snapshot comparison until an authorized retry-repair \
             test replaces this refusal"
        );
    }
    let prepare_start_chirho = evidence_chirho
        .find("pub(super) fn prepare_elected_app_route_deploy_chirho<")
        .unwrap();
    let commit_start_chirho = evidence_chirho
        .find("pub(super) fn commit_elected_app_route_deploy_chirho<")
        .unwrap();
    let prepare_chirho = &evidence_chirho[prepare_start_chirho..commit_start_chirho];
    let prepare_markers_chirho = [
        "snapshot_chirho()",
        "capture_mutable_state_chirho(root_chirho)",
        "validate_app_route_deploy_evidence_chirho(",
        "verified_app_route_records_chirho(",
        "refuse_existing_app_route_removal_chirho(",
        "refuse_pending_app_route_transition_chirho(",
        "app_route_ref_head_chirho(",
        "store_app_route_authority_state_chirho(",
        "get_object_chirho(root_chirho, &state_hash_chirho)",
        "observe_prepared_fence_lower_bound_chirho(",
        "sign_app_route_record_with_key_possession_chirho(",
        "bind_caller_verified_head_transition_from_prepared_fence_chirho(",
    ];
    let mut prior_chirho = 0usize;
    for marker_chirho in prepare_markers_chirho {
        let next_chirho = prepare_chirho[prior_chirho..]
            .find(marker_chirho)
            .map(|offset_chirho| prior_chirho + offset_chirho)
            .unwrap_or_else(|| panic!("elected route PREPARE lost {marker_chirho}"));
        assert!(next_chirho >= prior_chirho);
        prior_chirho = next_chirho;
    }

    let commit_end_chirho = evidence_chirho[commit_start_chirho..]
        .find("fn refuse_existing_app_route_removal_chirho(")
        .map(|offset_chirho| commit_start_chirho + offset_chirho)
        .unwrap();
    let commit_chirho = &evidence_chirho[commit_start_chirho..commit_end_chirho];
    let commit_markers_chirho = [
        "preflight_head_transition_chirho(",
        "require_current_prepare_state_chirho(",
        "current_root_signing_key_id_chirho(",
        "promote_chirho(",
        "append_recovered_jsonl_unlocked_chirho(",
        "complete_head_transition_chirho(",
    ];
    let mut prior_chirho = 0usize;
    for marker_chirho in commit_markers_chirho {
        let next_chirho = commit_chirho[prior_chirho..]
            .find(marker_chirho)
            .map(|offset_chirho| prior_chirho + offset_chirho)
            .unwrap_or_else(|| panic!("elected route COMMIT lost {marker_chirho}"));
        assert!(next_chirho >= prior_chirho);
        prior_chirho = next_chirho;
    }
}

#[test]
fn route_raw_ref_state_store_and_selected_consumers_stay_narrow_chirho() {
    // The per-file raw-route-ref occurrence MAP freeze and the state-store site count (==3) freeze
    // were demoted to the advisory structure report; the state-store confinement (all in the route
    // transition module), the no-raw-head-commit ban, and the receipt-gated-consumer claims stay RED.
    let state_store_sites_chirho =
        production_source_lines_matching_chirho("store_app_route_authority_state_chirho(");
    assert!(state_store_sites_chirho.iter().all(|(file_chirho, _, _)| {
        file_chirho == ROUTE_TRANSITION_CHIRHO || file_chirho == ROUTE_DEPLOY_EVIDENCE_CHIRHO
    }));
    assert!(
        production_source_lines_matching_chirho("refs_chirho::commit_head_chirho(")
            .into_iter()
            .all(|(file_chirho, _, _)| {
                file_chirho != ROUTE_TRANSITION_CHIRHO && file_chirho != ROUTE_REMOVAL_CHIRHO
            }),
        "app-route surfaces must move heads through the signed transition protocol, not raw head commits"
    );

    let subscribe_chirho = production_file_chirho(SUBSCRIPTION_CONTROL_CHIRHO);
    assert!(subscribe_chirho.contains("verified_selected_app_route_record_chirho("));
    assert!(!subscribe_chirho.contains("verified_app_route_records_chirho("));
    assert!(!subscribe_chirho.contains("resolve_app_route_chirho("));
}

#[test]
fn route_authority_state_is_control_plane_only_and_cas_verified_chirho() {
    let records_chirho = production_file_chirho(MODEL_ROUTE_RECORDS_CHIRHO);
    let state_start_chirho = records_chirho
        .find("pub struct AppRouteAuthorityStateChirho")
        .unwrap();
    let state_chirho = &records_chirho[state_start_chirho..];
    for required_chirho in [
        "schema_chirho",
        "app_chirho",
        "route_chirho",
        "owner_principal_chirho",
        "dag_chirho",
        "action_chirho",
        "request_body_policy_chirho",
    ] {
        assert!(state_chirho.contains(required_chirho));
    }
    for forbidden_chirho in ["Path", "path_chirho", "private", "payload", "body_chirho"] {
        assert!(!state_chirho.contains(forbidden_chirho));
    }
    let adapter_chirho = production_file_chirho(ROUTE_TRANSITION_CHIRHO);
    for required_chirho in [
        "put_object_chirho(root_chirho, state_chirho)",
        "get_object_chirho(root_chirho, &hash_chirho)",
        "stored_chirho != expected_chirho",
        "verified_head_transition_receipt_chirho(",
    ] {
        assert!(adapter_chirho.contains(required_chirho));
    }
}

#[test]
fn route_undeploy_recovers_positive_head_before_receipted_removal_chirho() {
    let root_chirho = production_file_chirho(APP_ROUTE_ROOT_CHIRHO);
    let undeploy_chirho = root_chirho
        .find("pub fn undeploy_app_route_chirho(")
        .unwrap();
    let body_chirho = &root_chirho[undeploy_chirho..];
    let recover_chirho = body_chirho
        .find("recover_app_route_head_unlocked_chirho(")
        .unwrap();
    let remove_chirho = body_chirho[recover_chirho..]
        .find("undeploy_app_route_head_unlocked_chirho(")
        .unwrap()
        + recover_chirho;
    assert!(recover_chirho < remove_chirho);
    let service_chirho = production_file_chirho(ROUTE_REMOVAL_CHIRHO);
    for required_chirho in [
        "app_route_ref_target_from_record_chirho(",
        "require_applied_app_route_record_chirho(",
        "append_signed_app_route_undeploy_record_unlocked_chirho(",
        "append_caller_verified_prepared_head_removal_unlocked_chirho(",
        "complete_head_removal_unlocked_chirho(",
    ] {
        assert!(service_chirho.contains(required_chirho));
    }
    assert!(production_source_lines_matching_chirho("head_removal_bridge_chirho").is_empty());
}

#[test]
fn route_model_and_params_policy_modules_stay_pure_chirho() {
    for path_chirho in [MODEL_ROUTE_TRANSITION_CHIRHO, MODEL_PARAMS_POLICY_CHIRHO] {
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
            assert!(!text_chirho.contains(forbidden_chirho));
        }
    }
}

#[test]
fn app_control_service_depends_downward_and_only_root_implements_its_port_chirho() {
    let manifest_chirho = std::fs::read_to_string(
        workspace_root_chirho().join("crates/runtime-chirho/cairn-app-control-chirho/Cargo.toml"),
    )
    .unwrap();
    for required_chirho in [
        "blake3",
        "cairn-core-chirho",
        "cairn-durable-chirho",
        "cairn-head-removal-chirho",
        "cairn-model-app-chirho",
        "cairn-seqlog-chirho",
        "cairn-writer-head-chirho",
    ] {
        assert!(manifest_chirho.contains(required_chirho));
    }
    for forbidden_chirho in [
        "cairn-chirho =",
        "cairn-cli-chirho",
        "cairn-serve-runtime-chirho",
        "cairn-signer-chirho",
        "axum",
        "clap",
        "stripe",
    ] {
        assert!(!manifest_chirho.contains(forbidden_chirho));
    }
    let service_chirho = production_file_chirho(ROUTE_TRANSITION_CHIRHO);
    for required_chirho in [
        "trait AppRouteAuthorityPortChirho",
        "append_signed_app_route_undeploy_record_unlocked_chirho(",
        "port_chirho.verified_app_route_records_chirho(",
        "port_chirho.sign_app_route_record_chirho(",
    ] {
        assert!(service_chirho.contains(required_chirho));
    }
    let evidence_chirho = production_file_chirho(ROUTE_DEPLOY_EVIDENCE_CHIRHO);
    for required_chirho in [
        "port_chirho.validate_app_route_deploy_evidence_chirho(",
        "port_chirho.verified_app_route_records_chirho(",
        "sign_app_route_record_with_key_possession_chirho(",
        "port_chirho.current_root_signing_key_id_chirho(",
    ] {
        assert!(evidence_chirho.contains(required_chirho));
    }
    for forbidden_chirho in [
        "cairn_head_removal_chirho::",
        "load_app_route_records_chirho(",
        "verify_with_pubkey_chirho(",
        "sign_message_chirho(",
        "sign_message_with_existing_key_chirho(",
        "cairn_chirho::",
    ] {
        assert!(!service_chirho.contains(forbidden_chirho));
    }
    let impls_chirho =
        production_source_lines_matching_chirho("impl AppRouteAuthorityPortChirho for")
            .into_iter()
            .map(|(file_chirho, _, _)| file_chirho)
            .collect::<Vec<_>>();
    assert_eq!(impls_chirho, vec![APP_ROUTE_ROOT_CHIRHO.to_string()]);

    let removal_chirho = production_file_chirho(ROUTE_REMOVAL_CHIRHO);
    for forbidden_chirho in [
        "load_app_route_records_chirho(",
        "verify_with_pubkey_chirho(",
        "sign_message_chirho(",
        "cairn_chirho::",
    ] {
        assert!(!removal_chirho.contains(forbidden_chirho));
    }
}
