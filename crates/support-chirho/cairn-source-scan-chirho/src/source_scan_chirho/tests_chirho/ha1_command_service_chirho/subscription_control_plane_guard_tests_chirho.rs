// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

const SUBSCRIPTION_CONTROL_PLANE_CRATE_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho";
const SUBSCRIPTION_CONTROL_PLANE_LIB_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/lib.rs";
const SUBSCRIPTION_CONTROL_PLANE_DIGESTS_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-control-plane-chirho/src/digests_chirho.rs";
const ROOT_APP_CONTROL_CHIRHO: &str = "src/app_runtime_chirho/app_chirho.rs";
const ROOT_REVIEW_CONTROL_CHIRHO: &str = "src/governance_flows_chirho/review_chirho/mod.rs";
const ROOT_SOURCE_REVIEW_CHIRHO: &str = "src/app_runtime_chirho/app_source_manifest_chirho.rs";
const MODEL_APP_OWNER_FOLD_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_record_fold_chirho.rs";

fn forbidden_control_plane_tokens_chirho() -> [&'static str; 28] {
    [
        "load_app_records_chirho(",
        "load_app_route_records_chirho(",
        "load_review_records_chirho(",
        "app_owner_chirho(",
        "for_display_chirho",
        "std::fs",
        "fs::write(",
        "File::create(",
        "OpenOptions",
        "store_chirho::put",
        "append_",
        "deploy_app_chirho(",
        "deploy_app_route_chirho(",
        "undeploy_app_chirho(",
        "undeploy_app_route_chirho(",
        "set_branch_chirho(",
        "commit_head_chirho(",
        "remove_branch_chirho(",
        "sign_message_chirho(",
        "signer_chirho::",
        "verify_with_",
        "verify_signature",
        "transfer_chirho(",
        "settle_",
        "provider_chirho",
        "append_gate1_authority_record_chirho(",
        "SseChirho",
        "WebSocketChirho",
    ]
}

fn forbidden_control_plane_sites_chirho(text_chirho: &str) -> Vec<&'static str> {
    forbidden_control_plane_tokens_chirho()
        .into_iter()
        .filter(|token_chirho| text_chirho.contains(token_chirho))
        .collect()
}

fn function_slice_chirho<'a>(text_chirho: &'a str, signature_chirho: &str) -> &'a str {
    let start_chirho = text_chirho
        .find(signature_chirho)
        .unwrap_or_else(|| panic!("missing function signature {signature_chirho}"));
    let after_start_chirho = &text_chirho[start_chirho + signature_chirho.len()..];
    let end_chirho = after_start_chirho
        .find("\npub fn ")
        .unwrap_or(after_start_chirho.len());
    &text_chirho[start_chirho..start_chirho + signature_chirho.len() + end_chirho]
}

#[test]
fn subscription_control_plane_service_uses_only_exact_verified_reads_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_root_chirho = root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_CRATE_CHIRHO);
    let manifest_chirho = std::fs::read_to_string(crate_root_chirho.join("Cargo.toml")).unwrap();
    assert!(manifest_chirho.contains("cairn-chirho ="));
    assert!(manifest_chirho.contains("constant_time_eq = \"=0.4.2\""));
    for forbidden_dependency_chirho in ["cairn-cli-chirho", "clap"] {
        assert!(
            !manifest_chirho.contains(forbidden_dependency_chirho),
            "subscription control-plane witness must not depend on {forbidden_dependency_chirho}"
        );
    }

    let source_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_LIB_CHIRHO)).unwrap();
    let digest_source_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_DIGESTS_CHIRHO))
            .unwrap();
    let production_chirho = format!(
        "{}\n{}",
        production_text_chirho(&source_chirho),
        production_text_chirho(&digest_source_chirho)
    );
    let offenders_chirho = forbidden_control_plane_sites_chirho(&production_chirho);
    assert!(
        offenders_chirho.is_empty(),
        "subscription control-plane witness must remain read-only and verified-loader-only: {offenders_chirho:?}"
    );
    for required_chirho in [
        "verified_selected_app_record_chirho(",
        "verified_selected_app_route_record_chirho(",
        "verified_review_records_chirho(",
        "load_app_source_review_report_for_promotion_chirho(",
        "existing_pubkey_hex_chirho(root_chirho)",
        "root_identity_digest_from_public_key_chirho(&root_public_key_chirho)",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "subscription control-plane witness must retain exact verified evidence call {required_chirho}"
        );
    }

    let source_review_chirho =
        std::fs::read_to_string(root_chirho.join(ROOT_SOURCE_REVIEW_CHIRHO)).unwrap();
    let promotion_loader_chirho = function_slice_chirho(
        &source_review_chirho,
        "pub fn load_app_source_review_report_for_promotion_chirho(",
    );
    assert!(
        promotion_loader_chirho.contains("validate_reviewed_source_report_for_promotion_chirho("),
        "canonical source-report loader must retain promotion validation"
    );
    assert!(
        source_review_chirho.contains("validate_app_source_review_declaration_binding_chirho("),
        "promotion validation must retain the typed manifest/declaration binding"
    );
}

#[test]
fn subscription_binding_digests_stay_opaque_domain_separated_and_constant_time_chirho() {
    let root_chirho = workspace_root_chirho();
    let digest_source_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_DIGESTS_CHIRHO))
            .unwrap();
    for domain_chirho in [
        "subscribe-root-identity-v1-chirho",
        "subscribe-app-identity-v1-chirho",
        "subscribe-route-identity-v1-chirho",
        "subscribe-view-identity-v1-chirho",
        "subscribe-principal-identity-v1-chirho",
        "subscribe-dependency-set-v1-chirho",
        "subscribe-generation-v1-chirho",
        "subscribe-control-plane-evidence-v1-chirho",
        "subscribe-authorization-binding-v1-chirho",
    ] {
        assert_eq!(
            digest_source_chirho.matches(domain_chirho).count(),
            1,
            "Subscribe digest domain must be declared exactly once: {domain_chirho}"
        );
    }
    for required_chirho in [
        "store_chirho::hash_object_chirho(",
        "GATE1_AUTHORITY_SOURCE_KIND_CHIRHO",
        "witness_chirho.declaration_chirho.declaration_chirho",
        "witness_chirho.declaration_chirho.dependencies_chirho",
        "witness_chirho.target_active_dag_chirho",
        "witness_chirho.root_identity_digest_chirho",
        "witness_chirho.app_record_chirho",
        "witness_chirho.route_record_chirho",
        "witness_chirho.review_record_chirho",
        "witness_chirho.source_review_report_chirho",
        "witness_chirho.source_review_report_hash_chirho",
        "witness_chirho.effective_manifest_hash_chirho",
    ] {
        assert!(
            digest_source_chirho.contains(required_chirho),
            "Subscribe digest derivation must retain exact input {required_chirho}"
        );
    }
    for forbidden_chirho in [
        "serde",
        "Serialize",
        "Deserialize",
        "Path",
        "pub fn as_",
        "pub fn raw_",
        "pub fn bytes_",
        "#[derive(PartialEq",
        "#[derive(Eq",
        "impl PartialEq for SubscriptionBindingDigestsChirho",
        "impl Eq for SubscriptionBindingDigestsChirho",
    ] {
        assert!(
            !digest_source_chirho.contains(forbidden_chirho),
            "opaque Subscribe digests must not gain {forbidden_chirho}"
        );
    }
    let comparator_chirho = function_slice_chirho(
        &digest_source_chirho,
        "fn constant_time_digest_matches_chirho(",
    );
    assert!(comparator_chirho.contains("constant_time_eq::constant_time_eq("));
    assert!(
        !comparator_chirho.contains(" == "),
        "digest comparison must never use ordinary equality"
    );
    let bundle_start_chirho = digest_source_chirho
        .find("pub struct SubscriptionBindingDigestsChirho {")
        .expect("opaque digest bundle exists");
    let bundle_tail_chirho = &digest_source_chirho[bundle_start_chirho..];
    let bundle_end_chirho = bundle_tail_chirho
        .find("\n}\n\nimpl SubscriptionBindingDigestsChirho")
        .expect("opaque digest bundle ends before its comparison methods");
    assert_eq!(
        bundle_tail_chirho[..bundle_end_chirho]
            .matches("\n    pub ")
            .count(),
        0
    );
}

#[test]
fn subscription_control_plane_witness_stays_private_and_non_renderable_chirho() {
    let root_chirho = workspace_root_chirho();
    let source_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_CONTROL_PLANE_LIB_CHIRHO)).unwrap();
    let struct_start_chirho = source_chirho
        .find("pub struct VerifiedSubscriptionControlPlaneWitnessChirho {")
        .expect("verified witness struct exists");
    let struct_tail_chirho = &source_chirho[struct_start_chirho..];
    let struct_end_chirho = struct_tail_chirho
        .find("\n}\n\nimpl VerifiedSubscriptionControlPlaneWitnessChirho")
        .expect("verified witness struct ends before its private impl");
    let struct_chirho = &struct_tail_chirho[..struct_end_chirho];
    assert_eq!(
        struct_chirho.matches("\n    pub ").count(),
        0,
        "verified witness fields must stay private"
    );
    assert_eq!(
        source_chirho
            .matches("let witness_chirho = VerifiedSubscriptionControlPlaneWitnessChirho {")
            .count(),
        1,
        "the mint path must remain the sole production witness struct-literal site"
    );
    for forbidden_chirho in [
        "#[derive(Debug",
        "impl Debug for VerifiedSubscriptionControlPlaneWitnessChirho",
        "impl Default for VerifiedSubscriptionControlPlaneWitnessChirho",
        "Serialize for VerifiedSubscriptionControlPlaneWitnessChirho",
        "Deserialize for VerifiedSubscriptionControlPlaneWitnessChirho",
        "pub fn new_chirho(",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "verified witness must not gain construction/rendering surface {forbidden_chirho}"
        );
    }
    let public_mint_tail_chirho = function_slice_chirho(
        &source_chirho,
        "pub fn current_subscription_control_plane_witness_chirho(",
    );
    let public_mint_end_chirho = public_mint_tail_chirho
        .find("\nfn try_current_subscription_control_plane_witness_chirho(")
        .expect("public generic mint ends before the private detailed validator");
    let public_mint_chirho = &public_mint_tail_chirho[..public_mint_end_chirho];
    assert!(public_mint_chirho.contains("Err(_)"));
    assert!(public_mint_chirho.contains("ResnapshotRequiredChirho"));
    assert!(
        !public_mint_chirho.contains("-> Result<"),
        "public mint must expose one generic resnapshot outcome, not detailed validation errors"
    );
}

#[test]
fn exact_verified_vector_helpers_keep_old_wrappers_delegating_chirho() {
    let root_chirho = workspace_root_chirho();
    let app_chirho = std::fs::read_to_string(root_chirho.join(ROOT_APP_CONTROL_CHIRHO)).unwrap();
    let verified_records_chirho =
        function_slice_chirho(&app_chirho, "pub fn verified_app_records_chirho(");
    assert!(verified_records_chirho.contains("load_app_records_chirho(root_chirho)?"));
    assert!(verified_records_chirho.contains("verify_app_records_chirho("));
    for wrapper_chirho in [
        "pub fn verified_app_owner_chirho(",
        "pub fn verified_app_owners_chirho(",
        "pub fn verified_app_deploy_dags_chirho(",
        "pub fn verify_apps_chirho(",
    ] {
        let wrapper_body_chirho = function_slice_chirho(&app_chirho, wrapper_chirho);
        assert!(
            wrapper_body_chirho.contains("verified_app_records_chirho("),
            "existing app wrapper {wrapper_chirho} must delegate to the exact verified vector"
        );
        assert!(!wrapper_body_chirho.contains("load_app_records_chirho("));
    }
    let owner_wrapper_chirho =
        function_slice_chirho(&app_chirho, "pub fn verified_app_owners_chirho(");
    assert!(owner_wrapper_chirho.contains("verified_app_owner_map_chirho("));
    let owner_fold_chirho =
        std::fs::read_to_string(root_chirho.join(MODEL_APP_OWNER_FOLD_CHIRHO)).unwrap();
    assert!(owner_fold_chirho.contains("for record_chirho in records_chirho"));
    assert!(owner_fold_chirho.contains("owners_chirho.insert("));
    for forbidden_chirho in [
        "cairn_chirho::",
        "std::fs",
        "Path",
        "load_",
        "verify_",
        "write(",
        "append_",
    ] {
        assert!(
            !owner_fold_chirho.contains(forbidden_chirho),
            "pure app owner fold cannot read, verify, or write through {forbidden_chirho}"
        );
    }

    let review_chirho =
        std::fs::read_to_string(root_chirho.join(ROOT_REVIEW_CONTROL_CHIRHO)).unwrap();
    let verified_reviews_chirho =
        function_slice_chirho(&review_chirho, "pub fn verified_review_records_chirho(");
    for required_chirho in [
        "app_chirho::verify_apps_chirho(root_chirho)?",
        "effect_pricing_chirho::verify_price_books_chirho(root_chirho)?",
        "validate_review_source_evidence_chirho(",
        "validate_review_policy_envelope_evidence_chirho(",
        "verify_with_pubkey_chirho(",
    ] {
        assert!(
            verified_reviews_chirho.contains(required_chirho),
            "exact review vector must retain validation {required_chirho}"
        );
    }
    for wrapper_chirho in [
        "pub fn verify_review_records_chirho(",
        "pub fn latest_promoted_source_review_record_chirho(",
    ] {
        let wrapper_body_chirho = function_slice_chirho(&review_chirho, wrapper_chirho);
        assert!(
            wrapper_body_chirho.contains("verified_review_records_chirho(root_chirho)?"),
            "existing review wrapper {wrapper_chirho} must delegate to the exact verified vector"
        );
        assert!(!wrapper_body_chirho.contains("load_review_records_chirho("));
    }
}

#[test]
fn subscription_control_plane_guard_fixture_catches_raw_review_loader_chirho() {
    let planted_chirho = "let records_chirho = load_review_records_chirho(root_chirho)?;";
    assert_eq!(
        forbidden_control_plane_sites_chirho(planted_chirho),
        vec!["load_review_records_chirho("]
    );
}
