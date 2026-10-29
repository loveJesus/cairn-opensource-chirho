// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

const SUBSCRIPTION_VIEW_REVIEW_CRATE_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-view-review-chirho";
const SUBSCRIPTION_VIEW_REVIEW_LIB_CHIRHO: &str =
    "crates/services-chirho/cairn-subscription-view-review-chirho/src/lib.rs";
const ROOT_REVIEW_CHIRHO: &str = "src/governance_flows_chirho/review_chirho/mod.rs";

fn forbidden_service_tokens_chirho() -> [&'static str; 16] {
    [
        "cairn_chirho::",
        "cairn-cli-chirho",
        "clap",
        "CommandChirho",
        "std::fs",
        "std::path",
        "PathBuf",
        "sign_message_chirho",
        "append_",
        "refs_chirho",
        "transfer_chirho",
        "settle_",
        "provider_chirho",
        "cairn_subscribe_chirho",
        "authority_log",
        "write_chirho(",
    ]
}

fn forbidden_service_sites_chirho(text_chirho: &str) -> Vec<&'static str> {
    forbidden_service_tokens_chirho()
        .into_iter()
        .filter(|token_chirho| text_chirho.contains(token_chirho))
        .collect()
}

#[test]
fn subscription_view_review_service_stays_below_root_and_cli_chirho() {
    let root_chirho = workspace_root_chirho();
    let cargo_chirho = std::fs::read_to_string(
        root_chirho
            .join(SUBSCRIPTION_VIEW_REVIEW_CRATE_CHIRHO)
            .join("Cargo.toml"),
    )
    .unwrap();
    for required_chirho in ["cairn-core-chirho", "cairn-model-app-chirho", "anyhow"] {
        assert!(
            cargo_chirho.contains(required_chirho),
            "subscription-view review service must keep its low dependency {required_chirho}"
        );
    }
    for forbidden_chirho in ["cairn-chirho =", "cairn-cli-chirho", "clap"] {
        assert!(
            !cargo_chirho.contains(forbidden_chirho),
            "subscription-view review service must not depend upward on {forbidden_chirho}"
        );
    }

    let service_chirho =
        std::fs::read_to_string(root_chirho.join(SUBSCRIPTION_VIEW_REVIEW_LIB_CHIRHO)).unwrap();
    let production_chirho = production_text_chirho(&service_chirho);
    let offenders_chirho = forbidden_service_sites_chirho(&production_chirho);
    assert!(
        offenders_chirho.is_empty(),
        "subscription-view review service must remain pure policy below root/CLI/write surfaces: {offenders_chirho:?}"
    );
    for required_chirho in [
        "SubscriptionViewReviewEvidencePortChirho",
        "load_effective_manifest_chirho",
        "load_declaration_chirho",
        "verified_module_evidence_chirho",
    ] {
        assert!(
            production_chirho.contains(required_chirho),
            "subscription-view review service must keep its verified-evidence port: {required_chirho}"
        );
    }
}

#[test]
fn subscription_view_review_common_promote_loader_keeps_binding_guard_chirho() {
    let root_chirho = workspace_root_chirho();
    let review_chirho = std::fs::read_to_string(root_chirho.join(ROOT_REVIEW_CHIRHO)).unwrap();
    let loader_start_chirho = review_chirho
        .find("fn load_source_review_report_chirho(")
        .expect("common RootReviewPort source-report loader exists");
    let loader_chirho = &review_chirho[loader_start_chirho..];
    let loader_end_chirho = loader_chirho
        .find("fn validate_effective_source_manifest_chirho(")
        .expect("source-report loader ends before effective-manifest validator");
    let loader_chirho = &loader_chirho[..loader_end_chirho];
    assert!(
        loader_chirho.contains("validate_app_source_review_declaration_binding_chirho("),
        "the common governance source-report loader must validate subscription declarations before promote"
    );
}

#[test]
fn subscription_view_review_guard_fixture_catches_upward_store_import_chirho() {
    let planted_chirho = "use cairn_chirho::store_chirho;";
    let offenders_chirho = forbidden_service_sites_chirho(planted_chirho);
    assert_eq!(offenders_chirho, vec!["cairn_chirho::"]);
}
