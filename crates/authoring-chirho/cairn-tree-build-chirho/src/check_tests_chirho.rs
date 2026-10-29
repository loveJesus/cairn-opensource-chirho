// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The checker passes the real demo tree clean and fails synthetic broken trees with stable codes.

use super::*;
use crate::emit_chirho::{
    load_app_descriptor_chirho, AppAssetChirho, AppDescriptorChirho, AppRootChirho,
};
use crate::tree_chirho::walk_app_tree_chirho;
use std::os::unix::fs::symlink as symlink_chirho;

fn codes_chirho(findings_chirho: &[FindingChirho]) -> Vec<String> {
    findings_chirho
        .iter()
        .map(|f_chirho| f_chirho.code_chirho.clone())
        .collect()
}

fn broken_unsatisfied_tree_chirho() -> PathBuf {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-json-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let role_chirho = add_impl_role_chirho(&dag_chirho, "a_chirho");
    std::fs::create_dir_all(role_chirho.join("in-x-message_v1-chirho")).unwrap();
    tmp_chirho
}

fn report_for_root_chirho(root_chirho: &Path) -> CheckReportChirho {
    let tree_chirho = walk_app_tree_chirho(root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(root_chirho).ok();
    check_report_chirho(check_app_tree_with_descriptor_chirho(
        &tree_chirho,
        descriptor_chirho.as_ref(),
    ))
}

/// Every checked-in example tree, so none of them can silently rot (the stale-link bug already
/// happened once and the checker caught it — this keeps it caught forever).
fn checked_in_example_roots_chirho() -> Vec<PathBuf> {
    let examples_chirho = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho");
    vec![
        examples_chirho.join("tree-contact-chirho"),
        examples_chirho.join("tree-pizzeria-chirho"),
        examples_chirho.join("tree-template-landing-chirho"),
    ]
}

#[test]
fn check_report_json_is_schema_tagged_and_stable_chirho() {
    let tmp_chirho = broken_unsatisfied_tree_chirho();
    let report_chirho = report_for_root_chirho(&tmp_chirho);
    assert_eq!(report_chirho.schema_chirho, CHECK_REPORT_SCHEMA_CHIRHO);
    assert!(!report_chirho.clean_chirho);
    assert_eq!(report_chirho.finding_count_chirho, 2);
    assert_eq!(
        codes_chirho(&report_chirho.findings_chirho),
        vec!["impl-dangling-chirho", "port-unsatisfied-chirho"]
    );
    let json_a_chirho = serde_json::to_value(&report_chirho).unwrap();
    let json_b_chirho = serde_json::to_value(report_for_root_chirho(&tmp_chirho)).unwrap();
    assert_eq!(json_a_chirho, json_b_chirho);
    assert_eq!(
        json_a_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some(CHECK_REPORT_SCHEMA_CHIRHO)
    );
    assert_eq!(
        json_a_chirho
            .get("findings_chirho")
            .and_then(|value_chirho| value_chirho.as_array())
            .and_then(|findings_chirho| findings_chirho.first())
            .and_then(|finding_chirho| finding_chirho.get("code_chirho"))
            .and_then(|code_chirho| code_chirho.as_str()),
        Some("impl-dangling-chirho")
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn checked_in_demo_trees_check_clean_chirho() {
    for root_chirho in checked_in_example_roots_chirho() {
        let findings_chirho = report_for_root_chirho(&root_chirho).findings_chirho;
        assert!(
            findings_chirho.is_empty(),
            "checked-in example {root_chirho:?} must check clean: {findings_chirho:?}"
        );
    }
}

/// Build a minimal one-dag tree skeleton under `root`, returning the dag dir.
fn scaffold_dag_chirho(root_chirho: &Path) -> PathBuf {
    let dag_chirho = root_chirho.join("dags_chirho/d_chirho");
    std::fs::create_dir_all(dag_chirho.join("surface_chirho")).unwrap();
    std::fs::create_dir_all(dag_chirho.join("nodes_chirho")).unwrap();
    dag_chirho
}

fn add_impl_role_chirho(dag_chirho: &Path, role_chirho: &str) -> PathBuf {
    let role_dir_chirho = dag_chirho.join("nodes_chirho").join(role_chirho);
    std::fs::create_dir_all(&role_dir_chirho).unwrap();
    // a bind: an impl symlink (target need not exist for binding detection).
    symlink_chirho(
        "../../../../src/x_chirho.rs",
        role_dir_chirho.join("x_chirho.rs"),
    )
    .unwrap();
    role_dir_chirho
}

fn add_resolving_impl_file_chirho(root_chirho: &Path) {
    write_resolving_impl_file_chirho(root_chirho, "// test impl placeholder\n");
}

fn write_resolving_impl_file_chirho(root_chirho: &Path, source_chirho: &str) {
    let src_chirho = root_chirho.join("src");
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(src_chirho.join("x_chirho.rs"), source_chirho).unwrap();
}

fn descriptor_with_assets_chirho(
    app_chirho: &str,
    asset_names_chirho: &[&str],
) -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: app_chirho.to_string(),
        owner_chirho: "owner/test-chirho".to_string(),
        package_chirho: "test-package-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            request_body_policy_chirho: None,
            dag_chirho: "d_chirho".to_string(),
            input_mode_chirho: "plain".to_string(),
            subject_chirho: None,
            safe_metadata_chirho: vec![],
            route_label_chirho: "home-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![],
        asset_chirho: asset_names_chirho
            .iter()
            .map(|name_chirho| AppAssetChirho {
                name_chirho: (*name_chirho).to_string(),
                path_chirho: format!("assets_chirho/{name_chirho}"),
                content_type_chirho: "text/css".to_string(),
            })
            .collect(),
    }
}

fn write_schema_chirho(root_chirho: &Path, type_chirho: &str, definition_chirho: &str) {
    let schema_dir_chirho = root_chirho.join("schemas_chirho");
    std::fs::create_dir_all(&schema_dir_chirho).unwrap();
    std::fs::write(
        schema_dir_chirho.join(format!("{type_chirho}-schema-chirho.toml")),
        format!(
            "schema_chirho = \"port-schema-v1-chirho\"\nname_chirho = \"{type_chirho}\"\ndefinition_chirho = \"{definition_chirho}\"\n"
        ),
    )
    .unwrap();
}

/// Add a blessed role whose binding is a `blessed-contract-chirho.toml` card with the given contents.
fn add_blessed_role_chirho(dag_chirho: &Path, role_chirho: &str, card_chirho: &str) -> PathBuf {
    let role_dir_chirho = dag_chirho.join("nodes_chirho").join(role_chirho);
    std::fs::create_dir_all(&role_dir_chirho).unwrap();
    std::fs::write(
        role_dir_chirho.join("blessed-contract-chirho.toml"),
        card_chirho,
    )
    .unwrap();
    role_dir_chirho
}

fn blessed_card_chirho(contract_chirho: &str, scope_chirho: &str, extra_chirho: &str) -> String {
    let contract_hash_chirho =
        crate::blessed_catalog_chirho::lookup_blessed_contract_chirho(contract_chirho)
            .expect("test contract exists")
            .contract_hash_chirho();
    format!(
        "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"{contract_chirho}\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"{scope_chirho}\"\nintent_chirho = \"Test the reviewed blessed contract.\"\n{extra_chirho}"
    )
}

#[test]
fn stale_same_app_asset_reference_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-stale-asset-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    write_resolving_impl_file_chirho(
        &tmp_chirho,
        "const CSS_CHIRHO: &str = \"/app-assets-chirho/demo-app-chirho/by-name-chirho/missing-chirho.css\";\n",
    );
    add_impl_role_chirho(&dag_chirho, "render_chirho");
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let descriptor_chirho =
        descriptor_with_assets_chirho("demo-app-chirho", &["present-chirho.css"]);
    let findings_chirho =
        check_app_tree_with_descriptor_chirho(&tree_chirho, Some(&descriptor_chirho));
    let finding_chirho = findings_chirho
        .iter()
        .find(|finding_chirho| finding_chirho.code_chirho == "stale-asset-reference-chirho")
        .unwrap_or_else(|| panic!("stale asset reference must be flagged: {findings_chirho:?}"));
    assert!(finding_chirho.where_chirho.contains("src/x_chirho.rs:1"));
    assert!(finding_chirho
        .expected_chirho
        .contains("missing-chirho.css"));
    assert!(finding_chirho.found_chirho.contains("missing-chirho.css"));
    assert!(finding_chirho.hint_chirho.contains("literal same-app"));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn asset_reference_check_ignores_by_hash_other_apps_and_unused_assets_chirho() {
    let tmp_chirho =
        std::env::temp_dir().join(format!("tb-asset-reference-scope-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    write_resolving_impl_file_chirho(
        &tmp_chirho,
        "const DECLARED_CHIRHO: &str = \"/app-assets-chirho/demo-app-chirho/by-name-chirho/present-chirho.css\";\n\
         const HASHED_CHIRHO: &str = \"/app-assets-chirho/demo-app-chirho/by-hash-chirho/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/present-chirho.css\";\n\
         const OTHER_APP_CHIRHO: &str = \"/app-assets-chirho/other-app-chirho/by-name-chirho/missing-chirho.css\";\n",
    );
    add_impl_role_chirho(&dag_chirho, "render_chirho");
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let descriptor_chirho = descriptor_with_assets_chirho(
        "demo-app-chirho",
        &["present-chirho.css", "unused-chirho.css"],
    );
    let findings_chirho =
        check_app_tree_with_descriptor_chirho(&tree_chirho, Some(&descriptor_chirho));
    assert!(
        !codes_chirho(&findings_chirho).contains(&"stale-asset-reference-chirho".to_string()),
        "declared, by-hash, other-app, and unused assets must not be stale-reference findings: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn incomplete_query_card_is_flagged_chirho() {
    // The advertised rule is "the checker fails closed on incomplete query cards", so a query card
    // missing caller_chirho or max_rows_chirho must surface a finding at the checker layer itself.
    let incomplete_cards_chirho = [
        // missing caller_chirho
        blessed_card_chirho("query", "orders-chirho", "max_rows_chirho = 50\n"),
        // missing max_rows_chirho
        blessed_card_chirho(
            "query",
            "orders-chirho",
            "caller_chirho = \"order-query-caller\"\n",
        ),
    ];
    for (i_chirho, card_chirho) in incomplete_cards_chirho.iter().enumerate() {
        let tmp_chirho = std::env::temp_dir().join(format!(
            "tb-query-incomplete-{}-{i_chirho}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_chirho);
        let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
        add_blessed_role_chirho(&dag_chirho, "q_chirho", card_chirho.as_str());
        let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            codes_chirho(&findings_chirho)
                .contains(&"blessed-card-incomplete-chirho".to_string()),
            "incomplete query card #{i_chirho} must surface blessed-card-incomplete-chirho: {findings_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp_chirho);
    }
}

#[test]
fn incomplete_llm_card_is_flagged_chirho() {
    // The llm contract requires scope + caller + positive max_tokens + positive max_price_per_token;
    // an incomplete llm card must surface blessed-card-incomplete at the checker layer, mirroring
    // the query coverage. Each card pins the correct catalog hash so it fails on the missing
    // capability field, not on the contract ref.
    let incomplete_cards_chirho = [
        // missing caller_chirho
        blessed_card_chirho(
            "llm",
            "summarize-chirho",
            "max_tokens_chirho = 4096\nmax_price_per_token_chirho = 2\n",
        ),
        // missing max_tokens_chirho
        blessed_card_chirho(
            "llm",
            "summarize-chirho",
            "caller_chirho = \"summary-caller-chirho\"\nmax_price_per_token_chirho = 2\n",
        ),
        // zero max_tokens_chirho
        blessed_card_chirho(
            "llm",
            "summarize-chirho",
            "caller_chirho = \"summary-caller-chirho\"\nmax_tokens_chirho = 0\nmax_price_per_token_chirho = 2\n",
        ),
        // missing max_price_per_token_chirho
        blessed_card_chirho(
            "llm",
            "summarize-chirho",
            "caller_chirho = \"summary-caller-chirho\"\nmax_tokens_chirho = 4096\n",
        ),
        // non-positive max_price_per_token_chirho
        blessed_card_chirho(
            "llm",
            "summarize-chirho",
            "caller_chirho = \"summary-caller-chirho\"\nmax_tokens_chirho = 4096\nmax_price_per_token_chirho = 0\n",
        ),
    ];
    for (i_chirho, card_chirho) in incomplete_cards_chirho.iter().enumerate() {
        let tmp_chirho = std::env::temp_dir().join(format!(
            "tb-llm-incomplete-{}-{i_chirho}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_chirho);
        let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
        add_blessed_role_chirho(&dag_chirho, "ask_chirho", card_chirho.as_str());
        let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            codes_chirho(&findings_chirho)
                .contains(&"blessed-card-incomplete-chirho".to_string()),
            "incomplete llm card #{i_chirho} must surface blessed-card-incomplete-chirho: {findings_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp_chirho);
    }
}

#[test]
fn incomplete_template_app_deploy_card_is_flagged_chirho() {
    // template-app-deploy requires only a non-empty scope_chirho; an empty-scope card must surface
    // blessed-card-incomplete at the checker layer. The card still pins the correct catalog hash so
    // it fails on the missing scope, not on the contract ref.
    let contract_hash_chirho =
        crate::blessed_catalog_chirho::lookup_blessed_contract_chirho("template-app-deploy")
            .expect("template-app-deploy contract exists")
            .contract_hash_chirho();
    let card_chirho = format!(
        "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"template-app-deploy\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"\"\nintent_chirho = \"Test an incomplete deploy card.\"\n"
    );
    let tmp_chirho = std::env::temp_dir().join(format!(
        "tb-template-app-deploy-incomplete-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    add_blessed_role_chirho(&dag_chirho, "deploy_chirho", &card_chirho);
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        codes_chirho(&findings_chirho).contains(&"blessed-card-incomplete-chirho".to_string()),
        "incomplete template-app-deploy card must surface blessed-card-incomplete-chirho: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn complete_query_card_is_not_flagged_incomplete_chirho() {
    // The same rule must not over-fire: a complete query card (scope + caller + positive max_rows)
    // lowers cleanly, so it carries no blessed-card-incomplete finding.
    let tmp_chirho = std::env::temp_dir().join(format!("tb-query-complete-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    add_blessed_role_chirho(
        &dag_chirho,
        "q_chirho",
        &blessed_card_chirho(
            "query",
            "orders-chirho",
            "caller_chirho = \"order-query-caller\"\nmax_rows_chirho = 50\n",
        ),
    );
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        !codes_chirho(&findings_chirho).contains(&"blessed-card-incomplete-chirho".to_string()),
        "a complete query card must not be flagged incomplete: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn canonical_reversion_preflight_rejects_uncontracted_effect_chirho() {
    let mut findings_chirho = Vec::new();
    check_canonical_reversion_resolution_chirho(
        "d_chirho/uncontracted_chirho",
        &["paid:echo_paid_chirho:user/demo-chirho".to_string()],
        &mut findings_chirho,
    );
    assert_eq!(
        codes_chirho(&findings_chirho),
        vec!["blessed-reversion-unresolved-chirho"]
    );
    assert!(findings_chirho[0]
        .found_chirho
        .contains("no canonical world-effect door"));
}

#[test]
fn all_published_blessed_cards_resolve_static_reversion_chirho() {
    let cases_chirho = [
        ("write-store", ""),
        (
            "query",
            "caller_chirho = \"query-caller-chirho\"\nmax_rows_chirho = 50\n",
        ),
        ("template-app-deploy", ""),
        (
            "llm",
            "caller_chirho = \"llm-caller-chirho\"\nmax_tokens_chirho = 4096\nmax_price_per_token_chirho = 2\n",
        ),
    ];
    for (contract_chirho, extra_chirho) in cases_chirho {
        let tmp_chirho = std::env::temp_dir().join(format!(
            "tb-reversion-{contract_chirho}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_chirho);
        let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
        add_blessed_role_chirho(
            &dag_chirho,
            "effect_chirho",
            &blessed_card_chirho(contract_chirho, "scope-chirho", extra_chirho),
        );
        let findings_chirho = check_app_tree_chirho(&walk_app_tree_chirho(&tmp_chirho));
        assert!(
            !codes_chirho(&findings_chirho)
                .contains(&"blessed-reversion-unresolved-chirho".to_string()),
            "published contract {contract_chirho} must resolve a canonical static reversion plan: {findings_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(tmp_chirho);
    }
}

#[test]
fn blessed_card_must_pin_catalog_hash_chirho() {
    let cases_chirho = [
        (
            "missing",
            "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\nscope_chirho = \"orders-chirho\"\nintent_chirho = \"Test a missing hash.\"\n".to_string(),
        ),
        (
            "mismatch",
            "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"not-the-registry-ref\"\nscope_chirho = \"orders-chirho\"\nintent_chirho = \"Test a mismatched hash.\"\n".to_string(),
        ),
    ];
    for (label_chirho, card_chirho) in cases_chirho {
        let tmp_chirho = std::env::temp_dir().join(format!(
            "tb-blessed-hash-{label_chirho}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_chirho);
        let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
        add_blessed_role_chirho(&dag_chirho, "save_chirho", &card_chirho);
        let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            codes_chirho(&findings_chirho)
                .contains(&"blessed-contract-ref-invalid-chirho".to_string()),
            "case {label_chirho} must fail closed on blessed-contract-ref-invalid-chirho: {findings_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(&tmp_chirho);
    }
}

#[test]
fn descriptor_v2_cards_refuse_legacy_unknown_and_missing_review_fields_chirho() {
    let contract_hash_chirho =
        crate::blessed_catalog_chirho::lookup_blessed_contract_chirho("write-store")
            .expect("write-store contract exists")
            .contract_hash_chirho();
    let cases_chirho = [
        (
            "legacy-schema-chirho",
            format!(
                "schema_chirho = \"blessed-card-v1-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"orders-chirho\"\nintent_chirho = \"Legacy cards cannot mint v2 authority.\"\n"
            ),
        ),
        (
            "unknown-field-chirho",
            format!(
                "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"orders-chirho\"\nintent_chirho = \"Unknown fields cannot ride outside review.\"\nambient_authority_chirho = true\n"
            ),
        ),
        (
            "missing-intent-chirho",
            format!(
                "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"orders-chirho\"\n"
            ),
        ),
    ];

    for (label_chirho, card_chirho) in cases_chirho {
        let tmp_chirho = std::env::temp_dir().join(format!(
            "tb-blessed-v2-{label_chirho}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_chirho);
        let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
        add_blessed_role_chirho(&dag_chirho, "save_chirho", &card_chirho);
        let findings_chirho = check_app_tree_chirho(&walk_app_tree_chirho(&tmp_chirho));
        assert!(
            codes_chirho(&findings_chirho)
                .contains(&"blessed-card-v2-invalid-chirho".to_string()),
            "case {label_chirho} must fail at the strict descriptor-v2 boundary: {findings_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(tmp_chirho);
    }
}

#[test]
fn unsatisfied_input_port_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-unsat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let role_chirho = add_impl_role_chirho(&dag_chirho, "a_chirho");
    // an input port dir with neither content nor symlink -> unsatisfied.
    std::fs::create_dir_all(role_chirho.join("in-x-message_v1-chirho")).unwrap();
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(codes_chirho(&findings_chirho).contains(&"port-unsatisfied-chirho".to_string()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn dangling_wire_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-dangle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let role_chirho = add_impl_role_chirho(&dag_chirho, "a_chirho");
    symlink_chirho(
        "../nowhere_chirho/out-y-message_v1-chirho",
        role_chirho.join("in-x-message_v1-chirho"),
    )
    .unwrap();
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(codes_chirho(&findings_chirho).contains(&"wire-dangling-chirho".to_string()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn type_mismatch_wire_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-type-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    // producer role with an out of type message_v1
    let producer_chirho = add_impl_role_chirho(&dag_chirho, "producer_chirho");
    std::fs::create_dir_all(producer_chirho.join("out-clean-message_v1-chirho")).unwrap();
    // consumer wires a form_post_v1 port to the message_v1 output -> mismatch
    let consumer_chirho = add_impl_role_chirho(&dag_chirho, "consumer_chirho");
    symlink_chirho(
        "../producer_chirho/out-clean-message_v1-chirho",
        consumer_chirho.join("in-thing-form_post_v1-chirho"),
    )
    .unwrap();
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(codes_chirho(&findings_chirho).contains(&"type-mismatch-chirho".to_string()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn schema_mismatch_wire_names_both_schemas_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-schema-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    write_schema_chirho(&tmp_chirho, "message_v1", "json:message-v1");
    write_schema_chirho(&tmp_chirho, "form_post_v1", "json:form-post-v1");
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let producer_chirho = add_impl_role_chirho(&dag_chirho, "producer_chirho");
    std::fs::create_dir_all(producer_chirho.join("out-clean-message_v1-chirho")).unwrap();
    let consumer_chirho = add_impl_role_chirho(&dag_chirho, "consumer_chirho");
    symlink_chirho(
        "../producer_chirho/out-clean-message_v1-chirho",
        consumer_chirho.join("in-thing-form_post_v1-chirho"),
    )
    .unwrap();

    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    let schema_finding_chirho = findings_chirho
        .iter()
        .find(|finding_chirho| finding_chirho.code_chirho == "schema-mismatch-chirho")
        .unwrap_or_else(|| panic!("schema mismatch must be flagged: {findings_chirho:?}"));
    assert!(schema_finding_chirho
        .expected_chirho
        .contains("form_post_v1"));
    assert!(schema_finding_chirho.found_chirho.contains("message_v1"));
    assert!(schema_finding_chirho.expected_chirho.contains("hash="));
    assert!(schema_finding_chirho.found_chirho.contains("hash="));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn schema_hash_match_allows_different_legacy_type_names_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-schema-equal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    add_resolving_impl_file_chirho(&tmp_chirho);
    write_schema_chirho(&tmp_chirho, "message_v1", "json:same-wire-payload");
    write_schema_chirho(&tmp_chirho, "form_post_v1", "json:same-wire-payload");
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let producer_chirho = add_impl_role_chirho(&dag_chirho, "producer_chirho");
    std::fs::create_dir_all(producer_chirho.join("out-clean-message_v1-chirho")).unwrap();
    let consumer_chirho = add_impl_role_chirho(&dag_chirho, "consumer_chirho");
    symlink_chirho(
        "../producer_chirho/out-clean-message_v1-chirho",
        consumer_chirho.join("in-thing-form_post_v1-chirho"),
    )
    .unwrap();

    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        findings_chirho.is_empty(),
        "matching explicit schema hashes should pass even if connection type tokens differ: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn invalid_port_schema_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-schema-invalid-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let schema_dir_chirho = tmp_chirho.join("schemas_chirho");
    std::fs::create_dir_all(&schema_dir_chirho).unwrap();
    std::fs::write(
        schema_dir_chirho.join("message_v1-schema-chirho.toml"),
        "schema_chirho = \"wrong-schema-chirho\"\ndefinition_chirho = \"\"\n",
    )
    .unwrap();
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let producer_chirho = add_impl_role_chirho(&dag_chirho, "producer_chirho");
    std::fs::create_dir_all(producer_chirho.join("out-clean-message_v1-chirho")).unwrap();

    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        codes_chirho(&findings_chirho).contains(&"port-schema-invalid-chirho".to_string()),
        "invalid schema file must be a checker finding: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn dangling_impl_symlink_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-impl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    // add_impl_role_chirho links to a src file that does not exist -> the impl link dangles.
    add_impl_role_chirho(&dag_chirho, "a_chirho");
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(codes_chirho(&findings_chirho).contains(&"impl-dangling-chirho".to_string()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn malformed_connection_name_is_flagged_not_dropped_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-malformed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    let role_chirho = add_impl_role_chirho(&dag_chirho, "a_chirho");
    // looks like a connection (in- prefix) but only 2 segments -> fails the grammar; must NOT be
    // silently dropped (fail-open) — it must surface as a finding (fail-closed).
    std::fs::create_dir_all(role_chirho.join("in-oops")).unwrap();
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        codes_chirho(&findings_chirho).contains(&"grammar-segment-count-chirho".to_string()),
        "malformed connection name must surface a grammar finding: {findings_chirho:?}"
    );
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}

#[test]
fn unbound_role_is_flagged_chirho() {
    let tmp_chirho = std::env::temp_dir().join(format!("tb-unbound-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
    let dag_chirho = scaffold_dag_chirho(&tmp_chirho);
    // a role dir with no impl symlink and no blessed ref
    std::fs::create_dir_all(dag_chirho.join("nodes_chirho/lonely_chirho")).unwrap();
    let tree_chirho = walk_app_tree_chirho(&tmp_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(codes_chirho(&findings_chirho).contains(&"role-unbound-chirho".to_string()));
    let _ = std::fs::remove_dir_all(&tmp_chirho);
}
