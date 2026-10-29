// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const ARCHIVED_EXTERNAL_SOURCE_PATHS_CHIRHO: [&str; 4] = [
    "src/economic_flows_chirho/external_chirho.rs",
    "src/economic_flows_chirho/external_legacy_ledger_chirho.rs",
    "src/privacy_compliance_chirho/external_legacy_evidence_chirho.rs",
    "crates/cairn-cli-chirho/src/cli_helpers_chirho/product_chirho/economic_chirho/external_provider_cli_chirho.rs",
];

#[test]
fn legacy_external_source_and_runtime_consumers_are_absent_chirho() {
    let root_chirho = workspace_root_chirho();
    for path_chirho in ARCHIVED_EXTERNAL_SOURCE_PATHS_CHIRHO {
        assert!(
            !root_chirho.join(path_chirho).exists(),
            "CF6 drop-source requires legacy external path '{path_chirho}' to stay absent"
        );
    }

    let lib_chirho = std::fs::read_to_string(root_chirho.join("src/lib.rs")).unwrap();
    assert!(!lib_chirho.contains("external_legacy_evidence_chirho"));
    assert!(!lib_chirho.contains("external_legacy_ledger_chirho"));
    assert!(!lib_chirho.contains("economic_flows_chirho/external_chirho.rs"));

    let snapshots_chirho = std::fs::read_to_string(root_chirho.join(
        "src/privacy_compliance_chirho/compliance_evidence_chirho/source_snapshots_chirho.rs",
    ))
    .unwrap();
    let data_rights_chirho = std::fs::read_to_string(
        root_chirho.join("src/privacy_compliance_chirho/data_rights_chirho.rs"),
    )
    .unwrap();
    let collectors_chirho = std::fs::read_to_string(
        root_chirho
            .join("src/privacy_compliance_chirho/data_rights_chirho/source_collectors_chirho.rs"),
    )
    .unwrap();
    let app_metering_chirho =
        std::fs::read_to_string(root_chirho.join("src/app_metering_chirho/resource_chirho.rs"))
            .unwrap();
    for source_chirho in [&snapshots_chirho, &data_rights_chirho, &collectors_chirho] {
        assert!(!source_chirho.contains("external_legacy"));
        assert!(!source_chirho.contains("external.usage-chirho"));
        assert!(!source_chirho.contains("external.provider-prices-chirho"));
    }
    assert!(!app_metering_chirho.contains("load_external_usage_chirho"));
    assert!(app_metering_chirho
        .contains("legacy external-usage resource bridges are unavailable after CF6"));

    for deleted_symbol_chirho in [
        "set_provider_price_chirho(",
        "record_external_usage_chirho(",
        "compute_external_cost_chirho(",
        "verify_external_usage_chirho(",
        "load_external_usage_chirho(",
        "provider_suspense_balances_chirho(",
    ] {
        assert!(
            production_source_lines_matching_chirho(deleted_symbol_chirho).is_empty(),
            "legacy external production symbol '{deleted_symbol_chirho}' must stay absent"
        );
    }
}

#[test]
fn archived_external_sources_have_only_the_typed_tag_recovery_path_chirho() {
    let root_chirho = workspace_root_chirho();
    let compliance_chirho = std::fs::read_to_string(
        root_chirho.join("src/privacy_compliance_chirho/compliance_evidence_chirho.rs"),
    )
    .unwrap();
    for required_chirho in [
        "ArchivedComplianceSourceVerdictChirho",
        "source-archived-chirho",
        "recover-verifier-from-tag-chirho",
        "archive-chirho/26-07-20-cf6-wave1-money-spine",
        "external.usage-chirho",
        "external.provider-prices-chirho",
    ] {
        assert!(
            compliance_chirho.contains(required_chirho),
            "archived external source handling must pin '{required_chirho}'"
        );
    }

    let args_chirho =
        std::fs::read_to_string(root_chirho.join("crates/cairn-cli-chirho/src/args_chirho.rs"))
            .unwrap();
    for command_chirho in [
        "provider-price-set",
        "provider-prices",
        "external-verify",
        "external-usage",
        "provider-suspense",
    ] {
        assert!(
            !args_chirho.contains(command_chirho),
            "archived external CLI command '{command_chirho}' must stay absent"
        );
    }
}
