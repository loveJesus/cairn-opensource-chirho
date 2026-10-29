// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The CLI source guards: display-bound listings, the reviewed raw root-load inventory, and report-shape tests.

#[test]
fn signed_evidence_cli_display_handlers_stay_display_bound_chirho() {
    let source_chirho = production_main_source_chirho();
    // RETARGETED AT CF6 WAVE-1. These tokens named `realtime_chirho`, whose module was deleted with
    // the realtime write-side, so the guard was demanding a path that cannot exist -- passing or
    // failing against nothing rather than pinning a property. The two loaders now live in DIFFERENT
    // modules and that split is the point: the DISPLAY loader is ledger-bound because it RUNS the
    // verification and reports failure as a per-row label, while the RAW loader is the plain evidence
    // read. Pinning the CLI to the first and away from the second is the display-honesty contract.
    let guarded_chirho = [
        (
            "RealtimeSessionsChirho",
            "realtime_ledger_bound_evidence_chirho::load_realtime_sessions_for_display_chirho",
            "realtime_legacy_evidence_chirho::load_realtime_sessions_chirho",
        ),
        (
            "RealtimeEventsChirho",
            "realtime_ledger_bound_evidence_chirho::load_realtime_events_for_display_chirho",
            "realtime_legacy_evidence_chirho::load_realtime_events_chirho",
        ),
        (
            "RealtimeEpiloguesChirho",
            "realtime_ledger_bound_evidence_chirho::load_realtime_epilogues_for_display_chirho",
            "realtime_legacy_evidence_chirho::load_realtime_epilogues_chirho",
        ),
    ];

    for (command_chirho, display_loader_chirho, raw_loader_chirho) in guarded_chirho {
        let arm_chirho = production_main_command_arm_chirho(&source_chirho, command_chirho);
        assert!(
            arm_chirho.contains(display_loader_chirho),
            "{command_chirho} must use display loader {display_loader_chirho}"
        );
        assert!(
            !arm_chirho.contains(&format!("{raw_loader_chirho}(")),
            "{command_chirho} must not render through raw loader {raw_loader_chirho}"
        );
    }

    let volatile_arm_chirho =
        production_main_command_arm_chirho(&source_chirho, "VolatileEffectsChirho");
    assert!(
        volatile_arm_chirho.contains("report_command_chirho::run_volatile_effects_report_chirho"),
        "VolatileEffectsChirho must delegate through the report command service"
    );
    let report_command_source_chirho =
        include_str!("../../services-chirho/cairn-report-command-chirho/src/lib.rs");
    assert!(
        report_command_source_chirho
            .contains("effect_chirho::load_volatile_effect_records_for_display_chirho"),
        "volatile effect reports must use the display-bound loader in the report command service"
    );
    assert!(
        !report_command_source_chirho
            .contains("effect_chirho::load_volatile_effect_records_chirho("),
        "volatile effect reports must not render through the raw volatile effect loader"
    );
}

#[test]
fn reviewed_raw_cli_root_load_inventory_is_explicit_chirho() {
    let raw_root_loads_chirho = cli_root_raw_loader_calls_chirho(&production_main_source_chirho());

    let mut expected_chirho = vec![
        "agent_authority_chirho::load_agent_authority_response_records_chirho(root_chirho)?;",
        "agent_report_chirho::load_agent_report_charge_records_chirho(root_chirho)?;",
        "agent_report_chirho::load_agent_report_records_chirho(root_chirho)?;",
        "legal_hold_chirho::load_legal_hold_records_chirho(root_chirho)?;",
        "oauth_chirho::load_clients_chirho(root_chirho)?;",
        "identity_chirho::load_identities_chirho(root_chirho)?;",
        "refs_chirho::load_refs_chirho(root_chirho)?;",
        "legacy_evidence_readers_chirho::load_billing_compensations_chirho(root_chirho)?;",
        "legacy_evidence_readers_chirho::load_credit_holds_chirho(root_chirho)?;",
        "oauth_chirho::load_scoped_token_uses_chirho(root_chirho)?;",
        "resource_chirho::load_resource_usage_chirho(root_chirho)?;",
        "reversion_legacy_evidence_chirho::load_compensation_records_chirho(root_chirho)?;",
        "reversion_legacy_evidence_chirho::load_rollback_completions_chirho(root_chirho)?;",
        "reversion_legacy_evidence_chirho::load_rollback_events_chirho(root_chirho)?;",
        "review_chirho::load_review_records_chirho(root_chirho)?;",
        "native_worker_chirho::load_native_stateless_attestations_chirho(root_chirho)?;",
        "privacy_backup_chirho::load_privacy_backup_key_policy_records_chirho(root_chirho)?;",
        "privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(root_chirho)?;",
        "privacy_backup_chirho::load_privacy_replica_targets_chirho(root_chirho)?;",
        "privacy_chirho::load_privacy_erasure_records_chirho(root_chirho)?;",
        "retention_chirho::load_private_blob_retention_records_chirho(root_chirho)?;",
        "reversion_legacy_evidence_chirho::load_compensation_executions_chirho(root_chirho)?;",
        "reversion_legacy_evidence_chirho::load_manual_remediation_resolutions_chirho(root_chirho)?;",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    expected_chirho.sort();

    assert_eq!(
        raw_root_loads_chirho, expected_chirho,
        "new CLI root raw-loader use must be reviewed: route operator display through *_for_display_chirho when it is a signed-evidence listing, or add an explicit raw inventory entry with rationale"
    );
}

#[test]
fn raw_loader_inventory_detects_wrapped_root_calls_chirho() {
    let source_chirho = r#"
        let records_chirho = privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(
            root_chirho,
        )?;
        let display_chirho =
            effect_chirho::load_volatile_effect_records_for_display_chirho(root_chirho)?;
    "#;
    assert_eq!(
        cli_root_raw_loader_calls_chirho(source_chirho),
        vec![
            "privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(root_chirho)?;"
                .to_string()
        ]
    );
}

fn cli_root_raw_loader_calls_chirho(source_chirho: &str) -> Vec<String> {
    let mut calls_chirho = Vec::new();
    let mut statement_chirho = String::new();
    let mut collecting_chirho = false;
    for line_chirho in source_chirho.lines().map(str::trim) {
        if !collecting_chirho
            && line_chirho.contains("load_")
            && !line_chirho.contains("_for_display_chirho")
        {
            collecting_chirho = true;
            statement_chirho.clear();
        }
        if collecting_chirho {
            if !statement_chirho.is_empty() {
                statement_chirho.push(' ');
            }
            statement_chirho.push_str(line_chirho);
            if line_chirho.contains(';') {
                if let Some(call_chirho) =
                    normalized_single_root_loader_call_chirho(&statement_chirho)
                {
                    calls_chirho.push(call_chirho);
                }
                collecting_chirho = false;
                statement_chirho.clear();
            }
        }
    }
    calls_chirho.sort();
    calls_chirho
}

fn normalized_single_root_loader_call_chirho(statement_chirho: &str) -> Option<String> {
    let compact_chirho = statement_chirho
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if compact_chirho.contains("_for_display_chirho") {
        return None;
    }
    let load_start_chirho = compact_chirho.find("load_")?;
    let call_start_chirho = compact_chirho[..load_start_chirho]
        .rfind(|char_chirho: char| {
            !(char_chirho.is_ascii_alphanumeric() || char_chirho == '_' || char_chirho == ':')
        })
        .map(|index_chirho| index_chirho + 1)
        .unwrap_or(0);
    let open_offset_chirho = compact_chirho[load_start_chirho..].find('(')? + load_start_chirho;
    let close_offset_chirho =
        compact_chirho[open_offset_chirho + 1..].find(')')? + open_offset_chirho + 1;
    let args_chirho = compact_chirho[open_offset_chirho + 1..close_offset_chirho]
        .trim()
        .trim_end_matches(',')
        .trim();
    if args_chirho != "root_chirho" {
        return None;
    }
    let after_call_chirho = compact_chirho[close_offset_chirho + 1..].trim_start();
    if !after_call_chirho.starts_with("?;") {
        return None;
    }
    Some(format!(
        "{}(root_chirho)?;",
        &compact_chirho[call_start_chirho..open_offset_chirho]
    ))
}

fn production_main_source_chirho() -> String {
    cairn_chirho::source_scan_chirho::production_main_source_chirho()
}

fn production_main_command_arm_chirho(source_chirho: &str, command_chirho: &str) -> String {
    let needle_chirho = format!("CommandChirho::{command_chirho}");
    let start_chirho = source_chirho
        .find(&needle_chirho)
        .unwrap_or_else(|| panic!("missing command arm {command_chirho}"));
    let rest_chirho = &source_chirho[start_chirho..];
    let after_needle_chirho = &rest_chirho[needle_chirho.len()..];
    let end_chirho = after_needle_chirho
        .find("\n        CommandChirho::")
        .map(|offset_chirho| needle_chirho.len() + offset_chirho)
        .unwrap_or(rest_chirho.len());
    rest_chirho[..end_chirho].to_string()
}

// volatile_effect_verify_json_report_is_schema_tagged_chirho was demoted to the advisory structure
// report (report-serialization schema-tag shape) as a source-text proxy in
// cairn-source-scan-chirho::source_scan_chirho::structure_report_chirho.
