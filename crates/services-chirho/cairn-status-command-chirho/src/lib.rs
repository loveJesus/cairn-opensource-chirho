// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Status and review rendering helpers below the thin cairn CLI shell.

use cairn_chirho::economic_model_chirho::BillingSpendCapsChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{
    app_source_manifest_chirho, capability_plain_chirho::review_capability_power_body_chirho,
    identity_chirho, ops_custody_chirho, ops_restore_drill_chirho, review_chirho,
};

pub fn print_spend_caps_chirho(spend_caps_chirho: &BillingSpendCapsChirho) {
    let per_user_chirho = spend_caps_chirho
        .per_user_cap_chirho
        .map(|cap_chirho| cap_chirho.to_string())
        .unwrap_or_else(|| "(none)".to_string());
    let app_chirho = spend_caps_chirho
        .app_cap_chirho
        .map(|cap_chirho| cap_chirho.to_string())
        .unwrap_or_else(|| "(none)".to_string());
    println!("  spend caps: per-user={per_user_chirho} app={app_chirho}");
}
pub fn print_ops_restore_drill_chirho(
    report_chirho: &ops_restore_drill_chirho::OpsRestoreDrillReportChirho,
) {
    println!(
        "ops restore drill: restore_verified={} hosted_ops_blocker_closed={}",
        report_chirho.restore_verified_chirho, report_chirho.hosted_ops_blocker_closed_chirho
    );
    println!(
        "scope source={} restore={}",
        report_chirho.source_root_scope_chirho, report_chirho.restore_root_scope_chirho
    );
    println!(
        "copied cas_objects={} signed_jsonl_logs={} private_blob_keys={} signing_key_present={} versioned_store_present={} refs_present={} reflog_present={}",
        report_chirho.copied_surfaces_chirho.cas_objects_chirho,
        report_chirho.copied_surfaces_chirho.signed_jsonl_logs_chirho,
        report_chirho
            .copied_surfaces_chirho
            .private_blob_key_files_chirho,
        report_chirho.copied_surfaces_chirho.signing_key_present_chirho,
        report_chirho
            .copied_surfaces_chirho
            .versioned_store_present_chirho,
        report_chirho.copied_surfaces_chirho.refs_present_chirho,
        report_chirho.copied_surfaces_chirho.reflog_present_chirho
    );
    println!(
        "verified run_cache={}/{}/{} volatile={}/{} privacy_blobs={} privacy_findings={} ledger_entries={} versioned_entries={} refs_branches={} reflog_entries={}",
        report_chirho.verifier_counts_chirho.run_cache_runs_chirho,
        report_chirho.verifier_counts_chirho.run_cache_runkeys_chirho,
        report_chirho.verifier_counts_chirho.run_cache_runseals_chirho,
        report_chirho
            .verifier_counts_chirho
            .volatile_effect_records_chirho,
        report_chirho
            .verifier_counts_chirho
            .volatile_effect_objects_chirho,
        report_chirho
            .verifier_counts_chirho
            .privacy_blob_records_chirho,
        report_chirho
            .verifier_counts_chirho
            .privacy_scan_findings_chirho,
        report_chirho.verifier_counts_chirho.ledger_entries_chirho,
        report_chirho
            .verifier_counts_chirho
            .versioned_current_entries_chirho,
        report_chirho.verifier_counts_chirho.refs_branches_chirho,
        report_chirho.verifier_counts_chirho.reflog_entries_chirho
    );
    println!(
        "compliance pack={} records={} packs={} failed_sources={} coverage_gaps={} private_blob_roundtrip={}",
        report_chirho
            .verifier_counts_chirho
            .compliance_pack_chirho
            .0,
        report_chirho.verifier_counts_chirho.compliance_records_chirho,
        report_chirho.verifier_counts_chirho.compliance_packs_chirho,
        report_chirho
            .verifier_counts_chirho
            .compliance_failed_sources_chirho,
        report_chirho
            .verifier_counts_chirho
            .compliance_coverage_gaps_chirho,
        report_chirho.private_blob_roundtrip_chirho
    );
    for note_chirho in &report_chirho.honest_scope_chirho {
        println!("scope-note\t{note_chirho}");
    }
}

pub fn print_ops_custody_inventory_chirho(
    report_chirho: &ops_custody_chirho::OpsCustodyInventoryReportChirho,
) {
    println!(
        "ops custody inventory: custody_ready={} hosted_ops_blocker_closed={} findings={}",
        report_chirho.custody_ready_chirho,
        report_chirho.hosted_ops_blocker_closed_chirho,
        report_chirho.findings_chirho
    );
    println!("scope root={}", report_chirho.root_scope_chirho);
    println!(
        "signing_key checked={} present={} regular={} private={} symlink={} special={}",
        report_chirho.signing_key_chirho.checked_chirho,
        report_chirho.signing_key_chirho.present_chirho,
        report_chirho.signing_key_chirho.regular_file_chirho,
        report_chirho.signing_key_chirho.private_mode_chirho,
        report_chirho.signing_key_chirho.symlink_chirho,
        report_chirho.signing_key_chirho.special_chirho
    );
    print_ops_custody_directory_chirho(
        "private_blob_keys",
        &report_chirho.private_blob_keys_chirho,
    );
    print_ops_custody_directory_chirho("identity_keys", &report_chirho.identity_keys_chirho);
    print_ops_custody_directory_chirho(
        "private_secret_refs",
        &report_chirho.private_secret_refs_chirho,
    );
    println!(
        "descriptor_d_evidence_key scope={} present={} expected_size={} value_redacted={} required_when_composed={}",
        report_chirho.descriptor_d_evidence_key_chirho.scope_chirho,
        report_chirho.descriptor_d_evidence_key_chirho.present_chirho,
        report_chirho.descriptor_d_evidence_key_chirho.expected_size_chirho,
        report_chirho.descriptor_d_evidence_key_chirho.value_redacted_chirho,
        report_chirho
            .descriptor_d_evidence_key_chirho
            .required_when_composed_chirho
    );
    for signer_chirho in &report_chirho.ledger_host_signers_chirho {
        println!(
            "ledger_host_signer scope={} present={} expected_size={} value_redacted={} required_when_composed={}",
            signer_chirho.scope_chirho,
            signer_chirho.present_chirho,
            signer_chirho.expected_size_chirho,
            signer_chirho.value_redacted_chirho,
            signer_chirho.required_when_composed_chirho
        );
    }
    println!(
        "config checked={} present={} regular={} private={} ownership_checked={} owner_matches_selected_root={} root_binding_checked={} root_matches_selected={} config_tenant_configured={} publish_token_configured={} registration_token_configured={} ledger_host_configured={} values_redacted={}",
        report_chirho.config_file_chirho.file_chirho.checked_chirho,
        report_chirho.config_file_chirho.file_chirho.present_chirho,
        report_chirho.config_file_chirho.file_chirho.regular_file_chirho,
        report_chirho.config_file_chirho.file_chirho.private_mode_chirho,
        report_chirho.config_file_chirho.ownership_checked_chirho,
        report_chirho
            .config_file_chirho
            .owner_matches_selected_root_chirho,
        report_chirho
            .config_file_chirho
            .root_binding_chirho
            .checked_chirho,
        report_chirho
            .config_file_chirho
            .root_binding_chirho
            .effective_root_matches_selected_root_chirho,
        report_chirho
            .config_file_chirho
            .root_binding_chirho
            .config_tenant_configured_chirho,
        report_chirho
            .config_file_chirho
            .publish_token_configured_chirho,
        report_chirho
            .config_file_chirho
            .registration_token_configured_chirho,
        report_chirho
            .config_file_chirho
            .ledger_host_configured_chirho,
        report_chirho.config_file_chirho.token_values_redacted_chirho
    );
    println!(
        "env checked={} present={} regular={} private={} nonempty_assignments={} values_redacted={}",
        report_chirho.env_file_chirho.file_chirho.checked_chirho,
        report_chirho.env_file_chirho.file_chirho.present_chirho,
        report_chirho.env_file_chirho.file_chirho.regular_file_chirho,
        report_chirho.env_file_chirho.file_chirho.private_mode_chirho,
        report_chirho.env_file_chirho.nonempty_assignments_chirho,
        report_chirho.env_file_chirho.values_redacted_chirho
    );
    for note_chirho in &report_chirho.honest_scope_chirho {
        println!("scope-note\t{note_chirho}");
    }
}
fn print_ops_custody_directory_chirho(
    label_chirho: &str,
    posture_chirho: &ops_custody_chirho::OpsCustodyDirectoryPostureChirho,
) {
    println!(
        "{label_chirho} present={} directory={} private_dir={} files={} private_files={} broad_files={} child_dirs={} broad_child_dirs={} symlinks={} special={}",
        posture_chirho.present_chirho,
        posture_chirho.directory_chirho,
        posture_chirho.private_dir_mode_chirho,
        posture_chirho.files_chirho,
        posture_chirho.private_files_chirho,
        posture_chirho.broad_files_chirho,
        posture_chirho.child_directories_chirho,
        posture_chirho.broad_child_directories_chirho,
        posture_chirho.symlink_entries_chirho,
        posture_chirho.special_entries_chirho
    );
}
pub fn print_identity_credential_inventory_chirho(
    inventory_chirho: &identity_chirho::IdentityCredentialInventoryChirho,
) {
    println!(
        "identity credential inventory: rotation_ready={} identities={} key_files={}",
        inventory_chirho.legacy_rotation_ready_chirho,
        inventory_chirho.identity_records_chirho,
        inventory_chirho.key_files_chirho
    );
    println!(
        "credentials\targon2id={}\tlegacy_blake3={}\tcredentialless={}",
        inventory_chirho.argon2id_credentials_chirho,
        inventory_chirho.legacy_blake3_credentials_chirho,
        inventory_chirho.credentialless_keys_chirho
    );
    println!(
        "key_files\tinvalid={}\tmissing={}\textra={}",
        inventory_chirho.invalid_key_files_chirho,
        inventory_chirho.missing_key_files_chirho,
        inventory_chirho.extra_key_files_chirho
    );
    println!(
        "recovery_codes\theld={}\tinvalid={}\tgeneration_ahead_of_reset_records={}",
        inventory_chirho.recovery_codes_chirho,
        inventory_chirho.invalid_recovery_codes_chirho,
        inventory_chirho.generation_ahead_of_reset_records_chirho
    );
    for hash_chirho in &inventory_chirho.invalid_recovery_code_principal_hashes_chirho {
        println!("invalid-recovery-code-principal-hash\t{hash_chirho}");
    }
    for hash_chirho in &inventory_chirho.generation_ahead_principal_hashes_chirho {
        println!("generation-ahead-principal-hash\t{hash_chirho}");
    }
    for hash_chirho in &inventory_chirho.legacy_principal_hashes_chirho {
        println!("legacy-principal-hash\t{hash_chirho}");
    }
    for hash_chirho in &inventory_chirho.invalid_principal_hashes_chirho {
        println!("invalid-principal-hash\t{hash_chirho}");
    }
    for hash_chirho in &inventory_chirho.missing_key_principal_hashes_chirho {
        println!("missing-key-principal-hash\t{hash_chirho}");
    }
    for hash_chirho in &inventory_chirho.extra_key_principal_hashes_chirho {
        println!("extra-key-principal-hash\t{hash_chirho}");
    }
}
pub fn print_app_source_candidate_chirho(
    report_chirho: &app_source_manifest_chirho::AppSourceCandidateReportChirho,
) {
    let source_manifest_flags_chirho =
        source_manifest_cli_flags_chirho(&report_chirho.source_manifest_chirho);
    println!(
        "source manifest candidate app '{}' owner={} root_dag={} (not deployed)",
        report_chirho.app_chirho, report_chirho.owner_chirho, report_chirho.root_dag_chirho.0
    );
    if let Some(source_manifest_chirho) = &report_chirho.source_manifest_chirho {
        println!(
            "manifest_effective\t{}",
            source_manifest_chirho.effective_manifest_hash_chirho.0
        );
        if let Some(raw_manifest_hash_chirho) = &source_manifest_chirho.raw_manifest_hash_chirho {
            println!("manifest_raw\t{}", raw_manifest_hash_chirho.0);
        }
    }
    println!(
        "review with: review-diff --app {} --candidate {}",
        report_chirho.app_chirho, report_chirho.root_dag_chirho.0
    );
    println!(
        "promote reviewed hash with: review-promote --app {} --owner {} --candidate {}{}",
        report_chirho.app_chirho,
        report_chirho.owner_chirho,
        report_chirho.root_dag_chirho.0,
        source_manifest_flags_chirho
    );
    println!(
        "nodes={} dags={} modules={} routes={} input_mode={} response_content_type={}",
        report_chirho.nodes_chirho.len(),
        report_chirho.dags_chirho.len(),
        report_chirho.modules_chirho.len(),
        report_chirho.routes_chirho.len(),
        report_chirho
            .input_mode_chirho
            .as_ref()
            .map(|mode_chirho| format!("{mode_chirho:?}"))
            .unwrap_or_else(|| "(none)".to_string()),
        report_chirho
            .response_content_type_chirho
            .as_deref()
            .unwrap_or("(none)")
    );
    for route_chirho in &report_chirho.routes_chirho {
        println!(
            "route {} -> dag {} input_mode={} response_content_type={}",
            route_chirho.route_chirho,
            route_chirho.dag_chirho.0,
            route_chirho
                .input_mode_chirho
                .as_ref()
                .map(|mode_chirho| format!("{mode_chirho:?}"))
                .unwrap_or_else(|| "(none)".to_string()),
            route_chirho
                .response_content_type_chirho
                .as_deref()
                .unwrap_or("(none)")
        );
    }
}

/// Renders every verified root/route undo plan without capability payload values.
pub fn app_source_undo_plan_review_body_chirho(
    reviews_chirho: &[app_source_manifest_chirho::VerifiedAppSourceUndoPlanReviewChirho],
    include_binding_ids_chirho: bool,
) -> String {
    if reviews_chirho.is_empty() {
        return "undo plans: pre-v2 candidate makes no static-undo authority claim".to_string();
    }
    let mut lines_chirho = vec![format!(
        "verified undo plans: {} root/route DAG(s)",
        reviews_chirho.len()
    )];
    for (plan_index_chirho, review_chirho) in reviews_chirho.iter().enumerate() {
        if include_binding_ids_chirho {
            lines_chirho.push(format!(
                "plan {} dag={} plan_cas={} plan_digest={} contract_set={} effects={} max_depth={}",
                plan_index_chirho + 1,
                review_chirho.dag_chirho.0,
                review_chirho.plan_cas_chirho.0,
                review_chirho.plan_digest_chirho.0,
                review_chirho.contract_set_digest_chirho.0,
                review_chirho.effect_count_chirho,
                review_chirho.max_depth_chirho,
            ));
        } else {
            lines_chirho.push(format!(
                "plan {} effects={} max_depth={}",
                plan_index_chirho + 1,
                review_chirho.effect_count_chirho,
                review_chirho.max_depth_chirho,
            ));
        }
        for door_chirho in &review_chirho.doors_chirho {
            lines_chirho.push(format!(
                "  door {} contract={} effect={} support={} depends_on={} disposition={} produced_evidence={} residuals={} gate_required={} remediation_required={} privacy={} config_ports={}",
                door_chirho.position_chirho,
                door_chirho.contract_chirho,
                door_chirho.effect_kind_chirho,
                list_or_none_chirho(&door_chirho.supporting_kinds_chirho),
                positions_or_none_chirho(&door_chirho.depends_on_positions_chirho),
                door_chirho.disposition_chirho,
                list_or_none_chirho(&door_chirho.produced_evidence_chirho),
                list_or_none_chirho(&door_chirho.residuals_chirho),
                door_chirho.admission_gate_required_chirho,
                door_chirho.remediation_required_chirho,
                door_chirho.privacy_class_chirho,
                list_or_none_chirho(&door_chirho.config_ports_chirho),
            ));
            for (step_index_chirho, step_chirho) in door_chirho.steps_chirho.iter().enumerate() {
                lines_chirho.push(format!(
                    "    step {} action={} evidence={} verification={}",
                    step_index_chirho + 1,
                    step_chirho.action_chirho,
                    list_or_none_chirho(&step_chirho.required_evidence_chirho),
                    step_chirho.verification_chirho,
                ));
            }
        }
    }
    lines_chirho.join("\n")
}

fn list_or_none_chirho(values_chirho: &[String]) -> String {
    if values_chirho.is_empty() {
        "(none)".to_string()
    } else {
        values_chirho.join(",")
    }
}

fn positions_or_none_chirho(values_chirho: &[usize]) -> String {
    if values_chirho.is_empty() {
        "(none)".to_string()
    } else {
        values_chirho
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

pub fn print_app_source_review_chirho(
    report_chirho: &app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    print_app_source_candidate_chirho(&report_chirho.candidate_chirho);
    if let Some(source_review_report_chirho) = &report_chirho.source_review_report_chirho {
        println!("source_review_report\t{}", source_review_report_chirho.0);
    }
    let source_report_flags_chirho =
        source_review_report_cli_flags_chirho(&report_chirho.source_review_report_chirho);
    println!("review surface (not deployed)");
    print_review_diff_chirho(&report_chirho.review_chirho);
    println!(
        "promote only after human approval: review-promote --app {} --owner {} --candidate {}{}",
        report_chirho.candidate_chirho.app_chirho,
        report_chirho.candidate_chirho.owner_chirho,
        report_chirho.candidate_chirho.root_dag_chirho.0,
        source_report_flags_chirho
    );
}
fn source_review_report_cli_flags_chirho(
    source_review_report_chirho: &Option<HashChirho>,
) -> String {
    source_review_report_chirho
        .as_ref()
        .map(|hash_chirho| format!(" --source-review-report {}", hash_chirho.0))
        .unwrap_or_default()
}

fn source_manifest_cli_flags_chirho(
    source_manifest_chirho: &Option<app_source_manifest_chirho::AppSourceManifestEvidenceChirho>,
) -> String {
    let Some(source_manifest_chirho) = source_manifest_chirho else {
        return String::new();
    };
    let mut flags_chirho = format!(
        " --source-manifest {}",
        source_manifest_chirho.effective_manifest_hash_chirho.0
    );
    if let Some(raw_manifest_hash_chirho) = &source_manifest_chirho.raw_manifest_hash_chirho {
        flags_chirho.push_str(&format!(" --raw-manifest {}", raw_manifest_hash_chirho.0));
    }
    flags_chirho
}

pub fn print_review_diff_chirho(diff_chirho: &review_chirho::ReviewSurfaceDiffChirho) {
    println!("app\t{}", diff_chirho.app_chirho);
    println!(
        "live\t{}",
        diff_chirho
            .live_chirho
            .as_ref()
            .map(|hash_chirho| hash_chirho.0.as_str())
            .unwrap_or("(none)")
    );
    println!("candidate\t{}", diff_chirho.candidate_chirho.0);
    println!(
        "price_book\t{}",
        diff_chirho
            .price_book_chirho
            .as_ref()
            .map(|hash_chirho| hash_chirho.0.as_str())
            .unwrap_or("(none)")
    );
    println!(
        "nodes\t{} -> {}\tedges\t{} -> {}",
        diff_chirho.live_node_count_chirho,
        diff_chirho.candidate_node_count_chirho,
        diff_chirho.live_edge_count_chirho,
        diff_chirho.candidate_edge_count_chirho
    );
    println!(
        "cost_token\t{} -> {}\tdelta={}",
        diff_chirho.live_cost_token_chirho,
        diff_chirho.candidate_cost_token_chirho,
        diff_chirho.cost_delta_token_chirho
    );
    for cap_chirho in &diff_chirho.added_capabilities_chirho {
        let power_chirho = review_capability_power_body_chirho(cap_chirho);
        println!("capability_added\t{cap_chirho}\ncapability_added_power\t{power_chirho}");
    }
    for cap_chirho in &diff_chirho.removed_capabilities_chirho {
        let power_chirho = review_capability_power_body_chirho(cap_chirho);
        println!("capability_removed\t{cap_chirho}\ncapability_removed_power\t{power_chirho}");
    }
    for effect_chirho in &diff_chirho.candidate_paid_effects_chirho {
        println!(
            "candidate_paid_effect\t{}\tcount={}\tunit={}\ttotal={}\tsource={}",
            effect_chirho.effect_chirho,
            effect_chirho.count_chirho,
            effect_chirho.unit_cost_token_chirho,
            effect_chirho.total_cost_token_chirho,
            effect_chirho.source_chirho
        );
    }
    for warning_chirho in &diff_chirho.warnings_chirho {
        println!("warning\t{warning_chirho}");
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::app_source_undo_plan_review_body_chirho;
    use cairn_chirho::app_source_manifest_chirho::{
        VerifiedAppSourceUndoDoorReviewChirho, VerifiedAppSourceUndoPlanReviewChirho,
        VerifiedAppSourceUndoStepReviewChirho,
    };
    use cairn_chirho::model_chirho::HashChirho;

    #[test]
    fn undo_plan_review_body_exposes_semantics_and_redacts_steward_ids_chirho() {
        let hash_chirho = HashChirho("a".repeat(64));
        let reviews_chirho = vec![VerifiedAppSourceUndoPlanReviewChirho {
            dag_chirho: hash_chirho.clone(),
            plan_cas_chirho: hash_chirho.clone(),
            plan_digest_chirho: hash_chirho.clone(),
            contract_set_digest_chirho: hash_chirho,
            effect_count_chirho: 2,
            max_depth_chirho: 8,
            doors_chirho: vec![
                VerifiedAppSourceUndoDoorReviewChirho {
                    position_chirho: 1,
                    contract_chirho: "query-chirho".into(),
                    effect_kind_chirho: "query-chirho".into(),
                    supporting_kinds_chirho: vec!["user-identity-chirho".into()],
                    depends_on_positions_chirho: Vec::new(),
                    produced_evidence_chirho: vec!["response-ref-chirho".into()],
                    disposition_chirho: "observation-only-chirho/read-only-capability-chirho"
                        .into(),
                    steps_chirho: Vec::new(),
                    residuals_chirho: Vec::new(),
                    admission_gate_required_chirho: false,
                    remediation_required_chirho: false,
                    privacy_class_chirho: "direct-chirho".into(),
                    config_ports_chirho: Vec::new(),
                },
                VerifiedAppSourceUndoDoorReviewChirho {
                    position_chirho: 2,
                    contract_chirho: "write-store-chirho".into(),
                    effect_kind_chirho: "write-store-chirho".into(),
                    supporting_kinds_chirho: Vec::new(),
                    depends_on_positions_chirho: vec![1],
                    produced_evidence_chirho: vec!["before-image-ref-chirho".into()],
                    disposition_chirho: "compensable-chirho".into(),
                    steps_chirho: vec![VerifiedAppSourceUndoStepReviewChirho {
                        action_chirho: "conditional-restore-chirho".into(),
                        required_evidence_chirho: vec!["post-state-fingerprint-chirho".into()],
                        verification_chirho: "verify-post-fingerprint-chirho".into(),
                    }],
                    residuals_chirho: vec!["external-visibility-chirho".into()],
                    admission_gate_required_chirho: true,
                    remediation_required_chirho: false,
                    privacy_class_chirho: "direct-chirho".into(),
                    config_ports_chirho: vec!["provider-config-chirho".into()],
                },
            ],
        }];

        let technical_chirho = app_source_undo_plan_review_body_chirho(&reviews_chirho, true);
        for required_chirho in [
            "write-store-chirho",
            "support=user-identity-chirho",
            "depends_on=1",
            "before-image-ref-chirho",
            "conditional-restore-chirho",
            "post-state-fingerprint-chirho",
            "external-visibility-chirho",
            "gate_required=true",
            "privacy=direct-chirho",
            "max_depth=8",
        ] {
            assert!(technical_chirho.contains(required_chirho));
        }
        assert!(technical_chirho.contains(&"a".repeat(64)));

        let steward_chirho = app_source_undo_plan_review_body_chirho(&reviews_chirho, false);
        assert!(!steward_chirho.contains(&"a".repeat(64)));
        assert!(steward_chirho.contains("conditional-restore-chirho"));
    }
}
