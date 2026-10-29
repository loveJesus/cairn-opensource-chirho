// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Report command bodies below the thin cairn CLI shell.

use cairn_chirho::model_chirho::{CapabilityChirho, HashChirho};
use cairn_chirho::{
    compliance_evidence_chirho, data_residency_chirho, data_rights_chirho, effect_chirho,
    legal_hold_chirho, privacy_backup_chirho, privacy_chirho, retention_chirho, verify_chirho,
};
use cairn_learner_handover_chirho as learner_handover_drill_chirho;
use cairn_operator_smoke_chirho::agent_authored_backend_smoke_chirho;
use cairn_operator_smoke_chirho::contact_example_smoke_chirho;
use cairn_operator_smoke_chirho::credits_demo_smoke_chirho::continuation_chirho;
pub use cairn_operator_smoke_chirho::credits_demo_smoke_chirho::{
    CreditsDemoConcurrencyTokenRequestChirho, CreditsDemoInputsAuthorRequestChirho,
    CreditsDemoProviderPrepareRequestChirho,
};
use std::path::Path;

pub const PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO: &str = "privacy-verify-report-v1-chirho";
pub const VOLATILE_EFFECT_LIST_REPORT_SCHEMA_CHIRHO: &str = "volatile-effect-list-v1-chirho";
pub const VOLATILE_EFFECT_VERIFY_REPORT_SCHEMA_CHIRHO: &str =
    "volatile-effect-verify-report-v1-chirho";

fn current_time_ms_chirho() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, serde::Serialize)]
pub struct PrivacyVerifyCliReportChirho {
    pub schema_chirho: &'static str,
    pub blob_records_chirho: usize,
    pub erasure_records_chirho: usize,
    pub access_records_chirho: usize,
    pub legal_hold_records_chirho: usize,
    pub active_legal_holds_chirho: usize,
    pub backup_key_policy_records_chirho: usize,
    pub replica_targets_chirho: usize,
    pub erasure_propagation_records_chirho: usize,
    pub privacy_retention_records_chirho: usize,
    pub export_evidence_records_chirho: usize,
}

pub fn privacy_verify_cli_report_chirho(
    report_chirho: &privacy_chirho::PrivacyVerifyReportChirho,
    legal_hold_report_chirho: &legal_hold_chirho::LegalHoldVerifyReportChirho,
    backup_report_chirho: &privacy_backup_chirho::PrivacyBackupVerifyReportChirho,
    retention_records_chirho: usize,
    export_records_chirho: usize,
) -> PrivacyVerifyCliReportChirho {
    PrivacyVerifyCliReportChirho {
        schema_chirho: PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO,
        blob_records_chirho: report_chirho.blob_records_chirho,
        erasure_records_chirho: report_chirho.erasure_records_chirho,
        access_records_chirho: report_chirho.access_records_chirho,
        legal_hold_records_chirho: legal_hold_report_chirho.records_chirho,
        active_legal_holds_chirho: legal_hold_report_chirho.active_holds_chirho,
        backup_key_policy_records_chirho: backup_report_chirho.backup_key_policy_records_chirho,
        replica_targets_chirho: backup_report_chirho.replica_targets_chirho,
        erasure_propagation_records_chirho: backup_report_chirho.erasure_propagation_records_chirho,
        privacy_retention_records_chirho: retention_records_chirho,
        export_evidence_records_chirho: export_records_chirho,
    }
}

fn privacy_verify_cli_evidence_records_chirho(
    report_chirho: &PrivacyVerifyCliReportChirho,
) -> usize {
    report_chirho.blob_records_chirho
        + report_chirho.erasure_records_chirho
        + report_chirho.access_records_chirho
        + report_chirho.legal_hold_records_chirho
        + report_chirho.backup_key_policy_records_chirho
        + report_chirho.replica_targets_chirho
        + report_chirho.erasure_propagation_records_chirho
        + report_chirho.privacy_retention_records_chirho
        + report_chirho.export_evidence_records_chirho
}

#[derive(Debug, serde::Serialize)]
pub struct VolatileEffectListCliReportChirho {
    pub schema_chirho: &'static str,
    pub records_chirho: Vec<VolatileEffectListEntryChirho>,
}

#[derive(Debug, serde::Serialize)]
pub struct VolatileEffectListEntryChirho {
    pub line_chirho: u64,
    pub valid_chirho: bool,
    pub validation_error_chirho: Option<String>,
    pub seq_chirho: Option<u64>,
    pub effect_seq_chirho: Option<u64>,
    pub capability_chirho: Option<CapabilityChirho>,
    pub idem_key_chirho: Option<HashChirho>,
    pub request_chirho: Option<HashChirho>,
    pub response_chirho: Option<HashChirho>,
    pub record_sig_chirho: Option<String>,
}

pub fn volatile_effect_list_cli_report_chirho(
    records_chirho: &[effect_chirho::VolatileEffectDisplayRecordChirho],
) -> VolatileEffectListCliReportChirho {
    VolatileEffectListCliReportChirho {
        schema_chirho: VOLATILE_EFFECT_LIST_REPORT_SCHEMA_CHIRHO,
        records_chirho: records_chirho
            .iter()
            .map(|record_chirho| {
                if let Some(raw_record_chirho) = &record_chirho.record_chirho {
                    let effect_chirho = &raw_record_chirho.effect_chirho;
                    VolatileEffectListEntryChirho {
                        line_chirho: record_chirho.line_chirho,
                        valid_chirho: record_chirho.valid_chirho(),
                        validation_error_chirho: record_chirho.validation_error_chirho.clone(),
                        seq_chirho: Some(raw_record_chirho.seq_chirho),
                        effect_seq_chirho: Some(effect_chirho.seq_chirho),
                        capability_chirho: Some(effect_chirho.capability_chirho.clone()),
                        idem_key_chirho: Some(effect_chirho.idem_key_chirho.clone()),
                        request_chirho: Some(effect_chirho.request_chirho.clone()),
                        response_chirho: effect_chirho.response_chirho.clone(),
                        record_sig_chirho: Some(raw_record_chirho.sig_chirho.clone()),
                    }
                } else {
                    VolatileEffectListEntryChirho {
                        line_chirho: record_chirho.line_chirho,
                        valid_chirho: false,
                        validation_error_chirho: record_chirho.validation_error_chirho.clone(),
                        seq_chirho: None,
                        effect_seq_chirho: None,
                        capability_chirho: None,
                        idem_key_chirho: None,
                        request_chirho: None,
                        response_chirho: None,
                        record_sig_chirho: None,
                    }
                }
            })
            .collect(),
    }
}

pub fn volatile_effect_list_text_chirho(
    records_chirho: &[effect_chirho::VolatileEffectDisplayRecordChirho],
) -> String {
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        let status_chirho = if record_chirho.valid_chirho() {
            "VALID"
        } else {
            "INVALID"
        };
        if let Some(raw_record_chirho) = &record_chirho.record_chirho {
            let effect_chirho = &raw_record_chirho.effect_chirho;
            let response_chirho = effect_chirho
                .response_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str())
                .unwrap_or("(pending)");
            out_chirho.push_str(&format!(
                "#{}\t{}\teffect_seq={}\t{:?}\tidem={}\trequest={}\tresponse={}\trecord_sig={}…",
                raw_record_chirho.seq_chirho,
                status_chirho,
                effect_chirho.seq_chirho,
                effect_chirho.capability_chirho,
                effect_chirho.idem_key_chirho.0,
                effect_chirho.request_chirho.0,
                response_chirho,
                &raw_record_chirho.sig_chirho[..raw_record_chirho.sig_chirho.len().min(16)]
            ));
        } else {
            out_chirho.push_str(&format!(
                "line={}\t{}\tunparseable volatile effect record",
                record_chirho.line_chirho, status_chirho
            ));
        }
        if let Some(error_chirho) = &record_chirho.validation_error_chirho {
            out_chirho.push_str(&format!("\tvalidation_error={error_chirho}"));
        }
        out_chirho.push('\n');
    }
    out_chirho
}

#[derive(Debug, serde::Serialize)]
pub struct VolatileEffectVerifyCliReportChirho {
    pub schema_chirho: &'static str,
    pub records_chirho: usize,
    pub objects_chirho: usize,
}

pub fn volatile_effect_verify_cli_report_chirho(
    report_chirho: &verify_chirho::VolatileEffectVerifyReportChirho,
) -> VolatileEffectVerifyCliReportChirho {
    VolatileEffectVerifyCliReportChirho {
        schema_chirho: VOLATILE_EFFECT_VERIFY_REPORT_SCHEMA_CHIRHO,
        records_chirho: report_chirho.records_chirho,
        objects_chirho: report_chirho.objects_chirho,
    }
}

pub fn run_volatile_effects_report_chirho(
    root_chirho: &Path,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let records_chirho =
        effect_chirho::load_volatile_effect_records_for_display_chirho(root_chirho)?;
    if json_chirho {
        let report_chirho = volatile_effect_list_cli_report_chirho(&records_chirho);
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        if records_chirho.is_empty() {
            println!("(no volatile effects)");
        }
        print!("{}", volatile_effect_list_text_chirho(&records_chirho));
    }
    Ok(())
}

pub fn run_volatile_effects_verify_report_chirho(
    root_chirho: &Path,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = verify_chirho::verify_volatile_effect_records_chirho(root_chirho)?;
    if json_chirho {
        let cli_report_chirho = volatile_effect_verify_cli_report_chirho(&report_chirho);
        println!("{}", serde_json::to_string_pretty(&cli_report_chirho)?);
    } else {
        println!(
            "verified: {} volatile effect records + {} request/response objects",
            report_chirho.records_chirho, report_chirho.objects_chirho
        );
    }
    Ok(())
}

pub fn run_contact_example_smoke_report_chirho(
    root_chirho: &Path,
    manifest_chirho: Option<&Path>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let manifest_chirho = manifest_chirho
        .map(Path::to_path_buf)
        .unwrap_or_else(contact_example_smoke_chirho::default_contact_example_manifest_path_chirho);
    let report_chirho = contact_example_smoke_chirho::run_contact_example_smoke_chirho(
        root_chirho,
        &manifest_chirho,
    )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "contact example transition evidence OK: manifest={} app={} owner={} server={}",
            report_chirho.manifest_hash_chirho.0,
            report_chirho.app_chirho,
            report_chirho.owner_chirho,
            report_chirho.server_chirho
        );
        println!(
            "wire page={} submit={} list={} missing_auth={} app_state={} app_reveal={}",
            report_chirho.page_chirho.status_chirho,
            report_chirho.submit_chirho.status_chirho,
            report_chirho.list_refresh_chirho.status_chirho,
            report_chirho.missing_owner_session_chirho.status_chirho,
            report_chirho.app_state_chirho.status_chirho,
            report_chirho.reveal_chirho.status_chirho
        );
        for read_chirho in &report_chirho.read_evidence_chirho {
            println!("read posture={}", read_chirho.path_posture_chirho());
        }
        println!(
            "safe contact key={} raw_body_absent_from_cas={} private_blob_roundtrip={} privacy_scan_findings={}",
            report_chirho.persisted_chirho.contact_key_chirho,
            report_chirho.private_body_chirho.raw_body_absent_from_cas_chirho,
            report_chirho
                .private_body_chirho
                .private_blob_roundtrip_verified_chirho,
            report_chirho.privacy_scan_chirho.findings_chirho.len()
        );
        println!(
            "persisted effects={} volatile_effects={} safe_surfaces_scanned={}",
            report_chirho
                .persisted_chirho
                .persistent_effect_records_chirho,
            report_chirho
                .persisted_chirho
                .volatile_effect_records_chirho,
            report_chirho
                .persisted_chirho
                .contact_safe_surfaces_scanned_chirho
        );
        println!("CRM flow removed pending DAG-app rebuild — contact coverage unchanged");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_credits_demo_smoke_report_chirho(
    root_chirho: &Path,
    config_chirho: &Path,
    expected_config_digest_chirho: &str,
    plan_chirho: &Path,
    expected_plan_digest_chirho: &str,
    issuer_secret_name_chirho: &str,
    activation_authorization_chirho: &Path,
    expected_activation_authorization_digest_chirho: &str,
    payer_credential_secret_name_chirho: &str,
    app_root_chirho: &Path,
    manifest_chirho: Option<&Path>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let packet_chirho =
        cairn_operator_smoke_chirho::credits_demo_smoke_chirho::run_credits_demo_smoke_chirho(
            &cairn_operator_smoke_chirho::credits_demo_smoke_chirho::CreditsDemoSmokeInputsChirho {
                root_chirho,
                config_path_chirho: config_chirho,
                expected_config_digest_chirho,
                plan_path_chirho: plan_chirho,
                expected_plan_digest_chirho,
                issuer_secret_name_chirho,
                activation_authorization_path_chirho: activation_authorization_chirho,
                expected_activation_authorization_digest_chirho,
                payer_credential_secret_name_chirho,
                app_root_chirho,
                manifest_path_chirho: manifest_chirho,
                reviewed_payer_principal_chirho: None,
            },
        )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&packet_chirho)?);
    } else {
        println!(
            "credits-demo LocalPhaseB PASS={} phase_c_precondition={} delete_authorized={} \
             conservation(mint={} l1={} after_l2={} final={} settlement_final={} no_refund={}) \
             verifier_suite={} no_legacy={} credits_smoke={}",
            packet_chirho.pass_chirho,
            packet_chirho.phase_c_precondition_chirho,
            packet_chirho.delete_authorized_chirho,
            packet_chirho.conservation_chirho.minted_chirho,
            packet_chirho.conservation_chirho.balance_l1_chirho,
            packet_chirho.conservation_chirho.balance_after_l2_chirho,
            packet_chirho.conservation_chirho.balance_final_chirho,
            packet_chirho.conservation_chirho.settlement_final_chirho,
            packet_chirho.conservation_chirho.no_refund_chirho,
            packet_chirho.verifier_suite_chirho.green_chirho,
            packet_chirho.no_legacy_chirho.green_chirho,
            packet_chirho.credits_smoke_chirho.green_chirho,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_credits_demo_geo_seed_report_chirho(
    root_chirho: &Path,
    config_chirho: &Path,
    expected_config_digest_chirho: &str,
    plan_chirho: &Path,
    expected_plan_digest_chirho: &str,
    issuer_secret_name_chirho: &str,
    activation_authorization_chirho: &Path,
    expected_activation_authorization_digest_chirho: &str,
    payer_credential_secret_name_chirho: &str,
    app_root_chirho: &Path,
    manifest_chirho: Option<&Path>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho =
        cairn_operator_smoke_chirho::credits_demo_smoke_chirho::run_credits_demo_geo_seed_chirho(
            &cairn_operator_smoke_chirho::credits_demo_smoke_chirho::CreditsDemoSmokeInputsChirho {
                root_chirho,
                config_path_chirho: config_chirho,
                expected_config_digest_chirho,
                plan_path_chirho: plan_chirho,
                expected_plan_digest_chirho,
                issuer_secret_name_chirho,
                activation_authorization_path_chirho: activation_authorization_chirho,
                expected_activation_authorization_digest_chirho,
                payer_credential_secret_name_chirho,
                app_root_chirho,
                manifest_path_chirho: manifest_chirho,
                reviewed_payer_principal_chirho: None,
            },
            // THE SHIPPING POSTURE, stated at the shipping call site rather than defaulted out of
            // sight: this CLI injects NO resident opener. It therefore reaches only the refusing
            // production door, and a test-kind-marked config is refused before any mutation.
            None,
        )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "credits-demo geo seed={} era={} payer={} plan_mint={} source_review_report={} \
             projection={} served_money_arc_executed={}",
            report_chirho.geo_seeded_chirho,
            report_chirho.writer_authority_era_chirho,
            report_chirho.payer_chirho,
            report_chirho.plan_mint_amount_chirho,
            report_chirho.source_review_report_chirho,
            report_chirho.projection_name_chirho,
            report_chirho.served_money_arc_executed_chirho,
        );
    }
    Ok(())
}

pub fn run_credits_demo_inputs_author_report_chirho(
    request_chirho: &CreditsDemoInputsAuthorRequestChirho<'_>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho =
        cairn_operator_smoke_chirho::credits_demo_smoke_chirho::author_credits_demo_inputs_chirho(
            request_chirho,
        )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "credits-demo inputs authored: payer={} plan_digest={} config_digest={} \
             destination_authority_enrollment_digest={} \
             identity_verified={} custody_verified={} signer_refs={} provider_refs={} \
             (review the digest, then pass it explicitly to credits-demo-smoke)",
            report_chirho.payer_chirho,
            report_chirho.plan_digest_chirho,
            report_chirho.config_digest_chirho,
            report_chirho.destination_authority_enrollment_digest_chirho,
            report_chirho.existing_identity_verified_chirho,
            report_chirho.existing_secret_custody_verified_chirho,
            report_chirho.signer_secret_ref_count_chirho,
            report_chirho.provider_secret_ref_count_chirho,
        );
    }
    Ok(())
}

pub fn run_credits_demo_provider_prepare_report_chirho(
    request_chirho: &CreditsDemoProviderPrepareRequestChirho<'_>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = cairn_operator_smoke_chirho::credits_demo_smoke_chirho::prepare_credits_demo_provider_chirho(request_chirho)?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "credits-demo provider prepared outside smoke: operator_established={} \
             cairn_minted={} schema_installed={} values={}/{} forward={} compensation={}",
            report_chirho.operator_established_chirho,
            report_chirho.cairn_minted_chirho,
            report_chirho.schema_installed_chirho,
            report_chirho.target_values_rows_chirho,
            report_chirho.total_values_rows_chirho,
            report_chirho.forward_decision_rows_chirho,
            report_chirho.compensation_receipt_rows_chirho,
        );
    }
    Ok(())
}

/// Print only the verified opaque token so shell capture cannot confuse it with status prose.
pub fn run_credits_demo_concurrency_token_report_chirho(
    request_chirho: &CreditsDemoConcurrencyTokenRequestChirho<'_>,
) -> anyhow::Result<()> {
    let token_chirho =
        cairn_operator_smoke_chirho::credits_demo_smoke_chirho::read_credits_demo_concurrency_token_chirho(
            request_chirho,
        )?;
    println!("{token_chirho}");
    Ok(())
}

/// Give a root lifecycle state through the tested primitives, then self-check what was created.
///
/// **Two modes, because the primitive has two and they are not interchangeable.**
/// `bootstrap_cas_lifecycle_chirho` requires an EMPTY root and refuses a populated one with
/// `CasLifecycleLegacyRootRequiresOfflineMigrationChirho`. A pre-F4 root that already holds objects
/// is exactly that case, so it needs `migrate_cas_lifecycle_offline_chirho` — whose own contract
/// says *the caller owns proof that no publisher, collector, or whole-root replacement is
/// concurrent*. That obligation cannot be checked from here, so the operator asserts it by name.
///
/// Neither path fabricates state: both go through the tested primitives, and an already-initialized
/// root is refused by the primitive itself with `CasLifecycleAlreadyInitializedOrPartialChirho`.
pub fn run_cas_lifecycle_bootstrap_report_chirho(
    root_chirho: &Path,
    offline_migration_quiesced_chirho: bool,
) -> anyhow::Result<()> {
    use cairn_chirho::durable_chirho::cas_lifecycle_chirho;

    if offline_migration_quiesced_chirho {
        println!(
            "mode: OFFLINE MIGRATION of a populated root — you have asserted the root is quiesced \
             (no concurrent publisher, collector, or whole-root replacement)"
        );
        cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho(root_chirho)?;
    } else {
        println!("mode: BOOTSTRAP of an empty root");
        cas_lifecycle_chirho::bootstrap_cas_lifecycle_chirho(root_chirho)?;
    }

    // SELF-CHECK: reopen from scratch and take a fresh SHARED read. This proves the state that was
    // just created is actually openable and readable, rather than trusting the create call's return.
    let reopened_chirho = cas_lifecycle_chirho::CasLifecycleRootChirho::open_chirho(root_chirho)?;
    let snapshot_chirho = reopened_chirho.snapshot_chirho()?;
    let incarnation_chirho = snapshot_chirho
        .root_incarnation_chirho()
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect::<String>();
    println!(
        "lifecycle self-check OK: reopened, incarnation={} deletion_generation={}",
        incarnation_chirho,
        snapshot_chirho.deletion_generation_chirho()
    );
    Ok(())
}

/// Re-enter a CONSUMED credits-demo root and drive its reviewed app, route, and price doors.
pub fn run_credits_demo_continuation_report_chirho(
    root_chirho: &Path,
    reviewed_inputs_dir_chirho: &Path,
    expected_config_digest_chirho: &str,
    storage_namespace_chirho: &str,
) -> anyhow::Result<()> {
    let inventory_chirho =
        continuation_chirho::inventory_consumed_root_chirho(root_chirho, storage_namespace_chirho)?;
    continuation_chirho::require_consumed_root_chirho(&inventory_chirho)?;
    println!(
        "credits-demo continuation inventory: app_head={} route_heads={} price_head={}",
        inventory_chirho
            .app_head_chirho
            .as_ref()
            .map(|h_chirho| h_chirho.0.as_str())
            .unwrap_or("absent"),
        inventory_chirho.route_heads_chirho.len(),
        inventory_chirho
            .price_book_head_chirho
            .as_ref()
            .map(|h_chirho| h_chirho.0.as_str())
            .unwrap_or("absent"),
    );
    println!(
        "next phase: {:?}",
        continuation_chirho::next_phase_chirho(&inventory_chirho)
    );
    let report_chirho = continuation_chirho::run_credits_demo_continuation_chirho(
        root_chirho,
        reviewed_inputs_dir_chirho,
        expected_config_digest_chirho,
        storage_namespace_chirho,
    )?;
    println!(
        "continuation entered {:?} with {} mutation(s) attempted",
        report_chirho.entered_phase_chirho, report_chirho.mutations_attempted_chirho
    );
    Ok(())
}

/// One-time migration for a consumed root that predates bounded reviewed-candidate pointers.
///
/// The explicit hash is operational input, not source configuration. The operator-smoke boundary
/// verifies the stored report and its candidate closure before it creates the pointer.
pub fn run_credits_demo_reviewed_candidate_pin_report_chirho(
    root_chirho: &Path,
    source_review_report_chirho: &str,
) -> anyhow::Result<()> {
    let pointer_chirho = continuation_chirho::pin_reviewed_candidate_coordinates_chirho(
        root_chirho,
        source_review_report_chirho,
    )?;
    println!(
        "credits-demo reviewed candidate pinned: app={} report={} candidate={}",
        pointer_chirho.app_chirho,
        pointer_chirho.source_review_report_chirho.0,
        pointer_chirho.candidate_root_dag_chirho.0
    );
    Ok(())
}

pub fn run_agent_authored_backend_smoke_report_chirho(
    root_chirho: &Path,
    manifest_chirho: Option<&Path>,
    overcap_manifest_chirho: Option<&Path>,
    undeclared_effect_manifest_chirho: Option<&Path>,
    brief_chirho: Option<&Path>,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let manifest_chirho = manifest_chirho.map(Path::to_path_buf).unwrap_or_else(
        agent_authored_backend_smoke_chirho::default_agent_authored_backend_manifest_path_chirho,
    );
    let brief_chirho = brief_chirho.map(Path::to_path_buf).unwrap_or_else(
        agent_authored_backend_smoke_chirho::default_agent_authored_backend_brief_path_chirho,
    );
    let overcap_manifest_chirho = overcap_manifest_chirho.map(Path::to_path_buf).unwrap_or_else(
        agent_authored_backend_smoke_chirho::default_agent_authored_backend_overcap_manifest_path_chirho,
    );
    let undeclared_effect_manifest_chirho = undeclared_effect_manifest_chirho
        .map(Path::to_path_buf)
        .unwrap_or_else(
            agent_authored_backend_smoke_chirho::default_agent_authored_backend_undeclared_effect_manifest_path_chirho,
        );
    let report_chirho =
        agent_authored_backend_smoke_chirho::run_agent_authored_backend_smoke_chirho(
            root_chirho,
            &manifest_chirho,
            &overcap_manifest_chirho,
            &undeclared_effect_manifest_chirho,
            &brief_chirho,
        )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "agent-authored backend smoke OK: manifest={} overcap_manifest={} brief={} app={} owner={} producer={} server={}",
            report_chirho.manifest_hash_chirho.0,
            report_chirho.overcap_manifest_hash_chirho.0,
            report_chirho.brief_hash_chirho.0,
            report_chirho.app_chirho,
            report_chirho.owner_chirho,
            report_chirho.producer_chirho,
            report_chirho.server_chirho
        );
        println!(
            "candidate dag={} nodes={} caps_added={} cost={} agent_report=#{} verified_reports={} review_record=#{} verified_reviews={}",
            report_chirho.candidate_chirho.root_dag_chirho.0,
            report_chirho.review_diff_chirho.candidate_node_count_chirho,
            report_chirho.review_diff_chirho.added_capabilities_chirho.len(),
            report_chirho.review_diff_chirho.candidate_cost_token_chirho,
            report_chirho.agent_report_seq_chirho,
            report_chirho.agent_reports_verified_chirho,
            report_chirho.promotion_chirho.seq_chirho,
            report_chirho.review_records_verified_chirho
        );
        println!(
            "containment overcap_caps={} overcap_rejected={} overcap_ref_absent={} undeclared_review_caps={} undeclared_runtime_blocked={} wire missing_policy={} undeclared={} serve={} rollback={} raw_body_absent_before_policy={} effects={}/{} app_ref_removed={} undeclared_ref_removed={}",
            report_chirho
                .overcap_review_diff_chirho
                .added_capabilities_chirho
                .len(),
            report_chirho.overcap_promotion_rejected_chirho,
            report_chirho.overcap_app_ref_absent_chirho,
            report_chirho
                .undeclared_effect_review_diff_chirho
                .added_capabilities_chirho
                .len(),
            report_chirho.undeclared_effect_runtime_blocked_chirho,
            report_chirho.missing_policy_chirho.status_chirho,
            report_chirho.undeclared_effect_chirho.status_chirho,
            report_chirho.serve_chirho.status_chirho,
            report_chirho.rollback_chirho.status_chirho,
            report_chirho.missing_policy_raw_body_absent_from_cas_chirho,
            report_chirho.persistent_effect_records_chirho,
            report_chirho.volatile_effect_records_chirho,
            report_chirho.app_ref_removed_after_rollback_chirho,
            report_chirho.undeclared_effect_app_ref_removed_after_rollback_chirho
        );
    }
    Ok(())
}

pub fn run_learner_handover_drill_report_chirho(
    fixture_root_chirho: Option<&Path>,
    allow_non_fixture_root_chirho: bool,
    json_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = learner_handover_drill_chirho::run_learner_handover_drill_chirho(
        fixture_root_chirho,
        allow_non_fixture_root_chirho,
    )?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "learner handover drill OK: steps={}/{} apps={} persistent_effects={} volatile_effects={} route={}/{} projection_rows={}",
            report_chirho.steps_run_chirho,
            report_chirho.steps_total_chirho,
            report_chirho.app_listing_chirho.verified_apps_chirho,
            report_chirho
                .signed_effects_chirho
                .persistent_effects_verified_chirho,
            report_chirho.signed_effects_chirho.volatile_effects_verified_chirho,
            report_chirho.route_rollback_chirho.app_chirho,
            report_chirho.route_rollback_chirho.route_chirho,
            report_chirho
                .query_projection_chirho
                .rows_projected_chirho
        );
    }
    Ok(())
}

pub fn run_privacy_verify_report_command_chirho(
    root_chirho: &Path,
    json_chirho: bool,
    fail_on_empty_evidence_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = privacy_chirho::verify_privacy_logs_chirho(root_chirho)?;
    let legal_hold_report_chirho = legal_hold_chirho::verify_legal_holds_chirho(root_chirho)?;
    let backup_report_chirho = privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)?;
    let retention_records_chirho =
        retention_chirho::verify_private_blob_retention_chirho(root_chirho)?;
    let export_records_chirho =
        data_rights_chirho::verify_subject_export_evidence_chirho(root_chirho)?;
    let cli_report_chirho = privacy_verify_cli_report_chirho(
        &report_chirho,
        &legal_hold_report_chirho,
        &backup_report_chirho,
        retention_records_chirho,
        export_records_chirho,
    );
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&cli_report_chirho)?);
    } else {
        println!(
            "verified {} privacy blob record(s), {} erasure record(s), {} privacy access record(s), {} legal hold record(s), {} active legal hold(s), {} backup key policy record(s), {} replica target(s), {} erasure propagation record(s), {} privacy retention record(s), {} export evidence record(s)",
            cli_report_chirho.blob_records_chirho,
            cli_report_chirho.erasure_records_chirho,
            cli_report_chirho.access_records_chirho,
            cli_report_chirho.legal_hold_records_chirho,
            cli_report_chirho.active_legal_holds_chirho,
            cli_report_chirho.backup_key_policy_records_chirho,
            cli_report_chirho.replica_targets_chirho,
            cli_report_chirho.erasure_propagation_records_chirho,
            cli_report_chirho.privacy_retention_records_chirho,
            cli_report_chirho.export_evidence_records_chirho
        );
    }
    enforce_privacy_verify_fail_on_empty_evidence_chirho(
        &cli_report_chirho,
        fail_on_empty_evidence_chirho,
    )?;
    Ok(())
}

pub fn run_privacy_scan_report_command_chirho(
    root_chirho: &Path,
    json_chirho: bool,
    fail_on_findings_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho)?;
    if json_chirho {
        println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    } else {
        println!(
            "privacy-scan jsonl_files={} jsonl_rows={} json_objects={} findings={} effect_records={} effect_cas_objects={} effect_cas_json_objects={} effect_cas_private_ciphertexts_skipped={} effect_cas_binary_objects_skipped={} effect_form_fields={} seqlog_quarantine_files={} seqlog_quarantine_bytes={}",
            report_chirho.jsonl_files_chirho,
            report_chirho.jsonl_rows_chirho,
            report_chirho.json_objects_chirho,
            report_chirho.findings_chirho.len(),
            report_chirho.effect_records_chirho,
            report_chirho.effect_cas_objects_chirho,
            report_chirho.effect_cas_json_objects_chirho,
            report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
            report_chirho.effect_cas_binary_objects_skipped_chirho,
            report_chirho.effect_form_fields_chirho,
            report_chirho.seqlog_quarantine_files_chirho,
            report_chirho.seqlog_quarantine_bytes_chirho
        );
        for finding_chirho in &report_chirho.findings_chirho {
            let line_chirho = finding_chirho
                .line_chirho
                .map(|line_chirho| format!(":{line_chirho}"))
                .unwrap_or_default();
            println!(
                "{}{} {} {} - {}",
                finding_chirho.source_chirho,
                line_chirho,
                finding_chirho.path_chirho,
                finding_chirho.kind_chirho,
                finding_chirho.detail_chirho
            );
        }
    }
    enforce_privacy_scan_fail_on_findings_chirho(&report_chirho, fail_on_findings_chirho)?;
    Ok(())
}

pub fn run_seqlog_scan_report_command_chirho(
    root_chirho: &Path,
    json_chirho: bool,
    fail_on_findings_chirho: bool,
) -> anyhow::Result<()> {
    let args_chirho = cairn_seqlog_scan_chirho::SeqlogScanArgsChirho {
        json_chirho,
        fail_on_findings_chirho,
    };
    cairn_seqlog_scan_chirho::run_seqlog_scan_chirho(root_chirho, &args_chirho)
}

pub struct ComplianceEvidenceGenerateCommandInputChirho<'a> {
    pub frameworks_chirho: &'a [String],
    pub period_start_ms_chirho: u64,
    pub period_end_ms_chirho: Option<u64>,
    pub generated_by_chirho: &'a str,
    pub fail_on_failed_sources_chirho: bool,
    pub fail_on_coverage_gaps_chirho: bool,
    pub fail_on_manual_controls_chirho: bool,
}

pub fn run_compliance_evidence_generate_report_command_chirho(
    root_chirho: &Path,
    input_chirho: ComplianceEvidenceGenerateCommandInputChirho<'_>,
) -> anyhow::Result<()> {
    let period_end_ms_chirho = input_chirho
        .period_end_ms_chirho
        .unwrap_or_else(current_time_ms_chirho);
    let receipt_chirho = compliance_evidence_chirho::generate_compliance_evidence_pack_chirho(
        root_chirho,
        input_chirho.frameworks_chirho,
        input_chirho.period_start_ms_chirho,
        period_end_ms_chirho,
        input_chirho.generated_by_chirho,
    )?;
    println!("{}", serde_json::to_string_pretty(&receipt_chirho)?);
    enforce_compliance_evidence_fail_on_failed_sources_chirho(
        &receipt_chirho.pack_body_chirho,
        input_chirho.fail_on_failed_sources_chirho,
    )?;
    enforce_compliance_evidence_fail_on_coverage_gaps_chirho(
        &receipt_chirho.pack_body_chirho,
        input_chirho.fail_on_coverage_gaps_chirho,
    )?;
    enforce_compliance_evidence_fail_on_manual_controls_chirho(
        &receipt_chirho.pack_body_chirho,
        input_chirho.fail_on_manual_controls_chirho,
    )?;
    Ok(())
}

pub fn run_compliance_evidence_show_report_command_chirho(
    root_chirho: &Path,
    pack_chirho: &str,
) -> anyhow::Result<()> {
    let pack_hash_chirho = HashChirho(pack_chirho.to_string());
    let pack_chirho = compliance_evidence_chirho::load_compliance_evidence_pack_chirho(
        root_chirho,
        &pack_hash_chirho,
    )?;
    println!("{}", serde_json::to_string_pretty(&pack_chirho)?);
    Ok(())
}

pub fn run_compliance_evidence_verify_report_command_chirho(
    root_chirho: &Path,
    pack_chirho: Option<&str>,
    fail_on_failed_sources_chirho: bool,
    fail_on_coverage_gaps_chirho: bool,
    fail_on_manual_controls_chirho: bool,
) -> anyhow::Result<()> {
    let pack_hash_chirho = pack_chirho.map(|pack_chirho| HashChirho(pack_chirho.to_string()));
    let verification_chirho = compliance_evidence_chirho::verify_compliance_evidence_chirho(
        root_chirho,
        pack_hash_chirho.as_ref(),
    )?;
    println!("{}", serde_json::to_string_pretty(&verification_chirho)?);
    enforce_compliance_evidence_verify_fail_on_failed_sources_chirho(
        &verification_chirho,
        fail_on_failed_sources_chirho,
    )?;
    enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho(
        &verification_chirho,
        fail_on_coverage_gaps_chirho,
    )?;
    enforce_compliance_evidence_verify_fail_on_manual_controls_chirho(
        &verification_chirho,
        fail_on_manual_controls_chirho,
    )?;
    Ok(())
}

pub fn run_data_residency_verify_report_command_chirho(
    root_chirho: &Path,
    fail_on_violations_chirho: bool,
) -> anyhow::Result<()> {
    let report_chirho = data_residency_chirho::verify_data_residency_chirho(root_chirho)?;
    println!("{}", serde_json::to_string_pretty(&report_chirho)?);
    enforce_data_residency_fail_on_violations_chirho(&report_chirho, fail_on_violations_chirho)?;
    Ok(())
}

pub fn enforce_privacy_scan_fail_on_findings_chirho(
    report_chirho: &privacy_chirho::PrivacyScanReportChirho,
    fail_on_findings_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_findings_chirho && !report_chirho.findings_chirho.is_empty() {
        anyhow::bail!(
            "privacy-scan found {} finding(s)",
            report_chirho.findings_chirho.len()
        );
    }
    Ok(())
}

pub fn enforce_privacy_verify_fail_on_empty_evidence_chirho(
    report_chirho: &PrivacyVerifyCliReportChirho,
    fail_on_empty_evidence_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_empty_evidence_chirho
        && privacy_verify_cli_evidence_records_chirho(report_chirho) == 0
    {
        anyhow::bail!("privacy-verify found no evidence record(s)");
    }
    Ok(())
}

pub fn enforce_data_residency_fail_on_violations_chirho(
    report_chirho: &data_residency_chirho::DataResidencyVerifyReportChirho,
    fail_on_violations_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_violations_chirho && report_chirho.noncompliant_attestations_chirho > 0 {
        anyhow::bail!(
            "data-residency-verify found {} noncompliant attestation(s)",
            report_chirho.noncompliant_attestations_chirho
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_fail_on_failed_sources_chirho(
    pack_chirho: &compliance_evidence_chirho::ComplianceEvidencePackChirho,
    fail_on_failed_sources_chirho: bool,
) -> anyhow::Result<()> {
    let failed_sources_chirho = pack_chirho
        .sources_chirho
        .iter()
        .filter(|source_chirho| source_chirho.status_chirho == "failed-chirho")
        .count();
    if fail_on_failed_sources_chirho && failed_sources_chirho > 0 {
        anyhow::bail!(
            "compliance-evidence found {} failed source(s)",
            failed_sources_chirho
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_fail_on_coverage_gaps_chirho(
    pack_chirho: &compliance_evidence_chirho::ComplianceEvidencePackChirho,
    fail_on_coverage_gaps_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_coverage_gaps_chirho && !pack_chirho.coverage_gaps_chirho.is_empty() {
        anyhow::bail!(
            "compliance-evidence found {} coverage gap(s)",
            pack_chirho.coverage_gaps_chirho.len()
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_fail_on_manual_controls_chirho(
    pack_chirho: &compliance_evidence_chirho::ComplianceEvidencePackChirho,
    fail_on_manual_controls_chirho: bool,
) -> anyhow::Result<()> {
    let manual_controls_chirho = pack_chirho
        .controls_chirho
        .iter()
        .filter(|control_chirho| control_chirho.status_chirho == "manual-required-chirho")
        .count();
    if fail_on_manual_controls_chirho && manual_controls_chirho > 0 {
        anyhow::bail!(
            "compliance-evidence found {} manual-required control(s)",
            manual_controls_chirho
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_verify_fail_on_failed_sources_chirho(
    verification_chirho: &compliance_evidence_chirho::ComplianceEvidenceVerificationChirho,
    fail_on_failed_sources_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_failed_sources_chirho && verification_chirho.failed_sources_chirho > 0 {
        anyhow::bail!(
            "compliance-evidence verification found {} failed source(s)",
            verification_chirho.failed_sources_chirho
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho(
    verification_chirho: &compliance_evidence_chirho::ComplianceEvidenceVerificationChirho,
    fail_on_coverage_gaps_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_coverage_gaps_chirho && verification_chirho.coverage_gaps_chirho > 0 {
        anyhow::bail!(
            "compliance-evidence verification found {} coverage gap(s)",
            verification_chirho.coverage_gaps_chirho
        );
    }
    Ok(())
}

pub fn enforce_compliance_evidence_verify_fail_on_manual_controls_chirho(
    verification_chirho: &compliance_evidence_chirho::ComplianceEvidenceVerificationChirho,
    fail_on_manual_controls_chirho: bool,
) -> anyhow::Result<()> {
    if fail_on_manual_controls_chirho && verification_chirho.manual_controls_chirho > 0 {
        anyhow::bail!(
            "compliance-evidence verification found {} manual-required control(s)",
            verification_chirho.manual_controls_chirho
        );
    }
    Ok(())
}
