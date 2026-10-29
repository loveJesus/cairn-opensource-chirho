// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Tests for data_rights_chirho (split out to keep the module under the line cap).

use super::*;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho};
use crate::{
    app_chirho, cas_chirho, data_residency_chirho, effect_pricing_chirho, identity_chirho,
    privacy_chirho, realtime_legacy_evidence_chirho, review_chirho, store_chirho, tenant_chirho,
};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-data-rights-test-{}-{}-{}",
        std::process::id(),
        n_chirho,
        now_ms_chirho()
    ))
}

fn deploy_test_app_chirho(root_chirho: &Path, app_name_chirho: &str, owner_chirho: &str) -> String {
    let node_chirho = test_node_chirho(root_chirho, &format!("{app_name_chirho}_node_chirho"));
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        root_chirho,
        app_name_chirho,
        dag_chirho.clone(),
        owner_chirho,
    )
    .unwrap();
    dag_chirho.0
}

fn test_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_chirho = cas_chirho::add_chirho(root_chirho, name_chirho.as_bytes()).unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: wasm_chirho,
        entry_chirho: name_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 1,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

fn write_jsonl_records_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn copy_private_blob_key_to_replica_chirho(
    primary_chirho: &Path,
    replica_chirho: &Path,
    key_chirho: &str,
) {
    let from_chirho = primary_chirho
        .join("privacy-keys-chirho")
        .join(format!("{key_chirho}.json"));
    let to_dir_chirho = replica_chirho.join("privacy-keys-chirho");
    std::fs::create_dir_all(&to_dir_chirho).unwrap();
    std::fs::copy(
        from_chirho,
        to_dir_chirho.join(format!("{key_chirho}.json")),
    )
    .unwrap();
}

fn register_crm_safe_user_identity_principal_chirho(root_chirho: &Path) -> String {
    for _attempt_chirho in 0..64 {
        let principal_chirho = identity_chirho::register_identity_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
        )
        .unwrap()
        .principal_chirho;
        let tail_chirho = principal_chirho.strip_prefix("user/").unwrap_or_default();
        if tail_chirho
            .chars()
            .any(|ch_chirho| ch_chirho.is_ascii_alphabetic())
        {
            return principal_chirho;
        }
    }
    panic!("could not register a CRM-safe opaque user identity principal");
}

fn invalid_signature_chirho() -> String {
    "00".repeat(64)
}

#[test]
fn subject_export_surface_inventory_covers_production_jsonl_logs_chirho() {
    let reviewed_chirho = reviewed_subject_export_log_files_chirho();
    let reviewed_dynamic_chirho =
        BTreeSet::from([crate::source_scan_chirho::REFS_REFLOG_LOGICAL_SURFACE_CHIRHO]);
    let production_logs_chirho =
        crate::source_scan_chirho::production_jsonl_logical_surface_inventory_chirho();
    let missing_chirho = production_logs_chirho.coverage_gaps_chirho(
        |file_chirho| reviewed_chirho.contains(file_chirho),
        |logical_name_chirho| reviewed_dynamic_chirho.contains(logical_name_chirho),
    );
    let unexplained_chirho = crate::privacy_chirho::unexplained_literal_root_gaps_chirho(
        &missing_chirho.literal_root_files_chirho,
    )
    .unwrap_or_else(|stale_chirho| panic!("{stale_chirho}"));
    assert!(
        unexplained_chirho.is_empty(),
        "literal production signed JSONL logs lack M27 subject-export review: {unexplained_chirho:?}"
    );
    assert!(
        missing_chirho
            .dynamic_per_branch_populations_chirho
            .is_empty(),
        "dynamic production signed JSONL populations lack subject-export review: {:?}",
        missing_chirho.dynamic_per_branch_populations_chirho
    );
}

#[test]
fn subject_export_surface_inventory_tracks_privacy_review_chirho() {
    let export_review_chirho = reviewed_subject_export_log_files_chirho();
    let privacy_review_chirho = privacy_chirho::reviewed_signed_log_files_chirho();
    let missing_from_export_chirho = privacy_review_chirho
        .iter()
        .filter(|file_chirho| !export_review_chirho.contains(**file_chirho))
        .copied()
        .collect::<Vec<_>>();
    let extra_in_export_chirho = export_review_chirho
        .iter()
        .filter(|file_chirho| !privacy_review_chirho.contains(**file_chirho))
        .copied()
        .collect::<Vec<_>>();
    assert!(
            missing_from_export_chirho.is_empty() && extra_in_export_chirho.is_empty(),
            "M27 privacy review and subject-export review inventories diverged; missing_from_export={missing_from_export_chirho:?} extra_in_export={extra_in_export_chirho:?}"
        );
}

#[test]
fn portable_export_verifier_preflight_covers_loaded_source_modules_chirho() {
    let source_chirho = include_str!("../data_rights_chirho.rs");
    let production_chirho = source_chirho
        .split("\n#[cfg(test)]")
        .next()
        .unwrap_or(source_chirho);
    let verifier_start_chirho = production_chirho
        .find("fn verify_subject_portable_export_source_logs_chirho")
        .unwrap();
    let verifier_end_chirho = production_chirho
        .find("fn verify_export_source_chirho")
        .unwrap();
    let verifier_text_chirho = &production_chirho[verifier_start_chirho..verifier_end_chirho];

    let mut loaded_modules_chirho = BTreeSet::new();
    for line_chirho in production_chirho.lines() {
        let Some((before_chirho, _after_chirho)) = line_chirho.split_once("::load_") else {
            continue;
        };
        let Some(module_chirho) = before_chirho
            .split(|ch_chirho: char| !(ch_chirho.is_ascii_alphanumeric() || ch_chirho == '_'))
            .rfind(|part_chirho| !part_chirho.is_empty())
        else {
            continue;
        };
        if module_chirho.ends_with("_chirho") {
            loaded_modules_chirho.insert(module_chirho.to_string());
        }
    }
    if production_chirho.contains("load_subject_export_evidence_records_chirho(root_chirho)") {
        loaded_modules_chirho.insert("data_rights_chirho".to_string());
    }

    let missing_chirho = loaded_modules_chirho
        .iter()
        .filter(|module_chirho| match module_chirho.as_str() {
            "data_rights_chirho" => {
                !verifier_text_chirho.contains("verify_subject_export_evidence_chirho")
            }
            "effect_chirho" => !verifier_text_chirho
                .contains("verify_chirho::verify_volatile_effect_records_chirho"),
            _ => !verifier_text_chirho.contains(&format!("{module_chirho}::verify_")),
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing_chirho.is_empty(),
        "portable export reads source modules without preflight verifiers: {missing_chirho:?}"
    );
}

#[test]
fn portable_export_includes_verified_head_removal_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let other_owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_test_app_chirho(&root_chirho, "removalrightsapp", &owner_chirho);
    assert!(
        app_chirho::undeploy_app_chirho(&root_chirho, "removalrightsapp", &owner_chirho).unwrap()
    );

    let owner_export_chirho =
        export_subject_portable_data_chirho(&root_chirho, &owner_chirho, false).unwrap();
    let removal_export_chirho = owner_export_chirho
        .records_chirho
        .iter()
        .find(|record_chirho| record_chirho.source_chirho == "refs.head-removals-chirho")
        .unwrap();
    assert_eq!(
        removal_export_chirho.record_chirho["owner_principal_chirho"],
        owner_chirho
    );
    assert_eq!(
        removal_export_chirho.record_chirho["branch_chirho"],
        "app/removalrightsapp"
    );

    let other_export_chirho =
        export_subject_portable_data_chirho(&root_chirho, &other_owner_chirho, false).unwrap();
    assert!(!other_export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| record_chirho.source_chirho == "refs.head-removals-chirho"));

    let mut removal_records_chirho =
        crate::head_removal_transition_chirho::load_head_removal_evidence_values_chirho(
            &root_chirho,
        )
        .unwrap();
    removal_records_chirho[0]["sig_chirho"] = serde_json::Value::String(invalid_signature_chirho());
    write_jsonl_records_chirho(
        &root_chirho.join("head-removals-chirho.jsonl"),
        &removal_records_chirho,
    );
    let error_chirho =
        export_subject_portable_data_chirho(&root_chirho, &owner_chirho, false).unwrap_err();
    let error_chain_chirho = error_chirho
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        error_chain_chirho.contains("verify refs.head-removals-chirho"),
        "{error_chain_chirho}"
    );
    assert!(
        error_chain_chirho.contains("signature invalid"),
        "{error_chain_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn portable_export_redacts_backup_replica_paths_chirho() {
    let root_chirho = tmp_root_chirho();
    let replica_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&replica_chirho).unwrap();
    let subject_chirho = "operator/export-backup-redaction";
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            subject_chirho,
        ),
        subject_chirho,
        b"secret",
    )
    .unwrap();
    copy_private_blob_key_to_replica_chirho(
        &root_chirho,
        &replica_chirho,
        &blob_chirho.key_id_chirho,
    );

    let target_chirho = privacy_backup_chirho::register_privacy_replica_chirho(
        &root_chirho,
        "backup/export-redaction",
        &replica_chirho,
        subject_chirho,
    )
    .unwrap();
    privacy_backup_chirho::declare_privacy_backup_key_policy_chirho(
        &root_chirho,
        "durable-backups-ciphertext-only",
        subject_chirho,
    )
    .unwrap();
    let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
        &root_chirho,
        subject_chirho,
        subject_chirho,
        "subject-export-path-redaction",
    )
    .unwrap();
    let propagation_chirho = privacy_backup_chirho::propagate_privacy_erasure_to_replica_chirho(
        &root_chirho,
        erasure_chirho.seq_chirho,
        "backup/export-redaction",
        subject_chirho,
    )
    .unwrap();

    let replica_path_chirho = std::fs::canonicalize(&replica_chirho)
        .unwrap()
        .display()
        .to_string();
    assert_eq!(target_chirho.root_chirho, replica_path_chirho);
    let internal_propagations_chirho =
        privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho(&root_chirho)
            .unwrap();
    assert_eq!(
        internal_propagations_chirho[0].replica_root_chirho,
        replica_path_chirho
    );
    let backup_report_chirho =
        privacy_backup_chirho::verify_privacy_backups_chirho(&root_chirho).unwrap();
    assert_eq!(backup_report_chirho.replica_targets_chirho, 1);
    assert_eq!(backup_report_chirho.erasure_propagation_records_chirho, 1);

    let export_chirho = export_subject_portable_data_with_evidence_chirho(
        &root_chirho,
        subject_chirho,
        true,
        subject_chirho,
    )
    .unwrap();
    let redacted_propagation_chirho = export_chirho
        .backup_erasure_propagations_chirho
        .first()
        .unwrap();
    assert_eq!(
        redacted_propagation_chirho.seq_chirho,
        propagation_chirho.seq_chirho
    );
    assert_eq!(
        redacted_propagation_chirho.replica_root_scope_chirho,
        SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO
    );
    assert!(redacted_propagation_chirho.source_record_verified_chirho);
    assert_eq!(
        redacted_propagation_chirho.redacted_fields_chirho,
        vec!["replica_root_chirho".to_string()]
    );
    let redacted_propagation_json_chirho =
        serde_json::to_value(redacted_propagation_chirho).unwrap();
    assert!(redacted_propagation_json_chirho
        .get("replica_root_chirho")
        .is_none());
    let replica_target_export_chirho = export_chirho
        .records_chirho
        .iter()
        .find(|record_chirho| record_chirho.source_chirho == "privacy.replica-targets-chirho")
        .unwrap();
    assert_eq!(
        replica_target_export_chirho.record_chirho["schema_chirho"],
        SUBJECT_EXPORT_REPLICA_TARGET_SCHEMA_CHIRHO
    );
    assert_eq!(
        replica_target_export_chirho.record_chirho["root_scope_chirho"],
        SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO
    );
    assert_eq!(
        replica_target_export_chirho.record_chirho["redacted_fields_chirho"],
        serde_json::json!(["root_chirho"])
    );
    assert!(replica_target_export_chirho
        .record_chirho
        .get("root_chirho")
        .is_none());
    assert_eq!(
        export_chirho
            .export_evidence_chirho
            .as_ref()
            .unwrap()
            .backup_propagation_record_seqs_chirho,
        vec![propagation_chirho.seq_chirho]
    );
    assert_eq!(
        verify_subject_export_evidence_chirho(&root_chirho).unwrap(),
        1
    );
    let export_json_chirho = serde_json::to_string(&export_chirho).unwrap();
    assert!(export_json_chirho.contains(SUBJECT_EXPORT_REPLICA_ROOT_REDACTED_CHIRHO));
    assert!(!export_json_chirho.contains(&replica_path_chirho));

    let _ = std::fs::remove_dir_all(&root_chirho);
    let _ = std::fs::remove_dir_all(&replica_chirho);
}

#[test]
fn portable_export_requires_verified_identity_rows_chirho() {
    let root_chirho = tmp_root_chirho();
    let user_chirho = register_crm_safe_user_identity_principal_chirho(&root_chirho);
    let export_chirho =
        export_subject_portable_data_chirho(&root_chirho, &user_chirho, false).unwrap();
    assert!(export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| record_chirho.source_chirho == "identity.records-chirho"));

    let mut records_chirho = identity_chirho::load_identities_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_records_chirho(
        &root_chirho.join("identities-chirho.jsonl"),
        &records_chirho,
    );
    let export_error_chirho = format!(
        "{:?}",
        export_subject_portable_data_chirho(&root_chirho, &user_chirho, false).unwrap_err()
    );
    assert!(export_error_chirho.contains("verify identity.records-chirho"));
    assert!(export_error_chirho.contains("identity entry 0 signature invalid"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn portable_export_requires_verified_pricebook_and_review_rows_chirho() {
    let pricebook_root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &pricebook_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_test_app_chirho(&pricebook_root_chirho, "rightsapp", &owner_chirho);
    effect_pricing_chirho::set_price_book_chirho(
        &pricebook_root_chirho,
        "rightsapp",
        &owner_chirho,
        Some(3),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    let export_chirho =
        export_subject_portable_data_chirho(&pricebook_root_chirho, &owner_chirho, false).unwrap();
    assert!(export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| record_chirho.source_chirho == "pricebook.records-chirho"));

    let mut price_records_chirho =
        effect_pricing_chirho::load_price_book_records_chirho(&pricebook_root_chirho).unwrap();
    price_records_chirho[0].sig_chirho = invalid_signature_chirho();
    write_jsonl_records_chirho(
        &pricebook_root_chirho.join("pricebook-records-chirho.jsonl"),
        &price_records_chirho,
    );
    let export_error_chirho = format!(
        "{:?}",
        export_subject_portable_data_chirho(&pricebook_root_chirho, &owner_chirho, false)
            .unwrap_err()
    );
    assert!(export_error_chirho.contains("verify pricebook.records-chirho"));
    assert!(export_error_chirho.contains("price book record 0 signature invalid"));
    let _ = std::fs::remove_dir_all(&pricebook_root_chirho);

    let review_root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &review_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_test_app_chirho(&review_root_chirho, "rightsapp", &owner_chirho);
    let candidate_node_chirho =
        test_node_chirho(&review_root_chirho, "rightsapp_candidate_node_chirho");
    let candidate_chirho = store_chirho::put_object_chirho(
        &review_root_chirho,
        &DagChirho {
            nodes_chirho: vec![candidate_node_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    review_chirho::reject_candidate_chirho(
        &review_root_chirho,
        "rightsapp",
        &owner_chirho,
        candidate_chirho,
        "portable export verifier regression",
    )
    .unwrap();
    let export_chirho =
        export_subject_portable_data_chirho(&review_root_chirho, &owner_chirho, false).unwrap();
    assert!(export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| record_chirho.source_chirho == "review.records-chirho"));

    let mut review_records_chirho =
        review_chirho::load_review_records_chirho(&review_root_chirho).unwrap();
    review_records_chirho[0].sig_chirho = invalid_signature_chirho();
    write_jsonl_records_chirho(
        &review_root_chirho.join("review-records-chirho.jsonl"),
        &review_records_chirho,
    );
    let export_error_chirho = format!(
        "{:?}",
        export_subject_portable_data_chirho(&review_root_chirho, &owner_chirho, false).unwrap_err()
    );
    assert!(export_error_chirho.contains("verify review.records-chirho"));
    assert!(export_error_chirho.contains("review record 0 signature invalid"));
    let _ = std::fs::remove_dir_all(&review_root_chirho);
}

#[test]
fn portable_export_omits_archived_external_and_requires_verified_volatile_rows_chirho() {
    let archived_root_chirho = tmp_root_chirho();
    let user_chirho = identity_chirho::register_identity_chirho(
        &archived_root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let export_chirho =
        export_subject_portable_data_chirho(&archived_root_chirho, &user_chirho, false).unwrap();
    assert!(export_chirho
        .records_chirho
        .iter()
        .all(|record_chirho| record_chirho.source_chirho != "external.usage-chirho"));
    assert!(export_chirho
        .records_chirho
        .iter()
        .all(|record_chirho| { !record_chirho.source_chirho.starts_with("promotions.") }));
    assert!(!archived_root_chirho
        .join("external-usage-chirho.jsonl")
        .exists());
    assert!(!archived_root_chirho
        .join("provider-price-records-chirho.jsonl")
        .exists());
    for retired_file_chirho in [
        "coupon-issues-chirho.jsonl",
        "coupon-redemptions-chirho.jsonl",
        "stripe-identity-verifications-chirho.jsonl",
    ] {
        assert!(!archived_root_chirho.join(retired_file_chirho).exists());
    }
    let _ = std::fs::remove_dir_all(&archived_root_chirho);

    let volatile_root_chirho = tmp_root_chirho();
    let user_chirho = identity_chirho::register_identity_chirho(
        &volatile_root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    effect_chirho::run_effect_chirho(
        &volatile_root_chirho,
        0,
        cas_chirho::hash_chirho(b"portable export volatile read"),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: format!("{user_chirho}/store"),
        },
        b"",
    )
    .unwrap();
    let export_chirho =
        export_subject_portable_data_chirho(&volatile_root_chirho, &user_chirho, false).unwrap();
    assert!(export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| { record_chirho.source_chirho == "effects.volatile-records-chirho" }));

    let mut volatile_records_chirho =
        effect_chirho::load_volatile_effect_records_chirho(&volatile_root_chirho).unwrap();
    volatile_records_chirho[0].sig_chirho = invalid_signature_chirho();
    write_jsonl_records_chirho(
        &effect_chirho::volatile_effect_records_path_chirho(&volatile_root_chirho),
        &volatile_records_chirho,
    );
    let export_error_chirho = format!(
        "{:?}",
        export_subject_portable_data_chirho(&volatile_root_chirho, &user_chirho, false)
            .unwrap_err()
    );
    assert!(export_error_chirho.contains("verify volatile-effects-chirho"));
    assert!(
        export_error_chirho.contains("volatile effect record seq 0 failed signature verification")
    );
    let _ = std::fs::remove_dir_all(&volatile_root_chirho);
}

/// A realtime corpus that PARSES but cannot VERIFY, for the fail-closed arm below.
///
/// The writer that used to build a verifiable corpus (open/record/close/reveal) died with the money
/// spine at CF6 wave-1, and rebuilding one by hand would mean re-implementing that writer's
/// arithmetic and hand-signing legacy ledger entries for a reserve the verifier asserts
/// unconditionally -- pinning V1 realtime economics that die anyway. So this corpus is deliberately
/// unverifiable, and the arm below pins what that MUST cause.
fn write_unverifiable_realtime_corpus_chirho(root_chirho: &Path) {
    use realtime_legacy_evidence_chirho as rt_chirho;
    std::fs::create_dir_all(root_chirho).unwrap();
    let payload_chirho = privacy_chirho::store_private_blob_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("alice"),
        "alice",
        b"private symptom detail",
    )
    .unwrap();
    let event_chirho = rt_chirho::RealtimeEventRecordChirho {
        seq_chirho: 0,
        session_id_chirho: "rt_export".to_string(),
        kind_chirho: rt_chirho::RealtimeEventKindChirho::UserSpokeChirho,
        payload_chirho,
        billable_seconds_chirho: 0,
        amount_token_chirho: 0,
        ledger_seq_chirho: None,
        at_ms_chirho: 1_700_000_000_001,
        sig_chirho: "00".to_string(),
    };
    std::fs::write(
        rt_chirho::events_path_chirho(root_chirho),
        format!("{}\n", serde_json::to_string(&event_chirho).unwrap()),
    )
    .unwrap();
}

/// A portable subject export REFUSES when a source log will not verify, and names the source.
///
/// **This property had no test at all**, which a census confirmed while rebuilding the arm below:
/// the only trace of it was one `with_context` line in production. It is the M129/M130 gate --
/// exports are the artifact that TRAVELS, so an export assembled from evidence that does not verify
/// is the one output you can never take back.
///
/// The failure mode it guards is not a crash but a QUIET one: an export that skipped an
/// unverifiable log would still be a well-formed export, just missing records, and the subject
/// receiving it has no way to tell.
#[test]
fn portable_export_refuses_a_source_log_that_does_not_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    write_unverifiable_realtime_corpus_chirho(&root_chirho);

    let error_chirho = export_subject_portable_data_chirho(&root_chirho, "alice", true)
        .expect_err("an export must refuse evidence it cannot verify, not omit it")
        .to_string();

    // ASSERT THE REASON. "It errored" is satisfied by a missing directory or an unreadable file --
    // neither of which would prove the export CHECKED anything.
    assert!(
        error_chirho.contains("realtime.sessions/events-chirho"),
        "the refusal must name the source that failed, or an operator cannot act on it: {error_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Plaintext travels to the SUBJECT and never to an operator reading the same records.
///
/// **Pinned here without a realtime corpus on purpose.** This boundary belongs to the portable
/// export layer, not to realtime -- it was only ever exercised THROUGH realtime because that arm
/// happened to build the richest fixture. When wave-1 deleted realtime's writer, a census showed
/// this was the single place in the file asserting an operator export carries no plaintext, so
/// letting it die with the writer would have retired a live privacy boundary by accident. Rebuilt
/// on the smallest corpus that exercises it, it now survives the realtime rebuild too.
#[test]
fn an_operator_export_carries_the_access_record_but_never_the_plaintext_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("alice"),
        "alice",
        b"private symptom detail",
    )
    .unwrap();
    privacy_chirho::append_privacy_access_record_chirho(
        &root_chirho,
        "alice",
        "owner/admin",
        "voiceapp",
        "row/alice-transcript-chirho",
        "support-investigation-chirho",
        &blob_chirho,
    )
    .unwrap();

    // THE SUBJECT: gets the plaintext. Asserted first, so the operator assertion below is a
    // statement about WHO reads rather than about an export that carries nothing either way.
    let subject_export_chirho =
        export_subject_portable_data_chirho(&root_chirho, "alice", true).unwrap();
    assert_eq!(subject_export_chirho.private_blobs_chirho.len(), 1);
    assert!(subject_export_chirho
        .private_blobs_chirho
        .iter()
        .all(|item_chirho| item_chirho.plaintext_base64_chirho.is_some()));

    // THE OPERATOR: sees THAT an access happened, and none of what was accessed.
    let operator_export_chirho =
        export_subject_portable_data_chirho(&root_chirho, "owner/admin", false).unwrap();
    assert!(
        operator_export_chirho.private_blobs_chirho.is_empty(),
        "an operator export must carry no private blobs at all"
    );
    assert_eq!(
        operator_export_chirho.privacy_access_records_chirho.len(),
        1,
        "the access record itself must still travel -- suppressing it would hide the disclosure"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn portable_export_includes_data_residency_control_logs_chirho() {
    let platform_root_chirho = tmp_root_chirho();
    let root_chirho =
        tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho")
            .unwrap();
    let operator_chirho = "owner/residency-export-chirho";
    data_residency_chirho::set_data_residency_policy_chirho(
        &root_chirho,
        &[String::from("us-east-1")],
        &[String::from("us-east-1")],
        operator_chirho,
        true,
    )
    .unwrap();
    data_residency_chirho::attest_data_residency_chirho(
        &root_chirho,
        "us-east-1",
        "us-east-1",
        "us-east-1",
        "operator-attested-chirho",
        operator_chirho,
    )
    .unwrap();

    let export_chirho =
        export_subject_portable_data_chirho(&root_chirho, operator_chirho, false).unwrap();
    let sources_chirho: BTreeSet<String> = export_chirho
        .records_chirho
        .iter()
        .map(|record_chirho| record_chirho.source_chirho.clone())
        .collect();
    assert!(sources_chirho.contains("data-residency.policies-chirho"));
    assert!(sources_chirho.contains("data-residency.attestations-chirho"));
    let policy_export_chirho = export_chirho
        .records_chirho
        .iter()
        .find(|record_chirho| record_chirho.source_chirho == "data-residency.policies-chirho")
        .unwrap();
    assert_eq!(
        policy_export_chirho.retention_policy_chirho.category_chirho,
        retention_chirho::DataRetentionCategoryChirho::ComplianceControlAuditChirho
    );
    let tenant_export_chirho =
        export_subject_portable_data_chirho(&root_chirho, "tenant-a-chirho", false).unwrap();
    assert!(tenant_export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| { record_chirho.source_chirho == "data-residency.policies-chirho" }));
    let _ = std::fs::remove_dir_all(&platform_root_chirho);
}

#[test]
fn export_evidence_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = tmp_root_chirho();
    let export_chirho = export_subject_portable_data_with_evidence_chirho(
        &root_chirho,
        "user/alice",
        false,
        "owner/privacy-admin",
    )
    .unwrap();
    let evidence_chirho = export_chirho.export_evidence_chirho.as_ref().unwrap();
    assert_eq!(
        evidence_chirho.schema_chirho,
        SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO
    );
    let path_chirho = subject_export_evidence_records_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    assert_eq!(
        text_chirho
            .matches(SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO)
            .count(),
        1
    );

    std::fs::write(
        &path_chirho,
        text_chirho.replace(
            SUBJECT_EXPORT_EVIDENCE_RECORD_SCHEMA_CHIRHO,
            "subject-export-evidence-record-v9-chirho",
        ),
    )
    .unwrap();
    let error_chirho = verify_subject_export_evidence_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported subject export evidence schema"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn legacy_export_evidence_records_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    export_subject_portable_data_with_evidence_chirho(
        &root_chirho,
        "user/alice",
        false,
        "owner/privacy-admin",
    )
    .unwrap();
    let mut records_chirho = load_subject_export_evidence_records_chirho(&root_chirho).unwrap();
    for record_chirho in &mut records_chirho {
        record_chirho.schema_chirho.clear();
        record_chirho.sig_chirho.clear();
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &subject_export_evidence_no_schema_message_chirho(record_chirho).unwrap(),
        )
        .unwrap();
    }
    let legacy_text_chirho = records_chirho
        .iter()
        .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        subject_export_evidence_records_path_chirho(&root_chirho),
        format!("{legacy_text_chirho}\n"),
    )
    .unwrap();
    let text_chirho =
        std::fs::read_to_string(subject_export_evidence_records_path_chirho(&root_chirho)).unwrap();
    assert!(!text_chirho.contains("schema_chirho"));
    assert_eq!(
        verify_subject_export_evidence_chirho(&root_chirho).unwrap(),
        1
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn export_evidence_verify_accepts_legacy_records_without_backup_field_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut record_chirho = SubjectExportEvidenceRecordChirho {
        schema_chirho: String::new(),
        seq_chirho: 0,
        subject_chirho: "user/legacy".to_string(),
        requested_by_chirho: "owner/privacy-admin".to_string(),
        include_private_chirho: false,
        private_blob_key_ids_chirho: Vec::new(),
        erasure_record_seqs_chirho: Vec::new(),
        backup_propagation_record_seqs_chirho: Vec::new(),
        legal_hold_record_seqs_chirho: Vec::new(),
        source_counts_chirho: Vec::new(),
        at_ms_chirho: 123,
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &subject_export_evidence_legacy_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    #[derive(Serialize)]
    struct LegacyRecordChirho<'a> {
        seq_chirho: u64,
        subject_chirho: &'a str,
        requested_by_chirho: &'a str,
        include_private_chirho: bool,
        private_blob_key_ids_chirho: &'a [String],
        erasure_record_seqs_chirho: &'a [u64],
        source_counts_chirho: &'a [SubjectExportSourceCountChirho],
        at_ms_chirho: u64,
        sig_chirho: &'a str,
    }
    let legacy_chirho = LegacyRecordChirho {
        seq_chirho: record_chirho.seq_chirho,
        subject_chirho: &record_chirho.subject_chirho,
        requested_by_chirho: &record_chirho.requested_by_chirho,
        include_private_chirho: record_chirho.include_private_chirho,
        private_blob_key_ids_chirho: &record_chirho.private_blob_key_ids_chirho,
        erasure_record_seqs_chirho: &record_chirho.erasure_record_seqs_chirho,
        source_counts_chirho: &record_chirho.source_counts_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        sig_chirho: &record_chirho.sig_chirho,
    };
    std::fs::write(
        subject_export_evidence_records_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&legacy_chirho).unwrap()),
    )
    .unwrap();
    assert_eq!(
        verify_subject_export_evidence_chirho(&root_chirho).unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
