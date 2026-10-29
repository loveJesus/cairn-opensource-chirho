// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::collections::BTreeSet;

/// A scoped write — the shape every shipped app uses — leaves the response OFF the public plane,
/// and the scan reports it as a skipped private ciphertext rather than failing on a missing
/// object. Its sibling above pins the other half of the rule: an object that IS in public CAS
/// stays scanned even when a private DAG value record exists at the same hash.
#[test]
fn privacy_scan_skips_a_sealed_write_response_only_when_public_cas_lacks_it_chirho() {
    let root_chirho = tmp_root_chirho();
    let value_chirho = b"name_chirho=Cleo+Example&email_chirho=cleo%40example.com";
    let request_chirho = crate::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: crate::effect_chirho::SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/scoped-scan".to_string(),
        value_base64_chirho: base64::engine::general_purpose::STANDARD
            .encode(value_chirho.as_slice()),
    };
    let effect_chirho = crate::effect_chirho::run_effect_chirho(
        &root_chirho,
        0,
        crate::model_chirho::HashChirho("scan-scoped-write".to_string()),
        crate::model_chirho::CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho".to_string(),
        },
        &serde_json::to_vec(&request_chirho).unwrap(),
    )
    .unwrap();

    // Precondition that makes the counts below mean what they say: the response plaintext really
    // is gone from public CAS, and the request really is still there as JSON.
    let response_hash_chirho = effect_chirho.response_chirho.clone().unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &response_hash_chirho).is_err());
    assert!(cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).is_ok());

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.effect_records_chirho, 1);
    assert_eq!(report_chirho.effect_cas_json_objects_chirho, 1);
    assert_eq!(
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        1
    );
    assert_eq!(report_chirho.effect_cas_objects_chirho, 0);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_flags_email_card_and_free_text_without_echoing_value_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("leaky-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"actor_chirho":"user/alice","contact_chirho":"alice@example.com","sig_chirho":"alice@example.com","card_chirho":"4242 4242 4242 4242","ssn_chirho":"123-45-6789","phone_chirho":"+1 (415) 234-7890","message_chirho":"Please delete this private note before shipping."}"#,
    )
    .unwrap();
    let _policy_hash_chirho = cas_chirho::add_chirho(
        &root_chirho,
        br#"{"redaction_note_chirho":"Dogfood support payloads stay private and can be crypto-shredded by retention policy."}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.jsonl_files_chirho, 1);
    assert_eq!(report_chirho.jsonl_rows_chirho, 1);
    assert_eq!(report_chirho.json_objects_chirho, 1);
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "email-like-chirho"));
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.path_chirho == "$.sig_chirho"));
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "payment-card-like-chirho"));
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "ssn-like-chirho"));
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "phone-like-chirho"));
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "raw-free-text-field-chirho"));
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.redaction_note_chirho"
            && finding_chirho.kind_chirho == "raw-free-text-field-chirho"
    }));
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.redaction_note_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("4242 4242"));
    assert!(!report_text_chirho.contains("123-45-6789"));
    assert!(!report_text_chirho.contains("415) 234"));
    assert!(!report_text_chirho.contains("Please delete this private note"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// The seqlog head-checkpoint sidecar (`<log>.jsonl.head-chirho`) is excluded from the scan BY
// DESIGN: it is machine-written {schema, record count, byte length, tail blake3} — never a private
// payload — while the log it summarizes IS scanned. This pins the disposition (sweep finding,
// 2026-07-15) so a future walker change that silently starts or stops scanning sidecars fails here.
#[test]
fn privacy_scan_skips_seqlog_head_sidecars_by_design_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("head-demo-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"contact_chirho":"alice@example.com"}"#,
    )
    .unwrap();
    // A realistic reseed-shaped sidecar body, exactly what production writes next to the log.
    std::fs::write(
        root_chirho.join("head-demo-log-chirho.jsonl.head-chirho"),
        r#"{"schema_chirho":"seqlog-head-v1-chirho","record_count_chirho":1,"byte_len_chirho":52,"last_line_len_chirho":52,"last_line_blake3_chirho":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    // The log is the one scanned surface; the sidecar is not a surface.
    assert_eq!(report_chirho.jsonl_files_chirho, 1);
    // The log's finding proves the scan ran; no finding may reference the sidecar.
    assert!(report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.kind_chirho == "email-like-chirho"));
    assert!(!report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.source_chirho.contains("head-chirho")));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_structural_detectors_reject_low_confidence_tokens_chirho() {
    assert!(contains_ssn_like_chirho("subject ssn 123-45-6789"));
    assert!(!contains_ssn_like_chirho("invalid 000-45-6789"));
    assert!(!contains_ssn_like_chirho("invalid 666-45-6789"));
    assert!(!contains_ssn_like_chirho("invalid 901-45-6789"));
    assert!(!contains_ssn_like_chirho("invalid 123-00-6789"));
    assert!(!contains_ssn_like_chirho("invalid 123-45-0000"));
    assert_eq!(
        privacy_scan_field_chirho("$.sources_chirho[0].notes_chirho[0]"),
        "notes_chirho"
    );
    assert!(phone_like_field_chirho("$.phone_chirho"));
    assert!(looks_like_phone_number_chirho("+1 (415) 234-7890"));
    assert!(looks_like_phone_number_chirho("4152347890"));
    assert!(!looks_like_phone_number_chirho("123-45-6789"));
    assert!(!phone_like_field_chirho("$.caller_chirho"));
    assert!(looks_like_timestamp_value_chirho("1780022399063"));
    assert!(privacy_scan_timestamp_field_chirho("$.at_chirho"));
    let mut findings_chirho = Vec::new();
    inspect_privacy_string_chirho(
        "runtime-record-chirho",
        None,
        "$.at_chirho",
        "1780022399063",
        &mut findings_chirho,
    );
    assert!(findings_chirho.is_empty());
}

#[test]
fn privacy_scan_hash_fields_do_not_trip_card_windows_chirho() {
    let hash_with_luhn_window_chirho = format!("4242424242424242{}", "a".repeat(48));
    let mut findings_chirho = Vec::new();
    for path_chirho in [
        "$.billing_policy_chirho",
        "$.to_chirho",
        "$.app_ref_chirho",
        "$.pubkey_chirho",
        "$.base_chirho",
        "$.previous_chirho",
        "$.proof_chirho",
        "$.added_doc_chirho",
        "$.doc_chirho",
        "$.pack_chirho",
        "$.request_chirho",
        "$.response_chirho",
        "$.effect_chirho",
        "$.effect_response_chirho",
        "$.verified_chirho.effect_idem_keys_chirho[0]",
        "$.idem_key_chirho",
        "$.idempotency_key_chirho",
        "$.effects_chirho[0].idem_key_chirho",
        "$.related_effect_ids_chirho[0]",
        "$.related_run_ids_chirho[0]",
        "$.parents_chirho[0]",
        "$.key_chirho",
        "$.principal_chirho",
        "$.row_key_chirho",
        "$.source_refs_chirho[0].ref_chirho",
        "$.wallet_chirho",
        "$.feedback_sig_chirho",
        "$.candidate_chirho.root_dag_chirho",
        "$.candidate_chirho.modules_chirho[0].module_chirho",
        "$.node_def_chirho.impl_wasm_chirho",
        "$.runtime_package_chirho.module_chirho",
        "$.previous_module_chirho",
        "$.review_chirho.candidate_chirho",
        "$.result_hash_chirho",
        "$.trace_chirho",
        "$.prev_authority_record_digest_chirho",
        "$.state_chirho",
        "$.previous_state_chirho",
        "$.new_state_chirho",
        "$.final_state_chirho",
        "$.inputs_chirho.in",
        "$.outputs_chirho.out",
        "$.nodes_chirho[0]",
    ] {
        inspect_privacy_string_chirho(
            "hash-record-chirho",
            None,
            path_chirho,
            &hash_with_luhn_window_chirho,
            &mut findings_chirho,
        );
    }
    assert!(findings_chirho.is_empty());

    let prefixed_digest_with_luhn_window_chirho =
        format!("gate1-authority-record-digest-v1-chirho:{hash_with_luhn_window_chirho}");
    inspect_privacy_string_chirho(
        "gate1-authority-record-chirho",
        None,
        "$.prev_authority_record_digest_chirho",
        &prefixed_digest_with_luhn_window_chirho,
        &mut findings_chirho,
    );
    assert!(findings_chirho.is_empty());

    inspect_privacy_string_chirho(
        "mail-record-chirho",
        None,
        "$.to_chirho",
        "billing@example.com",
        &mut findings_chirho,
    );
    assert!(findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.to_chirho"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    assert!(findings_chirho.iter().all(|finding_chirho| {
        finding_chirho.path_chirho != "$.principal_chirho"
            && finding_chirho.path_chirho != "$.wallet_chirho"
    }));

    inspect_privacy_string_chirho(
        "mail-record-chirho",
        None,
        "$.principal_chirho",
        "user/alice@example.com",
        &mut findings_chirho,
    );
    assert!(findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.principal_chirho"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));

    inspect_privacy_string_chirho(
        "candidate-record-chirho",
        None,
        "$.review_chirho.candidate_chirho",
        "Candidate draft contains unclassified prose and should not be treated as a hash.",
        &mut findings_chirho,
    );
    assert!(findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "candidate-record-chirho"
            && finding_chirho.path_chirho == "$.review_chirho.candidate_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));

    inspect_privacy_string_chirho(
        "candidate-module-record-chirho",
        None,
        "$.candidate_chirho.modules_chirho[0].module_chirho",
        "4242 4242 4242 4242",
        &mut findings_chirho,
    );
    assert!(findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "candidate-module-record-chirho"
            && finding_chirho.path_chirho == "$.candidate_chirho.modules_chirho[0].module_chirho"
            && finding_chirho.kind_chirho == "payment-card-like-chirho"
    }));

    inspect_privacy_string_chirho(
        "candidate-module-prose-record-chirho",
        None,
        "$.candidate_chirho.modules_chirho[0].module_chirho",
        "This module field is not a hash and should still be classified.",
        &mut findings_chirho,
    );
    assert!(findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "candidate-module-prose-record-chirho"
            && finding_chirho.path_chirho == "$.candidate_chirho.modules_chirho[0].module_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));

    let safe_row_chirho = format!(
        r#"{{"schema_chirho":"perffection-intake-record-v1-chirho","key_chirho":"perffection-intake-chirho/{hash_with_luhn_window_chirho}","blob_chirho":{{"ciphertext_chirho":"{hash_with_luhn_window_chirho}"}}}}"#
    );
    inspect_privacy_string_chirho(
        "query-row-chirho",
        None,
        "$.rows_chirho[0].value_chirho",
        &safe_row_chirho,
        &mut findings_chirho,
    );
    assert!(!findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "query-row-chirho"
            && finding_chirho.kind_chirho == "payment-card-like-chirho"
    }));
}

#[test]
fn privacy_scan_compliance_source_errors_are_status_text_not_plaintext_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(root_chirho.join("objects-chirho").join("ab")).unwrap();
    std::fs::write(
        root_chirho
            .join("objects-chirho")
            .join("ab")
            .join("compliance-pack-chirho"),
        r#"{"schema_chirho":"compliance-evidence-pack-v1-chirho","sources_chirho":[{"source_chirho":"privacy.scan-findings-chirho","status_chirho":"failed-chirho","records_chirho":6,"error_chirho":"privacy scan found 6 finding(s)"},{"source_chirho":"bad-source-chirho","status_chirho":"failed-chirho","records_chirho":1,"error_chirho":"contact security@example.com before shipping"}]}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.sources_chirho[0].error_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.sources_chirho[1].error_chirho"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("security@example.com"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_flags_semantic_pii_fields_without_echoing_values_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("semantic-pii-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"name_chirho":"Alice Smith","shipping_address_chirho":"123 Main Street","dob_chirho":"1984-03-12","app_chirho":"support-app","safe_ref_chirho":"user/opaque-123"}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.name_chirho"
            && finding_chirho.kind_chirho == "person-name-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.shipping_address_chirho"
            && finding_chirho.kind_chirho == "postal-address-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.dob_chirho"
            && finding_chirho.kind_chirho == "birth-date-like-chirho"
    }));
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.app_chirho"
            || finding_chirho.path_chirho == "$.safe_ref_chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("Alice Smith"));
    assert!(!report_text_chirho.contains("123 Main Street"));
    assert!(!report_text_chirho.contains("1984-03-12"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_keeps_free_text_backstop_for_semantic_pii_fields_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("semantic-free-text-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"legal_name_chirho":"Alice Beth Catherine Danielle Eleanor Francesca","shipping_address_chirho":"Apartment two north building beside the library","dob_chirho":"March twelfth nineteen eighty four","safe_ref_chirho":"user/opaque-123"}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    for path_chirho in [
        "$.legal_name_chirho",
        "$.shipping_address_chirho",
        "$.dob_chirho",
    ] {
        assert!(
            report_chirho.findings_chirho.iter().any(|finding_chirho| {
                finding_chirho.path_chirho == path_chirho
                    && finding_chirho.kind_chirho == "semantic-pii-free-text-field-chirho"
            }),
            "missing semantic free-text finding for {path_chirho}"
        );
    }
    assert!(!report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| { finding_chirho.path_chirho == "$.safe_ref_chirho" }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("Alice Beth"));
    assert!(!report_text_chirho.contains("Apartment two"));
    assert!(!report_text_chirho.contains("March twelfth"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_flags_unclassified_free_text_fields_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("unknown-field-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"actor_chirho":"user/alice","memo_chirho":"metered replay settlement for run hash","opaque_chirho":"tenant/alpha/ref-1","commentary_chirho":"This newly added signed string field has not been classified yet."}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.commentary_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.memo_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));
    assert!(!report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho == "$.opaque_chirho"
            && finding_chirho.kind_chirho == "unclassified-free-text-field-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("newly added signed string"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_recurses_nested_signed_logs_but_skips_private_dirs_chirho() {
    let root_chirho = tmp_root_chirho();
    let tenant_dir_chirho = root_chirho.join("tenants-chirho").join("tenant-a-chirho");
    std::fs::create_dir_all(&tenant_dir_chirho).unwrap();
    std::fs::write(
        tenant_dir_chirho.join("nested-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"message_chirho":"Please contact alice@example.com about this private nested tenant payload."}"#,
    )
    .unwrap();
    let skipped_dir_chirho = root_chirho.join("privacy-keys-chirho");
    std::fs::create_dir_all(&skipped_dir_chirho).unwrap();
    std::fs::write(
        skipped_dir_chirho.join("skipped-log-chirho.jsonl"),
        r#"{"message_chirho":"bob@example.com should not be scanned from key dirs"}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.jsonl_files_chirho, 1);
    assert_eq!(report_chirho.jsonl_rows_chirho, 1);
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "tenants-chirho/tenant-a-chirho/nested-log-chirho.jsonl"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("bob@example.com"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_covers_seqlog_quarantine_sidecars_chirho() {
    let root_chirho = tmp_root_chirho();
    let quarantine_dir_chirho = root_chirho
        .join(crate::seqlog_chirho::SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join("nested-chirho");
    std::fs::create_dir_all(&quarantine_dir_chirho).unwrap();
    std::fs::write(
        quarantine_dir_chirho.join("fragment-chirho.jsonl-fragment-chirho"),
        b"{\"message_chirho\":\"contact alice@example.com before restoring\"",
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.seqlog_quarantine_files_chirho, 1);
    assert!(report_chirho.seqlog_quarantine_bytes_chirho > 0);
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("seqlog-quarantine:seqlog-quarantine-chirho/")
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_covers_runtime_json_surfaces_chirho() {
    let root_chirho = tmp_root_chirho();
    for dir_chirho in RUNTIME_JSON_SCAN_DIRS_CHIRHO {
        std::fs::create_dir_all(root_chirho.join(dir_chirho)).unwrap();
    }
    std::fs::write(
        root_chirho.join("effects-chirho").join("effect-leak"),
        r#"{"request_chirho":"hash-only","message_chirho":"Contact alice@example.com from the effect surface."}"#,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("runs-chirho").join("run-leak"),
        r#"{"trace_chirho":"hash-only","message_chirho":"Call 4242 4242 4242 4242 from the run surface."}"#,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("runkeys-chirho").join("runkey-leak"),
        r#"{"inputs_chirho":{"message_chirho":"This runkey payload should be private content, not inline text."}}"#,
    )
    .unwrap();
    // A propagation requirement is digests and key ids only; a leaked address nested in it is found.
    let requirement_dir_chirho = root_chirho
        .join("privacy-erasure-propagation-chirho")
        .join("ab")
        .join("cd".repeat(32));
    std::fs::create_dir_all(&requirement_dir_chirho).unwrap();
    std::fs::write(
        requirement_dir_chirho.join("0.requirement.json"),
        r#"{"key_ids_chirho":["ab"],"note_chirho":"erase bob@example.com everywhere"}"#,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("runseals-chirho").join("seal-leak"),
        r#"{"run_chirho":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","message_chirho":"This runseal sidecar drift surface should also be scanned."}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.json_objects_chirho, 5);
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("privacy-erasure-propagation-chirho/")
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "effects-chirho/effect-leak"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "runs-chirho/run-leak"
            && finding_chirho.kind_chirho == "payment-card-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "runkeys-chirho/runkey-leak"
            && finding_chirho.kind_chirho == "raw-free-text-field-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.source_chirho == "runseals-chirho/seal-leak"
            && finding_chirho.kind_chirho == "raw-free-text-field-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("4242 4242"));
    assert!(!report_text_chirho.contains("runkey payload"));
    assert!(!report_text_chirho.contains("runseal sidecar"));
    assert!(!report_text_chirho.contains("bob@example.com"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_treats_writer_fence_root_path_as_metadata_chirho() {
    let root_chirho = tmp_root_chirho();
    let fences_dir_chirho = root_chirho.join("writer-fences-chirho");
    std::fs::create_dir_all(&fences_dir_chirho).unwrap();
    std::fs::write(
        fences_dir_chirho.join("writer-fence-chirho.json"),
        r#"{"group_chirho":{"canonical_root_chirho":"/tmp/cairn-root-4242424242424242-chirho"},"epoch_chirho":1}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(report_chirho.findings_chirho.is_empty());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_covers_persistent_effect_non_json_cas_bodies_chirho() {
    let root_chirho = tmp_root_chirho();
    let body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery+near+the+river";
    crate::effect_chirho::run_effect_chirho(
        &root_chirho,
        0,
        crate::model_chirho::HashChirho("effect-form-pii".to_string()),
        crate::model_chirho::CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho/latest".to_string(),
        },
        body_chirho,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.effect_records_chirho, 1);
    // Legacy reify sends the value as its own request bytes, so request and response resolve to
    // ONE public object at ONE address. The F4 seal removes the value from the versioned store and
    // stores the response privately, but that public request copy survives — the named §2.6
    // residual (the value was persisted upstream of the write arm, which cannot retroactively seal
    // it). The scan must keep reporting it: an object PRESENT in public CAS is never skipped just
    // because a private DAG value record exists at the same hash.
    assert_eq!(report_chirho.effect_cas_objects_chirho, 2);
    assert_eq!(report_chirho.effect_cas_json_objects_chirho, 0);
    assert_eq!(
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        0
    );
    assert_eq!(report_chirho.effect_cas_binary_objects_skipped_chirho, 0);
    assert_eq!(report_chirho.effect_form_fields_chirho, 6);
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("effects-chirho/effect-form-pii:request:")
            && finding_chirho.path_chirho == "$.form_chirho.email_chirho"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("effects-chirho/effect-form-pii:request:")
            && finding_chirho.path_chirho == "$.form_chirho.name_chirho"
            && finding_chirho.kind_chirho == "person-name-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("effects-chirho/effect-form-pii:request:")
            && finding_chirho.path_chirho == "$.form_chirho.message_chirho"
            && finding_chirho.kind_chirho == "raw-free-text-field-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("Alice Example"));
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("Apartment above the bakery"));
    let report_value_chirho = serde_json::to_value(&report_chirho).unwrap();
    assert_eq!(
        report_value_chirho["schema_chirho"],
        PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_value_chirho["effect_records_chirho"], 1);
    assert_eq!(report_value_chirho["effect_cas_objects_chirho"], 2);
    assert_eq!(report_value_chirho["effect_cas_json_objects_chirho"], 0);
    assert_eq!(
        report_value_chirho["effect_cas_private_ciphertexts_skipped_chirho"],
        0
    );
    assert_eq!(
        report_value_chirho["effect_cas_binary_objects_skipped_chirho"],
        0
    );
    assert_eq!(report_value_chirho["effect_form_fields_chirho"], 6);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_covers_volatile_effect_non_json_cas_bodies_chirho() {
    let root_chirho = tmp_root_chirho();
    let body_chirho =
        b"name_chirho=Beth+Example&email_chirho=beth%40example.com&message_chirho=Please+call+about+the+private+medical+note";
    crate::effect_chirho::run_effect_chirho(
        &root_chirho,
        0,
        crate::model_chirho::HashChirho("volatile-form-pii".to_string()),
        crate::model_chirho::CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "contacts-chirho/latest".to_string(),
        },
        body_chirho,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        PRIVACY_SCAN_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.effect_records_chirho, 2);
    assert!(report_chirho.effect_cas_objects_chirho >= 2);
    assert_eq!(
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        0
    );
    assert_eq!(report_chirho.effect_cas_binary_objects_skipped_chirho, 0);
    assert!(report_chirho.effect_form_fields_chirho >= 6);
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("volatile-effects-chirho.jsonl#seq=0:request:")
            && finding_chirho.path_chirho == "$.form_chirho.email_chirho"
            && finding_chirho.kind_chirho == "email-like-chirho"
    }));
    assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho
            .source_chirho
            .starts_with("volatile-effects-chirho.jsonl#seq=0:request:")
            && finding_chirho.path_chirho == "$.form_chirho.message_chirho"
            && finding_chirho.kind_chirho == "raw-free-text-field-chirho"
    }));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("Beth Example"));
    assert!(!report_text_chirho.contains("beth@example.com"));
    assert!(!report_text_chirho.contains("private medical note"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_reports_effect_cas_coverage_counters_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/abcdef0123456789",
        ),
        "user/abcdef0123456789",
        b"send receipt to alice@example.com",
    )
    .unwrap();
    let json_hash_chirho =
        cas_chirho::add_chirho(&root_chirho, br#"{"safe_ref_chirho":"opaque/ref"}"#).unwrap();
    let binary_hash_chirho = cas_chirho::add_chirho(&root_chirho, &[0xff, 0xfe]).unwrap();
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_dir_chirho).unwrap();
    for (name_chirho, request_chirho) in [
        (
            "private-ciphertext-effect",
            blob_chirho.ciphertext_chirho.clone(),
        ),
        ("json-effect", json_hash_chirho),
        ("binary-effect", binary_hash_chirho),
    ] {
        let effect_chirho = EffectChirho {
            seq_chirho: 0,
            idem_key_chirho: HashChirho(name_chirho.to_string()),
            capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
            request_chirho,
            response_chirho: None,
            sig_chirho: "test-sig-chirho".to_string(),
            at_chirho: "0".to_string(),
        };
        std::fs::write(
            effects_dir_chirho.join(name_chirho),
            serde_json::to_vec_pretty(&effect_chirho).unwrap(),
        )
        .unwrap();
    }

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.effect_records_chirho, 3);
    assert_eq!(report_chirho.effect_cas_objects_chirho, 0);
    assert_eq!(report_chirho.effect_cas_json_objects_chirho, 1);
    assert_eq!(
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        1
    );
    assert_eq!(report_chirho.effect_cas_binary_objects_skipped_chirho, 1);
    assert_eq!(report_chirho.effect_form_fields_chirho, 0);
    assert!(report_chirho.findings_chirho.is_empty());
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("send receipt"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_skips_effect_hashes_backed_by_private_dag_values_chirho() {
    let root_chirho = tmp_root_chirho();
    let private_hash_chirho = crate::dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/private-dag-scan-chirho",
        ),
        "user/private-dag-scan-chirho",
        b"description_chirho=Alice+Example&email_chirho=alice%40example.com",
        crate::dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &private_hash_chirho).is_err());

    let effect_chirho = EffectChirho {
        seq_chirho: 0,
        idem_key_chirho: HashChirho("private-dag-effect-chirho".to_string()),
        capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
        request_chirho: private_hash_chirho,
        response_chirho: None,
        sig_chirho: "test-sig-chirho".to_string(),
        at_chirho: "0".to_string(),
    };
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_dir_chirho).unwrap();
    std::fs::write(
        effects_dir_chirho.join("private-dag-effect"),
        serde_json::to_vec_pretty(&effect_chirho).unwrap(),
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.effect_records_chirho, 1);
    assert_eq!(report_chirho.effect_cas_objects_chirho, 0);
    assert_eq!(
        report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        1
    );
    assert!(report_chirho.findings_chirho.is_empty());
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("alice@example.com"));
    assert!(!report_text_chirho.contains("Alice Example"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// F3 (S2 adversarial review): the private-value skip is earned by ABSENCE, and a tampered public
/// object is not absence. Before this, any `get_chirho` error qualified — so an attacker who
/// corrupted a public object at a hash that also had a private record turned the loudest signal
/// this scan can receive into a counter that reads as healthy.
///
/// MIGRATION PATH — if this arm goes red because the scan SKIPPED instead of erroring, the tamper is
/// being laundered again. If the refusal names something other than the content address, read it:
/// the error identity, not merely the fact of an error, is what this pins.
#[test]
fn privacy_scan_refuses_a_tampered_public_object_it_could_have_skipped_chirho() {
    let root_chirho = tmp_root_chirho();
    let private_hash_chirho = crate::dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/private-dag-tamper-chirho",
        ),
        "user/private-dag-tamper-chirho",
        b"description_chirho=Alice+Example&email_chirho=alice%40example.com",
        crate::dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();

    let effect_chirho = EffectChirho {
        seq_chirho: 0,
        idem_key_chirho: HashChirho("private-dag-tamper-effect-chirho".to_string()),
        capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
        request_chirho: private_hash_chirho.clone(),
        response_chirho: None,
        sig_chirho: "test-sig-chirho".to_string(),
        at_chirho: "0".to_string(),
    };
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_dir_chirho).unwrap();
    std::fs::write(
        effects_dir_chirho.join("private-dag-tamper-effect"),
        serde_json::to_vec_pretty(&effect_chirho).unwrap(),
    )
    .unwrap();

    // POSITIVE CONTROL: absent from public CAS + a private record ⇒ a clean, counted skip. This is
    // the state the tampered case below is one file away from, so it is what makes the difference
    // attributable to the tamper rather than to the fixture.
    assert!(cas_chirho::get_chirho(&root_chirho, &private_hash_chirho).is_err());
    let clean_report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(
        clean_report_chirho.effect_cas_private_ciphertexts_skipped_chirho,
        1
    );

    // THE TAMPER: bytes that do not hash to the address they sit at, placed in public CAS at the
    // hash the private record covers.
    let object_path_chirho = root_chirho
        .join("objects-chirho")
        .join(&private_hash_chirho.0[0..2])
        .join(&private_hash_chirho.0[2..]);
    std::fs::create_dir_all(object_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(&object_path_chirho, b"tampered public bytes chirho").unwrap();

    let error_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap_err();
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("content address mismatch"),
        "a tampered public object must refuse by its content-address identity, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&private_hash_chirho.0),
        "the refusal must name the object it is about, got: {text_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The THIRD case, and the one nothing guarded: an object that is PRESENT but UNREADABLE.
///
/// `AbsentChirho` (skip allowed) and `TamperedChirho` (fail closed) each had an arm; the outcome
/// between them did not. A read that could not happen says NOTHING about whether plaintext sits at
/// that address, so treating it as absence lets the scan take the private skip over an object it
/// never looked at.
///
/// Measured, so the arm is not merely plausible: folding `UnreadableChirho` into
/// `scan_effect_cas_object_chirho`'s absent arm leaves this the ONLY failure among the 27 tests
/// selected by `cargo test -p cairn-chirho --lib -- privacy_scan`, and it fails on a report reading
/// `effect_cas_private_ciphertexts_skipped_chirho: 1` with `findings_chirho: []` — a clean, counted
/// private skip over an object the scan never read.
///
/// The plant is a DIRECTORY at the object path — EISDIR, which no file mode can mask and which a
/// root-running test cannot ignore the way it ignores mode 000.
///
/// MIGRATION PATH — if this goes red with an `Ok` report, unreadable is being laundered into
/// absence again and the scan is skipping over objects it did not read. If it goes red with a
/// refusal naming a CONTENT ADDRESS MISMATCH, the read is being misclassified as tamper; if it
/// names RECORD VERIFICATION, the fixture stopped producing a verifiable record and the arm is
/// no longer testing the unreadable branch at all.
#[test]
fn privacy_scan_refuses_an_unreadable_public_object_it_could_have_skipped_chirho() {
    let root_chirho = tmp_root_chirho();
    let private_hash_chirho = crate::dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/private-dag-unreadable-chirho",
        ),
        "user/private-dag-unreadable-chirho",
        b"description_chirho=Alice+Example&email_chirho=alice%40example.com",
        crate::dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();

    let effects_dir_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_dir_chirho).unwrap();
    std::fs::write(
        effects_dir_chirho.join("private-dag-unreadable-effect"),
        serde_json::to_vec_pretty(&EffectChirho {
            seq_chirho: 0,
            idem_key_chirho: HashChirho("private-dag-unreadable-effect-chirho".to_string()),
            capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
            request_chirho: private_hash_chirho.clone(),
            response_chirho: None,
            sig_chirho: "test-sig-chirho".to_string(),
            at_chirho: "0".to_string(),
        })
        .unwrap(),
    )
    .unwrap();

    // POSITIVE CONTROL: genuinely absent from public CAS + a record that verifies ⇒ a clean,
    // counted skip. The unreadable case below is ONE mkdir away from this state, so the difference
    // is attributable to the plant rather than to the fixture.
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &private_hash_chirho),
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "fixture: the private value must start ABSENT from public CAS"
    );
    let control_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(
        control_chirho.effect_cas_private_ciphertexts_skipped_chirho, 1,
        "the probe granted no skip even for a real private DAG value, so a later refusal would \
         prove nothing about the plant"
    );
    assert!(control_chirho.findings_chirho.is_empty());

    // THE PLANT: a directory where the object file would sit. The object path now EXISTS and cannot
    // be read — which is exactly the state an `is_err()`-shaped probe reports as "absent".
    let object_path_chirho = root_chirho
        .join("objects-chirho")
        .join(&private_hash_chirho.0[0..2])
        .join(&private_hash_chirho.0[2..]);
    std::fs::create_dir_all(&object_path_chirho).unwrap();
    // Proof the plant applied, before anything depends on it: the read now reports UNREADABLE, and
    // specifically not ABSENT (which would leave this arm exercising the control's branch).
    let planted_outcome_chirho =
        cas_chirho::read_verified_chirho(&root_chirho, &private_hash_chirho);
    assert!(
        matches!(
            planted_outcome_chirho,
            cas_chirho::CasReadOutcomeChirho::UnreadableChirho(_)
        ),
        "the planted directory did not make the object unreadable, so the assertion below would \
         pass over the ABSENT branch: {planted_outcome_chirho:?}"
    );

    let error_chirho = scan_privacy_surfaces_chirho(&root_chirho)
        .expect_err("privacy scan took the private skip over an object it could not read");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains(&private_hash_chirho.0),
        "the refusal must name the object it is about, got: {text_chirho}"
    );
    // POSITIVE IDENTITY: the refusal carries the read's own io error, and it is not a NotFound —
    // i.e. the scan refused because the read FAILED, not because the object was absent.
    let io_error_chirho = error_chirho
        .downcast_ref::<std::io::Error>()
        .expect("the refusal must carry the underlying read error");
    assert_ne!(
        io_error_chirho.kind(),
        std::io::ErrorKind::NotFound,
        "an unreadable object refused as if it were absent, got: {text_chirho}"
    );
    // NEGATIVE IDENTITY: not the two neighbouring refusals this must not be confused with.
    assert!(
        !text_chirho.contains("content address mismatch"),
        "an unreadable object was misclassified as tamper, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("claimed only by records that do not verify"),
        "the fixture stopped producing a verifiable record, so this arm no longer reaches the \
         unreadable branch, got: {text_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// F4-S3 review finding 3: the private-value skip is earned by a record that VERIFIES, never by a
/// line that merely CLAIMS. `private_dag_value_recorded_chirho` parses the JSONL without checking
/// schema, signature, subject or blob ownership, so ONE appended line naming any hash used to buy a
/// counted "private skip" — the scan reporting zero findings over evidence that is not there, which
/// is the exact failure a privacy scan exists to prevent.
///
/// MIGRATION PATH — if this goes red with an `Ok` report, the bare existence check is back and the
/// scan is green-by-emptiness again. If it goes red with a refusal that names something other than
/// record verification, read the refusal before changing the assertion: the IDENTITY is what this
/// pins, not the mere fact of an error.
#[test]
fn privacy_scan_refuses_a_private_skip_claimed_only_by_an_unverifiable_record_chirho() {
    let root_chirho = tmp_root_chirho();

    // POSITIVE CONTROL FIRST. "Zero findings" and "it refused" are both cheap to obtain from a
    // fixture that never reached the branch at all, so prove the same probe DOES grant a skip when
    // the evidence is really there — then the refusal below is attributable to the forged line.
    let real_hash_chirho = crate::dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/scan-verified-skip-chirho",
        ),
        "user/scan-verified-skip-chirho",
        b"description_chirho=Verified+Skip&email_chirho=verified%40example.com",
        crate::dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    let effects_dir_chirho = root_chirho.join("effects-chirho");
    std::fs::create_dir_all(&effects_dir_chirho).unwrap();
    std::fs::write(
        effects_dir_chirho.join("verified-private-effect"),
        serde_json::to_vec_pretty(&EffectChirho {
            seq_chirho: 0,
            idem_key_chirho: HashChirho("verified-private-effect-chirho".to_string()),
            capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
            request_chirho: real_hash_chirho,
            response_chirho: None,
            sig_chirho: "test-sig-chirho".to_string(),
            at_chirho: "0".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    let control_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert_eq!(
        control_chirho.effect_cas_private_ciphertexts_skipped_chirho, 1,
        "the probe granted no skip even for a real private DAG value, so a later refusal would \
         prove nothing about the forgery"
    );
    assert!(control_chirho.findings_chirho.is_empty());

    // THE FORGERY: a hash nothing backs — no object, no ciphertext, no key, no signature — claimed
    // by a single appended line. Append access to the log is the whole attack.
    let forged_hash_chirho =
        cas_chirho::hash_chirho(b"bytes that were never stored anywhere chirho");
    assert!(
        matches!(
            cas_chirho::read_verified_chirho(&root_chirho, &forged_hash_chirho),
            cas_chirho::CasReadOutcomeChirho::AbsentChirho(_)
        ),
        "fixture: the forged hash must be ABSENT from public CAS, or this arm exercises the wrong \
         branch of the scan"
    );
    let records_path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let before_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    let forged_line_chirho = serde_json::json!({
        "schema_chirho": crate::dag_private_value_chirho::PRIVATE_DAG_VALUE_SCHEMA_CHIRHO,
        "seq_chirho": before_chirho.lines().count(),
        "subject_chirho": "user/scan-forged-claim-chirho",
        "value_hash_chirho": forged_hash_chirho.0,
        "blob_chirho": {
            "alg_chirho": "xchacha20poly1305-chirho",
            "key_id_chirho": "forged-key-id-chirho",
            "nonce_chirho": "00".repeat(24),
            "mac_chirho": "00".repeat(32),
            "ciphertext_chirho": cas_chirho::hash_chirho(b"no such ciphertext chirho").0,
        },
        "bytes_chirho": 0,
        "at_ms_chirho": 0,
        "sig_chirho": "",
    });
    std::fs::write(
        &records_path_chirho,
        format!("{before_chirho}{forged_line_chirho}\n"),
    )
    .unwrap();
    // Proof the append landed before anything depends on it.
    let after_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    assert_eq!(
        after_chirho.lines().count(),
        before_chirho.lines().count() + 1,
        "the forged line was not appended, so the assertion below would pass over an unmutated log"
    );

    std::fs::write(
        effects_dir_chirho.join("forged-private-effect"),
        serde_json::to_vec_pretty(&EffectChirho {
            seq_chirho: 1,
            idem_key_chirho: HashChirho("forged-private-effect-chirho".to_string()),
            capability_chirho: crate::model_chirho::CapabilityChirho::ClockChirho,
            request_chirho: forged_hash_chirho.clone(),
            response_chirho: None,
            sig_chirho: "test-sig-chirho".to_string(),
            at_chirho: "0".to_string(),
        })
        .unwrap(),
    )
    .unwrap();

    let error_chirho = scan_privacy_surfaces_chirho(&root_chirho)
        .expect_err("privacy scan reported a clean skip over a hash nothing backs");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the scan refused for some other reason than record verification: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&forged_hash_chirho.0),
        "the refusal must name the hash it is about: {text_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_treats_verified_app_params_as_public_content_chirho() {
    let root_chirho = tmp_root_chirho();
    let params_chirho = serde_json::json!({
        "business_name_chirho": "Public Params Books",
        "tagline_chirho": "Readable stories without leaked drafts",
        "contact_chirho": "Visit the downtown reading room",
        "features_chirho": [
            {
                "title_chirho": "Shelves",
                "body_chirho": "Hand-picked titles for thoughtful public readers."
            }
        ]
    });
    let params_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &params_chirho).unwrap();
    let wrapper_chirho = serde_json::json!({
        "app_params_chirho": params_chirho.clone()
    });
    let _wrapper_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &wrapper_chirho).unwrap();
    let unverified_report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(unverified_report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| finding_chirho.path_chirho == "$.tagline_chirho"));
    assert!(unverified_report_chirho
        .findings_chirho
        .iter()
        .any(|finding_chirho| {
            finding_chirho.path_chirho == "$.app_params_chirho.tagline_chirho"
        }));

    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let dag_hash_chirho = crate::store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "public-params-app-chirho",
        dag_hash_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    crate::app_chirho::set_app_params_hash_chirho(
        &root_chirho,
        "public-params-app-chirho",
        None,
        &owner_chirho.principal_chirho,
        params_hash_chirho,
        true,
    )
    .unwrap();

    let verified_report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(
        verified_report_chirho.findings_chirho.is_empty(),
        "verified public app params should not be privacy findings: {:?}",
        verified_report_chirho.findings_chirho
    );

    let records_path_chirho = root_chirho.join("app-params-records-chirho.jsonl");
    let mut record_text_chirho = std::fs::read_to_string(&records_path_chirho).unwrap();
    record_text_chirho = record_text_chirho.replace("public-params-app-chirho", "tampered-app");
    std::fs::write(records_path_chirho, record_text_chirho).unwrap();
    let tampered_error_chirho = scan_privacy_surfaces_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(!tampered_error_chirho.is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_does_not_flag_encrypted_blob_plaintext_chirho() {
    let root_chirho = tmp_root_chirho();
    store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/abcdef0123456789",
        ),
        "user/abcdef0123456789",
        b"send receipt to alice@example.com",
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(report_chirho.findings_chirho.is_empty());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reviewed_signed_surface_inventory_covers_production_jsonl_logs_chirho() {
    let reviewed_chirho = reviewed_signed_log_files_chirho();
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
        "literal production signed JSONL logs lack M27 privacy-surface review: {unexplained_chirho:?}"
    );
    assert!(
        missing_chirho
            .dynamic_per_branch_populations_chirho
            .is_empty(),
        "dynamic production signed JSONL populations lack privacy-surface review: {:?}",
        missing_chirho.dynamic_per_branch_populations_chirho
    );
}

#[cfg(unix)]
#[test]
fn private_blob_key_file_is_private_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("anon"),
        "anon",
        b"secret",
    )
    .unwrap();
    let dir_mode_chirho = std::fs::metadata(keys_dir_chirho(&root_chirho))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let key_mode_chirho =
        std::fs::metadata(key_path_chirho(&root_chirho, &blob_chirho.key_id_chirho))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
    assert_eq!(dir_mode_chirho, 0o700);
    assert_eq!(key_mode_chirho, 0o600);
    let _ = std::fs::remove_dir_all(&root_chirho);
}
