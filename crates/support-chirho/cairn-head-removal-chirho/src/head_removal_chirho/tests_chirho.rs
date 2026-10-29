// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_core_chirho::{cas_chirho, refs_chirho};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-head-removal-test-{nanos_chirho}-{n_chirho}"))
}

fn branch_hash_chirho(root_chirho: &Path, bytes_chirho: &[u8]) -> HashChirho {
    cas_chirho::add_chirho(root_chirho, bytes_chirho).unwrap()
}

fn evidence_input_chirho<'a>(
    branch_chirho: &'a str,
    from_chirho: &'a HashChirho,
) -> HeadRemovalEvidenceInputChirho<'a> {
    HeadRemovalEvidenceInputChirho {
        branch_chirho,
        from_chirho,
        kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
        app_chirho: "headremovalapp",
        route_chirho: None,
        owner_principal_chirho: "owner/abcdefabcdefabcd",
        domain_log_chirho: "app-records-chirho.jsonl",
        domain_seq_chirho: 0,
    }
}

fn frozen_hash_chirho() -> HashChirho {
    HashChirho("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string())
}

#[test]
fn head_removal_record_serialization_stays_stable_chirho() {
    let record_chirho = HeadRemovalRecordChirho {
        seq_chirho: 7,
        schema_chirho: HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO.to_string(),
        branch_chirho: "app/frozen/route-chirho".to_string(),
        from_chirho: frozen_hash_chirho(),
        kind_chirho: HeadRemovalKindChirho::AppRouteUndeployChirho,
        app_chirho: "frozenapp".to_string(),
        route_chirho: Some("inbox".to_string()),
        owner_principal_chirho: "owner/abcdefabcdefabcd".to_string(),
        domain_log_chirho: "app-records-chirho.jsonl".to_string(),
        domain_seq_chirho: 11,
        at_ms_chirho: 123456789,
        sig_chirho: "sig-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        "{\"seq_chirho\":7,\"schema_chirho\":\"head-removal-record-v1-chirho\",\"branch_chirho\":\"app/frozen/route-chirho\",\"from_chirho\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"kind_chirho\":\"AppRouteUndeployChirho\",\"app_chirho\":\"frozenapp\",\"route_chirho\":\"inbox\",\"owner_principal_chirho\":\"owner/abcdefabcdefabcd\",\"domain_log_chirho\":\"app-records-chirho.jsonl\",\"domain_seq_chirho\":11,\"at_ms_chirho\":123456789,\"sig_chirho\":\"sig-chirho\"}"
    );
    assert_eq!(
        String::from_utf8(head_removal_record_message_chirho(&record_chirho).unwrap()).unwrap(),
        "{\"seq_chirho\":7,\"schema_chirho\":\"head-removal-record-v1-chirho\",\"branch_chirho\":\"app/frozen/route-chirho\",\"from_chirho\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"kind_chirho\":\"AppRouteUndeployChirho\",\"app_chirho\":\"frozenapp\",\"route_chirho\":\"inbox\",\"owner_principal_chirho\":\"owner/abcdefabcdefabcd\",\"domain_log_chirho\":\"app-records-chirho.jsonl\",\"domain_seq_chirho\":11,\"at_ms_chirho\":123456789,\"sig_chirho\":\"\"}"
    );
}

#[test]
fn head_removal_record_omits_absent_route_chirho() {
    let record_chirho = HeadRemovalRecordChirho {
        seq_chirho: 8,
        schema_chirho: HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO.to_string(),
        branch_chirho: "app/frozen".to_string(),
        from_chirho: frozen_hash_chirho(),
        kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
        app_chirho: "frozenapp".to_string(),
        route_chirho: None,
        owner_principal_chirho: "owner/abcdefabcdefabcd".to_string(),
        domain_log_chirho: "app-records-chirho.jsonl".to_string(),
        domain_seq_chirho: 12,
        at_ms_chirho: 123456790,
        sig_chirho: "sig-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        "{\"seq_chirho\":8,\"schema_chirho\":\"head-removal-record-v1-chirho\",\"branch_chirho\":\"app/frozen\",\"from_chirho\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"kind_chirho\":\"AppUndeployChirho\",\"app_chirho\":\"frozenapp\",\"owner_principal_chirho\":\"owner/abcdefabcdefabcd\",\"domain_log_chirho\":\"app-records-chirho.jsonl\",\"domain_seq_chirho\":12,\"at_ms_chirho\":123456790,\"sig_chirho\":\"sig-chirho\"}"
    );
}

#[test]
fn head_removal_failpoints_are_scoped_by_root_chirho() {
    let first_root_chirho = tmp_root_chirho();
    let second_root_chirho = tmp_root_chirho();
    set_head_removal_failpoint_chirho(
        &first_root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    );

    maybe_fail_head_removal_step_chirho(
        &second_root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    )
    .unwrap();
    let error_chirho = maybe_fail_head_removal_step_chirho(
        &first_root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("injected head removal failure"));
    maybe_fail_head_removal_step_chirho(
        &first_root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    )
    .unwrap();

    let _ = std::fs::remove_dir_all(&first_root_chirho);
    let _ = std::fs::remove_dir_all(&second_root_chirho);
}

#[test]
fn head_removal_records_are_signed_and_tamper_fails_chirho() {
    let root_chirho = tmp_root_chirho();
    let hash_chirho = branch_hash_chirho(&root_chirho, b"head-removal target");
    refs_chirho::set_branch_chirho(&root_chirho, "app/headremovalapp", hash_chirho.clone())
        .unwrap();

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        append_head_removal_record_unlocked_chirho(
            &root_chirho,
            evidence_input_chirho("app/headremovalapp", &hash_chirho),
        )
        .map(|_| ())
    })
    .unwrap();

    assert_eq!(verify_head_removal_records_chirho(&root_chirho).unwrap(), 1);
    let mut records_chirho = load_head_removal_records_chirho(&root_chirho).unwrap();
    records_chirho[0].owner_principal_chirho = "owner/badbadbadbadbada".to_string();
    std::fs::write(
        head_removal_records_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&records_chirho[0]).unwrap()),
    )
    .unwrap();
    let error_chirho = verify_head_removal_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn branch_remove_requires_matching_signed_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let first_chirho = branch_hash_chirho(&root_chirho, b"first target");
    let second_chirho = branch_hash_chirho(&root_chirho, b"second target");
    refs_chirho::set_branch_chirho(&root_chirho, "app/headremovalapp", first_chirho.clone())
        .unwrap();
    let record_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        append_head_removal_record_unlocked_chirho(
            &root_chirho,
            evidence_input_chirho("app/headremovalapp", &first_chirho),
        )
    })
    .unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/headremovalapp", second_chirho).unwrap();

    let error_chirho = remove_branch_after_evidence_chirho(&root_chirho, &record_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("moved from signed removal head"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn branch_remove_rejects_tampered_signed_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let hash_chirho = branch_hash_chirho(&root_chirho, b"tamper target");
    refs_chirho::set_branch_chirho(&root_chirho, "app/headremovalapp", hash_chirho.clone())
        .unwrap();
    let mut record_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        append_head_removal_record_unlocked_chirho(
            &root_chirho,
            evidence_input_chirho("app/headremovalapp", &hash_chirho),
        )
    })
    .unwrap();
    let replacement_chirho = if record_chirho.sig_chirho.starts_with("00") {
        "ff"
    } else {
        "00"
    };
    record_chirho
        .sig_chirho
        .replace_range(0..2, replacement_chirho);

    let error_chirho = remove_branch_after_evidence_chirho(&root_chirho, &record_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("signature invalid"), "{error_chirho}");
    assert!(refs_chirho::load_refs_chirho(&root_chirho)
        .unwrap()
        .branches_chirho
        .contains_key("app/headremovalapp"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
