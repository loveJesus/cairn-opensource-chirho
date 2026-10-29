// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::DagChirho;
use cairn_gate1_authority_log_chirho::authority_log_chirho::{
    append_gate1_authority_record_unlocked_chirho, load_gate1_authority_records_chirho,
    verify_gate1_authority_log_chirho, Gate1AuthorityAppendInputChirho,
};
use cairn_model_gate1_chirho::GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-resource-gate1-dual-write-{nanos_chirho}-{n_chirho}"
    ))
}

fn deploy_owned_app_chirho(root_chirho: &Path, name_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho =
        crate::cas_chirho::add_chirho(root_chirho, b"resource gate marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, name_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

fn write_jsonl_chirho<TChirho: Serialize>(path_chirho: &Path, records_chirho: &[TChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn write_lines_chirho(path_chirho: &Path, lines_chirho: &[String]) {
    let mut text_chirho = lines_chirho.join("\n");
    text_chirho.push('\n');
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn noncanonical_line_chirho<TChirho: Serialize>(record_chirho: &TChirho) -> String {
    let canonical_chirho = serde_json::to_string(record_chirho).unwrap();
    let physical_chirho = canonical_chirho.replacen("{\"seq_chirho\":", "{ \"seq_chirho\" : ", 1);
    assert_ne!(physical_chirho, canonical_chirho);
    physical_chirho
}

fn demo_policy_for_tests_chirho() -> (Vec<ResourceMeterChirho>, Vec<ResourceActionPolicyChirho>) {
    (
        vec![ResourceMeterChirho {
            resource_chirho: "resource_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1000),
            app_limit_chirho: Some(10_000),
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "main_chirho".to_string(),
            action_chirho: "run_chirho".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "resource_credit_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
}

fn set_policy_for_tests_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> (HashChirho, ResourcePolicyRecordChirho) {
    let (meters_chirho, actions_chirho) = demo_policy_for_tests_chirho();
    let (policy_hash_chirho, _policy_chirho, record_chirho) = set_resource_policy_chirho(
        root_chirho,
        app_chirho,
        owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    (policy_hash_chirho, record_chirho)
}

fn usage_input_chirho(app_chirho: &str, user_chirho: &str) -> ResourceUsageInputChirho {
    ResourceUsageInputChirho {
        app_chirho: app_chirho.to_string(),
        user_chirho: user_chirho.to_string(),
        actor_chirho: None,
        section_chirho: "main_chirho".to_string(),
        action_chirho: "run_chirho".to_string(),
        effect_chirho: None,
        run_chirho: None,
        bridges_chirho: Vec::new(),
    }
}

fn policy_authority_records_chirho(
    root_chirho: &Path,
) -> Vec<cairn_model_gate1_chirho::Gate1AuthorityLogRecordChirho> {
    load_gate1_authority_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.family_chirho
                == cairn_model_gate1_chirho::GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO
        })
        .collect()
}

fn unset_authority_records_chirho(
    root_chirho: &Path,
) -> Vec<cairn_model_gate1_chirho::Gate1AuthorityLogRecordChirho> {
    load_gate1_authority_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.family_chirho
                == cairn_model_gate1_chirho::GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO
        })
        .collect()
}

fn usage_authority_records_chirho(
    root_chirho: &Path,
) -> Vec<cairn_model_gate1_chirho::Gate1AuthorityLogRecordChirho> {
    load_gate1_authority_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.family_chirho
                == cairn_model_gate1_chirho::GATE1_RESOURCE_USAGE_FAMILY_CHIRHO
        })
        .collect()
}

fn append_policy_old_road_without_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> ResourcePolicyRecordChirho {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |_writer_fence_chirho| {
        let previous_chirho = current_resource_policy_hash_chirho(root_chirho, app_chirho)?;
        let (meters_chirho, actions_chirho) = demo_policy_for_tests_chirho();
        let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
            app_chirho,
            owner_chirho,
            meters_chirho,
            actions_chirho,
            previous_chirho.clone(),
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        match &previous_chirho {
            Some(expected_chirho) => refs_chirho::compare_and_set_branch_chirho(
                root_chirho,
                &resource_policy_ref_chirho(app_chirho),
                expected_chirho,
                hash_chirho.clone(),
                "resource-policy",
            )?,
            None => refs_chirho::set_branch_chirho(
                root_chirho,
                &resource_policy_ref_chirho(app_chirho),
                hash_chirho.clone(),
            )?,
        }
        append_v1_policy_record_old_road_for_test_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho,
            previous_chirho,
        )
    })
    .unwrap()
}

/// Fixture-only complete v1-era dual-write set: raw ref move, v1 old-road row, and its gate1
/// authority envelope — the honest legacy store shape production no longer writes.
fn set_v1_policy_with_authority_for_test_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> ResourcePolicyRecordChirho {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        let previous_chirho = refs_chirho::load_refs_chirho(root_chirho)?
            .branches_chirho
            .get(&resource_policy_ref_chirho(app_chirho))
            .cloned();
        let (meters_chirho, actions_chirho) = demo_policy_for_tests_chirho();
        let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
            app_chirho,
            owner_chirho,
            meters_chirho,
            actions_chirho,
            previous_chirho.clone(),
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        match &previous_chirho {
            Some(expected_chirho) => refs_chirho::compare_and_set_branch_chirho(
                root_chirho,
                &resource_policy_ref_chirho(app_chirho),
                expected_chirho,
                hash_chirho.clone(),
                "resource-policy",
            )?,
            None => refs_chirho::set_branch_chirho(
                root_chirho,
                &resource_policy_ref_chirho(app_chirho),
                hash_chirho.clone(),
            )?,
        }
        let record_chirho = append_v1_policy_record_old_road_for_test_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho,
            previous_chirho,
        )?;
        let family_line_chirho = gate1_authority_chirho::resource_policy_line_at_seq_chirho(
            root_chirho,
            record_chirho.seq_chirho,
        )?;
        append_gate1_authority_record_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
            Gate1AuthorityAppendInputChirho {
                family_chirho: GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
                family_seq_chirho: record_chirho.seq_chirho,
                family_line_chirho: &family_line_chirho,
                at_ms_chirho: record_chirho.at_ms_chirho,
            },
        )?;
        Ok(record_chirho)
    })
    .unwrap()
}

/// Fixture-only v1-era policy row appender: production writes only v2 rows now, so legacy
/// reconcile/read coverage hand-builds the v1 shape it exercises.
fn append_v1_policy_record_old_road_for_test_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    policy_hash_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
) -> Result<ResourcePolicyRecordChirho> {
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
        &policy_records_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = ResourcePolicyRecordChirho {
                seq_chirho,
                schema_chirho: RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
                app_chirho: app_chirho.to_string(),
                owner_principal_chirho: owner_chirho.to_string(),
                resource_policy_chirho: policy_hash_chirho.clone(),
                previous_chirho: previous_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: None,
                sig_chirho: String::new(),
            };
            let message_chirho = resource_policy_record_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            Ok(record_chirho)
        },
    )
}

fn append_unset_old_road_without_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> ResourcePolicyUnsetRecordChirho {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |_writer_fence_chirho| {
        let previous_chirho = refs_chirho::load_refs_chirho(root_chirho)?
            .branches_chirho
            .get(&resource_policy_ref_chirho(app_chirho))
            .cloned()
            .expect("resource policy required for unset fixture");
        append_resource_policy_unset_record_old_road_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            previous_chirho,
            0,
        )
    })
    .unwrap()
}

fn append_pending_unset_without_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> ResourcePolicyUnsetRecordChirho {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |_writer_fence_chirho| {
        let branch_chirho = resource_policy_ref_chirho(app_chirho);
        let previous_chirho = current_resource_policy_hash_chirho(root_chirho, app_chirho)?
            .expect("resource policy required for unset fixture");
        let unset_chirho = append_resource_policy_unset_record_old_road_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            previous_chirho.clone(),
            0,
        )?;
        head_removal_chirho::append_head_removal_record_unlocked_chirho(
            root_chirho,
            head_removal_chirho::HeadRemovalEvidenceInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &previous_chirho,
                kind_chirho: head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho,
                app_chirho,
                route_chirho: None,
                owner_principal_chirho: owner_chirho,
                domain_log_chirho: "resource-policy-unset-records-chirho.jsonl",
                domain_seq_chirho: unset_chirho.seq_chirho,
            },
        )?;
        Ok(unset_chirho)
    })
    .unwrap()
}

fn append_usage_old_road_without_authority_chirho(
    root_chirho: &Path,
    input_chirho: ResourceUsageInputChirho,
) -> ResourceUsageRecordChirho {
    writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, |_writer_fence_chirho| {
        let actor_value_chirho = input_chirho
            .actor_chirho
            .clone()
            .unwrap_or_else(|| input_chirho.user_chirho.clone());
        append_resource_usage_old_road_unlocked_chirho(
            root_chirho,
            input_chirho,
            actor_value_chirho,
        )
    })
    .unwrap()
}

fn reconcile_unsets_chirho(root_chirho: &Path, app_chirho: &str) {
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        gate1_authority_chirho::reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
        )
    })
    .unwrap();
}

#[test]
fn resource_dual_write_binds_exact_old_road_line_bytes_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcegate");
    set_policy_for_tests_chirho(&root_chirho, "resourcegate", &owner_chirho);
    let usage_chirho = record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourcegate", "user/alice"),
    )
    .unwrap();
    let unset_chirho = unset_resource_policy_chirho(&root_chirho, "resourcegate", &owner_chirho)
        .unwrap()
        .expect("unset should record");

    let policy_lines_chirho =
        gate1_authority_chirho::resource_policy_lines_chirho(&root_chirho).unwrap();
    let unset_lines_chirho =
        gate1_authority_chirho::resource_policy_unset_lines_chirho(&root_chirho).unwrap();
    let usage_lines_chirho =
        gate1_authority_chirho::resource_usage_lines_chirho(&root_chirho).unwrap();

    assert_eq!(
        policy_authority_records_chirho(&root_chirho)[0].family_line_chirho,
        policy_lines_chirho[0]
    );
    assert_eq!(
        usage_authority_records_chirho(&root_chirho)[0].family_line_chirho,
        usage_lines_chirho[usage_chirho.seq_chirho as usize]
    );
    assert_eq!(
        unset_authority_records_chirho(&root_chirho)[0].family_line_chirho,
        unset_lines_chirho[unset_chirho.seq_chirho as usize]
    );
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn policy_set_forward_completes_missing_resource_policy_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcepolicymissing");
    append_policy_old_road_without_authority_chirho(
        &root_chirho,
        "resourcepolicymissing",
        &owner_chirho,
    );
    assert!(policy_authority_records_chirho(&root_chirho).is_empty());

    set_policy_for_tests_chirho(&root_chirho, "resourcepolicymissing", &owner_chirho);

    let records_chirho = policy_authority_records_chirho(&root_chirho);
    let lines_chirho = gate1_authority_chirho::resource_policy_lines_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 2);
    assert_eq!(records_chirho[0].family_line_chirho, lines_chirho[0]);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn unset_pending_return_forward_completes_missing_resource_unset_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceunsetmissing");
    set_policy_for_tests_chirho(&root_chirho, "resourceunsetmissing", &owner_chirho);
    let old_chirho = append_pending_unset_without_authority_chirho(
        &root_chirho,
        "resourceunsetmissing",
        &owner_chirho,
    );
    assert!(unset_authority_records_chirho(&root_chirho).is_empty());

    let returned_chirho =
        unset_resource_policy_chirho(&root_chirho, "resourceunsetmissing", &owner_chirho)
            .unwrap()
            .expect("pending unset should finish");
    let records_chirho = unset_authority_records_chirho(&root_chirho);
    let lines_chirho =
        gate1_authority_chirho::resource_policy_unset_lines_chirho(&root_chirho).unwrap();

    assert_eq!(returned_chirho.seq_chirho, old_chirho.seq_chirho);
    assert_eq!(records_chirho.len(), 1);
    assert_eq!(records_chirho[0].family_line_chirho, lines_chirho[0]);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn usage_append_forward_completes_missing_resource_usage_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceusagemissing");
    set_policy_for_tests_chirho(&root_chirho, "resourceusagemissing", &owner_chirho);
    append_usage_old_road_without_authority_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagemissing", "user/alice"),
    );
    assert!(usage_authority_records_chirho(&root_chirho).is_empty());

    record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagemissing", "user/bob"),
    )
    .unwrap();

    let records_chirho = usage_authority_records_chirho(&root_chirho);
    let lines_chirho = gate1_authority_chirho::resource_usage_lines_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 2);
    assert_eq!(records_chirho[0].family_line_chirho, lines_chirho[0]);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfilled_resource_policy_preserves_noncanonical_old_road_line_bytes_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcepolicynoncanon");
    let record_chirho = append_policy_old_road_without_authority_chirho(
        &root_chirho,
        "resourcepolicynoncanon",
        &owner_chirho,
    );
    let physical_line_chirho = noncanonical_line_chirho(&record_chirho);
    write_lines_chirho(
        &policy_records_path_chirho(&root_chirho),
        std::slice::from_ref(&physical_line_chirho),
    );

    set_policy_for_tests_chirho(&root_chirho, "resourcepolicynoncanon", &owner_chirho);
    let records_chirho = policy_authority_records_chirho(&root_chirho);

    assert_eq!(records_chirho[0].family_line_chirho, physical_line_chirho);
    assert_ne!(
        records_chirho[0].family_line_chirho,
        serde_json::to_string(&record_chirho).unwrap()
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfilled_resource_unset_preserves_noncanonical_old_road_line_bytes_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceunsetnoncanon");
    set_policy_for_tests_chirho(&root_chirho, "resourceunsetnoncanon", &owner_chirho);
    let record_chirho = append_unset_old_road_without_authority_chirho(
        &root_chirho,
        "resourceunsetnoncanon",
        &owner_chirho,
    );
    let physical_line_chirho = noncanonical_line_chirho(&record_chirho);
    write_lines_chirho(
        &policy_unset_records_path_chirho(&root_chirho),
        std::slice::from_ref(&physical_line_chirho),
    );

    reconcile_unsets_chirho(&root_chirho, "resourceunsetnoncanon");
    let records_chirho = unset_authority_records_chirho(&root_chirho);

    assert_eq!(records_chirho[0].family_line_chirho, physical_line_chirho);
    assert_ne!(
        records_chirho[0].family_line_chirho,
        serde_json::to_string(&record_chirho).unwrap()
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfilled_resource_usage_preserves_noncanonical_old_road_line_bytes_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceusagenoncanon");
    set_policy_for_tests_chirho(&root_chirho, "resourceusagenoncanon", &owner_chirho);
    let record_chirho = append_usage_old_road_without_authority_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagenoncanon", "user/alice"),
    );
    let physical_line_chirho = noncanonical_line_chirho(&record_chirho);
    write_lines_chirho(
        &usage_records_path_chirho(&root_chirho),
        std::slice::from_ref(&physical_line_chirho),
    );

    record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagenoncanon", "user/bob"),
    )
    .unwrap();
    let records_chirho = usage_authority_records_chirho(&root_chirho);

    assert_eq!(records_chirho[0].family_line_chirho, physical_line_chirho);
    assert_ne!(
        records_chirho[0].family_line_chirho,
        serde_json::to_string(&record_chirho).unwrap()
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfill_rejects_tampered_non_tail_resource_policy_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcepolicytamper");
    append_policy_old_road_without_authority_chirho(
        &root_chirho,
        "resourcepolicytamper",
        &owner_chirho,
    );
    append_policy_old_road_without_authority_chirho(
        &root_chirho,
        "resourcepolicytamper",
        &owner_chirho,
    );
    let mut records_chirho = load_resource_policy_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(&policy_records_path_chirho(&root_chirho), &records_chirho);

    let error_chirho = set_resource_policy_chirho(
        &root_chirho,
        "resourcepolicytamper",
        &owner_chirho,
        demo_policy_for_tests_chirho().0,
        demo_policy_for_tests_chirho().1,
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("resource policy record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfill_rejects_tampered_non_tail_resource_unset_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceunsettamper");
    set_policy_for_tests_chirho(&root_chirho, "resourceunsettamper", &owner_chirho);
    append_unset_old_road_without_authority_chirho(
        &root_chirho,
        "resourceunsettamper",
        &owner_chirho,
    );
    append_unset_old_road_without_authority_chirho(
        &root_chirho,
        "resourceunsettamper",
        &owner_chirho,
    );
    let mut records_chirho = load_resource_policy_unset_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(
        &policy_unset_records_path_chirho(&root_chirho),
        &records_chirho,
    );

    let error_chirho =
        with_resource_policy_authority_scope_chirho(&root_chirho, "resourceunsettamper", |writer_fence_chirho| {
            gate1_authority_chirho::reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
                &root_chirho,
                writer_fence_chirho,
            )
        })
        .unwrap_err()
        .to_string();

    assert!(error_chirho.contains("resource policy unset record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn backfill_rejects_tampered_non_tail_resource_usage_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceusagetamper");
    set_policy_for_tests_chirho(&root_chirho, "resourceusagetamper", &owner_chirho);
    append_usage_old_road_without_authority_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagetamper", "user/alice"),
    );
    append_usage_old_road_without_authority_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagetamper", "user/bob"),
    );
    let mut records_chirho = load_resource_usage_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(&usage_records_path_chirho(&root_chirho), &records_chirho);

    let error_chirho = record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagetamper", "user/charlie"),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("resource usage record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn resource_policy_set_fails_closed_on_tampered_history_chirho() {
    // Money ruling 7 (2026-07-12) reversed the D-era "no full verify on the positive set fast path"
    // optimization: the resource-policy set now mirrors billing and recovers/verifies the full
    // signed history on every set, because the torn-completion crash window (ref moved, Applied
    // receipt not yet appended) is invisible to a parse-only probe and would otherwise wedge the
    // app forever. A consequence the adversarial fleet demanded: a set on a store whose history
    // carries a tampered non-tail signature now fails closed instead of silently appending, exactly
    // as billing does. The verified-prefix watermark is the standing perf fix for the added cost.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcepolicycurrent");
    set_v1_policy_with_authority_for_test_chirho(
        &root_chirho,
        "resourcepolicycurrent",
        &owner_chirho,
    );
    set_v1_policy_with_authority_for_test_chirho(
        &root_chirho,
        "resourcepolicycurrent",
        &owner_chirho,
    );
    let mut records_chirho = load_resource_policy_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(&policy_records_path_chirho(&root_chirho), &records_chirho);

    let (meters_chirho, actions_chirho) = demo_policy_for_tests_chirho();
    let set_error_chirho = set_resource_policy_chirho(
        &root_chirho,
        "resourcepolicycurrent",
        &owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(
        set_error_chirho.contains("resource policy record 0 signature invalid"),
        "set must fail closed on a tampered non-tail row, not append over unverified history: {set_error_chirho}"
    );
    assert!(verify_resource_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("resource policy record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn current_resource_unset_prefix_reconcile_does_not_full_verify_old_road_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceunsetcurrent");
    set_policy_for_tests_chirho(&root_chirho, "resourceunsetcurrent", &owner_chirho);
    unset_resource_policy_chirho(&root_chirho, "resourceunsetcurrent", &owner_chirho).unwrap();
    set_policy_for_tests_chirho(&root_chirho, "resourceunsetcurrent", &owner_chirho);
    unset_resource_policy_chirho(&root_chirho, "resourceunsetcurrent", &owner_chirho).unwrap();
    let mut records_chirho = load_resource_policy_unset_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(
        &policy_unset_records_path_chirho(&root_chirho),
        &records_chirho,
    );

    let report_chirho =
        with_resource_policy_authority_scope_chirho(&root_chirho, "resourceunsetcurrent", |writer_fence_chirho| {
            gate1_authority_chirho::reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
                &root_chirho,
                writer_fence_chirho,
            )
        })
        .unwrap();
    let verify_error_chirho = verify_resource_policy_unsets_chirho(&root_chirho)
        .unwrap_err()
        .to_string();

    assert_eq!(report_chirho.backfilled_chirho, 0);
    assert!(verify_error_chirho.contains("resource policy unset record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn current_resource_usage_prefix_reconcile_does_not_full_verify_old_road_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourceusagecurrent");
    set_policy_for_tests_chirho(&root_chirho, "resourceusagecurrent", &owner_chirho);
    record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagecurrent", "user/alice"),
    )
    .unwrap();
    record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagecurrent", "user/bob"),
    )
    .unwrap();
    let mut records_chirho = load_resource_usage_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    write_jsonl_chirho(&usage_records_path_chirho(&root_chirho), &records_chirho);

    record_resource_usage_chirho(
        &root_chirho,
        usage_input_chirho("resourceusagecurrent", "user/charlie"),
    )
    .unwrap();
    let verify_error_chirho = verify_resource_usage_chirho(&root_chirho)
        .unwrap_err()
        .to_string();

    assert!(verify_error_chirho.contains("resource usage record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn resource_policy_authority_scope_does_not_deadlock_under_contention_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "resourcedeadlock");
    set_policy_for_tests_chirho(&root_chirho, "resourcedeadlock", &owner_chirho);
    let (done_tx_chirho, done_rx_chirho) = mpsc::channel();

    for worker_chirho in 0..3 {
        let tx_chirho = done_tx_chirho.clone();
        let root_for_thread_chirho = root_chirho.clone();
        let owner_for_thread_chirho = owner_chirho.clone();
        std::thread::spawn(move || {
            for n_chirho in 0..4 {
                match worker_chirho {
                    0 => {
                        let _ = set_policy_for_tests_chirho(
                            &root_for_thread_chirho,
                            "resourcedeadlock",
                            &owner_for_thread_chirho,
                        );
                    }
                    1 => {
                        let _ = unset_resource_policy_chirho(
                            &root_for_thread_chirho,
                            "resourcedeadlock",
                            &owner_for_thread_chirho,
                        );
                    }
                    _ => {
                        let _ = record_resource_usage_chirho(
                            &root_for_thread_chirho,
                            usage_input_chirho(
                                "resourcedeadlock",
                                &format!("user/contention-{n_chirho}"),
                            ),
                        );
                    }
                }
            }
            tx_chirho.send(worker_chirho).unwrap();
        });
    }
    drop(done_tx_chirho);
    for _ in 0..3 {
        done_rx_chirho
            .recv_timeout(Duration::from_secs(15))
            .expect("resource policy authority lock nesting should not deadlock");
    }

    let _ = std::fs::remove_dir_all(root_chirho);
}
