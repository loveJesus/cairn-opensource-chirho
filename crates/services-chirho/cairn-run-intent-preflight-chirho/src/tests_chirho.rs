// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_chirho::effect_chirho::run_intent_chirho;
use cairn_chirho::model_chirho::{NodeDefChirho, PortChirho, RequestContextChirho};
use cairn_chirho::{cas_chirho, store_chirho};
use clap::Parser;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
struct RunIntentStartupPreflightArgsHarnessChirho {
    #[command(flatten)]
    args_chirho: RunIntentStartupPreflightArgsChirho,
}

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-run-intent-startup-preflight-{nanos_chirho}-{n_chirho}",
        nanos_chirho = now_nanos_chirho()
    ))
}

fn now_nanos_chirho() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn now_ms_chirho() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn tree_bytes_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit_chirho(
        root_chirho: &Path,
        dir_chirho: &Path,
        out_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) {
        if !dir_chirho.exists() {
            return;
        }
        let mut entries_chirho = std::fs::read_dir(dir_chirho)
            .unwrap()
            .map(|entry_chirho| entry_chirho.unwrap().path())
            .collect::<Vec<_>>();
        entries_chirho.sort();
        for path_chirho in entries_chirho {
            if path_chirho.is_dir() {
                visit_chirho(root_chirho, &path_chirho, out_chirho);
            } else {
                out_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                    std::fs::read(&path_chirho).unwrap(),
                );
            }
        }
    }
    let mut out_chirho = BTreeMap::new();
    visit_chirho(root_chirho, root_chirho, &mut out_chirho);
    out_chirho
}

fn store_one_node_dag_chirho(root_chirho: &Path) -> HashChirho {
    let impl_hash_chirho = cas_chirho::add_chirho(
        root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    )
    .unwrap();
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &NodeDefChirho {
            name_chirho: "upcase_chirho".to_string(),
            impl_wasm_chirho: impl_hash_chirho,
            entry_chirho: "upcase_chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: vec![],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn write_run_intent_records_chirho(
    root_chirho: &Path,
    records_chirho: &[run_intent_chirho::RunIntentRecordChirho],
) {
    let text_chirho = records_chirho
        .iter()
        .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        run_intent_chirho::run_intent_records_path_chirho(root_chirho),
        format!("{text_chirho}\n"),
    )
    .unwrap();
}

fn resign_record_chirho(
    root_chirho: &Path,
    record_chirho: &mut run_intent_chirho::RunIntentRecordChirho,
) {
    record_chirho.sig_chirho.clear();
    let message_chirho = serde_json::to_vec(record_chirho).unwrap();
    record_chirho.sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_chirho(root_chirho, &message_chirho)
            .unwrap();
}

#[test]
fn startup_preflight_args_parse_json_fail_flags_chirho() {
    let parsed_chirho = RunIntentStartupPreflightArgsHarnessChirho::try_parse_from([
        "preflight-chirho",
        "--json",
        "--fail-on-findings",
    ])
    .unwrap();
    assert!(parsed_chirho.args_chirho.json_chirho);
    assert!(parsed_chirho.args_chirho.fail_on_findings_chirho);
}

#[test]
fn startup_preflight_reports_empty_root_without_touching_it_chirho() {
    let root_chirho = tmp_root_chirho();
    let report_chirho = run_intent_startup_preflight_report_chirho(&root_chirho);
    assert_eq!(
        report_chirho.schema_chirho,
        "run-intent-startup-preflight-report-v1-chirho"
    );
    assert_eq!(report_chirho.records_chirho, 0);
    assert!(report_chirho.verified_chirho);
    assert!(!report_chirho.startup_recovery_would_block_chirho);
    assert!(report_chirho.read_only_chirho);
    assert!(report_chirho.resume_not_attempted_chirho);
    assert!(
        !root_chirho.exists(),
        "empty-root preflight must not create files"
    );
}

#[test]
fn startup_preflight_blocks_invalid_pending_transition_read_only_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho);
    run_intent_chirho::run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"blocked", None)
        .unwrap();
    let mut records_chirho =
        run_intent_chirho::load_run_intent_records_chirho(&root_chirho).unwrap();
    let mut extra_pending_chirho = records_chirho[0].clone();
    extra_pending_chirho.seq_chirho = records_chirho.len() as u64;
    extra_pending_chirho.status_chirho = "pending-chirho".to_string();
    extra_pending_chirho.error_kind_chirho = None;
    extra_pending_chirho.error_digest_chirho = None;
    extra_pending_chirho.at_ms_chirho = now_ms_chirho();
    resign_record_chirho(&root_chirho, &mut extra_pending_chirho);
    records_chirho.push(extra_pending_chirho);
    write_run_intent_records_chirho(&root_chirho, &records_chirho);
    let before_chirho = tree_bytes_snapshot_chirho(&root_chirho);

    let report_chirho = run_intent_startup_preflight_report_chirho(&root_chirho);

    assert!(!report_chirho.verified_chirho);
    assert!(report_chirho.startup_recovery_would_block_chirho);
    assert!(
        report_chirho.findings_chirho[0].contains("invalid transition to pending-chirho"),
        "{report_chirho:#?}"
    );
    assert_eq!(
        tree_bytes_snapshot_chirho(&root_chirho),
        before_chirho,
        "blocked-root preflight must not append recovery records or create sentinels"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn startup_preflight_reports_resume_prereq_without_resuming_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho);
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user@example.test".to_string(),
        app_chirho: "demo-app-chirho".to_string(),
        owner_principal_chirho: "owner@example.test".to_string(),
        client_id_chirho: "client-chirho".to_string(),
        token_hash_chirho: "missing-token-hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    run_intent_chirho::run_dag_with_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"pending-app",
        Some(&context_chirho),
    )
    .unwrap();
    let records_chirho = run_intent_chirho::load_run_intent_records_chirho(&root_chirho).unwrap();
    write_run_intent_records_chirho(&root_chirho, &records_chirho[0..1]);
    let before_chirho = tree_bytes_snapshot_chirho(&root_chirho);

    let report_chirho = run_intent_startup_preflight_report_chirho(&root_chirho);

    assert!(report_chirho.verified_chirho);
    assert_eq!(report_chirho.unfinished_chirho, 1);
    assert_eq!(report_chirho.pending_chirho, 1);
    assert_eq!(report_chirho.resume_prereq_failed_chirho, 1);
    assert!(report_chirho.startup_recovery_would_block_chirho);
    assert!(
        report_chirho.findings_chirho[0].contains("run-intent-resume-prereq-failed-chirho"),
        "{report_chirho:#?}"
    );
    assert_eq!(
        run_intent_chirho::load_run_intent_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1,
        "preflight must not append a failed/running/done recovery record"
    );
    assert_eq!(tree_bytes_snapshot_chirho(&root_chirho), before_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// An aborted run (the pre-effect brick's reader, agy #25907) is not an unfinished run: startup recovery leaves it for
/// its own retry, so the preflight neither counts it nor blocks on it. Before the reader, the shared verifier refused
/// the status, and the preflight reported every root that held one as blocked.
///
/// The positive control: the same run cut back to PENDING and RUNNING is one unfinished, running run.
#[test]
fn startup_preflight_neither_counts_nor_blocks_on_an_aborted_run_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho);
    run_intent_chirho::run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"aborted", None)
        .unwrap();
    let records_chirho = run_intent_chirho::load_run_intent_records_chirho(&root_chirho).unwrap();
    let mut history_chirho = records_chirho[0..2].to_vec();
    write_run_intent_records_chirho(&root_chirho, &history_chirho);
    let control_chirho = run_intent_startup_preflight_report_chirho(&root_chirho);
    assert!(control_chirho.verified_chirho, "{control_chirho:#?}");
    assert_eq!(
        (
            control_chirho.unfinished_chirho,
            control_chirho.running_chirho
        ),
        (1, 1),
        "the control: a running run is unfinished"
    );

    let mut aborted_chirho = records_chirho[1].clone();
    aborted_chirho.seq_chirho = 2;
    aborted_chirho.status_chirho = "aborted-chirho".to_string();
    aborted_chirho.error_kind_chirho = Some("DagPreEffectRefusedChirho".to_string());
    aborted_chirho.error_digest_chirho = Some(cas_chirho::hash_chirho(
        b"preflight aborted arm refusal chirho",
    ));
    aborted_chirho.at_ms_chirho = now_ms_chirho();
    resign_record_chirho(&root_chirho, &mut aborted_chirho);
    history_chirho.push(aborted_chirho);
    write_run_intent_records_chirho(&root_chirho, &history_chirho);
    let before_chirho = tree_bytes_snapshot_chirho(&root_chirho);

    let report_chirho = run_intent_startup_preflight_report_chirho(&root_chirho);

    assert!(report_chirho.verified_chirho, "{report_chirho:#?}");
    assert_eq!(report_chirho.records_chirho, 3);
    assert_eq!(
        (
            report_chirho.unfinished_chirho,
            report_chirho.pending_chirho,
            report_chirho.running_chirho
        ),
        (0, 0, 0)
    );
    assert!(
        report_chirho.findings_chirho.is_empty(),
        "{report_chirho:#?}"
    );
    assert!(!report_chirho.startup_recovery_would_block_chirho);
    assert_eq!(
        tree_bytes_snapshot_chirho(&root_chirho),
        before_chirho,
        "the preflight stays read-only"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
