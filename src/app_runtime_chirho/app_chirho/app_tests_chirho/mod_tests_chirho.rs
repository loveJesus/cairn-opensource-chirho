// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "control_plane_record_tests_chirho.rs"]
mod control_plane_record_tests_chirho;
#[path = "elected_app_deploy_tests_chirho.rs"]
mod elected_app_deploy_tests_chirho;
#[path = "elected_app_route_deploy_tests_chirho.rs"]
mod elected_app_route_deploy_tests_chirho;
#[path = "request_access_policy_tests_chirho.rs"]
mod request_access_policy_tests_chirho;

#[path = "ha2_head_commit_tests_chirho.rs"]
mod ha2_head_commit_tests_chirho;
#[path = "ha2_head_removal_tests_chirho.rs"]
mod ha2_head_removal_tests_chirho;
#[path = "ha2_route_head_commit_tests_chirho.rs"]
mod ha2_route_head_commit_tests_chirho;
#[path = "ha2_route_head_removal_tests_chirho.rs"]
mod ha2_route_head_removal_tests_chirho;

#[path = "resolution_input_policy_tests_chirho.rs"]
mod resolution_input_policy_tests_chirho;
#[path = "verified_view_cache_scaling_tests_chirho.rs"]
mod verified_view_cache_scaling_tests_chirho;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-app-test-{nanos_chirho}-{n_chirho}"))
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).unwrap();
    }
    let mut out_chirho = String::new();
    for record_chirho in records_chirho {
        out_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        out_chirho.push('\n');
    }
    std::fs::write(path_chirho, out_chirho).unwrap();
}

fn production_source_lines_chirho() -> Vec<(String, usize, String)> {
    crate::source_scan_chirho::production_source_lines_chirho()
}

fn production_source_lines_matching_chirho(needle_chirho: &str) -> Vec<(String, usize, String)> {
    crate::source_scan_chirho::production_source_lines_matching_chirho(needle_chirho)
}

fn resign_app_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: AppRecordChirho,
) -> AppRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn resign_app_route_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: AppRouteRecordChirho,
) -> AppRouteRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_route_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn resign_app_input_policy_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: AppInputPolicyRecordChirho,
) -> AppInputPolicyRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_input_policy_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn resign_app_response_policy_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: AppResponsePolicyRecordChirho,
) -> AppResponsePolicyRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_response_policy_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn resign_app_route_response_policy_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: AppRouteResponsePolicyRecordChirho,
) -> AppRouteResponsePolicyRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &app_route_response_policy_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn fake_dag_chirho(root_chirho: &Path, marker_chirho: &[u8]) -> HashChirho {
    let marker_hash_chirho = crate::cas_chirho::add_chirho(root_chirho, marker_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}
