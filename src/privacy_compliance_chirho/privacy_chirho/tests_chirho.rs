// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::{EffectChirho, HashChirho};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "honest_scope_scan_tests_chirho.rs"]
mod honest_scope_scan_tests_chirho;

#[path = "private_blob_tests_chirho.rs"]
mod private_blob_tests_chirho;

#[path = "privacy_scan_surface_tests_chirho.rs"]
mod privacy_scan_surface_tests_chirho;

#[path = "blob_view_tests_chirho.rs"]
mod blob_view_tests_chirho;

#[path = "account_attribution_tests_chirho.rs"]
mod account_attribution_tests_chirho;

#[path = "erasure_capture_tests_chirho.rs"]
mod erasure_capture_tests_chirho;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let pid_chirho = std::process::id();
    std::env::temp_dir().join(format!(
        "cairn-privacy-test-{pid_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn write_jsonl_records_chirho<T: serde::Serialize>(
    path_chirho: &std::path::Path,
    records_chirho: &[T],
) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}
