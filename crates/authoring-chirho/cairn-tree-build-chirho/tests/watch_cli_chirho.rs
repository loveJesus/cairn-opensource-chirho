// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tree-build-watch-cli-{now_chirho}-{n_chirho}"))
}

fn read_json_line_chirho(reader_chirho: &mut impl BufRead) -> Value {
    let mut line_chirho = String::new();
    reader_chirho
        .read_line(&mut line_chirho)
        .expect("read watch JSON line");
    assert!(!line_chirho.trim().is_empty(), "watch emitted no JSON line");
    serde_json::from_str(&line_chirho).expect("watch line parses as JSON")
}

#[test]
fn watch_cli_reports_fresh_candidate_after_source_edit_chirho() {
    let root_chirho = tmp_root_chirho();
    let new_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("new")
        .arg("contact-form-chirho")
        .arg(&root_chirho)
        .output()
        .expect("run tree-build new");
    assert!(
        new_chirho.status.success(),
        "new stderr={}",
        String::from_utf8_lossy(&new_chirho.stderr)
    );

    let mut child_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("watch")
        .arg(&root_chirho)
        .arg("--cycles")
        .arg("2")
        .arg("--interval-ms")
        .arg("20")
        .arg("--json")
        .arg("--skip-guest-build")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tree-build watch");
    let stdout_chirho = child_chirho.stdout.take().expect("watch stdout");
    let mut stderr_chirho = child_chirho.stderr.take().expect("watch stderr");
    let mut reader_chirho = BufReader::new(stdout_chirho);

    let first_chirho = read_json_line_chirho(&mut reader_chirho);
    let first_watch_cycle_chirho = first_chirho
        .get("watch_cycle_fingerprint_chirho")
        .and_then(|value_chirho| value_chirho.as_str())
        .expect("first watch cycle fingerprint")
        .to_string();
    assert!(
        first_chirho
            .get("source_tree_blake3_chirho")
            .and_then(|value_chirho| value_chirho.as_str())
            .is_some(),
        "watch report should expose a content-only source tree digest"
    );

    let implementation_chirho =
        root_chirho.join("src/implementations_chirho/render_contact_form_chirho.rs");
    let mut source_chirho = std::fs::read_to_string(&implementation_chirho).unwrap();
    source_chirho.push_str("\n// watch edit chirho\n");
    std::fs::write(&implementation_chirho, source_chirho).unwrap();

    let second_chirho = read_json_line_chirho(&mut reader_chirho);
    let second_watch_cycle_chirho = second_chirho
        .get("watch_cycle_fingerprint_chirho")
        .and_then(|value_chirho| value_chirho.as_str())
        .expect("second watch cycle fingerprint")
        .to_string();
    assert_ne!(first_watch_cycle_chirho, second_watch_cycle_chirho);
    assert_eq!(
        second_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some("tree-build-watch-cycle-v2-chirho")
    );
    assert_eq!(
        second_chirho
            .get("preview_chirho")
            .and_then(|value_chirho| value_chirho.get("moved_refs_chirho"))
            .and_then(|value_chirho| value_chirho.as_bool()),
        Some(false)
    );

    let status_chirho = child_chirho.wait().expect("watch exits");
    let mut stderr_text_chirho = String::new();
    stderr_chirho
        .read_to_string(&mut stderr_text_chirho)
        .expect("read watch stderr");
    assert!(status_chirho.success(), "watch stderr={stderr_text_chirho}");
    let _ = std::fs::remove_dir_all(&root_chirho);
}
