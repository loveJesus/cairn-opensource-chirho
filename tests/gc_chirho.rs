// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use cairn_chirho::native_worker_chirho::{
    self, NativeProgramBuildRequestChirho, NativeSandboxModeChirho,
};
use cairn_chirho::{cas_chirho, gc_chirho, privacy_chirho, refs_chirho, seqlog_chirho};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const RUNTIME_RECORD_DIRS_CHIRHO: &[&str] = &[
    "runs-chirho",
    "effects-chirho",
    "runkeys-chirho",
    "runseals-chirho",
];

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-gc-test-{nanos_chirho}-{n_chirho}"))
}

#[test]
fn gc_collects_unreachable_keeps_reachable_chirho() {
    let root_chirho = tmp_root_chirho();
    let keep_chirho = cas_chirho::add_chirho(&root_chirho, b"keep-me").unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "main", keep_chirho.clone()).unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-garbage").unwrap();
    assert_ne!(keep_chirho, orphan_chirho);

    let report_chirho = gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(report_chirho.collected_chirho >= 1);
    assert!(report_chirho.kept_chirho >= 1);
    assert!(cas_chirho::get_chirho(&root_chirho, &keep_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_keeps_private_blob_ciphertext_referenced_only_by_signed_jsonl_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho("user/gc").unwrap(),
        "user/gc",
        b"keep private",
    )
    .unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-private-neighbor").unwrap();

    let report_chirho = gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(report_chirho.collected_chirho >= 1);
    assert!(cas_chirho::get_chirho(&root_chirho, &blob_chirho.ciphertext_chirho).is_ok());
    assert!(privacy_chirho::load_private_blob_chirho(&root_chirho, &blob_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_marks_signed_jsonl_hashes_transitively_chirho() {
    let root_chirho = tmp_root_chirho();
    let child_chirho = cas_chirho::add_chirho(&root_chirho, b"child-stone").unwrap();
    let parent_chirho = cas_chirho::add_chirho(&root_chirho, child_chirho.0.as_bytes()).unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-stone").unwrap();
    let tenant_log_chirho = root_chirho
        .join("tenants-chirho")
        .join("tenant-a-chirho")
        .join("nested-log-chirho.jsonl");
    std::fs::create_dir_all(tenant_log_chirho.parent().unwrap()).unwrap();
    std::fs::write(
        &tenant_log_chirho,
        format!("{{\"root_chirho\":\"{}\"}}\n", parent_chirho.0),
    )
    .unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &parent_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &child_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_keeps_candidate_undo_plan_referenced_by_signed_review_chirho() {
    let root_chirho = tmp_root_chirho();
    let plan_chirho = cas_chirho::add_chirho(&root_chirho, b"canonical-undo-plan-chirho").unwrap();
    let review_report_chirho = cas_chirho::add_chirho(
        &root_chirho,
        format!(
            "{{\"undo_plan_bindings_chirho\":[{{\"plan_cas_chirho\":\"{}\"}}]}}",
            plan_chirho.0
        )
        .as_bytes(),
    )
    .unwrap();
    let orphan_plan_chirho =
        cas_chirho::add_chirho(&root_chirho, b"unreviewed-undo-plan-chirho").unwrap();
    std::fs::write(
        root_chirho.join("app-source-reviews-chirho.jsonl"),
        format!(
            "{{\"source_review_report_chirho\":\"{}\"}}\n",
            review_report_chirho.0
        ),
    )
    .unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &review_report_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &plan_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_plan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_keeps_run_intent_request_stones_chirho() {
    let root_chirho = tmp_root_chirho();
    let request_chirho = cas_chirho::add_chirho(&root_chirho, b"admitted request").unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan request").unwrap();
    std::fs::write(
        root_chirho.join("run-intents-chirho.jsonl"),
        format!("{{\"request_chirho\":\"{}\"}}\n", request_chirho.0),
    )
    .unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &request_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_marks_seqlog_quarantine_sidecar_hashes_chirho() {
    let root_chirho = tmp_root_chirho();
    let keep_chirho = cas_chirho::add_chirho(&root_chirho, b"quarantined-root").unwrap();
    let child_chirho = cas_chirho::add_chirho(&root_chirho, keep_chirho.0.as_bytes()).unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-sidecar-peer").unwrap();
    let quarantine_path_chirho = root_chirho
        .join(seqlog_chirho::SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join("fragment-chirho.jsonl-fragment-chirho");
    std::fs::create_dir_all(quarantine_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(
        &quarantine_path_chirho,
        format!("{{\"child_chirho\":\"{}\"}}", child_chirho.0),
    )
    .unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &child_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &keep_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_marks_runtime_record_roots_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut kept_chirho = Vec::new();
    for dir_chirho in RUNTIME_RECORD_DIRS_CHIRHO {
        let payload_chirho =
            cas_chirho::add_chirho(&root_chirho, format!("{dir_chirho}-only").as_bytes()).unwrap();
        let record_path_chirho = root_chirho
            .join(dir_chirho)
            .join(format!("{dir_chirho}-record"));
        std::fs::create_dir_all(record_path_chirho.parent().unwrap()).unwrap();
        std::fs::write(&record_path_chirho, payload_chirho.0.as_bytes()).unwrap();
        kept_chirho.push(payload_chirho);
    }
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-runtime-neighbor").unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    for payload_chirho in kept_chirho {
        assert!(cas_chirho::get_chirho(&root_chirho, &payload_chirho).is_ok());
    }
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_keeps_jsonl_referenced_native_spec_closure_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let executable_path_chirho = root_chirho.join("native-fixture-chirho");
    std::fs::write(&executable_path_chirho, b"not-executed-by-gc").unwrap();
    let (spec_obj_chirho, spec_chirho) = native_worker_chirho::build_native_program_chirho(
        &root_chirho,
        &executable_path_chirho,
        NativeProgramBuildRequestChirho {
            name_chirho: "gc-native-spec-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: Vec::new(),
            capabilities_chirho: Vec::new(),
            timeout_ms_chirho: 100,
            max_memory_bytes_chirho: 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 0,
        },
    )
    .unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-native-neighbor").unwrap();
    std::fs::write(
        root_chirho.join("native-stateless-attestations-chirho.jsonl"),
        format!(
            "{{\"spec_chirho\":\"{}\",\"executable_chirho\":\"{}\"}}\n",
            spec_chirho.0, spec_obj_chirho.executable_chirho.0
        ),
    )
    .unwrap();

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(native_worker_chirho::load_native_program_chirho(&root_chirho, &spec_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &spec_obj_chirho.executable_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn gc_nested_log_behavior_skips_private_dirs_chirho() {
    let root_chirho = tmp_root_chirho();
    let nested_keep_chirho = cas_chirho::add_chirho(&root_chirho, b"nested-keep").unwrap();
    let private_skip_chirho = cas_chirho::add_chirho(&root_chirho, b"private-skip").unwrap();
    let object_skip_chirho = cas_chirho::add_chirho(&root_chirho, b"object-skip").unwrap();
    let tenant_log_chirho = root_chirho
        .join("tenants-chirho")
        .join("tenant-a-chirho")
        .join("log-chirho.jsonl");
    let private_log_chirho = root_chirho
        .join("privacy-keys-chirho")
        .join("key-log-chirho.jsonl");
    let object_log_chirho = root_chirho
        .join("objects-chirho")
        .join("aa")
        .join("object-log-chirho.jsonl");
    for (path_chirho, hash_chirho) in [
        (&tenant_log_chirho, &nested_keep_chirho),
        (&private_log_chirho, &private_skip_chirho),
        (&object_log_chirho, &object_skip_chirho),
    ] {
        std::fs::create_dir_all(path_chirho.parent().unwrap()).unwrap();
        std::fs::write(
            path_chirho,
            format!("{{\"hash_chirho\":\"{}\"}}\n", hash_chirho.0),
        )
        .unwrap();
    }

    gc_chirho::gc_chirho(&root_chirho).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &nested_keep_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &private_skip_chirho).is_err());
    assert!(cas_chirho::get_chirho(&root_chirho, &object_skip_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// **FAIL-CLOSED MARK: a read failure on enumerated root material refuses the whole pass.**
///
/// Marking decides what stays alive, so every error that shrinks the marked set shrinks it toward
/// DELETION. Before this, `gc_chirho` swallowed read errors and swept anyway — a briefly unreadable
/// root log meant fewer marks and more collection, silently. The pass now refuses and collects
/// nothing, because "I could not read a root" and "nothing references this" are different answers.
///
/// **Absence is deliberately still fine** — the conservative scanner's unresolvable 64-hex tokens are
/// `NotFound` and retain nothing, exactly as before. Only failure refuses.
#[cfg(unix)]
#[test]
fn gc_refuses_to_sweep_when_root_material_cannot_be_read_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = tmp_root_chirho();
    // A real signed root JSONL, plus a genuine orphan that a completed pass WOULD collect.
    let blob_chirho = privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho("user/gc-failclosed")
            .unwrap(),
        "user/gc-failclosed",
        b"private",
    )
    .unwrap();
    let orphan_chirho = cas_chirho::add_chirho(&root_chirho, b"orphan-failclosed-chirho").unwrap();

    let log_chirho = std::fs::read_dir(&root_chirho)
        .unwrap()
        .flatten()
        .map(|entry_chirho| entry_chirho.path())
        .find(|path_chirho| {
            path_chirho
                .extension()
                .and_then(|e_chirho| e_chirho.to_str())
                == Some("jsonl")
        })
        .expect("the fixture must produce a root JSONL for the mark phase to read");

    let original_mode_chirho = std::fs::metadata(&log_chirho).unwrap().permissions();
    std::fs::set_permissions(&log_chirho, std::fs::Permissions::from_mode(0o000)).unwrap();

    // FIXTURE PRECONDITION, asserted rather than assumed: if the read still succeeds (running as
    // root, or a permissive filesystem) the fixture cannot test anything and a pass below would be
    // meaningless. Fail loudly instead of reporting a green that measured nothing.
    assert!(
        std::fs::read(&log_chirho).is_err(),
        "fixture did not actually make the root log unreadable — do not trust the result below"
    );

    let error_chirho = gc_chirho::gc_chirho(&root_chirho)
        .expect_err("an unreadable root log must refuse the pass");
    assert!(
        format!("{error_chirho:#}").contains(gc_chirho::GC_MARK_REFUSAL_CHIRHO),
        "refusal must be the NAMED mark refusal, not an incidental I/O error: {error_chirho:#}"
    );

    // Zero deletions: the orphan a completed pass would have collected is untouched.
    assert!(
        cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_ok(),
        "a refused pass must collect NOTHING — not even a genuinely unreachable object"
    );
    assert!(cas_chirho::get_chirho(&root_chirho, &blob_chirho.ciphertext_chirho).is_ok());

    // NON-VACUITY: the same fixture, error removed, completes AND collects nonzero. Without this the
    // refusal above could be an artifact of a root that had nothing to collect in the first place.
    std::fs::set_permissions(&log_chirho, original_mode_chirho).unwrap();
    let report_chirho = gc_chirho::gc_chirho(&root_chirho)
        .expect("with the root log readable again the pass must complete");
    assert!(
        report_chirho.collected_chirho >= 1,
        "the control must actually collect something, or the refusal proved nothing"
    );
    assert!(
        cas_chirho::get_chirho(&root_chirho, &orphan_chirho).is_err(),
        "the orphan is collected once the pass can actually complete"
    );
    assert!(cas_chirho::get_chirho(&root_chirho, &blob_chirho.ciphertext_chirho).is_ok());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The other half of the ruling: **absence is NOT failure.** An unresolvable 64-hex token — the
/// conservative scanner's false positive, and arm 20's planted look-alike — must still mark nothing
/// and complete normally. If fail-closed had been implemented as "any getter error refuses", this
/// would refuse and every ordinary pass would break.
#[test]
fn gc_still_completes_when_a_scanned_token_resolves_to_no_stored_object_chirho() {
    let root_chirho = tmp_root_chirho();
    let keep_chirho = cas_chirho::add_chirho(&root_chirho, b"keep-me-failclosed").unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "main", keep_chirho.clone()).unwrap();
    // A syntactically valid 64-hex reference that was never stored: NotFound, not failure.
    let look_alike_chirho =
        cas_chirho::add_chirho(&root_chirho, "a".repeat(64).as_bytes()).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "look-alike", look_alike_chirho.clone()).unwrap();

    let report_chirho = gc_chirho::gc_chirho(&root_chirho)
        .expect("an unresolvable scanned token is absence, and must not refuse the pass");
    assert!(report_chirho.kept_chirho >= 2);
    assert!(cas_chirho::get_chirho(&root_chirho, &keep_chirho).is_ok());
    assert!(cas_chirho::get_chirho(&root_chirho, &look_alike_chirho).is_ok());

    let _ = std::fs::remove_dir_all(&root_chirho);
}
