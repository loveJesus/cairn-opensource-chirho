// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

#[test]
fn framed_native_warm_pool_reuses_one_process_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        eprintln!("skipping dynamic framed-worker smoke under Linux seccomp; use a static framed worker for Linux pool proof");
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let root_chirho = tmp_root_chirho("reuse");
        let spec_hash_chirho = build_framed_counter_spec_chirho(&root_chirho, 1);
        let warm_chirho = cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
            &root_chirho,
            &spec_hash_chirho,
        )
        .unwrap();
        assert_eq!(warm_chirho.warm_slots_chirho, 1);

        let first_chirho = run_framed_counter_chirho(&root_chirho, &spec_hash_chirho, b"alpha");
        let second_chirho = run_framed_counter_chirho(&root_chirho, &spec_hash_chirho, b"beta");
        assert_eq!(
            field_chirho(&first_chirho, "pid"),
            field_chirho(&second_chirho, "pid")
        );
        assert!(first_chirho.contains("count=1 ALPHA"));
        assert!(second_chirho.contains("count=2 BETA"));

        cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
            &root_chirho,
            &spec_hash_chirho,
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn framed_native_warm_pool_preserves_pure_output_across_reuse_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();
    let root_chirho = tmp_root_chirho("pure");
    let spec_hash_chirho = build_framed_upcase_spec_chirho(&root_chirho, 1);
    cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
        &root_chirho,
        &spec_hash_chirho,
    )
    .unwrap();

    assert_eq!(
        run_framed_worker_chirho(&root_chirho, &spec_hash_chirho, b"abc"),
        "ABC"
    );
    assert_eq!(
        run_framed_worker_chirho(&root_chirho, &spec_hash_chirho, b"xyz"),
        "XYZ"
    );

    cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
        &root_chirho,
        &spec_hash_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn framed_native_stateless_attestation_accepts_pure_worker_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        eprintln!("skipping dynamic framed-worker stateless smoke under Linux seccomp; use a static framed worker for Linux pool proof");
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let root_chirho = tmp_root_chirho("stateless-ok");
        let spec_hash_chirho = build_framed_upcase_spec_chirho(&root_chirho, 1);
        let record_chirho =
            cairn_chirho::native_worker_chirho::attest_native_program_stateless_chirho(
                &root_chirho,
                &spec_hash_chirho,
                b"abc",
            )
            .unwrap();
        assert_eq!(record_chirho.spec_chirho, spec_hash_chirho);
        assert_eq!(
            record_chirho.fresh_output_chirho,
            record_chirho.reused_first_output_chirho
        );
        assert_eq!(
            record_chirho.reused_first_output_chirho,
            record_chirho.reused_second_output_chirho
        );
        assert_eq!(
            cairn_chirho::native_worker_chirho::verify_native_stateless_attestations_chirho(
                &root_chirho
            )
            .unwrap(),
            1
        );
        let verification_chirho = cairn_chirho::native_worker_chirho::verify_native_program_chirho(
            &root_chirho,
            &spec_hash_chirho,
        )
        .unwrap();
        assert!(verification_chirho.stateless_attested_chirho);

        cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
            &root_chirho,
            &spec_hash_chirho,
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn framed_native_stateless_attestation_rejects_stateful_worker_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        eprintln!("skipping dynamic framed-worker stateless smoke under Linux seccomp; use a static framed worker for Linux pool proof");
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let root_chirho = tmp_root_chirho("stateless-bad");
        let spec_hash_chirho = build_framed_counter_spec_chirho(&root_chirho, 1);
        let error_chirho =
            cairn_chirho::native_worker_chirho::attest_native_program_stateless_chirho(
                &root_chirho,
                &spec_hash_chirho,
                b"abc",
            )
            .unwrap_err()
            .to_string();
        assert!(
            error_chirho.contains("stateless"),
            "expected stateless attestation refusal, got: {error_chirho}"
        );
        assert_eq!(
            cairn_chirho::native_worker_chirho::load_native_stateless_attestations_chirho(
                &root_chirho
            )
            .unwrap()
            .len(),
            0
        );

        cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
            &root_chirho,
            &spec_hash_chirho,
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn framed_native_warm_pool_respawns_after_worker_exit_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        eprintln!("skipping dynamic framed-worker smoke under Linux seccomp; use a static framed worker for Linux pool proof");
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let root_chirho = tmp_root_chirho("respawn");
        let spec_hash_chirho = build_framed_counter_spec_chirho(&root_chirho, 1);
        cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
            &root_chirho,
            &spec_hash_chirho,
        )
        .unwrap();

        let exit_input_chirho =
            cairn_chirho::cas_chirho::add_chirho(&root_chirho, b"__exit_chirho__").unwrap();
        let error_chirho = cairn_chirho::native_worker_chirho::run_native_program_cached_chirho(
            &root_chirho,
            &spec_hash_chirho,
            &exit_input_chirho,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error_chirho.contains("response length"),
            "expected pooled worker EOF after forced exit, got: {error_chirho}"
        );

        let recovered_chirho =
            run_framed_counter_chirho(&root_chirho, &spec_hash_chirho, b"recovered");
        assert!(recovered_chirho.contains("count=1 RECOVERED"));

        cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
            &root_chirho,
            &spec_hash_chirho,
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn framed_native_warm_pool_refills_after_successful_worker_exit_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();
    let root_chirho = tmp_root_chirho("respond-exit");
    let spec_hash_chirho = build_framed_spec_with_timeout_chirho(
        &root_chirho,
        "native-framed-respond-exit-chirho",
        "__native-worker-framed-respond-exit-child",
        1,
        NATIVE_WARM_POOL_SMOKE_TIMEOUT_MS_CHIRHO,
    );
    cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
        &root_chirho,
        &spec_hash_chirho,
    )
    .unwrap();

    let first_chirho = run_framed_worker_chirho(&root_chirho, &spec_hash_chirho, b"first");
    assert!(first_chirho.contains("once FIRST"));
    let second_chirho = run_framed_worker_chirho(&root_chirho, &spec_hash_chirho, b"second");
    assert!(second_chirho.contains("once SECOND"));

    cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
        &root_chirho,
        &spec_hash_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn framed_native_warm_pool_times_out_and_refills_hung_worker_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();
    let root_chirho = tmp_root_chirho("timeout");
    // The timeout must fire on a HUNG worker yet still clear a cold worker's spawn+warm on the
    // recovery run below — even when the whole workspace suite is hammering the CPU. 50 ms was too
    // tight there and flaked under parallel load; 1000 ms matches the sibling overflow test and keeps
    // hang-detection fast enough. Do not re-tighten without decoupling the hang and recovery timeouts.
    let spec_hash_chirho = build_framed_counter_spec_with_timeout_chirho(&root_chirho, 1, 1000);
    cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
        &root_chirho,
        &spec_hash_chirho,
    )
    .unwrap();

    let hang_input_chirho =
        cairn_chirho::cas_chirho::add_chirho(&root_chirho, b"__hang_chirho__").unwrap();
    let error_chirho = cairn_chirho::native_worker_chirho::run_native_program_cached_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &hang_input_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("timed out"),
        "expected pooled worker timeout, got: {error_chirho}"
    );

    let recovered_chirho = run_framed_counter_chirho(&root_chirho, &spec_hash_chirho, b"after");
    assert!(recovered_chirho.contains("count=1 AFTER"));

    cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
        &root_chirho,
        &spec_hash_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn framed_native_warm_pool_refuses_overflow_while_slot_checked_out_chirho() {
    let _guard_chirho = native_warm_pool_test_guard_chirho();
    let root_chirho = tmp_root_chirho("overflow");
    let spec_hash_chirho = build_framed_counter_spec_with_timeout_chirho(
        &root_chirho,
        1,
        NATIVE_WARM_POOL_SMOKE_TIMEOUT_MS_CHIRHO,
    );
    cairn_chirho::native_worker_chirho::prewarm_native_program_chirho(
        &root_chirho,
        &spec_hash_chirho,
    )
    .unwrap();

    let hold_token_chirho = root_chirho
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap()
        .to_string();
    let (hold_ready_path_chirho, hold_release_path_chirho) =
        native_warm_pool_hold_paths_chirho(&hold_token_chirho);
    let hold_input_chirho = cairn_chirho::cas_chirho::add_chirho(
        &root_chirho,
        format!("__hold_chirho__:{hold_token_chirho}").as_bytes(),
    )
    .unwrap();
    let root_for_thread_chirho = root_chirho.clone();
    let spec_for_thread_chirho = spec_hash_chirho.clone();
    let hold_handle_chirho = std::thread::spawn(move || {
        cairn_chirho::native_worker_chirho::run_native_program_cached_chirho(
            &root_for_thread_chirho,
            &spec_for_thread_chirho,
            &hold_input_chirho,
            &[],
        )
    });
    wait_for_native_warm_pool_hold_ready_chirho(&hold_ready_path_chirho);

    let busy_input_chirho = cairn_chirho::cas_chirho::add_chirho(&root_chirho, b"busy").unwrap();
    let busy_result_chirho = cairn_chirho::native_worker_chirho::run_native_program_cached_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &busy_input_chirho,
        &[],
    );
    std::fs::write(&hold_release_path_chirho, b"release-chirho").unwrap();
    let (_hold_result_chirho, hold_hit_chirho) = hold_handle_chirho.join().unwrap().unwrap();
    assert!(!hold_hit_chirho);
    let _ = std::fs::remove_file(&hold_ready_path_chirho);
    let _ = std::fs::remove_file(&hold_release_path_chirho);

    let busy_error_chirho = busy_result_chirho.unwrap_err().to_string();
    assert!(
        busy_error_chirho.contains("no live worker slots"),
        "expected bounded pool overflow, got: {busy_error_chirho}"
    );

    let recovered_chirho = run_framed_counter_chirho(&root_chirho, &spec_hash_chirho, b"again");
    assert!(recovered_chirho.contains("count=2 AGAIN"));

    cairn_chirho::native_worker_chirho::shutdown_native_warm_pool_chirho(
        &root_chirho,
        &spec_hash_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
const NATIVE_WARM_POOL_SMOKE_TIMEOUT_MS_CHIRHO: u64 = 30_000;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn native_warm_pool_hold_paths_chirho(
    hold_token_chirho: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let temp_dir_chirho = std::env::temp_dir();
    (
        temp_dir_chirho.join(format!(
            "cairn-native-warm-pool-hold-ready-{hold_token_chirho}"
        )),
        temp_dir_chirho.join(format!(
            "cairn-native-warm-pool-hold-release-{hold_token_chirho}"
        )),
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn wait_for_native_warm_pool_hold_ready_chirho(hold_ready_path_chirho: &std::path::Path) {
    let deadline_chirho = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !hold_ready_path_chirho.is_file() {
        assert!(
            std::time::Instant::now() < deadline_chirho,
            "native warm-pool hold was not ready before the test deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn native_warm_pool_test_guard_chirho() -> std::sync::MutexGuard<'static, ()> {
    static TEST_LOCK_CHIRHO: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    TEST_LOCK_CHIRHO
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("native warm-pool test lock poisoned")
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn build_framed_counter_spec_chirho(
    root_chirho: &std::path::Path,
    warm_pool_size_chirho: usize,
) -> cairn_chirho::model_chirho::HashChirho {
    build_framed_counter_spec_with_timeout_chirho(
        root_chirho,
        warm_pool_size_chirho,
        NATIVE_WARM_POOL_SMOKE_TIMEOUT_MS_CHIRHO,
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn build_framed_upcase_spec_chirho(
    root_chirho: &std::path::Path,
    warm_pool_size_chirho: usize,
) -> cairn_chirho::model_chirho::HashChirho {
    build_framed_spec_with_timeout_chirho(
        root_chirho,
        "native-framed-upcase-chirho",
        "__native-worker-framed-upcase-child",
        warm_pool_size_chirho,
        NATIVE_WARM_POOL_SMOKE_TIMEOUT_MS_CHIRHO,
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn build_framed_counter_spec_with_timeout_chirho(
    root_chirho: &std::path::Path,
    warm_pool_size_chirho: usize,
    timeout_ms_chirho: u64,
) -> cairn_chirho::model_chirho::HashChirho {
    build_framed_spec_with_timeout_chirho(
        root_chirho,
        "native-framed-counter-chirho",
        "__native-worker-framed-counter-child",
        warm_pool_size_chirho,
        timeout_ms_chirho,
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn build_framed_spec_with_timeout_chirho(
    root_chirho: &std::path::Path,
    name_chirho: &str,
    child_command_chirho: &str,
    warm_pool_size_chirho: usize,
    timeout_ms_chirho: u64,
) -> cairn_chirho::model_chirho::HashChirho {
    let executable_chirho = std::path::PathBuf::from(env!("CARGO_BIN_EXE_cairn-chirho"));
    let (_spec_chirho, spec_hash_chirho) =
        cairn_chirho::native_worker_chirho::build_native_program_with_abi_chirho(
            root_chirho,
            &executable_chirho,
            cairn_chirho::native_worker_chirho::NativeProgramBuildRequestChirho {
                name_chirho: name_chirho.to_string(),
                argv_chirho: vec![child_command_chirho.to_string()],
                sandbox_mode_chirho:
                    cairn_chirho::native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho,
                allowed_syscalls_chirho:
                    cairn_chirho::native_worker_chirho::default_native_syscalls_chirho(),
                capabilities_chirho: Vec::new(),
                timeout_ms_chirho,
                max_memory_bytes_chirho: 256 * 1024 * 1024,
                max_input_bytes_chirho: 1024,
                max_output_bytes_chirho: 1024,
                warm_pool_size_chirho,
            },
            cairn_chirho::native_worker_chirho::native_abi_bytes_stdio_framed_chirho(),
        )
        .unwrap();
    spec_hash_chirho
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run_framed_counter_chirho(
    root_chirho: &std::path::Path,
    spec_hash_chirho: &cairn_chirho::model_chirho::HashChirho,
    input_chirho: &[u8],
) -> String {
    run_framed_worker_chirho(root_chirho, spec_hash_chirho, input_chirho)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run_framed_worker_chirho(
    root_chirho: &std::path::Path,
    spec_hash_chirho: &cairn_chirho::model_chirho::HashChirho,
    input_chirho: &[u8],
) -> String {
    let input_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, input_chirho).unwrap();
    let (result_chirho, hit_chirho) =
        cairn_chirho::native_worker_chirho::run_native_program_cached_chirho(
            root_chirho,
            spec_hash_chirho,
            &input_hash_chirho,
            &[],
        )
        .unwrap();
    assert!(!hit_chirho);
    let trace_chirho =
        cairn_chirho::cas_chirho::get_chirho(root_chirho, &result_chirho.trace_chirho).unwrap();
    assert!(String::from_utf8(trace_chirho)
        .unwrap()
        .contains("pooled=true"));
    let output_hash_chirho = result_chirho.outputs_chirho.get("out").unwrap();
    String::from_utf8(
        cairn_chirho::cas_chirho::get_chirho(root_chirho, output_hash_chirho).unwrap(),
    )
    .unwrap()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn field_chirho(line_chirho: &str, name_chirho: &str) -> String {
    let prefix_chirho = format!("{name_chirho}=");
    line_chirho
        .split_whitespace()
        .find_map(|part_chirho| part_chirho.strip_prefix(&prefix_chirho))
        .unwrap()
        .to_string()
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-native-warm-pool-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}
