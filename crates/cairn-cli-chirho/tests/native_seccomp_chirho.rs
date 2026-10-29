// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

#[test]
fn linux_seccomp_disallowed_syscall_smoke_chirho() {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("skipping Linux x86_64 seccomp smoke on this platform");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        run_linux_seccomp_disallowed_syscall_smoke_chirho();
    }
}

#[test]
fn linux_seccomp_static_framed_worker_beats_wasm_chirho() {
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        eprintln!("skipping Linux x86_64 static framed-worker seccomp benchmark on this platform");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        run_linux_seccomp_static_framed_worker_beats_wasm_chirho();
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux_seccomp_disallowed_syscall_smoke_chirho() {
    use cairn_chirho::{cas_chirho, native_worker_chirho};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-native-seccomp-test-{nanos_chirho}-{n_chirho}"
    ));
    let executable_chirho = PathBuf::from(env!("CARGO_BIN_EXE_cairn-chirho"));

    let (spec_chirho, spec_hash_chirho) = native_worker_chirho::build_native_program_chirho(
        &root_chirho,
        &executable_chirho,
        native_worker_chirho::NativeProgramBuildRequestChirho {
            name_chirho: "native-seccomp-smoke-chirho".to_string(),
            argv_chirho: vec!["__native-worker-forbidden-syscall-child".to_string()],
            sandbox_mode_chirho:
                native_worker_chirho::NativeSandboxModeChirho::RequiredSeccompChirho,
            allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
            capabilities_chirho: Vec::new(),
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 256 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 0,
        },
    )
    .unwrap();
    assert!(
        native_worker_chirho::sandbox_status_chirho(&spec_chirho).seccomp_enforced_chirho,
        "Linux x86_64 smoke must run only when seccomp-bpf is available"
    );

    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"").unwrap();
    let error_chirho = native_worker_chirho::run_native_program_cached_chirho(
        &root_chirho,
        &spec_hash_chirho,
        &input_hash_chirho,
        &[],
    )
    .unwrap_err()
    .to_string();

    assert!(
        error_chirho.contains("killed by signal"),
        "expected seccomp to kill the worker, got: {error_chirho}"
    );
    assert!(
        error_chirho.contains("31") || error_chirho.contains("SIGSYS"),
        "expected SIGSYS/seccomp signal detail, got: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_linux_seccomp_static_framed_worker_beats_wasm_chirho() {
    use cairn_chirho::{native_worker_chirho, runner_chirho};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-native-static-seccomp-test-{nanos_chirho}-{n_chirho}"
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    let worker_chirho = compile_static_framed_hot_loop_worker_chirho(&root_chirho);

    let iterations_chirho = 2_000_000_u64;
    let expected_chirho = native_hot_loop_for_test_chirho(iterations_chirho);
    let wasm_started_chirho = Instant::now();
    let wasm_chirho = runner_chirho::run_node_chirho(
        HOT_LOOP_WAT_FOR_TEST_CHIRHO.as_bytes(),
        "hot_loop_chirho",
        iterations_chirho as i64,
        iterations_chirho
            .saturating_mul(128)
            .saturating_add(1_000_000),
    )
    .unwrap();
    let wasm_elapsed_us_chirho = wasm_started_chirho.elapsed().as_micros() as u64;
    assert_eq!(wasm_chirho.result_chirho as u64, expected_chirho);

    let (spec_chirho, spec_hash_chirho) =
        native_worker_chirho::build_native_program_with_abi_chirho(
            &root_chirho,
            &worker_chirho,
            native_worker_chirho::NativeProgramBuildRequestChirho {
                name_chirho: "native-static-framed-hot-loop-chirho".to_string(),
                argv_chirho: Vec::new(),
                sandbox_mode_chirho:
                    native_worker_chirho::NativeSandboxModeChirho::RequiredSeccompChirho,
                allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
                capabilities_chirho: Vec::new(),
                timeout_ms_chirho: 5_000,
                max_memory_bytes_chirho: 64 * 1024 * 1024,
                max_input_bytes_chirho: 64,
                max_output_bytes_chirho: 64,
                warm_pool_size_chirho: 1,
            },
            native_worker_chirho::native_abi_bytes_stdio_framed_chirho(),
        )
        .unwrap();
    let warm_chirho =
        native_worker_chirho::prewarm_native_program_chirho(&root_chirho, &spec_hash_chirho)
            .unwrap();
    assert_eq!(warm_chirho.warm_slots_chirho, 1);
    assert!(warm_chirho.sandbox_chirho.seccomp_enforced_chirho);

    let input_chirho = iterations_chirho.to_string().into_bytes();
    let native_started_chirho = Instant::now();
    for _ in 0..3 {
        let outcome_chirho = native_worker_chirho::run_native_program_uncached_chirho(
            &root_chirho,
            &spec_hash_chirho,
            &spec_chirho,
            &input_chirho,
        )
        .unwrap();
        assert!(outcome_chirho.sandbox_chirho.seccomp_enforced_chirho);
        assert!(outcome_chirho.pooled_chirho);
        assert_eq!(
            String::from_utf8(outcome_chirho.output_chirho)
                .unwrap()
                .trim()
                .parse::<u64>()
                .unwrap(),
            expected_chirho
        );
    }
    let native_elapsed_us_chirho = native_started_chirho.elapsed().as_micros() as u64;
    native_worker_chirho::shutdown_native_warm_pool_chirho(&root_chirho, &spec_hash_chirho);

    eprintln!(
        "static RequiredSeccomp native benchmark: native={native_elapsed_us_chirho}us wasm={wasm_elapsed_us_chirho}us"
    );
    assert!(
        native_elapsed_us_chirho < wasm_elapsed_us_chirho,
        "expected static RequiredSeccomp native worker to beat WASM; native={native_elapsed_us_chirho}us wasm={wasm_elapsed_us_chirho}us"
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn compile_static_framed_hot_loop_worker_chirho(
    root_chirho: &std::path::Path,
) -> std::path::PathBuf {
    let source_chirho = root_chirho.join("static-framed-hot-loop-chirho.c");
    let worker_chirho = root_chirho.join("static-framed-hot-loop-chirho");
    std::fs::write(&source_chirho, STATIC_FRAMED_HOT_LOOP_C_CHIRHO).unwrap();
    let cc_chirho = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let output_chirho = std::process::Command::new(cc_chirho)
        .args([
            "-O2",
            "-static",
            "-nostdlib",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
        ])
        .arg("-o")
        .arg(&worker_chirho)
        .arg(&source_chirho)
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "static worker compile failed: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    worker_chirho
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn native_hot_loop_for_test_chirho(iterations_chirho: u64) -> u64 {
    let mut acc_chirho = 1_469_598_103_934_665_603u64;
    let mut i_chirho = 0u64;
    while i_chirho < iterations_chirho {
        let x_chirho = acc_chirho ^ i_chirho.wrapping_mul(6_364_136_223_846_793_005u64);
        let product_chirho = (x_chirho as u128).wrapping_mul(1_442_695_040_888_963_407u128);
        acc_chirho =
            (product_chirho as u64) ^ ((product_chirho >> 64) as u64) ^ x_chirho.rotate_left(17);
        i_chirho += 1;
    }
    acc_chirho
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const HOT_LOOP_WAT_FOR_TEST_CHIRHO: &str = r#"
    (module
      (func $mul_hi_u64_chirho (param $a i64) (param $b i64) (result i64)
        (local $mask i64)
        (local $a_lo i64)
        (local $a_hi i64)
        (local $b_lo i64)
        (local $b_hi i64)
        (local $p0 i64)
        (local $p1 i64)
        (local $p2 i64)
        (local $p3 i64)
        (local $carry i64)
        i64.const 4294967295
        local.set $mask
        local.get $a
        local.get $mask
        i64.and
        local.set $a_lo
        local.get $a
        i64.const 32
        i64.shr_u
        local.set $a_hi
        local.get $b
        local.get $mask
        i64.and
        local.set $b_lo
        local.get $b
        i64.const 32
        i64.shr_u
        local.set $b_hi
        local.get $a_lo
        local.get $b_lo
        i64.mul
        local.set $p0
        local.get $a_lo
        local.get $b_hi
        i64.mul
        local.set $p1
        local.get $a_hi
        local.get $b_lo
        i64.mul
        local.set $p2
        local.get $a_hi
        local.get $b_hi
        i64.mul
        local.set $p3
        local.get $p0
        i64.const 32
        i64.shr_u
        local.get $p1
        local.get $mask
        i64.and
        i64.add
        local.get $p2
        local.get $mask
        i64.and
        i64.add
        i64.const 32
        i64.shr_u
        local.set $carry
        local.get $p3
        local.get $p1
        i64.const 32
        i64.shr_u
        i64.add
        local.get $p2
        i64.const 32
        i64.shr_u
        i64.add
        local.get $carry
        i64.add)
      (func (export "hot_loop_chirho") (param $n i64) (result i64)
        (local $i i64)
        (local $acc i64)
        (local $x i64)
        (local $lo i64)
        (local $hi i64)
        i64.const 1469598103934665603
        local.set $acc
        loop $loop
          local.get $i
          local.get $n
          i64.lt_u
          if
            local.get $acc
            local.get $i
            i64.const 6364136223846793005
            i64.mul
            i64.xor
            local.set $x
            local.get $x
            i64.const 1442695040888963407
            i64.mul
            local.set $lo
            local.get $x
            i64.const 1442695040888963407
            call $mul_hi_u64_chirho
            local.set $hi
            local.get $lo
            local.get $hi
            i64.xor
            local.get $x
            i64.const 17
            i64.rotl
            i64.xor
            local.set $acc
            local.get $i
            i64.const 1
            i64.add
            local.set $i
            br $loop
          end
        end
        local.get $acc))
"#;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const STATIC_FRAMED_HOT_LOOP_C_CHIRHO: &str = r#"/* For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16 */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned long usize;

static long syscall3_chirho(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}

static void exit_chirho(int code) {
    syscall3_chirho(60, code, 0, 0);
    for (;;) {}
}

static long read_exact_chirho(unsigned char *buf, usize len) {
    usize done = 0;
    while (done < len) {
        long r = syscall3_chirho(0, 0, (long)(buf + done), (long)(len - done));
        if (r == 0) {
            return done == 0 ? 0 : -1;
        }
        if (r < 0) {
            return -1;
        }
        done += (usize)r;
    }
    return 1;
}

static void write_all_chirho(const unsigned char *buf, usize len) {
    usize done = 0;
    while (done < len) {
        long r = syscall3_chirho(1, 1, (long)(buf + done), (long)(len - done));
        if (r <= 0) {
            exit_chirho(5);
        }
        done += (usize)r;
    }
}

static u64 parse_u64_chirho(const unsigned char *buf, usize len) {
    u64 value = 0;
    for (usize i = 0; i < len; i++) {
        unsigned char ch = buf[i];
        if (ch >= '0' && ch <= '9') {
            value = value * 10 + (u64)(ch - '0');
        }
    }
    return value;
}

static u64 hot_loop_chirho(u64 iterations) {
    u64 acc = 1469598103934665603ULL;
    for (u64 i = 0; i < iterations; i++) {
        u64 x = acc ^ (i * 6364136223846793005ULL);
        unsigned __int128 product = ((unsigned __int128)x) * 1442695040888963407ULL;
        acc = (u64)product ^ (u64)(product >> 64) ^ ((x << 17) | (x >> (64 - 17)));
    }
    return acc;
}

static u32 decimal_chirho(u64 value, unsigned char *out) {
    unsigned char reversed[32];
    u32 len = 0;
    if (value == 0) {
        out[0] = '0';
        return 1;
    }
    while (value > 0) {
        reversed[len++] = (unsigned char)('0' + (value % 10));
        value /= 10;
    }
    for (u32 i = 0; i < len; i++) {
        out[i] = reversed[len - 1 - i];
    }
    return len;
}

void _start(void) {
    for (;;) {
        unsigned char len_buf[4];
        long status = read_exact_chirho(len_buf, 4);
        if (status == 0) {
            exit_chirho(0);
        }
        if (status < 0) {
            exit_chirho(2);
        }
        u32 len = ((u32)len_buf[0] << 24) | ((u32)len_buf[1] << 16) | ((u32)len_buf[2] << 8) | (u32)len_buf[3];
        if (len > 63) {
            exit_chirho(3);
        }
        unsigned char input[64];
        if (read_exact_chirho(input, len) != 1) {
            exit_chirho(4);
        }
        unsigned char output[32];
        u32 out_len = decimal_chirho(hot_loop_chirho(parse_u64_chirho(input, len)), output);
        unsigned char out_len_buf[4] = {
            (unsigned char)(out_len >> 24),
            (unsigned char)(out_len >> 16),
            (unsigned char)(out_len >> 8),
            (unsigned char)out_len
        };
        write_all_chirho(out_len_buf, 4);
        write_all_chirho(output, out_len);
    }
}
"#;
