// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Native worker CLI command helpers split out of dispatch_chirho.rs.

use crate::args_chirho::CommandChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{capability_spec_chirho, cas_chirho, native_worker_chirho, runner_chirho};
use std::path::Path;

const HOT_LOOP_WAT_CHIRHO: &str = r#"
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

fn native_hot_loop_chirho(iterations_chirho: u64) -> u64 {
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

fn native_hot_path_benchmark_chirho(
    root_chirho: &Path,
    iterations_chirho: u64,
    samples_chirho: usize,
    timeout_ms_chirho: u64,
    allow_unsupported_sandbox_chirho: bool,
    assert_native_faster_chirho: bool,
) -> anyhow::Result<serde_json::Value> {
    if samples_chirho == 0 {
        anyhow::bail!("native-bench requires --samples > 0");
    }
    let wasm_input_chirho = i64::try_from(iterations_chirho)
        .map_err(|_| anyhow::anyhow!("--iterations is too large for the scalar WASM ABI"))?;
    let wasm_fuel_limit_chirho = iterations_chirho
        .saturating_mul(128)
        .saturating_add(1_000_000);
    let expected_result_chirho = native_hot_loop_chirho(iterations_chirho);

    let wasm_started_chirho = std::time::Instant::now();
    let mut wasm_result_chirho = None;
    let mut wasm_fuel_used_chirho = 0u64;
    for _ in 0..samples_chirho {
        let outcome_chirho = runner_chirho::run_node_chirho(
            HOT_LOOP_WAT_CHIRHO.as_bytes(),
            "hot_loop_chirho",
            wasm_input_chirho,
            wasm_fuel_limit_chirho,
        )?;
        let result_chirho = outcome_chirho.result_chirho as u64;
        if result_chirho != expected_result_chirho {
            anyhow::bail!(
                "WASM hot-loop result mismatch: expected {}, got {}",
                expected_result_chirho,
                result_chirho
            );
        }
        wasm_result_chirho = Some(result_chirho);
        wasm_fuel_used_chirho =
            wasm_fuel_used_chirho.saturating_add(outcome_chirho.fuel_used_chirho);
    }
    let wasm_elapsed_us_chirho = wasm_started_chirho.elapsed().as_micros() as u64;

    let sandbox_mode_chirho = if allow_unsupported_sandbox_chirho {
        native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho
    } else {
        native_worker_chirho::NativeSandboxModeChirho::RequiredSeccompChirho
    };
    let executable_chirho = std::env::current_exe()?;
    let (spec_obj_chirho, spec_hash_chirho) =
        native_worker_chirho::build_native_program_with_abi_chirho(
            root_chirho,
            &executable_chirho,
            native_worker_chirho::NativeProgramBuildRequestChirho {
                name_chirho: "native-hot-loop-bench-chirho".to_string(),
                argv_chirho: vec!["__native-worker-framed-hot-loop-child".to_string()],
                sandbox_mode_chirho: sandbox_mode_chirho.clone(),
                allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
                capabilities_chirho: Vec::new(),
                timeout_ms_chirho,
                max_memory_bytes_chirho: 256 * 1024 * 1024,
                max_input_bytes_chirho: 64,
                max_output_bytes_chirho: 64,
                warm_pool_size_chirho: 1,
            },
            native_worker_chirho::native_abi_bytes_stdio_framed_chirho(),
        )?;
    let warm_chirho =
        native_worker_chirho::prewarm_native_program_chirho(root_chirho, &spec_hash_chirho)?;
    let native_input_chirho = iterations_chirho.to_string().into_bytes();
    let native_started_chirho = std::time::Instant::now();
    let mut native_result_chirho = None;
    for _ in 0..samples_chirho {
        let outcome_chirho = native_worker_chirho::run_native_program_uncached_chirho(
            root_chirho,
            &spec_hash_chirho,
            &spec_obj_chirho,
            &native_input_chirho,
        )?;
        let output_text_chirho = String::from_utf8(outcome_chirho.output_chirho)?;
        let result_chirho = output_text_chirho.trim().parse::<u64>()?;
        if result_chirho != expected_result_chirho {
            anyhow::bail!(
                "native hot-loop result mismatch: expected {}, got {}",
                expected_result_chirho,
                result_chirho
            );
        }
        native_result_chirho = Some(result_chirho);
    }
    let native_elapsed_us_chirho = native_started_chirho.elapsed().as_micros() as u64;
    native_worker_chirho::shutdown_native_warm_pool_chirho(root_chirho, &spec_hash_chirho);

    let native_faster_chirho = native_elapsed_us_chirho < wasm_elapsed_us_chirho;
    if assert_native_faster_chirho && !native_faster_chirho {
        anyhow::bail!(
            "native hot path did not beat WASM: native={}us wasm={}us",
            native_elapsed_us_chirho,
            wasm_elapsed_us_chirho
        );
    }
    let speedup_chirho = if native_elapsed_us_chirho > 0 {
        Some(wasm_elapsed_us_chirho as f64 / native_elapsed_us_chirho as f64)
    } else {
        None
    };

    Ok(serde_json::json!({
        "iterations_chirho": iterations_chirho,
        "samples_chirho": samples_chirho,
        "timeout_ms_chirho": timeout_ms_chirho,
        "sandbox_mode_chirho": format!("{:?}", sandbox_mode_chirho),
        "native_path_chirho": "run_native_program_uncached_chirho",
        "warm_slots_chirho": warm_chirho.warm_slots_chirho,
        "wasm_elapsed_us_chirho": wasm_elapsed_us_chirho,
        "native_elapsed_us_chirho": native_elapsed_us_chirho,
        "native_faster_chirho": native_faster_chirho,
        "speedup_chirho": speedup_chirho,
        "wasm_fuel_used_chirho": wasm_fuel_used_chirho,
        "wasm_result_chirho": wasm_result_chirho.unwrap_or(expected_result_chirho).to_string(),
        "native_result_chirho": native_result_chirho.unwrap_or(expected_result_chirho).to_string(),
    }))
}

pub(crate) fn handle_native_command_chirho(
    root_chirho: &Path,
    command_chirho: CommandChirho,
) -> anyhow::Result<Option<CommandChirho>> {
    match command_chirho {
        CommandChirho::NativeBuildChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::NativeBuildArgsChirho {
                executable_chirho,
                name_chirho,
                argv_chirho,
                abi_chirho,
                syscalls_chirho,
                capabilities_chirho,
                timeout_ms_chirho,
                max_memory_bytes_chirho,
                max_input_bytes_chirho,
                max_output_bytes_chirho,
                warm_pool_size_chirho,
                allow_unsupported_sandbox_chirho,
            } = args_chirho;
            let stem_chirho = executable_chirho
                .file_stem()
                .and_then(|s_chirho| s_chirho.to_str())
                .unwrap_or("native-worker-chirho")
                .to_string();
            let name_chirho = name_chirho.unwrap_or(stem_chirho);
            let sandbox_mode_chirho = if allow_unsupported_sandbox_chirho {
                native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho
            } else {
                native_worker_chirho::NativeSandboxModeChirho::RequiredSeccompChirho
            };
            let capabilities_chirho =
                capability_spec_chirho::parse_capabilities_chirho(&capabilities_chirho)?;
            let (_spec_chirho, spec_hash_chirho) =
                native_worker_chirho::build_native_program_with_abi_chirho(
                    root_chirho,
                    &executable_chirho,
                    native_worker_chirho::NativeProgramBuildRequestChirho {
                        name_chirho,
                        argv_chirho,
                        sandbox_mode_chirho,
                        allowed_syscalls_chirho: syscalls_chirho,
                        capabilities_chirho,
                        timeout_ms_chirho,
                        max_memory_bytes_chirho,
                        max_input_bytes_chirho,
                        max_output_bytes_chirho,
                        warm_pool_size_chirho,
                    },
                    &abi_chirho,
                )?;
            println!("{}", spec_hash_chirho.0);
            Ok(None)
        }
        CommandChirho::NativeShowChirho { spec_chirho } => {
            let spec_obj_chirho = native_worker_chirho::load_native_program_chirho(
                root_chirho,
                &HashChirho(spec_chirho),
            )?;
            println!("{}", serde_json::to_string_pretty(&spec_obj_chirho)?);
            Ok(None)
        }
        CommandChirho::NativeNodeBuildChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::NativeNodeBuildArgsChirho {
                spec_chirho,
                name_chirho,
            } = args_chirho;
            let (_node_chirho, node_hash_chirho) =
                native_worker_chirho::build_native_node_def_chirho(
                    root_chirho,
                    &HashChirho(spec_chirho),
                    name_chirho,
                )?;
            println!("{}", node_hash_chirho.0);
            Ok(None)
        }
        CommandChirho::NativePrewarmChirho { spec_chirho } => {
            let warm_chirho = native_worker_chirho::prewarm_native_program_chirho(
                root_chirho,
                &HashChirho(spec_chirho),
            )?;
            println!("{}", serde_json::to_string_pretty(&warm_chirho)?);
            Ok(None)
        }
        CommandChirho::NativeRunChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::NativeRunArgsChirho {
                spec_chirho,
                input_chirho,
            } = args_chirho;
            let input_hash_chirho = cas_chirho::add_chirho(root_chirho, input_chirho.as_bytes())?;
            let (result_chirho, cached_chirho) =
                native_worker_chirho::run_native_program_cached_chirho(
                    root_chirho,
                    &HashChirho(spec_chirho),
                    &input_hash_chirho,
                    &[],
                )?;
            let output_hash_chirho = result_chirho.outputs_chirho.get("out").cloned();
            let output_utf8_chirho = output_hash_chirho
                .as_ref()
                .and_then(|hash_chirho| cas_chirho::get_chirho(root_chirho, hash_chirho).ok())
                .and_then(|bytes_chirho| String::from_utf8(bytes_chirho).ok());
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "cached_chirho": cached_chirho,
                    "output_hash_chirho": output_hash_chirho,
                    "output_utf8_chirho": output_utf8_chirho,
                    "run_result_chirho": result_chirho,
                }))?
            );
            Ok(None)
        }
        CommandChirho::NativeVerifyChirho { spec_chirho } => {
            let verification_chirho = native_worker_chirho::verify_native_program_chirho(
                root_chirho,
                &HashChirho(spec_chirho),
            )?;
            println!("{}", serde_json::to_string_pretty(&verification_chirho)?);
            Ok(None)
        }
        CommandChirho::NativeStatelessAttestChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::NativeStatelessAttestArgsChirho {
                spec_chirho,
                probe_chirho,
            } = args_chirho;
            let record_chirho = native_worker_chirho::attest_native_program_stateless_chirho(
                root_chirho,
                &HashChirho(spec_chirho),
                probe_chirho.as_bytes(),
            )?;
            println!("{}", serde_json::to_string_pretty(&record_chirho)?);
            Ok(None)
        }
        CommandChirho::NativeStatelessAttestationsChirho => {
            let records_chirho =
                native_worker_chirho::load_native_stateless_attestations_chirho(root_chirho)?;
            if records_chirho.is_empty() {
                println!("(no native stateless attestations)");
            }
            for record_chirho in records_chirho {
                println!(
                    "#{}\tspec={}\tmethod={}\tprobe={}\toutput={}\tsandbox={}\tat_ms={}",
                    record_chirho.seq_chirho,
                    record_chirho.spec_chirho.0,
                    record_chirho.method_chirho,
                    record_chirho.probe_input_chirho.0,
                    record_chirho.fresh_output_chirho.0,
                    record_chirho.sandbox_chirho.seccomp_enforced_chirho,
                    record_chirho.at_ms_chirho
                );
            }
            Ok(None)
        }
        CommandChirho::NativeStatelessVerifyChirho => {
            let count_chirho =
                native_worker_chirho::verify_native_stateless_attestations_chirho(root_chirho)?;
            println!("verified {count_chirho} native stateless attestation(s)");
            Ok(None)
        }
        CommandChirho::NativeBenchChirho(args_chirho) => {
            let crate::args_chirho::core_args_chirho::NativeBenchArgsChirho {
                iterations_chirho,
                samples_chirho,
                timeout_ms_chirho,
                allow_unsupported_sandbox_chirho,
                assert_native_faster_chirho,
            } = args_chirho;
            let report_chirho = native_hot_path_benchmark_chirho(
                root_chirho,
                iterations_chirho,
                samples_chirho,
                timeout_ms_chirho,
                allow_unsupported_sandbox_chirho,
                assert_native_faster_chirho,
            )?;
            println!("{}", serde_json::to_string_pretty(&report_chirho)?);
            Ok(None)
        }
        CommandChirho::NativeWorkerUpcaseChildChirho => {
            use std::io::{Read, Write};
            let mut input_chirho = Vec::new();
            std::io::stdin().read_to_end(&mut input_chirho)?;
            for byte_chirho in &mut input_chirho {
                if byte_chirho.is_ascii_lowercase() {
                    *byte_chirho = byte_chirho.to_ascii_uppercase();
                }
            }
            std::io::stdout().write_all(&input_chirho)?;
            Ok(None)
        }
        CommandChirho::NativeWorkerForbiddenSyscallChildChirho => {
            let _bytes_chirho = std::fs::read("/__cairn_chirho_forbidden_syscall_probe__")?;
            println!("unexpected-forbidden-syscall-success-chirho");
            Ok(None)
        }
        CommandChirho::NativeWorkerFramedCounterChildChirho => {
            use std::io::{ErrorKind, Read, Write};
            let mut stdin_chirho = std::io::stdin();
            let mut stdout_chirho = std::io::stdout();
            let mut count_chirho = 0u64;
            loop {
                let mut input_len_bytes_chirho = [0u8; 4];
                match stdin_chirho.read_exact(&mut input_len_bytes_chirho) {
                    Ok(()) => {}
                    Err(error_chirho) if error_chirho.kind() == ErrorKind::UnexpectedEof => break,
                    Err(error_chirho) => return Err(error_chirho.into()),
                }
                let input_len_chirho = u32::from_be_bytes(input_len_bytes_chirho) as usize;
                let mut input_chirho = vec![0u8; input_len_chirho];
                stdin_chirho.read_exact(&mut input_chirho)?;
                if input_chirho == b"__exit_chirho__" {
                    std::process::exit(42);
                }
                if let Some(hold_token_bytes_chirho) =
                    input_chirho.strip_prefix(b"__hold_chirho__:")
                {
                    let hold_token_chirho = std::str::from_utf8(hold_token_bytes_chirho)?;
                    if hold_token_chirho.is_empty()
                        || hold_token_chirho.len() > 160
                        || !hold_token_chirho.bytes().all(|byte_chirho| {
                            byte_chirho.is_ascii_alphanumeric()
                                || matches!(byte_chirho, b'-' | b'_')
                        })
                    {
                        anyhow::bail!("native warm-pool hold token is invalid");
                    }
                    let hold_ready_path_chirho = std::env::temp_dir().join(format!(
                        "cairn-native-warm-pool-hold-ready-{hold_token_chirho}"
                    ));
                    let hold_release_path_chirho = std::env::temp_dir().join(format!(
                        "cairn-native-warm-pool-hold-release-{hold_token_chirho}"
                    ));
                    std::fs::write(&hold_ready_path_chirho, b"ready-chirho")?;
                    while !hold_release_path_chirho.is_file() {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    input_chirho = b"held-chirho".to_vec();
                }
                if input_chirho == b"__hang_chirho__" {
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                }
                count_chirho += 1;
                for byte_chirho in &mut input_chirho {
                    if byte_chirho.is_ascii_lowercase() {
                        *byte_chirho = byte_chirho.to_ascii_uppercase();
                    }
                }
                let mut output_chirho =
                    format!("pid={} count={} ", std::process::id(), count_chirho).into_bytes();
                output_chirho.extend(input_chirho);
                let output_len_chirho = u32::try_from(output_chirho.len())?;
                stdout_chirho.write_all(&output_len_chirho.to_be_bytes())?;
                stdout_chirho.write_all(&output_chirho)?;
                stdout_chirho.flush()?;
            }
            Ok(None)
        }
        CommandChirho::NativeWorkerFramedUpcaseChildChirho => {
            use std::io::{ErrorKind, Read, Write};
            let mut stdin_chirho = std::io::stdin();
            let mut stdout_chirho = std::io::stdout();
            loop {
                let mut input_len_bytes_chirho = [0u8; 4];
                match stdin_chirho.read_exact(&mut input_len_bytes_chirho) {
                    Ok(()) => {}
                    Err(error_chirho) if error_chirho.kind() == ErrorKind::UnexpectedEof => break,
                    Err(error_chirho) => return Err(error_chirho.into()),
                }
                let input_len_chirho = u32::from_be_bytes(input_len_bytes_chirho) as usize;
                let mut output_chirho = vec![0u8; input_len_chirho];
                stdin_chirho.read_exact(&mut output_chirho)?;
                for byte_chirho in &mut output_chirho {
                    if byte_chirho.is_ascii_lowercase() {
                        *byte_chirho = byte_chirho.to_ascii_uppercase();
                    }
                }
                let output_len_chirho = u32::try_from(output_chirho.len())?;
                stdout_chirho.write_all(&output_len_chirho.to_be_bytes())?;
                stdout_chirho.write_all(&output_chirho)?;
                stdout_chirho.flush()?;
            }
            Ok(None)
        }
        CommandChirho::NativeWorkerFramedRespondExitChildChirho => {
            use std::io::{Read, Write};
            let mut input_len_bytes_chirho = [0u8; 4];
            std::io::stdin().read_exact(&mut input_len_bytes_chirho)?;
            let input_len_chirho = u32::from_be_bytes(input_len_bytes_chirho) as usize;
            let mut input_chirho = vec![0u8; input_len_chirho];
            std::io::stdin().read_exact(&mut input_chirho)?;
            for byte_chirho in &mut input_chirho {
                if byte_chirho.is_ascii_lowercase() {
                    *byte_chirho = byte_chirho.to_ascii_uppercase();
                }
            }
            let mut output_chirho = format!("pid={} once ", std::process::id()).into_bytes();
            output_chirho.extend(input_chirho);
            let output_len_chirho = u32::try_from(output_chirho.len())?;
            std::io::stdout().write_all(&output_len_chirho.to_be_bytes())?;
            std::io::stdout().write_all(&output_chirho)?;
            std::io::stdout().flush()?;
            Ok(None)
        }
        CommandChirho::NativeWorkerFramedHotLoopChildChirho => {
            use std::io::{ErrorKind, Read, Write};
            let mut stdin_chirho = std::io::stdin();
            let mut stdout_chirho = std::io::stdout();
            loop {
                let mut input_len_bytes_chirho = [0u8; 4];
                match stdin_chirho.read_exact(&mut input_len_bytes_chirho) {
                    Ok(()) => {}
                    Err(error_chirho) if error_chirho.kind() == ErrorKind::UnexpectedEof => break,
                    Err(error_chirho) => return Err(error_chirho.into()),
                }
                let input_len_chirho = u32::from_be_bytes(input_len_bytes_chirho) as usize;
                let mut input_chirho = vec![0u8; input_len_chirho];
                stdin_chirho.read_exact(&mut input_chirho)?;
                let input_text_chirho = String::from_utf8(input_chirho)?;
                let iterations_chirho = input_text_chirho.trim().parse::<u64>()?;
                let output_chirho = native_hot_loop_chirho(iterations_chirho)
                    .to_string()
                    .into_bytes();
                let output_len_chirho = u32::try_from(output_chirho.len())?;
                stdout_chirho.write_all(&output_len_chirho.to_be_bytes())?;
                stdout_chirho.write_all(&output_chirho)?;
                stdout_chirho.flush()?;
            }
            Ok(None)
        }
        command_chirho => Ok(Some(command_chirho)),
    }
}
