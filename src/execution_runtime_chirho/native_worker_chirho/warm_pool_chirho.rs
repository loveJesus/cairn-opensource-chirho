// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Framed native worker warm-pool runtime.

use super::*;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

struct NativeWarmWorkerSlotChirho {
    child_chirho: Child,
    stdin_chirho: ChildStdin,
    stdout_chirho: ChildStdout,
}

struct NativeWarmPoolRuntimeChirho {
    slots_chirho: Vec<NativeWarmWorkerSlotChirho>,
    checked_out_chirho: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeWarmPoolCreateChirho {
    CreateChirho,
    ExistingOnlyChirho,
}

static NATIVE_WARM_POOLS_CHIRHO: OnceLock<Mutex<BTreeMap<String, NativeWarmPoolRuntimeChirho>>> =
    OnceLock::new();

pub fn prewarm_native_program_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
) -> Result<NativeWarmPoolChirho> {
    let spec_obj_chirho = load_native_program_chirho(root_chirho, spec_chirho)?;
    let executable_path_chirho =
        materialize_native_executable_chirho(root_chirho, spec_chirho, &spec_obj_chirho)?;
    let warm_slots_chirho = if spec_obj_chirho.abi_chirho == NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO {
        ensure_native_warm_pool_chirho(root_chirho, spec_chirho, &spec_obj_chirho)?
    } else {
        spec_obj_chirho.warm_pool_size_chirho
    };
    Ok(NativeWarmPoolChirho {
        spec_chirho: spec_chirho.clone(),
        executable_chirho: spec_obj_chirho.executable_chirho.clone(),
        materialized_executable_chirho: executable_path_chirho.display().to_string(),
        warm_slots_chirho,
        sandbox_chirho: sandbox_status_chirho(&spec_obj_chirho),
    })
}

pub fn shutdown_native_warm_pool_chirho(root_chirho: &Path, spec_chirho: &HashChirho) {
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let Some(pools_chirho) = NATIVE_WARM_POOLS_CHIRHO.get() else {
        return;
    };
    let Ok(mut pools_chirho) = pools_chirho.lock() else {
        return;
    };
    if let Some(mut pool_chirho) = pools_chirho.remove(&key_chirho) {
        for mut slot_chirho in pool_chirho.slots_chirho.drain(..) {
            let _ = slot_chirho.child_chirho.kill();
            let _ = slot_chirho.child_chirho.wait();
        }
    }
}

pub(super) fn run_native_stateless_probe_once_chirho(
    executable_path_chirho: &Path,
    spec_obj_chirho: &NativeProgramSpecChirho,
    probe_input_chirho: &[u8],
    timeout_chirho: Duration,
) -> Result<Vec<u8>> {
    let slot_chirho =
        spawn_native_warm_worker_slot_chirho(executable_path_chirho, spec_obj_chirho)?;
    let (slot_chirho, result_chirho) = run_native_framed_request_with_timeout_chirho(
        slot_chirho,
        probe_input_chirho.to_vec(),
        spec_obj_chirho.max_output_bytes_chirho,
        timeout_chirho,
    );
    if let Some(mut slot_chirho) = slot_chirho {
        let _ = slot_chirho.child_chirho.kill();
        let _ = slot_chirho.child_chirho.wait();
    }
    result_chirho
}

pub(super) fn run_native_stateless_probe_reused_chirho(
    executable_path_chirho: &Path,
    spec_obj_chirho: &NativeProgramSpecChirho,
    probe_input_chirho: &[u8],
    timeout_chirho: Duration,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let slot_chirho =
        spawn_native_warm_worker_slot_chirho(executable_path_chirho, spec_obj_chirho)?;
    let (slot_chirho, first_chirho) = run_native_framed_request_with_timeout_chirho(
        slot_chirho,
        probe_input_chirho.to_vec(),
        spec_obj_chirho.max_output_bytes_chirho,
        timeout_chirho,
    );
    let first_chirho = match first_chirho {
        Ok(first_chirho) => first_chirho,
        Err(error_chirho) => {
            if let Some(mut slot_chirho) = slot_chirho {
                let _ = slot_chirho.child_chirho.kill();
                let _ = slot_chirho.child_chirho.wait();
            }
            return Err(error_chirho);
        }
    };
    let slot_chirho = slot_chirho
        .ok_or_else(|| anyhow!("native stateless probe lost worker after first request"))?;
    let (slot_chirho, second_chirho) = run_native_framed_request_with_timeout_chirho(
        slot_chirho,
        probe_input_chirho.to_vec(),
        spec_obj_chirho.max_output_bytes_chirho,
        timeout_chirho,
    );
    match (slot_chirho, second_chirho) {
        (Some(mut slot_chirho), Ok(second_chirho)) => {
            let _ = slot_chirho.child_chirho.kill();
            let _ = slot_chirho.child_chirho.wait();
            Ok((first_chirho, second_chirho))
        }
        (Some(mut slot_chirho), Err(error_chirho)) => {
            let _ = slot_chirho.child_chirho.kill();
            let _ = slot_chirho.child_chirho.wait();
            Err(error_chirho)
        }
        (None, Ok(second_chirho)) => Ok((first_chirho, second_chirho)),
        (None, Err(error_chirho)) => Err(error_chirho),
    }
}

pub(super) fn run_native_program_pooled_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
    input_chirho: &[u8],
    sandbox_chirho: NativeSandboxStatusChirho,
) -> Result<NativeRunOutcomeChirho> {
    let started_chirho = Instant::now();
    let slot_chirho =
        take_native_warm_worker_slot_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
    let (slot_chirho, request_chirho) = run_native_framed_request_with_timeout_chirho(
        slot_chirho,
        input_chirho.to_vec(),
        spec_obj_chirho.max_output_bytes_chirho,
        Duration::from_millis(spec_obj_chirho.timeout_ms_chirho),
    );
    match request_chirho {
        Ok(output_chirho) => {
            let slot_chirho = slot_chirho
                .ok_or_else(|| anyhow!("native warm worker slot missing after successful run"))?;
            return_native_warm_worker_slot_chirho(
                root_chirho,
                spec_chirho,
                spec_obj_chirho,
                slot_chirho,
            )?;
            Ok(NativeRunOutcomeChirho {
                output_chirho,
                elapsed_ms_chirho: started_chirho.elapsed().as_millis() as u64,
                sandbox_chirho,
                pooled_chirho: true,
            })
        }
        Err(error_chirho) => {
            let _ = discard_native_warm_worker_slot_chirho(
                root_chirho,
                spec_chirho,
                spec_obj_chirho,
                slot_chirho,
            );
            Err(error_chirho)
        }
    }
}

fn ensure_native_warm_pool_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<usize> {
    ensure_native_warm_pool_with_mode_chirho(
        root_chirho,
        spec_chirho,
        spec_obj_chirho,
        NativeWarmPoolCreateChirho::CreateChirho,
    )
}

fn refill_existing_native_warm_pool_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<usize> {
    ensure_native_warm_pool_with_mode_chirho(
        root_chirho,
        spec_chirho,
        spec_obj_chirho,
        NativeWarmPoolCreateChirho::ExistingOnlyChirho,
    )
}

fn ensure_native_warm_pool_with_mode_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
    create_chirho: NativeWarmPoolCreateChirho,
) -> Result<usize> {
    validate_native_program_chirho(spec_obj_chirho)?;
    if spec_obj_chirho.abi_chirho != NATIVE_ABI_BYTES_STDIO_FRAMED_CHIRHO {
        return Ok(spec_obj_chirho.warm_pool_size_chirho);
    }
    if !spec_obj_chirho.capabilities_chirho.is_empty() {
        bail!("native warm pools are only for pure framed native executables");
    }
    let sandbox_chirho = sandbox_status_chirho(spec_obj_chirho);
    if matches!(
        spec_obj_chirho.sandbox_mode_chirho,
        NativeSandboxModeChirho::RequiredSeccompChirho
    ) && !sandbox_chirho.seccomp_enforced_chirho
    {
        bail!(
            "native worker requires seccomp but this platform cannot enforce it: {}",
            sandbox_chirho.reason_chirho
        );
    }
    let executable_path_chirho =
        materialize_native_executable_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
    let target_chirho = native_warm_pool_target_size_chirho(spec_obj_chirho);
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let pools_chirho = NATIVE_WARM_POOLS_CHIRHO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut pools_chirho = pools_chirho
        .lock()
        .map_err(|_| anyhow!("native warm pool lock poisoned"))?;
    let Some(pool_chirho) =
        native_warm_pool_for_key_chirho(&mut pools_chirho, key_chirho, create_chirho)
    else {
        return Ok(0);
    };
    let mut live_slots_chirho = Vec::new();
    for mut slot_chirho in pool_chirho.slots_chirho.drain(..) {
        if slot_chirho
            .child_chirho
            .try_wait()
            .context("poll native warm worker")?
            .is_none()
        {
            live_slots_chirho.push(slot_chirho);
        }
    }
    pool_chirho.slots_chirho = live_slots_chirho;
    while pool_chirho.slots_chirho.len() + pool_chirho.checked_out_chirho < target_chirho {
        pool_chirho
            .slots_chirho
            .push(spawn_native_warm_worker_slot_chirho(
                &executable_path_chirho,
                spec_obj_chirho,
            )?);
    }
    Ok(pool_chirho.slots_chirho.len())
}

fn native_warm_pool_for_key_chirho(
    pools_chirho: &mut BTreeMap<String, NativeWarmPoolRuntimeChirho>,
    key_chirho: String,
    create_chirho: NativeWarmPoolCreateChirho,
) -> Option<&mut NativeWarmPoolRuntimeChirho> {
    match create_chirho {
        NativeWarmPoolCreateChirho::CreateChirho => Some(
            pools_chirho
                .entry(key_chirho)
                .or_insert_with(empty_native_warm_pool_runtime_chirho),
        ),
        NativeWarmPoolCreateChirho::ExistingOnlyChirho => pools_chirho.get_mut(&key_chirho),
    }
}

fn decrement_existing_native_warm_pool_checkout_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
) -> Result<bool> {
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let pools_chirho = NATIVE_WARM_POOLS_CHIRHO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut pools_chirho = pools_chirho
        .lock()
        .map_err(|_| anyhow!("native warm pool lock poisoned"))?;
    let Some(pool_chirho) = native_warm_pool_for_key_chirho(
        &mut pools_chirho,
        key_chirho,
        NativeWarmPoolCreateChirho::ExistingOnlyChirho,
    ) else {
        return Ok(false);
    };
    pool_chirho.checked_out_chirho = pool_chirho.checked_out_chirho.saturating_sub(1);
    Ok(true)
}

fn take_native_warm_worker_slot_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<NativeWarmWorkerSlotChirho> {
    ensure_native_warm_pool_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let pools_chirho = NATIVE_WARM_POOLS_CHIRHO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut pools_chirho = pools_chirho
        .lock()
        .map_err(|_| anyhow!("native warm pool lock poisoned"))?;
    let pool_chirho = pools_chirho
        .get_mut(&key_chirho)
        .ok_or_else(|| anyhow!("native warm pool missing after prewarm"))?;
    let slot_chirho = pool_chirho
        .slots_chirho
        .pop()
        .ok_or_else(|| anyhow!("native warm pool has no live worker slots"))?;
    pool_chirho.checked_out_chirho += 1;
    Ok(slot_chirho)
}

fn return_native_warm_worker_slot_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
    mut slot_chirho: NativeWarmWorkerSlotChirho,
) -> Result<()> {
    let returned_worker_exited_chirho = slot_chirho
        .child_chirho
        .try_wait()
        .context("poll returned native warm worker")?
        .is_some();
    if returned_worker_exited_chirho {
        if decrement_existing_native_warm_pool_checkout_chirho(root_chirho, spec_chirho)? {
            refill_existing_native_warm_pool_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
        }
        return Ok(());
    }
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let pools_chirho = NATIVE_WARM_POOLS_CHIRHO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut pools_chirho = pools_chirho
        .lock()
        .map_err(|_| anyhow!("native warm pool lock poisoned"))?;
    let Some(pool_chirho) = native_warm_pool_for_key_chirho(
        &mut pools_chirho,
        key_chirho,
        NativeWarmPoolCreateChirho::ExistingOnlyChirho,
    ) else {
        let _ = slot_chirho.child_chirho.kill();
        let _ = slot_chirho.child_chirho.wait();
        return Ok(());
    };
    pool_chirho.checked_out_chirho = pool_chirho.checked_out_chirho.saturating_sub(1);
    if pool_chirho.slots_chirho.len() + pool_chirho.checked_out_chirho
        < native_warm_pool_target_size_chirho(spec_obj_chirho)
    {
        pool_chirho.slots_chirho.push(slot_chirho);
    } else {
        let _ = slot_chirho.child_chirho.kill();
        let _ = slot_chirho.child_chirho.wait();
    }
    Ok(())
}

fn discard_native_warm_worker_slot_chirho(
    root_chirho: &Path,
    spec_chirho: &HashChirho,
    spec_obj_chirho: &NativeProgramSpecChirho,
    slot_chirho: Option<NativeWarmWorkerSlotChirho>,
) -> Result<()> {
    if let Some(mut slot_chirho) = slot_chirho {
        let _ = slot_chirho.child_chirho.kill();
        let _ = slot_chirho.child_chirho.wait();
    }
    let key_chirho = native_warm_pool_key_chirho(root_chirho, spec_chirho);
    let pools_chirho = NATIVE_WARM_POOLS_CHIRHO.get_or_init(|| Mutex::new(BTreeMap::new()));
    let pool_existed_chirho = {
        let mut pools_chirho = pools_chirho
            .lock()
            .map_err(|_| anyhow!("native warm pool lock poisoned"))?;
        if let Some(pool_chirho) = native_warm_pool_for_key_chirho(
            &mut pools_chirho,
            key_chirho,
            NativeWarmPoolCreateChirho::ExistingOnlyChirho,
        ) {
            pool_chirho.checked_out_chirho = pool_chirho.checked_out_chirho.saturating_sub(1);
            true
        } else {
            false
        }
    };
    if pool_existed_chirho {
        refill_existing_native_warm_pool_chirho(root_chirho, spec_chirho, spec_obj_chirho)?;
    }
    Ok(())
}

fn spawn_native_warm_worker_slot_chirho(
    executable_path_chirho: &Path,
    spec_obj_chirho: &NativeProgramSpecChirho,
) -> Result<NativeWarmWorkerSlotChirho> {
    let mut command_chirho = Command::new(executable_path_chirho);
    command_chirho
        .args(&spec_obj_chirho.argv_chirho)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    apply_pre_exec_sandbox_chirho(&mut command_chirho, spec_obj_chirho)?;
    let mut child_chirho = command_chirho.spawn().context("spawn native warm worker")?;
    let stdin_chirho = child_chirho
        .stdin
        .take()
        .ok_or_else(|| anyhow!("native warm worker stdin was not captured"))?;
    let stdout_chirho = child_chirho
        .stdout
        .take()
        .ok_or_else(|| anyhow!("native warm worker stdout was not captured"))?;
    Ok(NativeWarmWorkerSlotChirho {
        child_chirho,
        stdin_chirho,
        stdout_chirho,
    })
}

fn empty_native_warm_pool_runtime_chirho() -> NativeWarmPoolRuntimeChirho {
    NativeWarmPoolRuntimeChirho {
        slots_chirho: Vec::new(),
        checked_out_chirho: 0,
    }
}

fn run_native_framed_request_chirho(
    slot_chirho: &mut NativeWarmWorkerSlotChirho,
    input_chirho: &[u8],
    max_output_bytes_chirho: usize,
) -> Result<Vec<u8>> {
    let input_len_chirho = u32::try_from(input_chirho.len())
        .map_err(|_| anyhow!("native framed input is too large"))?;
    slot_chirho
        .stdin_chirho
        .write_all(&input_len_chirho.to_be_bytes())
        .context("write native framed request length")?;
    slot_chirho
        .stdin_chirho
        .write_all(input_chirho)
        .context("write native framed request body")?;
    slot_chirho
        .stdin_chirho
        .flush()
        .context("flush native framed request")?;
    let mut output_len_bytes_chirho = [0u8; 4];
    slot_chirho
        .stdout_chirho
        .read_exact(&mut output_len_bytes_chirho)
        .context("read native framed response length")?;
    let output_len_chirho = u32::from_be_bytes(output_len_bytes_chirho) as usize;
    if output_len_chirho > max_output_bytes_chirho {
        bail!(
            "native warm worker output has {} bytes, over max {}",
            output_len_chirho,
            max_output_bytes_chirho
        );
    }
    let mut output_chirho = vec![0u8; output_len_chirho];
    slot_chirho
        .stdout_chirho
        .read_exact(&mut output_chirho)
        .context("read native framed response body")?;
    Ok(output_chirho)
}

fn run_native_framed_request_with_timeout_chirho(
    mut slot_chirho: NativeWarmWorkerSlotChirho,
    input_chirho: Vec<u8>,
    max_output_bytes_chirho: usize,
    timeout_chirho: Duration,
) -> (Option<NativeWarmWorkerSlotChirho>, Result<Vec<u8>>) {
    let child_id_chirho = slot_chirho.child_chirho.id();
    let (sender_chirho, receiver_chirho) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let result_chirho = run_native_framed_request_chirho(
            &mut slot_chirho,
            &input_chirho,
            max_output_bytes_chirho,
        );
        let _ = sender_chirho.send((slot_chirho, result_chirho));
    });
    match receiver_chirho.recv_timeout(timeout_chirho) {
        Ok((slot_chirho, result_chirho)) => (Some(slot_chirho), result_chirho),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            kill_native_process_by_id_chirho(child_id_chirho);
            match receiver_chirho.recv_timeout(Duration::from_secs(1)) {
                Ok((slot_chirho, _result_chirho)) => (
                    Some(slot_chirho),
                    Err(anyhow!(
                        "native warm worker timed out after {} ms",
                        timeout_chirho.as_millis()
                    )),
                ),
                Err(_error_chirho) => (
                    {
                        reap_native_process_by_id_chirho(child_id_chirho);
                        None
                    },
                    Err(anyhow!(
                        "native warm worker timed out after {} ms and did not shut down",
                        timeout_chirho.as_millis()
                    )),
                ),
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => (
            None,
            Err(anyhow!("native warm worker request thread disconnected")),
        ),
    }
}

fn kill_native_process_by_id_chirho(child_id_chirho: u32) {
    #[cfg(unix)]
    unsafe {
        let _ = libc::kill(child_id_chirho as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(not(unix))]
    {
        let _ = child_id_chirho;
    }
}

fn reap_native_process_by_id_chirho(child_id_chirho: u32) {
    #[cfg(unix)]
    unsafe {
        let mut status_chirho = 0;
        let _ = libc::waitpid(
            child_id_chirho as libc::pid_t,
            &mut status_chirho,
            libc::WNOHANG,
        );
    }
    #[cfg(not(unix))]
    {
        let _ = child_id_chirho;
    }
}

fn native_warm_pool_target_size_chirho(spec_obj_chirho: &NativeProgramSpecChirho) -> usize {
    spec_obj_chirho.warm_pool_size_chirho.max(1)
}

fn native_warm_pool_key_chirho(root_chirho: &Path, spec_chirho: &HashChirho) -> String {
    format!("{}::{}", root_chirho.display(), spec_chirho.0)
}
