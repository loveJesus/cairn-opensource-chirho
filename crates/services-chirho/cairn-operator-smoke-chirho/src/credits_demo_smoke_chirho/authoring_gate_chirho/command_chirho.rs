// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Runs the compile-time-selected Cargo executable with fixed deadlines and bounded stream capture.

use anyhow::{bail, Context, Result};
use cairn_chirho::cas_chirho;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const TRUSTED_CARGO_MAX_BYTES_CHIRHO: u64 = 128 * 1024 * 1024;
const CARGO_COMMAND_TIMEOUT_CHIRHO: Duration = Duration::from_secs(180);
const CARGO_COMMAND_CAPTURE_BYTES_CHIRHO: usize = 1024 * 1024;
const STREAM_DRAIN_GRACE_CHIRHO: Duration = Duration::from_secs(2);
const COMMAND_POLL_INTERVAL_CHIRHO: Duration = Duration::from_millis(10);
const MAX_COMMAND_DIAGNOSTIC_BYTES_CHIRHO: usize = 16_384;
const COMPILE_TIME_CARGO_PATH_CHIRHO: &str = match option_env!("CAIRN_TRUSTED_CARGO_PATH_CHIRHO") {
    Some(path_chirho) => path_chirho,
    None => env!("CARGO"),
};

#[derive(Clone, Debug)]
pub(super) struct TrustedCargoChirho {
    path_chirho: PathBuf,
    pub blake3_chirho: String,
}

#[derive(Debug)]
pub(super) struct BoundedCommandOutputChirho {
    pub status_chirho: ExitStatus,
    pub stdout_chirho: Vec<u8>,
    pub stderr_chirho: Vec<u8>,
}

#[derive(Clone, Copy)]
pub(super) struct CommandLimitsChirho {
    pub timeout_chirho: Duration,
    pub max_stream_bytes_chirho: usize,
}

impl Default for CommandLimitsChirho {
    fn default() -> Self {
        Self {
            timeout_chirho: CARGO_COMMAND_TIMEOUT_CHIRHO,
            max_stream_bytes_chirho: CARGO_COMMAND_CAPTURE_BYTES_CHIRHO,
        }
    }
}

pub(super) fn absolute_compile_time_cargo_path_chirho(configured_chirho: &str) -> Result<PathBuf> {
    let configured_chirho = PathBuf::from(configured_chirho);
    if !configured_chirho.is_absolute() {
        bail!(
            "compile-time Cargo executable path must be absolute: {}",
            configured_chirho.display()
        );
    }
    Ok(configured_chirho)
}

pub(super) fn trusted_cargo_chirho() -> Result<TrustedCargoChirho> {
    // Native builds use Cargo's rustc-provided path. A reviewed cross-build may instead bind the
    // target host's absolute toolchain path at compile time. Runtime `CARGO` cannot select the
    // executable that supplies promotion evidence in either case.
    let configured_chirho =
        absolute_compile_time_cargo_path_chirho(COMPILE_TIME_CARGO_PATH_CHIRHO)?;
    let path_chirho = configured_chirho.canonicalize().with_context(|| {
        format!(
            "canonicalize compile-time Cargo executable {}",
            configured_chirho.display()
        )
    })?;
    let metadata_chirho = std::fs::symlink_metadata(&path_chirho)
        .with_context(|| format!("inspect trusted Cargo executable {}", path_chirho.display()))?;
    if !metadata_chirho.is_file() || metadata_chirho.file_type().is_symlink() {
        bail!(
            "compile-time Cargo executable {} is not a regular non-symlink file",
            path_chirho.display()
        );
    }
    let bytes_chirho = read_bounded_file_chirho(
        &path_chirho,
        "trusted Cargo executable",
        TRUSTED_CARGO_MAX_BYTES_CHIRHO,
    )?;
    Ok(TrustedCargoChirho {
        path_chirho,
        blake3_chirho: cas_chirho::hash_chirho(&bytes_chirho).0,
    })
}

impl TrustedCargoChirho {
    pub(super) fn command_chirho(&self) -> Result<Command> {
        self.verify_unchanged_chirho()?;
        let mut command_chirho = Command::new(&self.path_chirho);
        // Remove caller-controlled compiler/build wrappers and target selection. Cargo itself
        // supplies the correct CARGO value to descendants after this trusted executable starts.
        for variable_chirho in [
            "CARGO",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
        ] {
            command_chirho.env_remove(variable_chirho);
        }
        command_chirho
            .env("CARGO_TERM_COLOR", "never")
            .env("RUST_BACKTRACE", "0");
        Ok(command_chirho)
    }

    pub(super) fn verify_unchanged_chirho(&self) -> Result<()> {
        let bytes_chirho = read_bounded_file_chirho(
            &self.path_chirho,
            "trusted Cargo executable",
            TRUSTED_CARGO_MAX_BYTES_CHIRHO,
        )?;
        if cas_chirho::hash_chirho(&bytes_chirho).0 != self.blake3_chirho {
            bail!("compile-time Cargo executable bytes changed during the authoring gate");
        }
        Ok(())
    }
}

pub(super) fn run_trusted_cargo_chirho(
    cargo_chirho: &TrustedCargoChirho,
    current_dir_chirho: &Path,
    target_dir_chirho: Option<&Path>,
    label_chirho: &str,
    args_chirho: &[&str],
) -> Result<BoundedCommandOutputChirho> {
    let mut command_chirho = cargo_chirho.command_chirho()?;
    command_chirho
        .args(args_chirho)
        .current_dir(current_dir_chirho);
    if let Some(target_dir_chirho) = target_dir_chirho {
        command_chirho.env("CARGO_TARGET_DIR", target_dir_chirho);
    }
    let output_chirho = run_bounded_command_chirho(
        &mut command_chirho,
        label_chirho,
        CommandLimitsChirho::default(),
    )?;
    cargo_chirho.verify_unchanged_chirho()?;
    if !output_chirho.status_chirho.success() {
        let exit_code_chirho = output_chirho.status_chirho.code().unwrap_or(-1);
        bail!(
            "credits-demo authoring step '{label_chirho}' failed with exit code \
             {exit_code_chirho}; stdout='{}'; stderr='{}'",
            bounded_diagnostic_chirho(&output_chirho.stdout_chirho),
            bounded_diagnostic_chirho(&output_chirho.stderr_chirho)
        );
    }
    Ok(output_chirho)
}

pub(super) fn run_bounded_command_chirho(
    command_chirho: &mut Command,
    label_chirho: &str,
    limits_chirho: CommandLimitsChirho,
) -> Result<BoundedCommandOutputChirho> {
    if limits_chirho.max_stream_bytes_chirho == 0 {
        bail!("command '{label_chirho}' has a zero-byte output bound");
    }
    command_chirho.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command_chirho.process_group(0);
    }
    let mut child_chirho = command_chirho
        .spawn()
        .with_context(|| format!("spawn credits-demo authoring command '{label_chirho}'"))?;
    let process_id_chirho = child_chirho.id();
    let stdout_chirho = child_chirho
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("command '{label_chirho}' stdout pipe was unavailable"))?;
    let stderr_chirho = child_chirho
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("command '{label_chirho}' stderr pipe was unavailable"))?;
    let overflow_chirho = Arc::new(AtomicBool::new(false));
    let (capture_sender_chirho, capture_receiver_chirho) = mpsc::channel();
    spawn_capture_chirho(
        StreamKindChirho::StdoutChirho,
        stdout_chirho,
        limits_chirho.max_stream_bytes_chirho,
        Arc::clone(&overflow_chirho),
        capture_sender_chirho.clone(),
    );
    spawn_capture_chirho(
        StreamKindChirho::StderrChirho,
        stderr_chirho,
        limits_chirho.max_stream_bytes_chirho,
        Arc::clone(&overflow_chirho),
        capture_sender_chirho,
    );

    let started_chirho = Instant::now();
    let mut timed_out_chirho = false;
    let mut output_exceeded_chirho = false;
    let status_chirho = loop {
        if overflow_chirho.load(Ordering::Acquire) {
            output_exceeded_chirho = true;
            terminate_command_tree_chirho(&mut child_chirho, process_id_chirho);
            break child_chirho
                .try_wait()
                .context("read terminated command status")?
                .ok_or_else(|| anyhow::anyhow!("terminated command did not exit"))?;
        }
        if started_chirho.elapsed() >= limits_chirho.timeout_chirho {
            timed_out_chirho = true;
            terminate_command_tree_chirho(&mut child_chirho, process_id_chirho);
            break child_chirho
                .try_wait()
                .context("read timed-out command status")?
                .ok_or_else(|| anyhow::anyhow!("timed-out command did not exit"))?;
        }
        if let Some(status_chirho) = child_chirho
            .try_wait()
            .with_context(|| format!("poll credits-demo authoring command '{label_chirho}'"))?
        {
            break status_chirho;
        }
        std::thread::sleep(COMMAND_POLL_INTERVAL_CHIRHO);
    };

    let captures_chirho = receive_captures_chirho(
        &capture_receiver_chirho,
        &mut child_chirho,
        process_id_chirho,
    )?;
    let mut stdout_bytes_chirho = Vec::new();
    let mut stderr_bytes_chirho = Vec::new();
    for capture_chirho in captures_chirho {
        match capture_chirho.kind_chirho {
            StreamKindChirho::StdoutChirho => stdout_bytes_chirho = capture_chirho.bytes_chirho,
            StreamKindChirho::StderrChirho => stderr_bytes_chirho = capture_chirho.bytes_chirho,
        }
    }
    if output_exceeded_chirho {
        bail!(
            "credits-demo authoring command '{label_chirho}' exceeded the {}-byte per-stream \
             output bound; stdout='{}'; stderr='{}'",
            limits_chirho.max_stream_bytes_chirho,
            bounded_diagnostic_chirho(&stdout_bytes_chirho),
            bounded_diagnostic_chirho(&stderr_bytes_chirho)
        );
    }
    if timed_out_chirho {
        bail!(
            "credits-demo authoring command '{label_chirho}' exceeded its {} ms timeout; \
             stdout='{}'; stderr='{}'",
            limits_chirho.timeout_chirho.as_millis(),
            bounded_diagnostic_chirho(&stdout_bytes_chirho),
            bounded_diagnostic_chirho(&stderr_bytes_chirho)
        );
    }
    Ok(BoundedCommandOutputChirho {
        status_chirho,
        stdout_chirho: stdout_bytes_chirho,
        stderr_chirho: stderr_bytes_chirho,
    })
}

#[derive(Clone, Copy)]
enum StreamKindChirho {
    StdoutChirho,
    StderrChirho,
}

struct StreamCaptureChirho {
    kind_chirho: StreamKindChirho,
    bytes_chirho: Vec<u8>,
}

fn spawn_capture_chirho(
    kind_chirho: StreamKindChirho,
    mut reader_chirho: impl Read + Send + 'static,
    max_bytes_chirho: usize,
    overflow_chirho: Arc<AtomicBool>,
    sender_chirho: mpsc::Sender<Result<StreamCaptureChirho, String>>,
) {
    std::thread::spawn(move || {
        let mut captured_chirho = Vec::with_capacity(max_bytes_chirho.min(16 * 1024));
        let mut chunk_chirho = [0_u8; 8192];
        loop {
            match reader_chirho.read(&mut chunk_chirho) {
                Ok(0) => break,
                Ok(read_chirho) => {
                    let remaining_chirho = max_bytes_chirho.saturating_sub(captured_chirho.len());
                    let retained_chirho = read_chirho.min(remaining_chirho);
                    captured_chirho.extend_from_slice(&chunk_chirho[..retained_chirho]);
                    if retained_chirho < read_chirho {
                        overflow_chirho.store(true, Ordering::Release);
                    }
                }
                Err(error_chirho) => {
                    let _result_chirho =
                        sender_chirho.send(Err(format!("capture command stream: {error_chirho}")));
                    return;
                }
            }
        }
        let _result_chirho = sender_chirho.send(Ok(StreamCaptureChirho {
            kind_chirho,
            bytes_chirho: captured_chirho,
        }));
    });
}

fn receive_captures_chirho(
    receiver_chirho: &mpsc::Receiver<Result<StreamCaptureChirho, String>>,
    child_chirho: &mut std::process::Child,
    process_id_chirho: u32,
) -> Result<Vec<StreamCaptureChirho>> {
    let mut captures_chirho = Vec::with_capacity(2);
    while captures_chirho.len() < 2 {
        match receiver_chirho.recv_timeout(STREAM_DRAIN_GRACE_CHIRHO) {
            Ok(Ok(capture_chirho)) => captures_chirho.push(capture_chirho),
            Ok(Err(error_chirho)) => bail!("{error_chirho}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                terminate_command_tree_chirho(child_chirho, process_id_chirho);
                match receiver_chirho.recv_timeout(STREAM_DRAIN_GRACE_CHIRHO) {
                    Ok(Ok(capture_chirho)) => captures_chirho.push(capture_chirho),
                    Ok(Err(error_chirho)) => bail!("{error_chirho}"),
                    Err(error_chirho) => {
                        bail!(
                            "command output pipes did not close after termination: {error_chirho}"
                        )
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("command output capture threads disconnected")
            }
        }
    }
    Ok(captures_chirho)
}

fn terminate_command_tree_chirho(child_chirho: &mut std::process::Child, process_id_chirho: u32) {
    #[cfg(unix)]
    {
        const SIGKILL_CHIRHO: i32 = 9;
        unsafe extern "C" {
            fn kill(process_chirho: i32, signal_chirho: i32) -> i32;
        }
        if let Ok(process_group_chirho) = i32::try_from(process_id_chirho) {
            // SAFETY: the child was placed in its own process group, and a negative pid requests
            // SIGKILL for that group. The return value is advisory because the leader may have
            // exited between polling and termination.
            let _result_chirho = unsafe { kill(-process_group_chirho, SIGKILL_CHIRHO) };
        }
    }
    let _result_chirho = child_chirho.kill();
    let _result_chirho = child_chirho.wait();
}

fn read_bounded_file_chirho(
    path_chirho: &Path,
    label_chirho: &str,
    max_chirho: u64,
) -> Result<Vec<u8>> {
    let file_chirho = std::fs::File::open(path_chirho)
        .with_context(|| format!("open {label_chirho} {}", path_chirho.display()))?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(max_chirho.saturating_add(1))
        .read_to_end(&mut bytes_chirho)
        .with_context(|| format!("read {label_chirho} {}", path_chirho.display()))?;
    if bytes_chirho.len() as u64 > max_chirho {
        bail!(
            "{label_chirho} {} exceeds the {} byte limit",
            path_chirho.display(),
            max_chirho
        );
    }
    Ok(bytes_chirho)
}

pub(super) fn bounded_diagnostic_chirho(bytes_chirho: &[u8]) -> String {
    let retained_chirho = bytes_chirho.len().min(MAX_COMMAND_DIAGNOSTIC_BYTES_CHIRHO);
    String::from_utf8_lossy(&bytes_chirho[..retained_chirho]).into_owned()
}
