// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Maintains a per-log O(1) head checkpoint sidecar so warm seq-derivation skips the full rescan.
//!
//! Boundary: the checkpoint proves only that the log TAIL is unchanged (byte length + last-line
//! hash); it deliberately does NOT re-validate interior lines, so same-length interior corruption
//! that preserves the tail is trusted by the warm fast path and is caught instead by the full-scan /
//! typed-load verify paths (equality-or-full-rescan; there is no tail-delta path).
//!
//! Every read here, of the sidecar and of the log, goes through the shared safe descriptor: no link is followed, no
//! pipe is waited on, and a regular file is required. A sidecar that fails that is a miss, since it is advisory; a log
//! that fails it is refused, since the log is the authority. Workflow: the shared JSONL absence brick,
//! `spec-chirho/tasklists-chirho/26-10-08_23-20-tasklist-jsonl_absence_cache_door-chirho.md`.

use anyhow::{anyhow, Context, Result};
use cairn_durable_chirho::log_path_chirho::open_log_no_follow_chirho;
use cairn_durable_chirho::write_file_durable_chirho;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Schema tag for the `<log>.head-chirho` sidecar. Any other value is treated as a miss (full
/// rescan) rather than misread, so bumping this string safely retires an old checkpoint layout.
pub(crate) const SEQLOG_HEAD_SCHEMA_CHIRHO: &str = "seqlog-head-v1-chirho";

/// Filename suffix appended to a log path to name its sibling checkpoint.
/// Exported so the migration disposition model can DERIVE a sidecar's disposition from its log's
/// rather than carrying a second copy of this literal. Two spellings of the same suffix is exactly
/// the drift that lets one of them fall out of date silently.
pub const SEQLOG_HEAD_SUFFIX_CHIRHO: &str = ".head-chirho";

/// The most bytes a sidecar is read for. A real checkpoint is a few hundred bytes, so a larger sidecar is a miss, and a
/// planted giant file costs one bounded read rather than an unbounded one.
const SEQLOG_HEAD_MAX_BYTES_CHIRHO: u64 = 4096;

/// Which tail read of the LOG is opening it: the fast path's tail check, or a reseed's fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogOpenStageChirho {
    TailCheckChirho,
    ReseedChirho,
}

/// The durable head checkpoint. It records only enough to prove, in O(1), that the log is byte-for
/// -byte the tail this checkpoint was written for; the record count is then trusted without a scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SeqlogHeadChirho {
    schema_chirho: String,
    record_count_chirho: u64,
    byte_len_chirho: u64,
    last_line_len_chirho: u64,
    last_line_blake3_chirho: String,
}

/// The three tail facts a fresh checkpoint is minted from.
struct SeqlogTailFingerprintChirho {
    byte_len_chirho: u64,
    last_line_len_chirho: u64,
    last_line_blake3_chirho: String,
}

/// The sidecar path for `log_path_chirho`: the log's own path with `.head-chirho` appended.
pub(crate) fn seqlog_head_path_chirho(log_path_chirho: &Path) -> PathBuf {
    let mut name_chirho = log_path_chirho.as_os_str().to_os_string();
    name_chirho.push(SEQLOG_HEAD_SUFFIX_CHIRHO);
    PathBuf::from(name_chirho)
}

/// O(1) seq-derivation: return the checkpointed record count only when the sidecar proves the log
/// tail is unchanged — right schema, equal byte length, and the recorded tail bytes still hash
/// equal. Any missing, torn, stale-behind, ahead (offset past EOF), or mismatched checkpoint returns
/// `None`, so the caller falls back to the full rescan and re-seeds. Equality-or-full-rescan only:
/// there is no tail-delta path, which is the safety argument. Never trusts a checkpoint that could
/// be ahead of the durable tail.
pub(crate) fn try_seqlog_head_fast_path_chirho(log_path_chirho: &Path) -> Result<Option<u64>> {
    let head_path_chirho = seqlog_head_path_chirho(log_path_chirho);
    // The sidecar is ADVISORY: unreadable for ANY reason (missing, a link, a pipe, a directory,
    // permissions, oversize, torn) is a miss, never an error and never a wait — the full rescan is
    // the authority, and real filesystem trouble will surface honestly against the log itself there.
    // A cache read must never fail a log operation.
    let Some(head_bytes_chirho) = read_seqlog_head_chirho(&head_path_chirho) else {
        return Ok(None);
    };
    let head_chirho: SeqlogHeadChirho = match serde_json::from_slice(&head_bytes_chirho) {
        Ok(head_chirho) => head_chirho,
        Err(_) => return Ok(None),
    };
    if head_chirho.schema_chirho != SEQLOG_HEAD_SCHEMA_CHIRHO {
        return Ok(None);
    }
    // The log is the authority, so it is opened as every other read of it is. Its length and tail
    // come from this one descriptor, so a swap after recovery examined the path is refused, never
    // followed.
    let mut log_file_chirho =
        open_log_for_tail_chirho(log_path_chirho, LogOpenStageChirho::TailCheckChirho)?;
    let current_len_chirho = log_file_chirho
        .metadata()
        .with_context(|| format!("stat {}", log_path_chirho.display()))?
        .len();
    if current_len_chirho != head_chirho.byte_len_chirho {
        return Ok(None);
    }
    if head_chirho.last_line_len_chirho > current_len_chirho {
        return Ok(None);
    }
    if head_chirho.byte_len_chirho != 0 && head_chirho.last_line_len_chirho == 0 {
        return Ok(None);
    }
    let tail_blake3_chirho = blake3_of_tail_chirho(
        &mut log_file_chirho,
        log_path_chirho,
        current_len_chirho,
        head_chirho.last_line_len_chirho,
    )?;
    if tail_blake3_chirho != head_chirho.last_line_blake3_chirho {
        return Ok(None);
    }
    Ok(Some(head_chirho.record_count_chirho))
}

/// Read the advisory sidecar through the shared safe descriptor, and at most one byte past the
/// bound. Anything that is not a small regular file is `None`: a miss.
fn read_seqlog_head_chirho(head_path_chirho: &Path) -> Option<Vec<u8>> {
    let file_chirho = open_log_no_follow_chirho(head_path_chirho).ok()??;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(SEQLOG_HEAD_MAX_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .ok()?;
    (bytes_chirho.len() as u64 <= SEQLOG_HEAD_MAX_BYTES_CHIRHO).then_some(bytes_chirho)
}

/// Open the LOG for a tail read through the shared safe descriptor. A log that vanished since
/// recovery examined it is an error, as the full scan's own open is.
fn open_log_for_tail_chirho(path_chirho: &Path, stage_chirho: LogOpenStageChirho) -> Result<File> {
    #[cfg(test)]
    before_log_open_chirho(stage_chirho, path_chirho);
    #[cfg(not(test))]
    let _ = stage_chirho;
    open_log_no_follow_chirho(path_chirho)
        .with_context(|| format!("open {} for its tail", path_chirho.display()))?
        .ok_or_else(|| anyhow!("{} disappeared during recovery", path_chirho.display()))
}

#[cfg(test)]
type BeforeLogOpenHookChirho = Box<dyn FnMut(LogOpenStageChirho, &Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_LOG_OPEN_CHIRHO: std::cell::RefCell<Option<BeforeLogOpenHookChirho>> =
        const { std::cell::RefCell::new(None) };
}

/// Test seam: run `hook_chirho` on this thread just before each tail read opens the log, after
/// recovery has examined the path, so an arm can swap the path at the real seam.
#[cfg(test)]
pub(crate) fn set_before_log_open_hook_chirho(
    hook_chirho: impl FnMut(LogOpenStageChirho, &Path) + 'static,
) {
    BEFORE_LOG_OPEN_CHIRHO
        .with(|slot_chirho| *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho)));
}

#[cfg(test)]
fn before_log_open_chirho(stage_chirho: LogOpenStageChirho, path_chirho: &Path) {
    BEFORE_LOG_OPEN_CHIRHO.with(|slot_chirho| {
        if let Some(hook_chirho) = slot_chirho.borrow_mut().as_mut() {
            hook_chirho(stage_chirho, path_chirho);
        }
    });
}

/// Re-seed the checkpoint from the log's current (post-append or post-repair) durable state.
///
/// Call only while holding the append lock, and only AFTER the log line is written and fsynced, so
/// the checkpoint can only ever lag — never lead — the durable tail. The write is a durable
/// temp+rename, so a crash mid-write leaves the previous (behind) sidecar or none, never a torn one.
pub(crate) fn reseed_seqlog_head_chirho(
    log_path_chirho: &Path,
    record_count_chirho: u64,
) -> Result<()> {
    let fingerprint_chirho = seqlog_tail_fingerprint_chirho(log_path_chirho)?;
    let head_chirho = SeqlogHeadChirho {
        schema_chirho: SEQLOG_HEAD_SCHEMA_CHIRHO.to_string(),
        record_count_chirho,
        byte_len_chirho: fingerprint_chirho.byte_len_chirho,
        last_line_len_chirho: fingerprint_chirho.last_line_len_chirho,
        last_line_blake3_chirho: fingerprint_chirho.last_line_blake3_chirho,
    };
    let head_path_chirho = seqlog_head_path_chirho(log_path_chirho);
    let text_chirho = serde_json::to_string(&head_chirho)
        .with_context(|| format!("encode seqlog head {}", head_path_chirho.display()))?;
    write_file_durable_chirho(&head_path_chirho, text_chirho.as_bytes())
        .with_context(|| format!("write seqlog head {}", head_path_chirho.display()))
}

fn seqlog_tail_fingerprint_chirho(path_chirho: &Path) -> Result<SeqlogTailFingerprintChirho> {
    let mut file_chirho = open_log_for_tail_chirho(path_chirho, LogOpenStageChirho::ReseedChirho)?;
    let byte_len_chirho = file_chirho
        .metadata()
        .with_context(|| format!("stat {}", path_chirho.display()))?
        .len();
    if byte_len_chirho == 0 {
        return Ok(SeqlogTailFingerprintChirho {
            byte_len_chirho: 0,
            last_line_len_chirho: 0,
            last_line_blake3_chirho: blake3::hash(b"").to_hex().to_string(),
        });
    }
    let last_line_start_chirho =
        last_line_start_chirho(&mut file_chirho, byte_len_chirho, path_chirho)?;
    let last_line_len_chirho = byte_len_chirho - last_line_start_chirho;
    file_chirho
        .seek(SeekFrom::Start(last_line_start_chirho))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut buf_chirho = vec![0u8; last_line_len_chirho as usize];
    file_chirho
        .read_exact(&mut buf_chirho)
        .with_context(|| format!("read tail {}", path_chirho.display()))?;
    Ok(SeqlogTailFingerprintChirho {
        byte_len_chirho,
        last_line_len_chirho,
        last_line_blake3_chirho: blake3::hash(&buf_chirho).to_hex().to_string(),
    })
}

/// Start offset of the final physical line, scanning backwards in bounded 8 KiB chunks (cost = last
/// line length, not file length). A single trailing newline is the line's terminator, not a blank
/// separator, so `<record>\n` reports the record plus its newline as one line.
fn last_line_start_chirho(
    file_chirho: &mut File,
    byte_len_chirho: u64,
    path_chirho: &Path,
) -> Result<u64> {
    file_chirho
        .seek(SeekFrom::Start(byte_len_chirho - 1))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut final_byte_chirho = [0u8; 1];
    file_chirho
        .read_exact(&mut final_byte_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut end_chirho = if final_byte_chirho[0] == b'\n' {
        byte_len_chirho - 1
    } else {
        byte_len_chirho
    };
    while end_chirho > 0 {
        let chunk_len_chirho = usize::min(end_chirho as usize, 8192);
        let start_chirho = end_chirho - chunk_len_chirho as u64;
        file_chirho
            .seek(SeekFrom::Start(start_chirho))
            .with_context(|| format!("seek {}", path_chirho.display()))?;
        let mut chunk_chirho = vec![0u8; chunk_len_chirho];
        file_chirho
            .read_exact(&mut chunk_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        if let Some(newline_chirho) = chunk_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        {
            return Ok(start_chirho + newline_chirho as u64 + 1);
        }
        end_chirho = start_chirho;
    }
    Ok(0)
}

/// blake3 of the final `tail_len_chirho` bytes of the already-opened log. The caller guarantees
/// `tail_len_chirho <= byte_len_chirho`, so the start offset never underflows.
fn blake3_of_tail_chirho(
    file_chirho: &mut File,
    path_chirho: &Path,
    byte_len_chirho: u64,
    tail_len_chirho: u64,
) -> Result<String> {
    file_chirho
        .seek(SeekFrom::Start(byte_len_chirho - tail_len_chirho))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut buf_chirho = vec![0u8; tail_len_chirho as usize];
    file_chirho
        .read_exact(&mut buf_chirho)
        .with_context(|| format!("read tail {}", path_chirho.display()))?;
    Ok(blake3::hash(&buf_chirho).to_hex().to_string())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_dir_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let dir_chirho =
            std::env::temp_dir().join(format!("cairn-seqlog-head-test-{nanos_chirho}-{n_chirho}"));
        std::fs::create_dir_all(&dir_chirho).unwrap();
        dir_chirho
    }

    #[test]
    fn head_path_is_sibling_with_suffix_chirho() {
        let path_chirho = Path::new("/store-chirho/family-chirho.jsonl");
        assert_eq!(
            seqlog_head_path_chirho(path_chirho),
            PathBuf::from("/store-chirho/family-chirho.jsonl.head-chirho")
        );
    }

    #[test]
    fn reseed_then_fast_path_returns_record_count_chirho() {
        let dir_chirho = tmp_dir_chirho();
        let log_chirho = dir_chirho.join("log-chirho.jsonl");
        std::fs::write(&log_chirho, b"{\"a\":0}\n{\"a\":1}\n{\"a\":2}\n").unwrap();

        reseed_seqlog_head_chirho(&log_chirho, 3).unwrap();
        assert_eq!(
            try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(),
            Some(3)
        );

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }

    #[test]
    fn fast_path_misses_when_length_grows_or_shrinks_chirho() {
        let dir_chirho = tmp_dir_chirho();
        let log_chirho = dir_chirho.join("log-chirho.jsonl");
        std::fs::write(&log_chirho, b"{\"a\":0}\n{\"a\":1}\n").unwrap();
        reseed_seqlog_head_chirho(&log_chirho, 2).unwrap();

        // Grow (a crash-appended line the checkpoint has not caught up to).
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log_chirho)
            .unwrap()
            .write_all(b"{\"a\":2}\n")
            .unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        // Shrink below the checkpoint (truncation): the checkpoint is now ahead.
        std::fs::write(&log_chirho, b"{\"a\":0}\n").unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }

    #[test]
    fn fast_path_misses_on_same_length_tail_mutation_chirho() {
        let dir_chirho = tmp_dir_chirho();
        let log_chirho = dir_chirho.join("log-chirho.jsonl");
        std::fs::write(&log_chirho, b"{\"a\":0}\n{\"a\":10}\n").unwrap();
        reseed_seqlog_head_chirho(&log_chirho, 2).unwrap();

        // Overwrite the last line with a different, same-length payload: length alone would pass,
        // so this proves the tail hash is load-bearing against equal-length replacement.
        std::fs::write(&log_chirho, b"{\"a\":0}\n{\"a\":99}\n").unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }

    #[test]
    fn fast_path_misses_on_missing_garbage_or_wrong_schema_sidecar_chirho() {
        let dir_chirho = tmp_dir_chirho();
        let log_chirho = dir_chirho.join("log-chirho.jsonl");
        std::fs::write(&log_chirho, b"{\"a\":0}\n").unwrap();

        // Missing sidecar.
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        // Garbage sidecar bytes.
        let head_path_chirho = seqlog_head_path_chirho(&log_chirho);
        std::fs::write(&head_path_chirho, b"not json at all").unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        // Well-formed JSON but wrong schema tag.
        std::fs::write(
            &head_path_chirho,
            b"{\"schema_chirho\":\"seqlog-head-v0-chirho\",\"record_count_chirho\":9,\"byte_len_chirho\":8,\"last_line_len_chirho\":8,\"last_line_blake3_chirho\":\"x\"}",
        )
        .unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }

    #[test]
    fn fast_path_rejects_zero_tail_len_for_nonempty_log_chirho() {
        let dir_chirho = tmp_dir_chirho();
        let log_chirho = dir_chirho.join("log-chirho.jsonl");
        std::fs::write(&log_chirho, b"{\"a\":0}\n").unwrap();
        let head_path_chirho = seqlog_head_path_chirho(&log_chirho);
        // Forged checkpoint: correct length, zero tail length, empty-hash — must not be trusted for
        // a non-empty log, or a fabricated record_count would sail through the tail check.
        let empty_hash_chirho = blake3::hash(b"").to_hex().to_string();
        std::fs::write(
            &head_path_chirho,
            format!(
                "{{\"schema_chirho\":\"seqlog-head-v1-chirho\",\"record_count_chirho\":999,\"byte_len_chirho\":8,\"last_line_len_chirho\":0,\"last_line_blake3_chirho\":\"{empty_hash_chirho}\"}}"
            ),
        )
        .unwrap();
        assert_eq!(try_seqlog_head_fast_path_chirho(&log_chirho).unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }

    #[test]
    fn tail_fingerprint_matches_single_and_multi_line_chirho() {
        let dir_chirho = tmp_dir_chirho();

        let single_chirho = dir_chirho.join("single-chirho.jsonl");
        std::fs::write(&single_chirho, b"{\"a\":0}\n").unwrap();
        let fingerprint_chirho = seqlog_tail_fingerprint_chirho(&single_chirho).unwrap();
        assert_eq!(fingerprint_chirho.byte_len_chirho, 8);
        assert_eq!(fingerprint_chirho.last_line_len_chirho, 8);
        assert_eq!(
            fingerprint_chirho.last_line_blake3_chirho,
            blake3::hash(b"{\"a\":0}\n").to_hex().to_string()
        );

        let multi_chirho = dir_chirho.join("multi-chirho.jsonl");
        std::fs::write(&multi_chirho, b"{\"a\":0}\n{\"bb\":1}\n").unwrap();
        let fingerprint_chirho = seqlog_tail_fingerprint_chirho(&multi_chirho).unwrap();
        assert_eq!(fingerprint_chirho.byte_len_chirho, 17);
        assert_eq!(fingerprint_chirho.last_line_len_chirho, 9);
        assert_eq!(
            fingerprint_chirho.last_line_blake3_chirho,
            blake3::hash(b"{\"bb\":1}\n").to_hex().to_string()
        );

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }
}
