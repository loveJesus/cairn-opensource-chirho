// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A test attempt log (a keyed checksum stands in for the signature, and a counter records every verification)
//! with a full-scan oracle that decides exactly as cairn's `ensure_public_auth_attempt_allowed_chirho` does today.

use crate::{AttemptLogChirho, AttemptRecordChirho, PathTakenChirho, WindowRulesChirho};
use anyhow::{bail, Result};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const WINDOW_MS_CHIRHO: u64 = 15 * 60 * 1000;
pub(crate) const TOLERANCE_MS_CHIRHO: u64 = WINDOW_MS_CHIRHO;
pub(crate) const FULL_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;
pub(crate) const SUCCESS_WINDOW_MS_CHIRHO: u64 = 60 * 60 * 1000;
pub(crate) const RULES_CHIRHO: WindowRulesChirho = WindowRulesChirho {
    window_ms_chirho: WINDOW_MS_CHIRHO,
    regression_tolerance_ms_chirho: TOLERANCE_MS_CHIRHO,
    full_verify_every_ms_chirho: FULL_EVERY_MS_CHIRHO,
    success_window_ms_chirho: SUCCESS_WINDOW_MS_CHIRHO,
};
pub(crate) const START_MS_CHIRHO: u64 = 1_800_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestRecordChirho {
    pub(crate) seq_chirho: u64,
    pub(crate) principal_chirho: String,
    pub(crate) endpoint_chirho: String,
    pub(crate) success_chirho: bool,
    pub(crate) at_ms_chirho: u64,
    pub(crate) sig_chirho: String,
}

impl AttemptRecordChirho for TestRecordChirho {
    fn principal_hash_chirho(&self) -> &str {
        &self.principal_chirho
    }
    fn endpoint_chirho(&self) -> &str {
        &self.endpoint_chirho
    }
    fn is_success_chirho(&self) -> bool {
        self.success_chirho
    }
    fn at_ms_chirho(&self) -> u64 {
        self.at_ms_chirho
    }
}

fn sig_chirho(
    verifier_chirho: &str,
    seq_chirho: u64,
    principal_chirho: &str,
    endpoint_chirho: &str,
    success_chirho: bool,
    at_ms_chirho: u64,
) -> String {
    let mut hasher_chirho = DefaultHasher::new();
    (
        verifier_chirho,
        seq_chirho,
        principal_chirho,
        endpoint_chirho,
        success_chirho,
        at_ms_chirho,
    )
        .hash(&mut hasher_chirho);
    format!("{:016x}", hasher_chirho.finish())
}

/// One signed line, newline included.
pub(crate) fn record_line_chirho(
    verifier_chirho: &str,
    seq_chirho: u64,
    principal_chirho: &str,
    endpoint_chirho: &str,
    success_chirho: bool,
    at_ms_chirho: u64,
) -> String {
    let outcome_chirho = if success_chirho { "S" } else { "F" };
    let sig_chirho = sig_chirho(
        verifier_chirho,
        seq_chirho,
        principal_chirho,
        endpoint_chirho,
        success_chirho,
        at_ms_chirho,
    );
    format!("{seq_chirho} {principal_chirho} {endpoint_chirho} {outcome_chirho} {at_ms_chirho} {sig_chirho}\n")
}

/// Parse one line. The view and the oracle share it, as the root crate's loader and view share theirs.
pub(crate) fn parse_test_line_chirho(line_chirho: &str) -> Result<TestRecordChirho> {
    let fields_chirho: Vec<&str> = line_chirho.split_whitespace().collect();
    let [seq_chirho, principal_chirho, endpoint_chirho, outcome_chirho, at_ms_chirho, sig_chirho] =
        fields_chirho.as_slice()
    else {
        bail!("malformed test attempt line");
    };
    let success_chirho = match *outcome_chirho {
        "S" => true,
        "F" => false,
        _ => bail!("malformed test attempt outcome"),
    };
    Ok(TestRecordChirho {
        seq_chirho: seq_chirho.parse()?,
        principal_chirho: principal_chirho.to_string(),
        endpoint_chirho: endpoint_chirho.to_string(),
        success_chirho,
        at_ms_chirho: at_ms_chirho.parse()?,
        sig_chirho: sig_chirho.to_string(),
    })
}

/// Verify one record as the `expected_seq_chirho`-th. The view and the oracle share it.
pub(crate) fn check_test_record_chirho(
    verifier_chirho: &str,
    record_chirho: &TestRecordChirho,
    expected_seq_chirho: u64,
) -> Result<()> {
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!(
            "test attempt seq gap at index {expected_seq_chirho}: entry seq is {}",
            record_chirho.seq_chirho
        );
    }
    let expected_sig_chirho = sig_chirho(
        verifier_chirho,
        record_chirho.seq_chirho,
        &record_chirho.principal_chirho,
        &record_chirho.endpoint_chirho,
        record_chirho.success_chirho,
        record_chirho.at_ms_chirho,
    );
    if record_chirho.sig_chirho != expected_sig_chirho {
        bail!(
            "test attempt {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub(crate) struct TestLogChirho {
    pub(crate) path_chirho: PathBuf,
    pub(crate) verifier_chirho: String,
    verified_chirho: AtomicU64,
    panic_at_seq_chirho: Option<u64>,
    owned_dir_chirho: Option<PathBuf>,
}

/// A background job's copy: the same file and key, its OWN verification counter (so a request's count never
/// includes a background job's), no planted panic, and it never removes the directory.
impl Clone for TestLogChirho {
    fn clone(&self) -> Self {
        self.handle_chirho(&self.verifier_chirho)
    }
}

impl AttemptLogChirho for TestLogChirho {
    type RecordChirho = TestRecordChirho;
    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_chirho
    }
    fn parse_chirho(&self, line_chirho: &str) -> Result<TestRecordChirho> {
        parse_test_line_chirho(line_chirho)
    }
    fn verify_chirho(
        &self,
        record_chirho: &TestRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        if self.panic_at_seq_chirho == Some(record_chirho.seq_chirho) {
            panic!("planted panic inside a view update");
        }
        self.verified_chirho.fetch_add(1, Ordering::SeqCst);
        check_test_record_chirho(&self.verifier_chirho, record_chirho, expected_seq_chirho)
    }
}

impl TestLogChirho {
    /// A log path in a fresh directory of its own; the file does not exist yet.
    pub(crate) fn new_chirho(name_chirho: &str) -> Self {
        let nanos_chirho = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since_chirho| since_chirho.as_nanos());
        let dir_chirho = std::env::temp_dir()
            .join("cairn-auth-attempt-window-chirho")
            .join(format!(
                "{name_chirho}-{}-{nanos_chirho}",
                std::process::id()
            ));
        std::fs::create_dir_all(&dir_chirho).expect("create test dir");
        Self {
            path_chirho: dir_chirho.join("attempts-chirho.jsonl"),
            verifier_chirho: "key-a-chirho".to_string(),
            verified_chirho: AtomicU64::new(0),
            panic_at_seq_chirho: None,
            owned_dir_chirho: Some(dir_chirho),
        }
    }

    /// Another handle on the same file: another reader, or the same log under a different verification key.
    pub(crate) fn handle_chirho(&self, verifier_chirho: &str) -> Self {
        Self {
            path_chirho: self.path_chirho.clone(),
            verifier_chirho: verifier_chirho.to_string(),
            verified_chirho: AtomicU64::new(0),
            panic_at_seq_chirho: None,
            owned_dir_chirho: None,
        }
    }

    /// A handle whose verifier panics on one record, to interrupt an update while it holds the lock.
    pub(crate) fn panicking_handle_chirho(&self, seq_chirho: u64) -> Self {
        let mut handle_chirho = self.handle_chirho(&self.verifier_chirho);
        handle_chirho.panic_at_seq_chirho = Some(seq_chirho);
        handle_chirho
    }

    pub(crate) fn verified_chirho(&self) -> u64 {
        self.verified_chirho.load(Ordering::SeqCst)
    }

    pub(crate) fn line_chirho(
        &self,
        seq_chirho: u64,
        principal_chirho: &str,
        endpoint_chirho: &str,
        success_chirho: bool,
        at_ms_chirho: u64,
    ) -> String {
        record_line_chirho(
            &self.verifier_chirho,
            seq_chirho,
            principal_chirho,
            endpoint_chirho,
            success_chirho,
            at_ms_chirho,
        )
    }

    /// Append one signed record in a single write, as the seqlog appender does.
    pub(crate) fn append_chirho(
        &self,
        seq_chirho: u64,
        principal_chirho: &str,
        endpoint_chirho: &str,
        success_chirho: bool,
        at_ms_chirho: u64,
    ) {
        let line_chirho = self.line_chirho(
            seq_chirho,
            principal_chirho,
            endpoint_chirho,
            success_chirho,
            at_ms_chirho,
        );
        self.append_raw_chirho(line_chirho.as_bytes());
    }

    pub(crate) fn append_raw_chirho(&self, bytes_chirho: &[u8]) {
        let mut file_chirho = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path_chirho)
            .expect("open test log");
        file_chirho
            .write_all(bytes_chirho)
            .expect("append test log");
    }
}

impl Drop for TestLogChirho {
    fn drop(&mut self) {
        if let Some(dir_chirho) = &self.owned_dir_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

/// Today's count, from a full scan of the file with `str::lines`, computed the way `identity_chirho.rs` computes
/// it: failures for the key with `at_ms >= now - window` and `seq` after the key's latest success.
pub(crate) fn full_scan_count_chirho(
    log_chirho: &TestLogChirho,
    principal_chirho: &str,
    endpoint_chirho: &str,
    now_ms_chirho: u64,
) -> Result<u64> {
    let text_chirho = match std::fs::read_to_string(&log_chirho.path_chirho) {
        Ok(text_chirho) => text_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error_chirho) => return Err(error_chirho.into()),
    };
    let mut records_chirho: Vec<TestRecordChirho> = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho = parse_test_line_chirho(line_chirho)?;
        check_test_record_chirho(
            &log_chirho.verifier_chirho,
            &record_chirho,
            records_chirho.len() as u64,
        )?;
        records_chirho.push(record_chirho);
    }
    let window_start_chirho = now_ms_chirho.saturating_sub(WINDOW_MS_CHIRHO);
    let latest_success_seq_chirho = records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.principal_chirho == principal_chirho
                && record_chirho.endpoint_chirho == endpoint_chirho
                && record_chirho.success_chirho
        })
        .map(|record_chirho| record_chirho.seq_chirho)
        .max();
    Ok(records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.principal_chirho == principal_chirho
                && record_chirho.endpoint_chirho == endpoint_chirho
                && !record_chirho.success_chirho
                && record_chirho.at_ms_chirho >= window_start_chirho
                && latest_success_seq_chirho
                    .map(|seq_chirho| record_chirho.seq_chirho > seq_chirho)
                    .unwrap_or(true)
        })
        .count() as u64)
}

/// The success limit's count, from a full scan: the principal's successes on `endpoints_chirho` with
/// `at_ms >= now - success window`. Never discounted, and no upper bound on `at_ms`, as the failure rule has none.
pub(crate) fn full_scan_success_count_chirho(
    log_chirho: &TestLogChirho,
    principal_chirho: &str,
    endpoints_chirho: &[&str],
    now_ms_chirho: u64,
) -> Result<u64> {
    let text_chirho = match std::fs::read_to_string(&log_chirho.path_chirho) {
        Ok(text_chirho) => text_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error_chirho) => return Err(error_chirho.into()),
    };
    let window_start_chirho = now_ms_chirho.saturating_sub(SUCCESS_WINDOW_MS_CHIRHO);
    let mut count_chirho = 0;
    for (index_chirho, line_chirho) in text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .enumerate()
    {
        let record_chirho = parse_test_line_chirho(line_chirho)?;
        check_test_record_chirho(
            &log_chirho.verifier_chirho,
            &record_chirho,
            index_chirho as u64,
        )?;
        if record_chirho.principal_chirho == principal_chirho
            && endpoints_chirho.contains(&record_chirho.endpoint_chirho.as_str())
            && record_chirho.success_chirho
            && record_chirho.at_ms_chirho >= window_start_chirho
        {
            count_chirho += 1;
        }
    }
    Ok(count_chirho)
}

/// The number of records a path verified.
pub(crate) fn verified_by_chirho(path_chirho: PathTakenChirho) -> u64 {
    match path_chirho {
        PathTakenChirho::MissingLogChirho | PathTakenChirho::UnchangedChirho => 0,
        PathTakenChirho::IncrementalChirho { folded_chirho } => folded_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            verified_chirho, ..
        } => verified_chirho,
    }
}

/// A small deterministic generator, so a failing seed reproduces.
pub(crate) struct RngChirho(pub(crate) u64);

impl RngChirho {
    pub(crate) fn next_chirho(&mut self) -> u64 {
        let mut x_chirho = self.0;
        x_chirho ^= x_chirho << 13;
        x_chirho ^= x_chirho >> 7;
        x_chirho ^= x_chirho << 17;
        self.0 = x_chirho;
        x_chirho
    }

    pub(crate) fn below_chirho(&mut self, bound_chirho: u64) -> u64 {
        self.next_chirho() % bound_chirho
    }
}
