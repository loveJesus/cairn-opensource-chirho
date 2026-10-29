// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Refs — the only mutable state in cairn: git-like branches, tags, and HEAD.
//!
//! Everything else in the store is immutable and content-addressed; a ref is just a movable
//! name pointing into it. **Rollback is moving a ref** (DESIGN §9). Every move is recorded in
//! an append-only reflog, so a branch's history is auditable and a rollback can itself be
//! undone by moving the ref forward again.

use crate::cas_chirho;
use crate::model_chirho::{HashChirho, RefsChirho};
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::{append_durable_line_chirho, write_file_durable_chirho};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// F2 Brick-3 Step 0 logical mutation-source marker. See
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/f2-chirho/f2-elected-door-dispatcher-design-chirho.md`.
pub const REFLOG_DYNAMIC_JSONL_MUTATION_SURFACE_CHIRHO: &str = "refs.reflog-chirho";

fn refs_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("refs-chirho.json")
}

pub fn reflog_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("reflog-chirho.jsonl")
}

/// One recorded ref move. The reflog is the append-only history of every branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflogEntryChirho {
    pub branch_chirho: String,
    pub from_chirho: Option<HashChirho>,
    pub to_chirho: HashChirho,
    pub reason_chirho: String,
    /// Epoch milliseconds. (Human-readable RFC3339 arrives with the signed effect log.)
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_log_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_line_digest_chirho: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub writer_fence_group_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_writer_fence_epoch_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_id_chirho: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadPreconditionChirho {
    ExpectedChirho(HashChirho),
    AbsentChirho,
    AnyCurrentChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadTransitionCommitOutcomeChirho {
    AppliedChirho,
    RepairedReflogChirho,
    AlreadyRecordedChirho,
}

pub fn head_precondition_from_previous_chirho(
    previous_chirho: Option<HashChirho>,
) -> HeadPreconditionChirho {
    previous_chirho.map_or(
        HeadPreconditionChirho::AbsentChirho,
        HeadPreconditionChirho::ExpectedChirho,
    )
}

/// Load the refs, or a fresh default (HEAD = "main") if none exist yet.
pub fn load_refs_chirho(root_chirho: &Path) -> Result<RefsChirho> {
    let path_chirho = refs_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(RefsChirho {
            head_chirho: "main".to_string(),
            ..Default::default()
        });
    }
    let bytes_chirho =
        std::fs::read(&path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    serde_json::from_slice(&bytes_chirho).context("decode refs-chirho.json")
}

/// Persist the refs as pretty JSON — this file is meant to be human-inspectable.
pub fn save_refs_chirho(root_chirho: &Path, refs_chirho: &RefsChirho) -> Result<()> {
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create {}", root_chirho.display()))?;
    let bytes_chirho = serde_json::to_vec_pretty(refs_chirho).context("encode refs-chirho.json")?;
    write_file_durable_chirho(&refs_path_chirho(root_chirho), &bytes_chirho)
        .context("write refs-chirho.json")?;
    Ok(())
}

/// Full reflog reads on the calling thread, for the serve-runtime growth arms. Thread-local, so
/// parallel tests with their own roots never perturb one another's counts.
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub mod reflog_read_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static READS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub fn reset_chirho() {
        READS_CHIRHO.with(|cell_chirho| cell_chirho.set(0));
    }

    pub fn count_chirho() -> u64 {
        READS_CHIRHO.with(|cell_chirho| cell_chirho.get())
    }

    /// Add reads counted on another thread, such as a served run's blocking-pool thread, to this thread's count.
    pub fn absorb_chirho(reads_chirho: u64) {
        READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + reads_chirho));
    }

    pub(super) fn note_read_chirho() {
        READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }
}

/// Read the full reflog, oldest first. A missing log ⇒ an empty history.
pub fn reflog_chirho(root_chirho: &Path) -> Result<Vec<ReflogEntryChirho>> {
    let path_chirho = reflog_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(vec![]);
    }
    #[cfg(any(test, feature = "test-hooks-chirho"))]
    reflog_read_metrics_chirho::note_read_chirho();
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho).context("decode reflog entry")?);
    }
    Ok(out_chirho)
}

/// Create or advance a branch to point at `to` (the object must exist in the store).
pub fn set_branch_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    to_chirho: HashChirho,
) -> Result<()> {
    ensure_object_exists_chirho(root_chirho, &to_chirho)?;
    move_branch_chirho(root_chirho, branch_chirho, to_chirho, "branch")
}

/// Roll a branch back to an earlier object hash. The branch must already exist and the target
/// object must be present. Rollback is simply moving the ref.
pub fn rollback_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    to_chirho: HashChirho,
) -> Result<()> {
    let refs_chirho = load_refs_chirho(root_chirho)?;
    if !refs_chirho.branches_chirho.contains_key(branch_chirho) {
        bail!("no such branch '{branch_chirho}' to roll back");
    }
    ensure_object_exists_chirho(root_chirho, &to_chirho)?;
    move_branch_chirho(root_chirho, branch_chirho, to_chirho, "rollback")
}

/// Move a branch only if its current head still matches `expected`.
pub fn compare_and_set_branch_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    expected_chirho: &HashChirho,
    to_chirho: HashChirho,
    reason_chirho: &str,
) -> Result<()> {
    let mut refs_chirho = load_refs_chirho(root_chirho)?;
    let current_chirho = refs_chirho
        .branches_chirho
        .get(branch_chirho)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no such branch '{branch_chirho}' to move"))?;
    if &current_chirho != expected_chirho {
        bail!(
            "branch '{branch_chirho}' moved from expected {} to {}; re-derive the rollback plan",
            expected_chirho.0,
            current_chirho.0
        );
    }
    ensure_object_exists_chirho(root_chirho, &to_chirho)?;
    refs_chirho
        .branches_chirho
        .insert(branch_chirho.to_string(), to_chirho.clone());
    save_refs_chirho(root_chirho, &refs_chirho)?;
    append_reflog_chirho(
        root_chirho,
        &ReflogEntryChirho {
            branch_chirho: branch_chirho.to_string(),
            from_chirho: Some(current_chirho),
            to_chirho,
            reason_chirho: reason_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            schema_chirho: String::new(),
            transition_id_chirho: String::new(),
            family_log_chirho: String::new(),
            family_seq_chirho: None,
            family_line_digest_chirho: String::new(),
            writer_fence_group_digest_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            applied_writer_fence_epoch_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
    )
}

/// Commit a mutable head while the caller already holds the store-wide append lock.
///
/// This function does not take any process or distributed writer token. It only performs the
/// lock-free refs update once the caller has provided the local critical section.
pub fn commit_head_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    precondition_chirho: HeadPreconditionChirho,
    to_chirho: HashChirho,
    reason_chirho: &str,
) -> Result<()> {
    ensure_object_exists_chirho(root_chirho, &to_chirho)?;
    let mut refs_chirho = load_refs_chirho(root_chirho)?;
    let current_chirho = refs_chirho.branches_chirho.get(branch_chirho).cloned();
    match &precondition_chirho {
        HeadPreconditionChirho::ExpectedChirho(expected_chirho) => {
            let Some(current_chirho) = &current_chirho else {
                bail!("no such branch '{branch_chirho}' to move");
            };
            if current_chirho != expected_chirho {
                bail!(
                    "branch '{branch_chirho}' moved from expected {} to {}; re-derive the head commit",
                    expected_chirho.0,
                    current_chirho.0
                );
            }
        }
        HeadPreconditionChirho::AbsentChirho => {
            if let Some(current_chirho) = &current_chirho {
                bail!(
                    "branch '{branch_chirho}' already exists at {}; expected absent head",
                    current_chirho.0
                );
            }
        }
        HeadPreconditionChirho::AnyCurrentChirho => {}
    }
    refs_chirho
        .branches_chirho
        .insert(branch_chirho.to_string(), to_chirho.clone());
    save_refs_chirho(root_chirho, &refs_chirho)?;
    append_reflog_chirho(
        root_chirho,
        &ReflogEntryChirho {
            branch_chirho: branch_chirho.to_string(),
            from_chirho: current_chirho,
            to_chirho,
            reason_chirho: reason_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            schema_chirho: String::new(),
            transition_id_chirho: String::new(),
            family_log_chirho: String::new(),
            family_seq_chirho: None,
            family_line_digest_chirho: String::new(),
            writer_fence_group_digest_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            applied_writer_fence_epoch_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
    )
}

/// Complete one caller-verified transition while the caller holds the writer and append locks.
///
/// This is a mechanism-only primitive. It neither verifies receipt signatures nor decides that a
/// reflog row is authoritative; the reviewed writer-head boundary owns those trust decisions.
pub fn commit_head_with_transition_receipt_chirho(
    root_chirho: &Path,
    receipt_chirho: &ReflogEntryChirho,
) -> Result<HeadTransitionCommitOutcomeChirho> {
    if receipt_chirho.transition_id_chirho.is_empty() {
        bail!("head transition receipt requires transition_id_chirho");
    }
    if receipt_chirho.from_chirho.as_ref() == Some(&receipt_chirho.to_chirho) {
        bail!("head transition receipt must move to a different hash");
    }
    ensure_object_exists_chirho(root_chirho, &receipt_chirho.to_chirho)?;

    let matching_receipts_chirho = reflog_chirho(root_chirho)?
        .into_iter()
        .filter(|entry_chirho| {
            entry_chirho.transition_id_chirho == receipt_chirho.transition_id_chirho
        })
        .collect::<Vec<_>>();
    match matching_receipts_chirho.as_slice() {
        [] => {}
        [recorded_chirho] if recorded_chirho == receipt_chirho => {
            return Ok(HeadTransitionCommitOutcomeChirho::AlreadyRecordedChirho);
        }
        [recorded_chirho] => {
            bail!(
                "head transition '{}' reflog receipt differs from the caller-verified receipt: {:?}",
                receipt_chirho.transition_id_chirho,
                recorded_chirho
            );
        }
        _ => {
            bail!(
                "head transition '{}' has duplicate reflog receipts",
                receipt_chirho.transition_id_chirho
            );
        }
    }

    let mut refs_chirho = load_refs_chirho(root_chirho)?;
    let current_chirho = refs_chirho
        .branches_chirho
        .get(&receipt_chirho.branch_chirho)
        .cloned();
    let outcome_chirho = if current_chirho == receipt_chirho.from_chirho {
        refs_chirho.branches_chirho.insert(
            receipt_chirho.branch_chirho.clone(),
            receipt_chirho.to_chirho.clone(),
        );
        save_refs_chirho(root_chirho, &refs_chirho)?;
        HeadTransitionCommitOutcomeChirho::AppliedChirho
    } else if current_chirho == Some(receipt_chirho.to_chirho.clone()) {
        HeadTransitionCommitOutcomeChirho::RepairedReflogChirho
    } else {
        bail!(
            "head transition '{}' branch '{}' is at {:?}, expected {:?} or {}",
            receipt_chirho.transition_id_chirho,
            receipt_chirho.branch_chirho,
            current_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str()),
            receipt_chirho
                .from_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.as_str()),
            receipt_chirho.to_chirho.0
        );
    };
    append_reflog_chirho(root_chirho, receipt_chirho)?;
    Ok(outcome_chirho)
}

/// Remove a branch ref (e.g. undeploy an app). Returns whether it existed. Objects stay in the
/// content-addressed store (gc reclaims them later) — only the movable ref is dropped.
pub fn remove_branch_chirho(root_chirho: &Path, branch_chirho: &str) -> Result<bool> {
    let mut refs_chirho = load_refs_chirho(root_chirho)?;
    let existed_chirho = refs_chirho.branches_chirho.remove(branch_chirho).is_some();
    if existed_chirho {
        save_refs_chirho(root_chirho, &refs_chirho)?;
    }
    Ok(existed_chirho)
}

/// The shared mechanism behind `set_branch` and `rollback`: update the ref, log the move.
fn move_branch_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    to_chirho: HashChirho,
    reason_chirho: &str,
) -> Result<()> {
    let mut refs_chirho = load_refs_chirho(root_chirho)?;
    let from_chirho = refs_chirho.branches_chirho.get(branch_chirho).cloned();
    refs_chirho
        .branches_chirho
        .insert(branch_chirho.to_string(), to_chirho.clone());
    save_refs_chirho(root_chirho, &refs_chirho)?;
    append_reflog_chirho(
        root_chirho,
        &ReflogEntryChirho {
            branch_chirho: branch_chirho.to_string(),
            from_chirho,
            to_chirho,
            reason_chirho: reason_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            schema_chirho: String::new(),
            transition_id_chirho: String::new(),
            family_log_chirho: String::new(),
            family_seq_chirho: None,
            family_line_digest_chirho: String::new(),
            writer_fence_group_digest_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            applied_writer_fence_epoch_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        },
    )
}

fn append_reflog_chirho(root_chirho: &Path, entry_chirho: &ReflogEntryChirho) -> Result<()> {
    let mut line_chirho = serde_json::to_vec(entry_chirho).context("encode reflog entry")?;
    line_chirho.push(b'\n');
    append_durable_line_chirho(&reflog_path_chirho(root_chirho), &line_chirho)
        .context("append reflog-chirho.jsonl")?;
    Ok(())
}

fn ensure_object_exists_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> Result<()> {
    cas_chirho::get_chirho(root_chirho, hash_chirho)
        .with_context(|| format!("target object {} is not in the store", hash_chirho.0))?;
    Ok(())
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-refs-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn branch_then_rollback_records_reflog_chirho() {
        let root_chirho = tmp_root_chirho();
        let h1_chirho = cas_chirho::add_chirho(&root_chirho, b"version one").unwrap();
        let h2_chirho = cas_chirho::add_chirho(&root_chirho, b"version two").unwrap();

        set_branch_chirho(&root_chirho, "main", h2_chirho.clone()).unwrap();
        assert_eq!(
            load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("main"),
            Some(&h2_chirho)
        );

        rollback_chirho(&root_chirho, "main", h1_chirho.clone()).unwrap();
        assert_eq!(
            load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("main"),
            Some(&h1_chirho)
        );

        let log_chirho = reflog_chirho(&root_chirho).unwrap();
        assert_eq!(log_chirho.len(), 2);
        assert_eq!(log_chirho[0].reason_chirho, "branch");
        assert_eq!(log_chirho[1].reason_chirho, "rollback");
        assert_eq!(log_chirho[1].from_chirho.as_ref(), Some(&h2_chirho));
        assert_eq!(log_chirho[1].to_chirho, h1_chirho);

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn rollback_unknown_branch_errors_chirho() {
        let root_chirho = tmp_root_chirho();
        let h_chirho = cas_chirho::add_chirho(&root_chirho, b"x").unwrap();
        assert!(rollback_chirho(&root_chirho, "ghost", h_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn set_branch_to_missing_object_errors_chirho() {
        let root_chirho = tmp_root_chirho();
        assert!(
            set_branch_chirho(&root_chirho, "main", HashChirho("deadbeef".to_string())).is_err()
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn commit_head_absent_rejects_existing_branch_chirho() {
        let root_chirho = tmp_root_chirho();
        let h1_chirho = cas_chirho::add_chirho(&root_chirho, b"version one").unwrap();
        let h2_chirho = cas_chirho::add_chirho(&root_chirho, b"version two").unwrap();
        commit_head_chirho(
            &root_chirho,
            "main",
            HeadPreconditionChirho::AbsentChirho,
            h1_chirho.clone(),
            "head-commit-test",
        )
        .unwrap();
        let error_chirho = commit_head_chirho(
            &root_chirho,
            "main",
            HeadPreconditionChirho::AbsentChirho,
            h2_chirho,
            "head-commit-test",
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("expected absent head"));
        assert_eq!(
            load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("main"),
            Some(&h1_chirho)
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn commit_head_stale_expected_fails_closed_chirho() {
        let root_chirho = tmp_root_chirho();
        let h1_chirho = cas_chirho::add_chirho(&root_chirho, b"version one").unwrap();
        let h2_chirho = cas_chirho::add_chirho(&root_chirho, b"version two").unwrap();
        let h3_chirho = cas_chirho::add_chirho(&root_chirho, b"version three").unwrap();
        commit_head_chirho(
            &root_chirho,
            "main",
            HeadPreconditionChirho::AbsentChirho,
            h1_chirho.clone(),
            "head-commit-test",
        )
        .unwrap();
        commit_head_chirho(
            &root_chirho,
            "main",
            HeadPreconditionChirho::ExpectedChirho(h1_chirho.clone()),
            h2_chirho.clone(),
            "head-commit-test",
        )
        .unwrap();
        let error_chirho = commit_head_chirho(
            &root_chirho,
            "main",
            HeadPreconditionChirho::ExpectedChirho(h1_chirho),
            h3_chirho,
            "head-commit-test",
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("moved from expected"));
        assert_eq!(
            load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("main"),
            Some(&h2_chirho)
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn legacy_reflog_serialization_stays_byte_identical_chirho() {
        let entry_chirho = ReflogEntryChirho {
            branch_chirho: "main".to_string(),
            from_chirho: Some(HashChirho("a".repeat(64))),
            to_chirho: HashChirho("b".repeat(64)),
            reason_chirho: "rollback".to_string(),
            at_ms_chirho: 123_456,
            schema_chirho: String::new(),
            transition_id_chirho: String::new(),
            family_log_chirho: String::new(),
            family_seq_chirho: None,
            family_line_digest_chirho: String::new(),
            writer_fence_group_digest_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            applied_writer_fence_epoch_chirho: None,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        };
        let expected_chirho = r#"{"branch_chirho":"main","from_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","to_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","reason_chirho":"rollback","at_ms_chirho":123456}"#;
        let encoded_chirho = serde_json::to_string(&entry_chirho).unwrap();
        assert_eq!(encoded_chirho, expected_chirho);
        assert_eq!(
            serde_json::to_string(
                &serde_json::from_str::<ReflogEntryChirho>(expected_chirho).unwrap()
            )
            .unwrap(),
            expected_chirho
        );
    }

    #[test]
    fn transition_receipt_core_applies_then_is_idempotent_chirho() {
        let root_chirho = tmp_root_chirho();
        let next_chirho = cas_chirho::add_chirho(&root_chirho, b"transition next").unwrap();
        let receipt_chirho = ReflogEntryChirho {
            branch_chirho: "transition/main".to_string(),
            from_chirho: None,
            to_chirho: next_chirho.clone(),
            reason_chirho: "synthetic-transition".to_string(),
            at_ms_chirho: 321,
            schema_chirho: "head-transition-receipt-v1-chirho".to_string(),
            transition_id_chirho: "head-transition-blake3-v1-chirho:test".to_string(),
            family_log_chirho: "synthetic-head-records-chirho.jsonl".to_string(),
            family_seq_chirho: Some(0),
            family_line_digest_chirho: "head-transition-family-line-blake3-v1-chirho:test"
                .to_string(),
            writer_fence_group_digest_chirho: "writer-fence-group-blake3-chirho:test".to_string(),
            prepared_writer_fence_epoch_chirho: Some(1),
            applied_writer_fence_epoch_chirho: Some(1),
            key_id_chirho: "mechanism-only".to_string(),
            sig_chirho: "not-verified-by-core".to_string(),
        };
        assert_eq!(
            commit_head_with_transition_receipt_chirho(&root_chirho, &receipt_chirho).unwrap(),
            HeadTransitionCommitOutcomeChirho::AppliedChirho
        );
        assert_eq!(
            commit_head_with_transition_receipt_chirho(&root_chirho, &receipt_chirho).unwrap(),
            HeadTransitionCommitOutcomeChirho::AlreadyRecordedChirho
        );
        assert_eq!(
            load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("transition/main"),
            Some(&next_chirho)
        );
        assert_eq!(reflog_chirho(&root_chirho).unwrap(), vec![receipt_chirho]);
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
