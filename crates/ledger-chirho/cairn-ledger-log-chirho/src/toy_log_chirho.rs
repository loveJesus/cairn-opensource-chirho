// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A TOY append-only log with crash-recoverable rotation over `LedgerStoragePortChirho` — the
//! minimal engine the Brick 2.0 proof harness exercises.
//!
//! It enforces the two fence invariants — F1 (each seq is appended exactly once: no gap, no
//! duplicate) and F2 (R-3a-1: each record carries the CURRENT SHARD LEASE handed to append, `e == E`,
//! and that lease is monotone non-decreasing along the chain, so a stale OR forged-future epoch is
//! fenced out) — and a crash-recoverable rotation that seals the active file into a numbered segment
//! (the RC4 D5 cut sequence, minimal: marker -> seal-rename -> fresh-active -> clear-marker). It is
//! NOT the money core (Brick 2.1): it exists only so the ports, the sim fault injection, and the
//! stateright models are validated on something small before real ledger authority trusts them.
//!
//! All state lives under one base prefix in the storage port: `<base>/active`, `<base>/rotation-marker`,
//! and `<base>/segment-NNNNNNNN`. It reads whole files per op — fine for a toy; the O(1) head
//! checkpoint that keeps the real core cheap is a Brick 2.1 concern.

use anyhow::{bail, Context, Result};
use cairn_ledger_model_chirho::{LedgerToyRecordChirho, ShardEpochChirho};
use serde::{Deserialize, Serialize};

use crate::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};

/// The outcome of an append attempt: applied, or fenced out (with why). Distinct from a storage
/// error, which surfaces as `Err` — a fence rejection is a normal, expected protocol answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppendOutcomeChirho {
    /// The record passed the fence and was durably appended.
    AppendedChirho,
    /// Rejected: the record's seq was not exactly tail+1 (F1 — no gap, no duplicate).
    RejectedSeqChirho {
        expected_chirho: u64,
        got_chirho: u64,
    },
    /// Rejected: the record's epoch does not match the current shard lease handed to append (R-3a-1 —
    /// a forged or future never-granted epoch), or that lease is behind the chain tail (a stale lease
    /// fenced by a newer chain entry). All three epochs are named so either failure is legible.
    RejectedEpochChirho {
        record_epoch_chirho: ShardEpochChirho,
        lease_epoch_chirho: ShardEpochChirho,
        chain_fence_chirho: ShardEpochChirho,
    },
}

/// The durable marker written first in a rotation, naming the segment the active file is being sealed
/// as. Its presence means a rotation is in flight and must be recovered before any append or rotate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationMarkerChirho {
    pub target_segment_chirho: u64,
}

/// What `recover_chirho` did — which cut it found the machine crashed at and finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcomeChirho {
    /// No marker present — nothing to recover.
    CleanChirho,
    /// Crashed after the marker, before the seal rename — finished seal + fresh active + clear.
    FinishedSealChirho,
    /// Crashed after the seal, before the fresh active — finished fresh active + clear.
    FinishedActiveChirho,
    /// Crashed after the fresh active, before clearing the marker — cleared it.
    FinishedClearChirho,
}

/// The outcome of a rotation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationOutcomeChirho {
    /// The active file was sealed into a fresh numbered segment.
    RotatedChirho,
    /// The active was absent or empty — nothing was sealed and NO marker was written (R-3b-1: an
    /// empty segment is never constructed, which would otherwise wedge recovery or reset the sequence).
    NothingToRotateChirho,
}

/// A toy append-only log rooted at one base prefix in a storage port.
pub struct ToyLogChirho<'s, S: LedgerStoragePortChirho> {
    storage_chirho: &'s S,
    base_chirho: String,
}

impl<'s, S: LedgerStoragePortChirho> ToyLogChirho<'s, S> {
    /// Bind a toy log rooted at `base` (all its files live under `<base>/...`).
    pub fn new_chirho(storage_chirho: &'s S, base_chirho: impl Into<String>) -> Self {
        Self {
            storage_chirho,
            base_chirho: base_chirho.into(),
        }
    }

    fn active_path_chirho(&self) -> StoragePathChirho {
        StoragePathChirho::new_chirho(format!("{}/active", self.base_chirho))
    }

    fn marker_path_chirho(&self) -> StoragePathChirho {
        StoragePathChirho::new_chirho(format!("{}/rotation-marker", self.base_chirho))
    }

    fn segment_path_chirho(&self, n_chirho: u64) -> StoragePathChirho {
        StoragePathChirho::new_chirho(format!("{}/segment-{n_chirho:08}", self.base_chirho))
    }

    fn segments_prefix_chirho(&self) -> StoragePathChirho {
        StoragePathChirho::new_chirho(format!("{}/segment-", self.base_chirho))
    }

    /// A rotation in flight blocks appends and new rotations until recovered — the marker is the
    /// barrier that keeps a half-sealed active from being written to or double-rotated.
    fn refuse_if_pending_chirho(&self) -> Result<()> {
        if self
            .storage_chirho
            .exists_chirho(&self.marker_path_chirho())?
        {
            bail!("toy-log-pending-rotation-chirho: recover before append/rotate");
        }
        Ok(())
    }

    fn parse_records_chirho(bytes_chirho: &[u8]) -> Result<Vec<LedgerToyRecordChirho>> {
        let mut out_chirho = Vec::new();
        for line_chirho in bytes_chirho.split(|byte_chirho| *byte_chirho == b'\n') {
            if line_chirho.is_empty() {
                continue;
            }
            let record_chirho: LedgerToyRecordChirho = serde_json::from_slice(line_chirho)
                .context("toy-log file has a malformed record line")?;
            out_chirho.push(record_chirho);
        }
        Ok(out_chirho)
    }

    /// Records currently durable in the active file (empty if absent).
    pub fn records_chirho(&self) -> Result<Vec<LedgerToyRecordChirho>> {
        let bytes_chirho = self
            .storage_chirho
            .read_all_chirho(&self.active_path_chirho())?
            .unwrap_or_default();
        Self::parse_records_chirho(&bytes_chirho)
    }

    /// The tail record of the active file (highest seq), or `None` if it is empty.
    pub fn tail_chirho(&self) -> Result<Option<LedgerToyRecordChirho>> {
        Ok(self.records_chirho()?.pop())
    }

    /// The tail record of the WHOLE log — the active file's tail, or (if the active is empty) the
    /// newest sealed segment's tail. This is what the append fence uses so the sequence CONTINUES
    /// across a rotation instead of resetting to 0 when the active is freshly emptied. (O(active + one
    /// segment); the real O(1) head is a 2.1 concern.)
    pub fn overall_tail_chirho(&self) -> Result<Option<LedgerToyRecordChirho>> {
        if let Some(active_tail_chirho) = self.tail_chirho()? {
            return Ok(Some(active_tail_chirho));
        }
        let segments_chirho = self.sealed_segments_chirho()?;
        if let Some(last_segment_chirho) = segments_chirho.last() {
            let bytes_chirho = self
                .storage_chirho
                .read_all_chirho(last_segment_chirho)?
                .unwrap_or_default();
            return Ok(Self::parse_records_chirho(&bytes_chirho)?.pop());
        }
        Ok(None)
    }

    /// The sealed segment paths, in ascending segment order.
    pub fn sealed_segments_chirho(&self) -> Result<Vec<StoragePathChirho>> {
        self.storage_chirho
            .list_chirho(&self.segments_prefix_chirho())
    }

    /// Every record across all sealed segments (in order) followed by the active file — the whole log
    /// as one sequence. Used to check F1/R1 (each seq appears exactly once) across a rotation.
    pub fn all_records_chirho(&self) -> Result<Vec<LedgerToyRecordChirho>> {
        let mut out_chirho = Vec::new();
        for segment_path_chirho in self.sealed_segments_chirho()? {
            let bytes_chirho = self
                .storage_chirho
                .read_all_chirho(&segment_path_chirho)?
                .unwrap_or_default();
            out_chirho.extend(Self::parse_records_chirho(&bytes_chirho)?);
        }
        out_chirho.extend(self.records_chirho()?);
        Ok(out_chirho)
    }

    /// Attempt to append `record` stamped by the writer holding `current_lease_epoch`, enforcing the
    /// fence (F1 seq, R-3a-1 lease-bound epoch). Returns the logical outcome; a storage crash — or a
    /// pending rotation — surfaces as `Err`.
    pub fn append_chirho(
        &self,
        record_chirho: LedgerToyRecordChirho,
        current_lease_epoch_chirho: ShardEpochChirho,
    ) -> Result<AppendOutcomeChirho> {
        self.refuse_if_pending_chirho()?;
        let (expected_seq_chirho, chain_fence_chirho) = match self.overall_tail_chirho()? {
            Some(tail_chirho) => (tail_chirho.seq_chirho + 1, tail_chirho.epoch_chirho),
            None => (0, 0),
        };
        if record_chirho.seq_chirho != expected_seq_chirho {
            return Ok(AppendOutcomeChirho::RejectedSeqChirho {
                expected_chirho: expected_seq_chirho,
                got_chirho: record_chirho.seq_chirho,
            });
        }
        // R-3a-1: the real append law is e == E (each record carries the CURRENT SHARD LEASE handed
        // in), not merely e >= chain-tail. A record claiming a future never-granted epoch
        // (record.epoch != lease) or a stale lease (lease < chain tail) is rejected; chain
        // monotonicity is kept as defense-in-depth so Model A can prove F3 against the engine itself.
        if record_chirho.epoch_chirho != current_lease_epoch_chirho
            || current_lease_epoch_chirho < chain_fence_chirho
        {
            return Ok(AppendOutcomeChirho::RejectedEpochChirho {
                record_epoch_chirho: record_chirho.epoch_chirho,
                lease_epoch_chirho: current_lease_epoch_chirho,
                chain_fence_chirho,
            });
        }
        let mut line_chirho =
            serde_json::to_vec(&record_chirho).context("toy-log record failed to serialize")?;
        line_chirho.push(b'\n');
        self.storage_chirho
            .append_durable_chirho(&self.active_path_chirho(), &line_chirho)?;
        Ok(AppendOutcomeChirho::AppendedChirho)
    }

    /// The number the next fresh rotation would seal into (one past the highest existing segment).
    fn next_segment_number_chirho(&self) -> Result<u64> {
        Ok(self.sealed_segments_chirho()?.len() as u64)
    }

    /// Seal the current active file into the next numbered segment and start a fresh active. The cut
    /// order is durable-marker first, so a crash at any point is recoverable by `recover_chirho`.
    /// Refuses to seal an absent or empty active (R-3b-1) — returns `NothingToRotateChirho` instead.
    pub fn rotate_chirho(&self) -> Result<RotationOutcomeChirho> {
        self.refuse_if_pending_chirho()?;
        // R-3b-1: refuse to seal an absent or empty active. Sealing nothing would either wedge
        // recovery (the seal rename ENOENTs after the marker is durable, leaving a marker no state can
        // resolve) or seal an EMPTY segment that makes overall_tail's newest-segment fallback return
        // None and reset the sequence (F1 resurrection). No empty segment is ever constructed.
        if self.records_chirho()?.is_empty() {
            return Ok(RotationOutcomeChirho::NothingToRotateChirho);
        }
        let target_chirho = self.next_segment_number_chirho()?;
        // W0: durable marker announcing the intended seal target.
        let marker_chirho = RotationMarkerChirho {
            target_segment_chirho: target_chirho,
        };
        self.storage_chirho.atomic_write_chirho(
            &self.marker_path_chirho(),
            &serde_json::to_vec(&marker_chirho).context("rotation marker failed to serialize")?,
        )?;
        // W1: seal — atomically rename active into the segment.
        self.storage_chirho.rename_chirho(
            &self.active_path_chirho(),
            &self.segment_path_chirho(target_chirho),
        )?;
        // W2: start a fresh empty active.
        self.storage_chirho
            .atomic_write_chirho(&self.active_path_chirho(), b"")?;
        // Clear the marker — rotation complete.
        self.storage_chirho
            .remove_chirho(&self.marker_path_chirho())?;
        Ok(RotationOutcomeChirho::RotatedChirho)
    }

    /// Reconcile a possibly-interrupted rotation. Idempotent: on a clean log it is a no-op, and
    /// re-running it after it finishes returns `CleanChirho`. Never duplicates or drops a segment.
    pub fn recover_chirho(&self) -> Result<RecoveryOutcomeChirho> {
        let marker_bytes_chirho = self
            .storage_chirho
            .read_all_chirho(&self.marker_path_chirho())?;
        let marker_chirho = match marker_bytes_chirho {
            None => return Ok(RecoveryOutcomeChirho::CleanChirho),
            Some(bytes_chirho) => serde_json::from_slice::<RotationMarkerChirho>(&bytes_chirho)
                .context("rotation marker is malformed")?,
        };
        let target_chirho = marker_chirho.target_segment_chirho;
        let active_exists_chirho = self
            .storage_chirho
            .exists_chirho(&self.active_path_chirho())?;
        let segment_exists_chirho = self
            .storage_chirho
            .exists_chirho(&self.segment_path_chirho(target_chirho))?;
        match (active_exists_chirho, segment_exists_chirho) {
            // Crashed after W0, before the seal rename: the seal never happened. Finish it.
            (true, false) => {
                self.storage_chirho.rename_chirho(
                    &self.active_path_chirho(),
                    &self.segment_path_chirho(target_chirho),
                )?;
                self.storage_chirho
                    .atomic_write_chirho(&self.active_path_chirho(), b"")?;
                self.storage_chirho.remove_chirho(&self.marker_path_chirho())?;
                Ok(RecoveryOutcomeChirho::FinishedSealChirho)
            }
            // Crashed after the seal, before the fresh active: segment is sealed, active is gone.
            (false, true) => {
                self.storage_chirho
                    .atomic_write_chirho(&self.active_path_chirho(), b"")?;
                self.storage_chirho.remove_chirho(&self.marker_path_chirho())?;
                Ok(RecoveryOutcomeChirho::FinishedActiveChirho)
            }
            // Crashed after the fresh active, before clearing the marker: everything is in place.
            (true, true) => {
                self.storage_chirho.remove_chirho(&self.marker_path_chirho())?;
                Ok(RecoveryOutcomeChirho::FinishedClearChirho)
            }
            // Atomic rename can never leave BOTH absent (it is active XOR segment). Refuse — R3.
            (false, false) => bail!(
                "toy-log-recover-ambiguous-chirho: marker names segment {target_chirho} but neither \
                 active nor that segment exists"
            ),
        }
    }
}
