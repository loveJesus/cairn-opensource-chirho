// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A crash-safe raft `Storage` for the election-only writer elector. It keeps an in-memory `MemStorage`
//! mirror (so every raft read is correct and fast) and, when a directory is configured, DURABLY persists
//! the hard state, conf state, and log entries — so a crash + restart recovers the term and the vote and
//! can NEVER double-vote in a term it already voted in (the safety property `MemStorage` alone could not
//! give). An ephemeral store (no directory) is the same `MemStorage` with no persistence, for tests and
//! shadow runs that do not need recovery. Election-only logs stay tiny, so there is deliberately no
//! compaction/snapshot path here (a future clustered elector that keeps a long log would add one).
//!
//! Durability order matches raft's persist-before-ack contract: `drain_ready` persists entries and then
//! the hard state (each fsync'd) BEFORE it releases the "persisted" messages, so an acknowledged entry is
//! always already on disk. The entries log is append-only and length-framed, so a crash mid-append leaves
//! at most a torn FINAL record, which the reader detects and drops; the hard/conf state use atomic
//! temp+rename replacement, so a reader sees either the old or the new complete file, never a torn one.

// prost-generated eraftpb structs (ConfState, …) carry version-specific hidden fields, so the robust,
// idiomatic way to build one is `default()` + field assignment rather than a struct literal.
#![allow(clippy::field_reassign_with_default)]

use anyhow::{anyhow, bail, Result};
use cairn_durable_chirho::{append_durable_line_chirho, write_file_durable_chirho};
use prost::Message as ProstMessageChirho;
use raft::eraftpb::{ConfState, Entry, HardState, Snapshot};
use raft::storage::{MemStorage, Storage};
use raft::{GetEntriesContext, RaftState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The atomically-replaced hard-state file (term, vote, commit) — the vote is the safety-critical datum.
const HARD_STATE_FILE_CHIRHO: &str = "raft-hardstate-chirho.bin";
/// The legacy conf-state file: bare `ConfState` prost bytes, no applied index. Written by pre-A1
/// (fixed-membership) stores. Still READ on open for backward compatibility (applied index := 0), but
/// never written — a store that has applied a membership change writes the membership file below.
const CONF_STATE_FILE_CHIRHO: &str = "raft-confstate-chirho.bin";
/// The A1 membership file (R1): a SINGLE atomically-replaced file carrying BOTH the current `ConfState`
/// (the voter/learner set) AND the applied index at which it was last written — an 8-byte little-endian
/// applied index followed by the prost-encoded `ConfState`. One file makes the "crash between the
/// conf-state write and a separate applied-index marker" window unrepresentable: a reader sees either
/// the old complete pair or the new complete pair, and the applied index it carries always matches the
/// membership it carries.
const MEMBERSHIP_FILE_CHIRHO: &str = "raft-membership-chirho.bin";
/// The append-only, length-framed log of appended entries, replayed in order on open.
const ENTRIES_LOG_FILE_CHIRHO: &str = "raft-entries-chirho.log";

/// A durable, election-only raft store: a `MemStorage` mirror for reads plus optional on-disk
/// persistence of the hard state, conf state, and entries log. Cheap to `clone` (the mirror is an `Arc`
/// internally and the directory is just a path), which `drain_ready` relies on.
#[derive(Clone)]
pub struct DurableRaftStoreChirho {
    mem_chirho: MemStorage,
    dir_chirho: Option<PathBuf>,
    /// The applied index to feed `RawNode` at construction: the MIN of the membership file's applied
    /// index (0 if none) and the durable hard-state commit, so applied can never exceed commit and
    /// `RawNode::new` cannot panic ("applied out of range"). Feeding it makes a committed-but-unpersisted
    /// conf change re-surface exactly once (and an already-persisted one not at all). Read-only after
    /// open; the live applied index is raft's own once running.
    recovered_applied_index_chirho: u64,
    /// In-process mirror of the applied configuration index carried by the same durable membership
    /// record as `ConfState`. It advances only after the atomic membership-file replacement succeeds,
    /// so a coherent election observation may lag after a failed write but can never lead durability.
    current_applied_conf_index_chirho: Arc<AtomicU64>,
}

impl DurableRaftStoreChirho {
    /// An ephemeral (non-persisted) store seeded with the voter set — for tests and shadow runs that do
    /// not need crash recovery. Behaves exactly like the bare `MemStorage` it wraps.
    pub fn ephemeral_chirho(voter_ids_chirho: Vec<u64>) -> Self {
        Self::ephemeral_with_learners_chirho(voter_ids_chirho, Vec::new())
    }

    /// An ephemeral store seeded with voters AND non-voting learners (async DR replicas that replicate the
    /// log but do not count toward the commit quorum and cannot be elected).
    pub fn ephemeral_with_learners_chirho(
        voter_ids_chirho: Vec<u64>,
        learner_ids_chirho: Vec<u64>,
    ) -> Self {
        Self {
            mem_chirho: MemStorage::new_with_conf_state(conf_state_chirho(
                voter_ids_chirho,
                learner_ids_chirho,
            )),
            dir_chirho: None,
            recovered_applied_index_chirho: 0,
            current_applied_conf_index_chirho: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Open (creating if absent) a durable store in `dir_chirho`, recovering any persisted conf state,
    /// entries, and hard state. On first open the passed voter set seeds and durably persists the conf
    /// state; on a later open the persisted conf state wins (the voter set is fixed for this group).
    pub fn open_chirho(dir_chirho: PathBuf, voter_ids_chirho: Vec<u64>) -> Result<Self> {
        Self::open_with_learners_chirho(dir_chirho, voter_ids_chirho, Vec::new())
    }

    /// Reopen a previously initialized durable store without creating a directory or seeding a new
    /// membership history. Authority-bearing serving uses this form so missing election state
    /// refuses instead of silently becoming a new single-node generation.
    pub fn open_existing_chirho(dir_chirho: PathBuf, voter_ids_chirho: Vec<u64>) -> Result<Self> {
        Self::open_existing_with_learners_chirho(dir_chirho, voter_ids_chirho, Vec::new())
    }

    /// Existing-only twin of [`Self::open_with_learners_chirho`].
    pub fn open_existing_with_learners_chirho(
        dir_chirho: PathBuf,
        voter_ids_chirho: Vec<u64>,
        learner_ids_chirho: Vec<u64>,
    ) -> Result<Self> {
        Self::open_with_mode_chirho(dir_chirho, voter_ids_chirho, learner_ids_chirho, true)
    }

    /// Open a durable store seeded with voters AND non-voting learners (the durable form of
    /// `ephemeral_with_learners_chirho`); the persisted conf state (voters + learners) wins on reopen.
    pub fn open_with_learners_chirho(
        dir_chirho: PathBuf,
        voter_ids_chirho: Vec<u64>,
        learner_ids_chirho: Vec<u64>,
    ) -> Result<Self> {
        Self::open_with_mode_chirho(dir_chirho, voter_ids_chirho, learner_ids_chirho, false)
    }

    fn open_with_mode_chirho(
        dir_chirho: PathBuf,
        voter_ids_chirho: Vec<u64>,
        learner_ids_chirho: Vec<u64>,
        existing_only_chirho: bool,
    ) -> Result<Self> {
        if existing_only_chirho {
            let directory_metadata_chirho = std::fs::symlink_metadata(&dir_chirho)?;
            if directory_metadata_chirho.file_type().is_symlink()
                || !directory_metadata_chirho.is_dir()
            {
                bail!("durable raft store is not an existing regular directory");
            }
        } else {
            std::fs::create_dir_all(&dir_chirho)?;
        }
        // Recover the membership + applied index, preferring the A1 membership file (conf state AND
        // applied index in one atomic record), then the legacy conf-state file (applied index := 0),
        // then seeding from the passed sets on a truly fresh directory.
        let (conf_chirho, membership_applied_index_chirho) =
            match read_membership_file_chirho(&dir_chirho.join(MEMBERSHIP_FILE_CHIRHO))? {
                Some(pair_chirho) => pair_chirho,
                None => {
                    match read_prost_file_chirho::<ConfState>(
                        &dir_chirho.join(CONF_STATE_FILE_CHIRHO),
                    )? {
                        Some(legacy_conf_chirho) => (legacy_conf_chirho, 0),
                        None => {
                            if existing_only_chirho {
                                bail!("durable raft store has no existing membership state");
                            }
                            let seed_chirho =
                                conf_state_chirho(voter_ids_chirho, learner_ids_chirho);
                            write_membership_file_chirho(
                                &dir_chirho.join(MEMBERSHIP_FILE_CHIRHO),
                                &seed_chirho,
                                0,
                            )?;
                            (seed_chirho, 0)
                        }
                    }
                }
            };
        let mem_chirho = MemStorage::new_with_conf_state(conf_chirho);
        // Replay the append-only entries log, one entry at a time and IN ORDER, so raft's own
        // truncate-on-conflict `append` reproduces the exact log the live node last held.
        for entry_chirho in read_entries_log_chirho(&dir_chirho.join(ENTRIES_LOG_FILE_CHIRHO))? {
            mem_chirho
                .wl()
                .append(&[entry_chirho])
                .map_err(|e_chirho| anyhow!("replay raft entry: {e_chirho}"))?;
        }
        let durable_commit_chirho = if let Some(mut hard_state_chirho) =
            read_prost_file_chirho::<HardState>(&dir_chirho.join(HARD_STATE_FILE_CHIRHO))?
        {
            // Defensive clamp: a persisted commit can never legitimately exceed the recovered log (raft
            // persists entries before advancing commit), but if a subtly-inconsistent file said so,
            // `RawNode::new` would panic on load. Clamping to the last recovered index is always safe.
            let last_index_chirho = mem_chirho.last_index().unwrap_or(0);
            if hard_state_chirho.commit > last_index_chirho {
                hard_state_chirho.commit = last_index_chirho;
            }
            let commit_chirho = hard_state_chirho.commit;
            mem_chirho.wl().set_hardstate(hard_state_chirho);
            commit_chirho
        } else {
            0
        };
        // Belt-and-braces: the applied index fed to `RawNode` must never exceed the durable commit, or
        // `RawNode::new` panics (`applied out of range`). A crash between a membership apply (which
        // persists applied=i) and its ready's hard-state write (commit=i) would leave applied ahead of
        // commit; clamp it down. Safe because re-applying the committed membership change is idempotent
        // (proven): the clamped node re-surfaces the committed entry, re-applies, and converges — this
        // also heals a historical or hand-restored root instead of boot-looping forever.
        let recovered_applied_index_chirho =
            membership_applied_index_chirho.min(durable_commit_chirho);
        Ok(Self {
            mem_chirho,
            dir_chirho: Some(dir_chirho),
            recovered_applied_index_chirho,
            current_applied_conf_index_chirho: Arc::new(AtomicU64::new(
                membership_applied_index_chirho,
            )),
        })
    }

    /// The applied index recovered on open — fed to `RawNode` as `Config.applied` so a committed conf
    /// change whose persist did not complete before a crash re-surfaces exactly once (0 on a fresh or
    /// legacy store).
    pub fn recovered_applied_index_chirho(&self) -> u64 {
        self.recovered_applied_index_chirho
    }

    /// The current applied configuration index without filesystem I/O. This is paired with the
    /// in-memory `ConfState` under the elector's raw-node lock when one coherent production election
    /// observation is needed. The value is updated only after durable membership persistence succeeds.
    pub fn current_applied_conf_index_chirho(&self) -> u64 {
        self.current_applied_conf_index_chirho
            .load(Ordering::Acquire)
    }

    /// The applied index in the durable membership file RIGHT NOW (0 on a fresh, legacy, or ephemeral
    /// store) — the live last-applied conf-change highwater, distinct from `recovered_applied_index_chirho`
    /// (the boot value) because runtime `ConfChange`s advance the on-disk marker via
    /// `set_conf_state_durable_chirho`. Read-only observability for the A1.5 `/membership-chirho` endpoint
    /// so a drill can assert the durable applied-index marker moved; never used for a correctness decision.
    pub fn durable_applied_conf_index_chirho(&self) -> Result<u64> {
        let Some(dir_chirho) = &self.dir_chirho else {
            return Ok(0); // ephemeral store: no durable marker
        };
        match read_membership_file_chirho(&dir_chirho.join(MEMBERSHIP_FILE_CHIRHO))? {
            Some((_conf_chirho, applied_index_chirho)) => Ok(applied_index_chirho),
            None => Ok(0),
        }
    }

    /// Apply a membership change durably (R1): set the new `ConfState` on the in-memory mirror AND write
    /// the membership file (conf state + the `applied_index_chirho` at which this change committed) as a
    /// SINGLE atomic replacement. Because the pair is one file, a reader can never see a new conf state
    /// with a stale applied index (or vice versa). Ephemeral stores update only the mirror.
    pub fn set_conf_state_durable_chirho(
        &self,
        conf_state_chirho: ConfState,
        applied_index_chirho: u64,
    ) -> Result<()> {
        if let Some(dir_chirho) = &self.dir_chirho {
            write_membership_file_chirho(
                &dir_chirho.join(MEMBERSHIP_FILE_CHIRHO),
                &conf_state_chirho,
                applied_index_chirho,
            )?;
        }
        self.mem_chirho.wl().set_conf_state(conf_state_chirho);
        self.current_applied_conf_index_chirho
            .store(applied_index_chirho, Ordering::Release);
        Ok(())
    }

    /// Append log entries to the mirror and, when durable, to the on-disk log — each fsync'd before this
    /// returns, so raft's persist-before-ack contract holds. The mirror append validates continuity
    /// first (it errors on a gap), so a bad batch never reaches disk.
    pub fn append_durable_chirho(&self, entries_chirho: &[Entry]) -> Result<()> {
        self.mem_chirho
            .wl()
            .append(entries_chirho)
            .map_err(|e_chirho| anyhow!("append raft entries to mirror: {e_chirho}"))?;
        if let Some(dir_chirho) = &self.dir_chirho {
            let path_chirho = dir_chirho.join(ENTRIES_LOG_FILE_CHIRHO);
            for entry_chirho in entries_chirho {
                append_durable_line_chirho(&path_chirho, &frame_entry_chirho(entry_chirho))?;
            }
        }
        Ok(())
    }

    /// Set the full hard state (term, vote, commit) on the mirror and durably (atomic replacement).
    pub fn set_hardstate_durable_chirho(&self, hard_state_chirho: HardState) -> Result<()> {
        self.mem_chirho
            .wl()
            .set_hardstate(hard_state_chirho.clone());
        self.persist_hard_state_chirho(&hard_state_chirho)
    }

    /// Advance just the commit index (one hard-state field) on the mirror and durably.
    pub fn set_commit_durable_chirho(&self, commit_chirho: u64) -> Result<()> {
        let hard_state_chirho = {
            let mut core_chirho = self.mem_chirho.wl();
            core_chirho.mut_hard_state().commit = commit_chirho;
            core_chirho.hard_state().clone()
        };
        self.persist_hard_state_chirho(&hard_state_chirho)
    }

    fn persist_hard_state_chirho(&self, hard_state_chirho: &HardState) -> Result<()> {
        if let Some(dir_chirho) = &self.dir_chirho {
            write_file_durable_chirho(
                &dir_chirho.join(HARD_STATE_FILE_CHIRHO),
                &hard_state_chirho.encode_to_vec(),
            )?;
        }
        Ok(())
    }
}

/// A `ConfState` with voters `voter_ids_chirho` and non-voting learners `learner_ids_chirho` (outgoing
/// empty — this elector has a fixed membership per group; learners replicate but never vote or win).
fn conf_state_chirho(voter_ids_chirho: Vec<u64>, learner_ids_chirho: Vec<u64>) -> ConfState {
    let mut conf_chirho = ConfState::default();
    conf_chirho.voters = voter_ids_chirho;
    conf_chirho.learners = learner_ids_chirho;
    conf_chirho
}

/// Frame one entry for the append-only log: a u32 little-endian length prefix + its prost bytes, so a
/// torn final record after a crash mid-append is detectable and skipped on replay.
fn frame_entry_chirho(entry_chirho: &Entry) -> Vec<u8> {
    let body_chirho = entry_chirho.encode_to_vec();
    let mut framed_chirho = Vec::with_capacity(4 + body_chirho.len());
    framed_chirho.extend_from_slice(&(body_chirho.len() as u32).to_le_bytes());
    framed_chirho.extend_from_slice(&body_chirho);
    framed_chirho
}

/// Read the append-only entries log, tolerating a torn FINAL record (a crash mid-append): parse
/// length-prefixed entries and stop at the first record whose body is not fully present.
fn read_entries_log_chirho(path_chirho: &Path) -> Result<Vec<Entry>> {
    let bytes_chirho = match std::fs::read(path_chirho) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e_chirho) => return Err(anyhow!("read raft entries log: {e_chirho}")),
    };
    let mut entries_chirho = Vec::new();
    let mut offset_chirho = 0usize;
    while offset_chirho + 4 <= bytes_chirho.len() {
        let len_chirho = u32::from_le_bytes(
            bytes_chirho[offset_chirho..offset_chirho + 4]
                .try_into()
                .expect("a 4-byte window is exactly a u32"),
        ) as usize;
        let start_chirho = offset_chirho + 4;
        let end_chirho = start_chirho + len_chirho;
        if end_chirho > bytes_chirho.len() {
            // Torn final record from a crash mid-append: stop at the last complete entry.
            break;
        }
        let entry_chirho = Entry::decode(&bytes_chirho[start_chirho..end_chirho])
            .map_err(|e_chirho| anyhow!("decode raft entry from log: {e_chirho}"))?;
        entries_chirho.push(entry_chirho);
        offset_chirho = end_chirho;
    }
    Ok(entries_chirho)
}

/// Serialize the membership record: an 8-byte little-endian applied index followed by the prost-encoded
/// `ConfState`. The fixed-width prefix makes parsing unambiguous and keeps the pair inseparable.
fn encode_membership_chirho(conf_state_chirho: &ConfState, applied_index_chirho: u64) -> Vec<u8> {
    let conf_bytes_chirho = conf_state_chirho.encode_to_vec();
    let mut out_chirho = Vec::with_capacity(8 + conf_bytes_chirho.len());
    out_chirho.extend_from_slice(&applied_index_chirho.to_le_bytes());
    out_chirho.extend_from_slice(&conf_bytes_chirho);
    out_chirho
}

/// Write the membership file atomically (temp + rename via the durable writer), so a reader sees either
/// the old or the new complete `(applied_index, conf_state)` pair, never a torn one.
fn write_membership_file_chirho(
    path_chirho: &Path,
    conf_state_chirho: &ConfState,
    applied_index_chirho: u64,
) -> Result<()> {
    write_file_durable_chirho(
        path_chirho,
        &encode_membership_chirho(conf_state_chirho, applied_index_chirho),
    )
    .map_err(|e_chirho| anyhow!("write raft membership file: {e_chirho}"))
}

/// Read the membership file, returning `(conf_state, applied_index)` or `None` if it does not exist. A
/// present file shorter than the 8-byte applied-index prefix is a corruption, not a legacy file (the
/// legacy conf-state file has a different name), so it errors rather than being silently misread.
fn read_membership_file_chirho(path_chirho: &Path) -> Result<Option<(ConfState, u64)>> {
    let bytes_chirho = match std::fs::read(path_chirho) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e_chirho) => return Err(anyhow!("read raft membership file: {e_chirho}")),
    };
    if bytes_chirho.len() < 8 {
        return Err(anyhow!(
            "raft membership file is {} bytes, shorter than the 8-byte applied-index prefix",
            bytes_chirho.len()
        ));
    }
    let applied_index_chirho = u64::from_le_bytes(
        bytes_chirho[..8]
            .try_into()
            .expect("an 8-byte window is exactly a u64"),
    );
    let conf_state_chirho = ConfState::decode(&bytes_chirho[8..])
        .map_err(|e_chirho| anyhow!("decode conf state from membership file: {e_chirho}"))?;
    Ok(Some((conf_state_chirho, applied_index_chirho)))
}

/// Read a prost-encoded state file, returning `None` if it does not exist. (A 0-byte file decodes to the
/// all-default message, which is the correct round-trip of an all-zero `HardState`.)
fn read_prost_file_chirho<T: ProstMessageChirho + Default>(
    path_chirho: &Path,
) -> Result<Option<T>> {
    match std::fs::read(path_chirho) {
        Ok(bytes_chirho) => {
            Ok(Some(T::decode(&bytes_chirho[..]).map_err(|e_chirho| {
                anyhow!("decode persisted raft state: {e_chirho}")
            })?))
        }
        Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e_chirho) => Err(anyhow!("read persisted raft state: {e_chirho}")),
    }
}

impl Storage for DurableRaftStoreChirho {
    fn initial_state(&self) -> raft::Result<RaftState> {
        self.mem_chirho.initial_state()
    }

    fn entries(
        &self,
        low_chirho: u64,
        high_chirho: u64,
        max_size_chirho: impl Into<Option<u64>>,
        context_chirho: GetEntriesContext,
    ) -> raft::Result<Vec<Entry>> {
        self.mem_chirho
            .entries(low_chirho, high_chirho, max_size_chirho, context_chirho)
    }

    fn term(&self, idx_chirho: u64) -> raft::Result<u64> {
        self.mem_chirho.term(idx_chirho)
    }

    fn first_index(&self) -> raft::Result<u64> {
        self.mem_chirho.first_index()
    }

    fn last_index(&self) -> raft::Result<u64> {
        self.mem_chirho.last_index()
    }

    fn snapshot(&self, request_index_chirho: u64, to_chirho: u64) -> raft::Result<Snapshot> {
        self.mem_chirho.snapshot(request_index_chirho, to_chirho)
    }
}
