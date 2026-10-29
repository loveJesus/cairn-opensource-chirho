// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! In-memory `LedgerStoragePortChirho` adapter with fault injection — the durable half of the sim.
//!
//! It models fsync-durable appends, atomic whole-object writes, atomic rename, and remove over an
//! in-memory object store, and injects torn writes / crashes from a [`FaultPlanChirho`] so the toy
//! log can be crash-tested at every rotation cut without touching a real disk. Single-threaded
//! (interior mutability via `RefCell`/`Cell`) because the whole sim is a deterministic schedule.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use anyhow::{bail, Result};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};

use crate::fault_chirho::{
    FaultKindChirho, FaultPlanChirho, ReadFaultKindChirho, ReadFaultPlanChirho,
};

/// One logical durability boundary exposed by [`LedgerStoragePortChirho`].
///
/// This records port calls, not an operating system's internal count of `fsync` syscalls. The CF1
/// write-amplification harness uses it to prove that the steady append path crosses the storage
/// durability port exactly once; a real adapter benchmark separately measures physical I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageMutationKindChirho {
    CreateDurableChirho,
    AppendDurableChirho,
    AtomicWriteChirho,
    RenameChirho,
    RemoveChirho,
    TruncateDurableChirho,
}

/// One attempted mutation, captured before its scripted fault is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageMutationEventChirho {
    pub index_chirho: u64,
    pub kind_chirho: StorageMutationKindChirho,
    pub primary_path_chirho: String,
    pub secondary_path_chirho: Option<String>,
}

/// Per-kind logical durability-call counts derived from the mutation trace.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageOperationCountsChirho {
    pub create_durable_calls_chirho: u64,
    pub append_durable_calls_chirho: u64,
    pub atomic_write_calls_chirho: u64,
    pub rename_calls_chirho: u64,
    pub remove_calls_chirho: u64,
    pub truncate_durable_calls_chirho: u64,
}

impl StorageOperationCountsChirho {
    /// Total attempted calls across the storage port's durable mutation methods.
    pub fn durability_call_count_chirho(self) -> u64 {
        self.create_durable_calls_chirho
            + self.append_durable_calls_chirho
            + self.atomic_write_calls_chirho
            + self.rename_calls_chirho
            + self.remove_calls_chirho
            + self.truncate_durable_calls_chirho
    }

    fn record_chirho(&mut self, kind_chirho: StorageMutationKindChirho) {
        match kind_chirho {
            StorageMutationKindChirho::CreateDurableChirho => {
                self.create_durable_calls_chirho += 1;
            }
            StorageMutationKindChirho::AppendDurableChirho => {
                self.append_durable_calls_chirho += 1;
            }
            StorageMutationKindChirho::AtomicWriteChirho => {
                self.atomic_write_calls_chirho += 1;
            }
            StorageMutationKindChirho::RenameChirho => {
                self.rename_calls_chirho += 1;
            }
            StorageMutationKindChirho::RemoveChirho => {
                self.remove_calls_chirho += 1;
            }
            StorageMutationKindChirho::TruncateDurableChirho => {
                self.truncate_durable_calls_chirho += 1;
            }
        }
    }
}

/// One logical READ the store served, for the read-amplification (D) evidence surface. The fence's
/// hot path must be `ObjectLen` + `ExactRange` only; a `FullRead` on the append/fence path is a
/// read-amplification regression (O(length) per append), which the D tests assert never happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageReadKindChirho {
    ObjectLenChirho,
    ExactRangeChirho,
    FullReadChirho,
}

/// One read the store served, captured with the requested window and how many bytes it returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageReadEventChirho {
    pub index_chirho: u64,
    pub kind_chirho: StorageReadKindChirho,
    pub path_chirho: String,
    /// The requested `(offset, len)` window — `None` for whole-object metadata / full reads.
    pub offset_chirho: Option<u64>,
    pub len_chirho: Option<u64>,
    /// Bytes the UNDERLYING read delivered/observed — NOT necessarily returned to the caller (check
    /// `ok_chirho`): a short read observes a partial prefix (`Some(2)`) that the adapter then rejects,
    /// while an absent / overflow / past-EOF read observes nothing (`None`).
    pub delivered_len_chirho: Option<u64>,
    pub ok_chirho: bool,
}

/// Per-kind read-call counts derived from the read trace — the D read-amplification surface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StorageReadCountsChirho {
    pub object_len_calls_chirho: u64,
    pub exact_range_calls_chirho: u64,
    pub full_read_calls_chirho: u64,
}

impl StorageReadCountsChirho {
    /// Total read calls across all three read methods.
    pub fn total_read_calls_chirho(self) -> u64 {
        self.object_len_calls_chirho + self.exact_range_calls_chirho + self.full_read_calls_chirho
    }

    fn record_chirho(&mut self, kind_chirho: StorageReadKindChirho) {
        match kind_chirho {
            StorageReadKindChirho::ObjectLenChirho => self.object_len_calls_chirho += 1,
            StorageReadKindChirho::ExactRangeChirho => self.exact_range_calls_chirho += 1,
            StorageReadKindChirho::FullReadChirho => self.full_read_calls_chirho += 1,
        }
    }
}

/// The inner range-read result plus how many bytes the UNDERLYING read observed. These differ on a
/// short read: the storage delivered a partial prefix (`observed_delivered = Some(2)`), which the
/// adapter then REJECTS — so the caller receives `Err` and zero bytes, yet the telemetry preserves that
/// a partial read happened (evidence D asked for), distinct from a read that delivered nothing.
struct RangeReadOutcomeChirho {
    result_chirho: Result<Vec<u8>>,
    observed_delivered_chirho: Option<u64>,
}

/// An in-memory, fault-injecting durable store.
pub struct SimStorageChirho {
    store_chirho: RefCell<BTreeMap<String, Vec<u8>>>,
    plan_chirho: FaultPlanChirho,
    mutating_op_count_chirho: Cell<u64>,
    mutation_trace_chirho: RefCell<Vec<StorageMutationEventChirho>>,
    crashed_chirho: Cell<bool>,
    read_plan_chirho: ReadFaultPlanChirho,
    range_read_count_chirho: Cell<u64>,
    read_trace_chirho: RefCell<Vec<StorageReadEventChirho>>,
}

impl SimStorageChirho {
    /// A fresh empty store under `plan` (no read faults; add them with `with_read_faults_chirho`).
    pub fn new_chirho(plan_chirho: FaultPlanChirho) -> Self {
        Self {
            store_chirho: RefCell::new(BTreeMap::new()),
            plan_chirho,
            mutating_op_count_chirho: Cell::new(0),
            mutation_trace_chirho: RefCell::new(Vec::new()),
            crashed_chirho: Cell::new(false),
            read_plan_chirho: ReadFaultPlanChirho::none_chirho(),
            range_read_count_chirho: Cell::new(0),
            read_trace_chirho: RefCell::new(Vec::new()),
        }
    }

    /// Install a scripted READ-fault plan (short reads on range reads). Builder over `new_chirho` /
    /// `restore_chirho` so existing mutation-fault callers are untouched.
    pub fn with_read_faults_chirho(mut self, read_plan_chirho: ReadFaultPlanChirho) -> Self {
        self.read_plan_chirho = read_plan_chirho;
        self
    }

    /// Restore from a durable snapshot (crash -> recover: the survived bytes reload into a fresh
    /// adapter, typically under a no-fault plan so recovery can run to completion).
    pub fn restore_chirho(
        snapshot_chirho: BTreeMap<String, Vec<u8>>,
        plan_chirho: FaultPlanChirho,
    ) -> Self {
        Self {
            store_chirho: RefCell::new(snapshot_chirho),
            plan_chirho,
            mutating_op_count_chirho: Cell::new(0),
            mutation_trace_chirho: RefCell::new(Vec::new()),
            crashed_chirho: Cell::new(false),
            read_plan_chirho: ReadFaultPlanChirho::none_chirho(),
            range_read_count_chirho: Cell::new(0),
            read_trace_chirho: RefCell::new(Vec::new()),
        }
    }

    /// A clone of the durable store as it stands — the bytes that would survive a crash right now.
    pub fn snapshot_chirho(&self) -> BTreeMap<String, Vec<u8>> {
        self.store_chirho.borrow().clone()
    }

    /// Has this store crashed? Once true, every mutating op refuses.
    pub fn is_crashed_chirho(&self) -> bool {
        self.crashed_chirho.get()
    }

    /// How many mutating ops have been attempted — the fault-plan index cursor.
    pub fn mutating_op_count_chirho(&self) -> u64 {
        self.mutating_op_count_chirho.get()
    }

    /// Attempted durability calls in order, including the call on which a scripted crash occurred.
    pub fn mutation_trace_chirho(&self) -> Vec<StorageMutationEventChirho> {
        self.mutation_trace_chirho.borrow().clone()
    }

    /// Per-kind counts over [`Self::mutation_trace_chirho`].
    pub fn operation_counts_chirho(&self) -> StorageOperationCountsChirho {
        let mut counts_chirho = StorageOperationCountsChirho::default();
        for event_chirho in self.mutation_trace_chirho.borrow().iter() {
            counts_chirho.record_chirho(event_chirho.kind_chirho);
        }
        counts_chirho
    }

    /// Every read the store served, in order — the D read-amplification evidence surface.
    pub fn read_trace_chirho(&self) -> Vec<StorageReadEventChirho> {
        self.read_trace_chirho.borrow().clone()
    }

    /// Per-kind read-call counts over [`Self::read_trace_chirho`].
    pub fn read_operation_counts_chirho(&self) -> StorageReadCountsChirho {
        let mut counts_chirho = StorageReadCountsChirho::default();
        for event_chirho in self.read_trace_chirho.borrow().iter() {
            counts_chirho.record_chirho(event_chirho.kind_chirho);
        }
        counts_chirho
    }

    /// Append one read event to the trace (its `index` is its position in the trace).
    fn record_read_chirho(
        &self,
        kind_chirho: StorageReadKindChirho,
        path_chirho: &StoragePathChirho,
        offset_chirho: Option<u64>,
        len_chirho: Option<u64>,
        delivered_len_chirho: Option<u64>,
        ok_chirho: bool,
    ) {
        let index_chirho = self.read_trace_chirho.borrow().len() as u64;
        self.read_trace_chirho
            .borrow_mut()
            .push(StorageReadEventChirho {
                index_chirho,
                kind_chirho,
                path_chirho: path_chirho.key_chirho().to_string(),
                offset_chirho,
                len_chirho,
                delivered_len_chirho,
                ok_chirho,
            });
    }

    /// The FAIL-CLOSED range-read logic (no telemetry — its caller records one event). Errors, in
    /// order: absent object, `offset + len` overflow, range past the object's current length, or a
    /// scripted short read. It returns EXACTLY `len` bytes or an `Err`, never a truncated prefix; the
    /// returned outcome also carries the UNDERLYING observed byte count (`Some(delivered)` on a short
    /// read even though the caller gets `Err`; `None` when no read reached the byte-copy stage).
    fn range_read_inner_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
        read_index_chirho: u64,
    ) -> RangeReadOutcomeChirho {
        let reject_chirho =
            |why_chirho: String, observed_chirho: Option<u64>| RangeReadOutcomeChirho {
                result_chirho: Err(anyhow::anyhow!("sim-range-read-chirho: {why_chirho}")),
                observed_delivered_chirho: observed_chirho,
            };

        let store_chirho = self.store_chirho.borrow();
        let bytes_chirho = match store_chirho.get(path_chirho.key_chirho()) {
            Some(bytes_chirho) => bytes_chirho,
            // A missing object delivered NO bytes (observed = None), distinct from a short read.
            None => {
                return reject_chirho(
                    format!(
                        "object {} absent (hot-path locator must exist)",
                        path_chirho.key_chirho()
                    ),
                    None,
                )
            }
        };
        let end_chirho = match offset_chirho.checked_add(len_chirho) {
            Some(end_chirho) => end_chirho,
            None => {
                return reject_chirho(
                    format!("offset {offset_chirho} + len {len_chirho} overflows u64"),
                    None,
                )
            }
        };
        if end_chirho > bytes_chirho.len() as u64 {
            return reject_chirho(
                format!(
                    "range [{offset_chirho}, {end_chirho}) past object length {}",
                    bytes_chirho.len()
                ),
                None,
            );
        }
        // In-bounds. A scripted short read models a truncated `pread`: the underlying read OBSERVED a
        // partial prefix, which we record as evidence, but the adapter fails closed and returns NONE of
        // it to the caller.
        if let ReadFaultKindChirho::ShortReadChirho {
            delivered_len_chirho,
        } = self.read_plan_chirho.at_chirho(read_index_chirho)
        {
            if delivered_len_chirho < len_chirho {
                let observed_chirho = delivered_len_chirho.min(len_chirho);
                return reject_chirho(
                    format!(
                        "short read delivered {observed_chirho} of {len_chirho} requested bytes"
                    ),
                    Some(observed_chirho),
                );
            }
        }
        RangeReadOutcomeChirho {
            result_chirho: Ok(bytes_chirho[offset_chirho as usize..end_chirho as usize].to_vec()),
            observed_delivered_chirho: Some(len_chirho),
        }
    }

    /// Take the next mutating-op fault, advancing the cursor. Err if already crashed.
    fn next_fault_chirho(
        &self,
        kind_chirho: StorageMutationKindChirho,
        primary_path_chirho: &StoragePathChirho,
        secondary_path_chirho: Option<&StoragePathChirho>,
    ) -> Result<FaultKindChirho> {
        if self.crashed_chirho.get() {
            bail!("sim-crash-chirho: storage already crashed; op refused");
        }
        let index_chirho = self.mutating_op_count_chirho.get();
        self.mutating_op_count_chirho.set(index_chirho + 1);
        self.mutation_trace_chirho
            .borrow_mut()
            .push(StorageMutationEventChirho {
                index_chirho,
                kind_chirho,
                primary_path_chirho: primary_path_chirho.key_chirho().to_string(),
                secondary_path_chirho: secondary_path_chirho
                    .map(|path_chirho| path_chirho.key_chirho().to_string()),
            });
        Ok(self.plan_chirho.at_chirho(index_chirho))
    }

    fn crash_chirho(&self, why_chirho: &str) -> anyhow::Error {
        self.crashed_chirho.set(true);
        anyhow::anyhow!("sim-crash-chirho: {why_chirho}")
    }
}

impl LedgerStoragePortChirho for SimStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<CreateDurableOutcomeChirho> {
        let fault_chirho = self.next_fault_chirho(
            StorageMutationKindChirho::CreateDurableChirho,
            path_chirho,
            None,
        )?;
        let mut store_chirho = self.store_chirho.borrow_mut();
        match store_chirho.entry(path_chirho.key_chirho().to_string()) {
            std::collections::btree_map::Entry::Occupied(_) => match fault_chirho {
                FaultKindChirho::NoneChirho => Ok(CreateDurableOutcomeChirho::AlreadyExistsChirho),
                FaultKindChirho::TearWriteChirho { .. } | FaultKindChirho::CrashBeforeChirho => {
                    Err(self.crash_chirho("crash before create collision; object unchanged"))
                }
            },
            std::collections::btree_map::Entry::Vacant(entry_chirho) => match fault_chirho {
                FaultKindChirho::NoneChirho => {
                    entry_chirho.insert(bytes_chirho.to_vec());
                    Ok(CreateDurableOutcomeChirho::CreatedChirho)
                }
                FaultKindChirho::TearWriteChirho { prefix_len_chirho } => {
                    let take_chirho = prefix_len_chirho.min(bytes_chirho.len());
                    entry_chirho.insert(bytes_chirho[..take_chirho].to_vec());
                    Err(self.crash_chirho(
                        "torn create; only a byte prefix is durable under the claimed name",
                    ))
                }
                FaultKindChirho::CrashBeforeChirho => {
                    Err(self.crash_chirho("crash before create; object remains absent"))
                }
            },
        }
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        match self.next_fault_chirho(
            StorageMutationKindChirho::AppendDurableChirho,
            path_chirho,
            None,
        )? {
            FaultKindChirho::NoneChirho => {
                self.store_chirho
                    .borrow_mut()
                    .entry(path_chirho.key_chirho().to_string())
                    .or_default()
                    .extend_from_slice(bytes_chirho);
                Ok(())
            }
            FaultKindChirho::TearWriteChirho { prefix_len_chirho } => {
                let take_chirho = prefix_len_chirho.min(bytes_chirho.len());
                self.store_chirho
                    .borrow_mut()
                    .entry(path_chirho.key_chirho().to_string())
                    .or_default()
                    .extend_from_slice(&bytes_chirho[..take_chirho]);
                Err(self.crash_chirho("torn append; only a byte prefix is durable"))
            }
            FaultKindChirho::CrashBeforeChirho => {
                Err(self.crash_chirho("crash before append; nothing durable"))
            }
        }
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<Vec<u8>>> {
        // Reads are NOT fault-gated and succeed even after a crash latch — this is post-mortem
        // inspection of the durable bytes (e.g. what survived a torn append). Mutations stay latched;
        // an in-flow recovery that reopens the machine belongs in `restore_chirho`, not a live read.
        // Recorded as a FullRead so the D surface can prove the fence's HOT path never full-reads.
        let bytes_chirho = self
            .store_chirho
            .borrow()
            .get(path_chirho.key_chirho())
            .cloned();
        self.record_read_chirho(
            StorageReadKindChirho::FullReadChirho,
            path_chirho,
            None,
            None,
            bytes_chirho.as_ref().map(|b_chirho| b_chirho.len() as u64),
            true,
        );
        Ok(bytes_chirho)
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> Result<Option<u64>> {
        // Metadata read: truthful and not fault-gated. The fence uses it to bound a range before it
        // reads, so learning a length never costs a whole-object read.
        let len_chirho = self
            .store_chirho
            .borrow()
            .get(path_chirho.key_chirho())
            .map(|b_chirho| b_chirho.len() as u64);
        self.record_read_chirho(
            StorageReadKindChirho::ObjectLenChirho,
            path_chirho,
            None,
            None,
            len_chirho,
            true,
        );
        Ok(len_chirho)
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        // The range-read cursor advances on EVERY range read (even a rejected one) so a scripted short
        // read addresses the Nth range read deterministically. Telemetry is recorded exactly once here,
        // from the inner logic's outcome — never a truncated prefix on failure.
        let read_index_chirho = self.range_read_count_chirho.get();
        self.range_read_count_chirho.set(read_index_chirho + 1);

        let outcome_chirho =
            self.range_read_inner_chirho(path_chirho, offset_chirho, len_chirho, read_index_chirho);
        self.record_read_chirho(
            StorageReadKindChirho::ExactRangeChirho,
            path_chirho,
            Some(offset_chirho),
            Some(len_chirho),
            outcome_chirho.observed_delivered_chirho,
            outcome_chirho.result_chirho.is_ok(),
        );
        outcome_chirho.result_chirho
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        // Atomic: no partial state is ever visible, so a tear degrades to a crash-before.
        match self.next_fault_chirho(
            StorageMutationKindChirho::AtomicWriteChirho,
            path_chirho,
            None,
        )? {
            FaultKindChirho::NoneChirho => {
                self.store_chirho
                    .borrow_mut()
                    .insert(path_chirho.key_chirho().to_string(), bytes_chirho.to_vec());
                Ok(())
            }
            FaultKindChirho::TearWriteChirho { .. } | FaultKindChirho::CrashBeforeChirho => {
                Err(self.crash_chirho("crash before atomic write; object unchanged"))
            }
        }
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> Result<()> {
        // The size change is atomic (ftruncate), so a tear degrades to crash-before (unchanged).
        match self.next_fault_chirho(
            StorageMutationKindChirho::TruncateDurableChirho,
            path_chirho,
            None,
        )? {
            FaultKindChirho::NoneChirho => {
                let mut store_chirho = self.store_chirho.borrow_mut();
                let bytes_chirho =
                    store_chirho
                        .get_mut(path_chirho.key_chirho())
                        .ok_or_else(|| {
                            anyhow::anyhow!("sim-truncate-enoent-chirho: object does not exist")
                        })?;
                if new_len_chirho > bytes_chirho.len() as u64 {
                    bail!("sim-truncate-grow-chirho: a truncate can only shorten");
                }
                bytes_chirho.truncate(new_len_chirho as usize);
                Ok(())
            }
            FaultKindChirho::TearWriteChirho { .. } | FaultKindChirho::CrashBeforeChirho => {
                Err(self.crash_chirho("crash before truncate; object unchanged"))
            }
        }
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> Result<()> {
        match self.next_fault_chirho(
            StorageMutationKindChirho::RenameChirho,
            from_chirho,
            Some(to_chirho),
        )? {
            FaultKindChirho::NoneChirho => {
                let mut store_chirho = self.store_chirho.borrow_mut();
                match store_chirho.remove(from_chirho.key_chirho()) {
                    Some(bytes_chirho) => {
                        store_chirho.insert(to_chirho.key_chirho().to_string(), bytes_chirho);
                        Ok(())
                    }
                    // A real fs rename of a missing source fails (ENOENT); a sim that silently
                    // no-ops would be MORE permissive than reality and let a toy-log bug (renaming
                    // an absent seal) pass here yet fail in production. This is a plain failure, not
                    // a crash — it does NOT latch the store; a lawful flow must exists()-check first.
                    None => bail!(
                        "sim-rename-enoent-chirho: rename source {} does not exist",
                        from_chirho.key_chirho()
                    ),
                }
            }
            FaultKindChirho::TearWriteChirho { .. } | FaultKindChirho::CrashBeforeChirho => {
                Err(self.crash_chirho("crash before rename; both names unchanged"))
            }
        }
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> Result<()> {
        match self.next_fault_chirho(StorageMutationKindChirho::RemoveChirho, path_chirho, None)? {
            FaultKindChirho::NoneChirho => {
                self.store_chirho
                    .borrow_mut()
                    .remove(path_chirho.key_chirho());
                Ok(())
            }
            FaultKindChirho::TearWriteChirho { .. } | FaultKindChirho::CrashBeforeChirho => {
                Err(self.crash_chirho("crash before remove; object unchanged"))
            }
        }
    }

    fn list_chirho(&self, prefix_chirho: &StoragePathChirho) -> Result<Vec<StoragePathChirho>> {
        let prefix_key_chirho = prefix_chirho.key_chirho();
        let mut out_chirho: Vec<StoragePathChirho> = self
            .store_chirho
            .borrow()
            .keys()
            .filter(|k_chirho| k_chirho.starts_with(prefix_key_chirho))
            .map(|k_chirho| StoragePathChirho::new_chirho(k_chirho.clone()))
            .collect();
        out_chirho.sort();
        Ok(out_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> Result<bool> {
        Ok(self
            .store_chirho
            .borrow()
            .contains_key(path_chirho.key_chirho()))
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn path_chirho(key_chirho: &str) -> StoragePathChirho {
        StoragePathChirho::new_chirho(key_chirho)
    }

    #[test]
    fn append_then_read_roundtrips_without_faults_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        store_chirho
            .append_durable_chirho(&path_chirho("log"), b"abc")
            .unwrap();
        store_chirho
            .append_durable_chirho(&path_chirho("log"), b"def")
            .unwrap();
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_chirho("log"))
                .unwrap()
                .unwrap(),
            b"abcdef"
        );
        assert!(!store_chirho.is_crashed_chirho());
    }

    #[test]
    fn create_is_exclusive_and_preserves_preexisting_bytes_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let path_local_chirho = path_chirho("exclusive");
        assert_eq!(
            store_chirho
                .create_durable_chirho(&path_local_chirho, b"first")
                .unwrap(),
            CreateDurableOutcomeChirho::CreatedChirho
        );
        assert_eq!(
            store_chirho
                .create_durable_chirho(&path_local_chirho, b"second")
                .unwrap(),
            CreateDurableOutcomeChirho::AlreadyExistsChirho
        );
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_local_chirho)
                .unwrap()
                .unwrap(),
            b"first"
        );
        let counts_chirho = store_chirho.operation_counts_chirho();
        assert_eq!(counts_chirho.create_durable_calls_chirho, 2);
        assert_eq!(counts_chirho.append_durable_calls_chirho, 0);
        assert_eq!(counts_chirho.durability_call_count_chirho(), 2);
    }

    #[test]
    fn torn_write_leaves_prefix_and_crashes_chirho() {
        // Tear the 2nd mutating op (index 1) down to a 1-byte prefix.
        let plan_chirho = FaultPlanChirho::single_chirho(
            1,
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 1,
            },
        );
        let store_chirho = SimStorageChirho::new_chirho(plan_chirho);
        store_chirho
            .append_durable_chirho(&path_chirho("log"), b"abc")
            .unwrap(); // op 0: ok
        let err_chirho = store_chirho
            .append_durable_chirho(&path_chirho("log"), b"XYZ")
            .unwrap_err(); // op 1: torn to "X"
        assert!(err_chirho.to_string().contains("sim-crash-chirho"));
        assert!(store_chirho.is_crashed_chirho());
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_chirho("log"))
                .unwrap()
                .unwrap(),
            b"abcX"
        );
        // Every op after the crash refuses.
        assert!(store_chirho
            .append_durable_chirho(&path_chirho("log"), b"more")
            .is_err());
    }

    #[test]
    fn crash_before_applies_nothing_chirho() {
        let plan_chirho = FaultPlanChirho::single_chirho(0, FaultKindChirho::CrashBeforeChirho);
        let store_chirho = SimStorageChirho::new_chirho(plan_chirho);
        assert!(store_chirho
            .append_durable_chirho(&path_chirho("log"), b"abc")
            .is_err());
        assert!(store_chirho.is_crashed_chirho());
        assert!(store_chirho
            .read_all_chirho(&path_chirho("log"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn snapshot_restore_recovers_durable_state_chirho() {
        let plan_chirho = FaultPlanChirho::single_chirho(
            1,
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 2,
            },
        );
        let store_chirho = SimStorageChirho::new_chirho(plan_chirho);
        store_chirho
            .append_durable_chirho(&path_chirho("log"), b"hello")
            .unwrap(); // op 0
        let _ = store_chirho
            .append_durable_chirho(&path_chirho("log"), b"WORLD")
            .unwrap_err(); // op 1: tear 2 -> "WO"
        let snapshot_chirho = store_chirho.snapshot_chirho();
        // Recover under a no-fault plan; the durable "helloWO" survives and we can continue.
        let recovered_chirho =
            SimStorageChirho::restore_chirho(snapshot_chirho, FaultPlanChirho::none_chirho());
        assert!(!recovered_chirho.is_crashed_chirho());
        assert_eq!(
            recovered_chirho
                .read_all_chirho(&path_chirho("log"))
                .unwrap()
                .unwrap(),
            b"helloWO"
        );
        recovered_chirho
            .append_durable_chirho(&path_chirho("log"), b"!")
            .unwrap();
        assert_eq!(
            recovered_chirho
                .read_all_chirho(&path_chirho("log"))
                .unwrap()
                .unwrap(),
            b"helloWO!"
        );
    }

    #[test]
    fn atomic_write_is_all_or_nothing_chirho() {
        // A tear on an atomic write applies nothing — atomicity means no partial object.
        let plan_chirho = FaultPlanChirho::single_chirho(
            1,
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 3,
            },
        );
        let store_chirho = SimStorageChirho::new_chirho(plan_chirho);
        store_chirho
            .atomic_write_chirho(&path_chirho("obj"), b"v1")
            .unwrap(); // op 0
        let _ = store_chirho
            .atomic_write_chirho(&path_chirho("obj"), b"v2-longer")
            .unwrap_err(); // op 1: crash-before
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_chirho("obj"))
                .unwrap()
                .unwrap(),
            b"v1"
        ); // unchanged
    }

    #[test]
    fn rename_moves_and_remove_deletes_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        store_chirho
            .atomic_write_chirho(&path_chirho("a"), b"x")
            .unwrap();
        store_chirho
            .rename_chirho(&path_chirho("a"), &path_chirho("b"))
            .unwrap();
        assert!(store_chirho
            .read_all_chirho(&path_chirho("a"))
            .unwrap()
            .is_none());
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_chirho("b"))
                .unwrap()
                .unwrap(),
            b"x"
        );
        store_chirho.remove_chirho(&path_chirho("b")).unwrap();
        assert!(!store_chirho.exists_chirho(&path_chirho("b")).unwrap());
    }

    #[test]
    fn rename_missing_source_fails_enoent_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        // Renaming a never-written source fails like real fs ENOENT — and does NOT latch the store.
        let err_chirho = store_chirho
            .rename_chirho(&path_chirho("missing"), &path_chirho("dest"))
            .unwrap_err();
        assert!(err_chirho.to_string().contains("sim-rename-enoent-chirho"));
        assert!(!store_chirho.is_crashed_chirho());
        // The store is still usable after the failed rename.
        store_chirho
            .atomic_write_chirho(&path_chirho("dest"), b"ok")
            .unwrap();
        assert_eq!(
            store_chirho
                .read_all_chirho(&path_chirho("dest"))
                .unwrap()
                .unwrap(),
            b"ok"
        );
    }

    #[test]
    fn list_is_prefix_filtered_and_sorted_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        store_chirho
            .atomic_write_chirho(&path_chirho("seg/2"), b"")
            .unwrap();
        store_chirho
            .atomic_write_chirho(&path_chirho("seg/1"), b"")
            .unwrap();
        store_chirho
            .atomic_write_chirho(&path_chirho("other"), b"")
            .unwrap();
        let listed_chirho: Vec<String> = store_chirho
            .list_chirho(&path_chirho("seg/"))
            .unwrap()
            .into_iter()
            .map(|p_chirho| p_chirho.0)
            .collect();
        assert_eq!(
            listed_chirho,
            vec!["seg/1".to_string(), "seg/2".to_string()]
        );
    }

    #[test]
    fn mutation_trace_counts_and_names_durability_calls_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        store_chirho
            .atomic_write_chirho(&path_chirho("active"), b"seed")
            .unwrap();
        store_chirho
            .append_durable_chirho(&path_chirho("active"), b"line")
            .unwrap();
        store_chirho
            .rename_chirho(&path_chirho("active"), &path_chirho("sealed"))
            .unwrap();
        store_chirho.remove_chirho(&path_chirho("sealed")).unwrap();

        let counts_chirho = store_chirho.operation_counts_chirho();
        assert_eq!(counts_chirho.append_durable_calls_chirho, 1);
        assert_eq!(counts_chirho.atomic_write_calls_chirho, 1);
        assert_eq!(counts_chirho.rename_calls_chirho, 1);
        assert_eq!(counts_chirho.remove_calls_chirho, 1);
        assert_eq!(counts_chirho.durability_call_count_chirho(), 4);
        assert_eq!(
            store_chirho.mutation_trace_chirho(),
            vec![
                StorageMutationEventChirho {
                    index_chirho: 0,
                    kind_chirho: StorageMutationKindChirho::AtomicWriteChirho,
                    primary_path_chirho: "active".to_string(),
                    secondary_path_chirho: None,
                },
                StorageMutationEventChirho {
                    index_chirho: 1,
                    kind_chirho: StorageMutationKindChirho::AppendDurableChirho,
                    primary_path_chirho: "active".to_string(),
                    secondary_path_chirho: None,
                },
                StorageMutationEventChirho {
                    index_chirho: 2,
                    kind_chirho: StorageMutationKindChirho::RenameChirho,
                    primary_path_chirho: "active".to_string(),
                    secondary_path_chirho: Some("sealed".to_string()),
                },
                StorageMutationEventChirho {
                    index_chirho: 3,
                    kind_chirho: StorageMutationKindChirho::RemoveChirho,
                    primary_path_chirho: "sealed".to_string(),
                    secondary_path_chirho: None,
                },
            ]
        );
    }

    #[test]
    fn crashing_call_is_traced_but_latched_followup_is_not_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
            0,
            FaultKindChirho::CrashBeforeChirho,
        ));
        assert!(store_chirho
            .append_durable_chirho(&path_chirho("journal"), b"line")
            .is_err());
        assert!(store_chirho
            .atomic_write_chirho(&path_chirho("checkpoint"), b"head")
            .is_err());

        let counts_chirho = store_chirho.operation_counts_chirho();
        assert_eq!(counts_chirho.append_durable_calls_chirho, 1);
        assert_eq!(counts_chirho.atomic_write_calls_chirho, 0);
        assert_eq!(counts_chirho.durability_call_count_chirho(), 1);
        assert_eq!(store_chirho.mutation_trace_chirho().len(), 1);
    }

    fn seeded_store_chirho(key_chirho: &str, bytes_chirho: &[u8]) -> SimStorageChirho {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        store_chirho
            .atomic_write_chirho(&path_chirho(key_chirho), bytes_chirho)
            .unwrap();
        store_chirho
    }

    #[test]
    fn range_read_returns_the_exact_window_chirho() {
        let store_chirho = seeded_store_chirho("log", b"abcdefghij");
        // A middle window returns exactly those bytes — no more, no less.
        assert_eq!(
            store_chirho
                .read_exact_range_chirho(&path_chirho("log"), 2, 3)
                .unwrap(),
            b"cde"
        );
        // A zero-length window at the end is in-bounds and empty.
        assert_eq!(
            store_chirho
                .read_exact_range_chirho(&path_chirho("log"), 10, 0)
                .unwrap(),
            b""
        );
        // The whole object by exact range.
        assert_eq!(
            store_chirho
                .read_exact_range_chirho(&path_chirho("log"), 0, 10)
                .unwrap(),
            b"abcdefghij"
        );
    }

    #[test]
    fn range_read_past_eof_fails_closed_chirho() {
        let store_chirho = seeded_store_chirho("log", b"abcdef");
        // One byte past the end is refused, never a short success.
        let err_chirho = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 4, 3)
            .unwrap_err();
        assert!(err_chirho.to_string().contains("past object length"));
        // Offset itself past EOF is refused too.
        assert!(store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 7, 1)
            .is_err());
    }

    #[test]
    fn range_read_offset_len_overflow_fails_closed_chirho() {
        let store_chirho = seeded_store_chirho("log", b"abc");
        let err_chirho = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), u64::MAX, 1)
            .unwrap_err();
        assert!(err_chirho.to_string().contains("overflows u64"));
    }

    #[test]
    fn range_read_of_absent_object_fails_closed_not_none_chirho() {
        let store_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        // A hot-path locator that points at a missing object is an integrity failure, not an empty Ok.
        let err_chirho = store_chirho
            .read_exact_range_chirho(&path_chirho("missing"), 0, 1)
            .unwrap_err();
        assert!(err_chirho.to_string().contains("absent"));
    }

    #[test]
    fn short_read_fault_fails_closed_and_does_not_latch_chirho() {
        // Script a short read on the 0th range read: the object HAS all 6 bytes, but the underlying
        // read delivers only 2 of the 4 requested. The adapter must fail closed, never return "ab".
        let store_chirho = seeded_store_chirho("log", b"abcdef").with_read_faults_chirho(
            ReadFaultPlanChirho::single_chirho(
                0,
                ReadFaultKindChirho::ShortReadChirho {
                    delivered_len_chirho: 2,
                },
            ),
        );
        let err_chirho = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 0, 4)
            .unwrap_err();
        assert!(err_chirho.to_string().contains("short read"));

        // D1: the trace preserves that the underlying read DELIVERED 2 partial bytes, then rejected them
        // (ok=false) — distinct from an absent/overflow read that delivered nothing. No full read.
        let trace_chirho = store_chirho.read_trace_chirho();
        assert_eq!(trace_chirho.len(), 1);
        assert_eq!(
            trace_chirho[0].kind_chirho,
            StorageReadKindChirho::ExactRangeChirho
        );
        assert_eq!(trace_chirho[0].offset_chirho, Some(0));
        assert_eq!(trace_chirho[0].len_chirho, Some(4));
        assert_eq!(trace_chirho[0].delivered_len_chirho, Some(2));
        assert!(!trace_chirho[0].ok_chirho);
        assert_eq!(
            store_chirho
                .read_operation_counts_chirho()
                .full_read_calls_chirho,
            0
        );

        // A read fault is NOT a durability crash — the store stays usable and the next read succeeds.
        assert!(!store_chirho.is_crashed_chirho());
        assert_eq!(
            store_chirho
                .read_exact_range_chirho(&path_chirho("log"), 0, 4)
                .unwrap(),
            b"abcd"
        );
    }

    #[test]
    fn metadata_length_is_not_a_durable_cut_range_read_revalidates_chirho() {
        // D2: object_len + read_exact_range are TWO calls, not one snapshot. B holds the single-writer
        // journal lock across its stable cut, but the adapter STILL revalidates CURRENT length — so if
        // the object is truncated/replaced between the calls, the range read fails closed on current
        // length rather than trusting the earlier metadata. Metadata length is not a durable cut.
        let store_chirho = seeded_store_chirho("log", b"abcdefghij"); // len 10
        assert_eq!(
            store_chirho.object_len_chirho(&path_chirho("log")).unwrap(),
            Some(10)
        );
        // The object shrinks to 5 bytes underneath a caller that observed length 10.
        store_chirho
            .atomic_write_chirho(&path_chirho("log"), b"abcde")
            .unwrap();
        let err_chirho = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 0, 10)
            .unwrap_err();
        assert!(err_chirho.to_string().contains("past object length"));

        // The trace shows the exact-range read failed on current length; nothing delivered; no full read.
        let trace_chirho = store_chirho.read_trace_chirho();
        let last_chirho = trace_chirho.last().unwrap();
        assert_eq!(
            last_chirho.kind_chirho,
            StorageReadKindChirho::ExactRangeChirho
        );
        assert!(!last_chirho.ok_chirho);
        assert_eq!(last_chirho.delivered_len_chirho, None);
        assert_eq!(
            store_chirho
                .read_operation_counts_chirho()
                .full_read_calls_chirho,
            0
        );
    }

    #[test]
    fn object_len_reports_length_or_none_chirho() {
        let store_chirho = seeded_store_chirho("log", b"abcdef");
        assert_eq!(
            store_chirho.object_len_chirho(&path_chirho("log")).unwrap(),
            Some(6)
        );
        assert_eq!(
            store_chirho
                .object_len_chirho(&path_chirho("absent"))
                .unwrap(),
            None
        );
    }

    #[test]
    fn read_trace_counts_reads_by_kind_chirho() {
        let store_chirho = seeded_store_chirho("log", b"abcdef");
        let _ = store_chirho.object_len_chirho(&path_chirho("log")).unwrap();
        let _ = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 0, 3)
            .unwrap();
        let _ = store_chirho
            .read_exact_range_chirho(&path_chirho("log"), 3, 3)
            .unwrap();
        let _ = store_chirho.read_all_chirho(&path_chirho("log")).unwrap();

        let counts_chirho = store_chirho.read_operation_counts_chirho();
        assert_eq!(counts_chirho.object_len_calls_chirho, 1);
        assert_eq!(counts_chirho.exact_range_calls_chirho, 2);
        assert_eq!(counts_chirho.full_read_calls_chirho, 1);
        assert_eq!(counts_chirho.total_read_calls_chirho(), 4);

        // The trace preserves the requested windows in order, for the D read-amplification evidence.
        let trace_chirho = store_chirho.read_trace_chirho();
        assert_eq!(trace_chirho.len(), 4);
        assert_eq!(
            trace_chirho[1].kind_chirho,
            StorageReadKindChirho::ExactRangeChirho
        );
        assert_eq!(trace_chirho[1].offset_chirho, Some(0));
        assert_eq!(trace_chirho[1].len_chirho, Some(3));
        assert_eq!(trace_chirho[1].delivered_len_chirho, Some(3));
        assert!(trace_chirho[1].ok_chirho);
    }
}
