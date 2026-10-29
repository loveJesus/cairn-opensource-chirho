// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Seeded, reproducible fault schedule for the sim adapters.
//!
//! A fault is a torn write, a crash-before-op, or nothing, scripted per mutating-operation index.
//! This is how the proof harness turns "what if the machine dies HERE" into a deterministic,
//! replayable test — the ledger's analogue of the RC4 W0-W3 rotation crash matrix.

use std::collections::BTreeMap;

/// One fault the sim injects at a chosen mutating-operation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FaultKindChirho {
    /// The operation completes normally and durably.
    #[default]
    NoneChirho,
    /// An APPEND or exclusive CREATE applies only its first `prefix_len_chirho` bytes durably, then
    /// the machine crashes (a torn write / interrupted fsync). The CREATE has claimed its final
    /// name, so the partial object remains exclusive. An ATOMIC replacement/rename/remove has no
    /// partial state, so there this degrades to a crash BEFORE the op: the op does not apply.
    TearWriteChirho { prefix_len_chirho: usize },
    /// The machine crashes just BEFORE this operation — nothing it would have written is durable.
    /// A crash BETWEEN two cuts is modeled as a `CrashBeforeChirho` on the second cut.
    CrashBeforeChirho,
}

/// A scripted fault schedule: at mutating-operation index `k`, inject `plan[k]` (default: none).
///
/// Scripting — not only seeding — is deliberate: the rotation crash matrix must crash at an EXACT
/// cut, not a random one. A seeded generator can be layered on top for fuzzing in a later increment.
#[derive(Clone, Debug, Default)]
pub struct FaultPlanChirho {
    scripted_chirho: BTreeMap<u64, FaultKindChirho>,
}

impl FaultPlanChirho {
    /// A plan that injects no faults — every operation succeeds durably.
    pub fn none_chirho() -> Self {
        Self::default()
    }

    /// A plan that injects `fault` at exactly mutating-operation index `op_index`.
    pub fn single_chirho(op_index_chirho: u64, fault_chirho: FaultKindChirho) -> Self {
        let mut scripted_chirho = BTreeMap::new();
        scripted_chirho.insert(op_index_chirho, fault_chirho);
        Self { scripted_chirho }
    }

    /// A plan from an explicit `(op_index, fault)` schedule.
    pub fn scripted_chirho(
        faults_chirho: impl IntoIterator<Item = (u64, FaultKindChirho)>,
    ) -> Self {
        Self {
            scripted_chirho: faults_chirho.into_iter().collect(),
        }
    }

    /// The fault scheduled at mutating-operation index `op_index` (none if unscheduled).
    pub fn at_chirho(&self, op_index_chirho: u64) -> FaultKindChirho {
        self.scripted_chirho
            .get(&op_index_chirho)
            .cloned()
            .unwrap_or(FaultKindChirho::NoneChirho)
    }
}

/// One fault the sim injects at a chosen range-READ boundary. Unlike a mutation fault, a read fault
/// does NOT crash-latch the store — a bad read is a fail-closed error the caller must handle, not a
/// durability loss.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum ReadFaultKindChirho {
    /// The range read delivers exactly the `len` bytes requested.
    #[default]
    NoneChirho,
    /// The underlying storage delivers only `delivered_len_chirho` of the requested bytes (a short
    /// `pread`). The adapter MUST fail closed on this — it must NEVER return the truncated prefix as a
    /// success, and NEVER retry into a full read.
    ShortReadChirho { delivered_len_chirho: u64 },
}

/// A scripted READ-fault schedule: at range-read index `k` (0-based over range reads only), inject
/// `plan[k]` (default: none). Range reads are the only faulted reads; `object_len` / `read_all` are
/// truthful metadata / post-mortem reads.
#[derive(Clone, Debug, Default)]
pub struct ReadFaultPlanChirho {
    scripted_chirho: BTreeMap<u64, ReadFaultKindChirho>,
}

impl ReadFaultPlanChirho {
    /// A plan that injects no read faults — every range read delivers all requested bytes.
    pub fn none_chirho() -> Self {
        Self::default()
    }

    /// A plan that injects `fault` at exactly range-read index `op_index`.
    pub fn single_chirho(op_index_chirho: u64, fault_chirho: ReadFaultKindChirho) -> Self {
        let mut scripted_chirho = BTreeMap::new();
        scripted_chirho.insert(op_index_chirho, fault_chirho);
        Self { scripted_chirho }
    }

    /// The read fault scheduled at range-read index `op_index` (none if unscheduled).
    pub fn at_chirho(&self, op_index_chirho: u64) -> ReadFaultKindChirho {
        self.scripted_chirho
            .get(&op_index_chirho)
            .cloned()
            .unwrap_or(ReadFaultKindChirho::NoneChirho)
    }
}
