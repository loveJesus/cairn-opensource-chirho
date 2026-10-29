// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The virtual-actor registry: a capacity-bounded map of HYDRATED cluster journals with bounded
//! refuse-newest mailboxes — memory O(active), never O(total clusters) (CF1 clause 4, spec L1).
//!
//! SYNCHRONOUS portable core: hydration opens a journal through the SAME ports, passivation is
//! checkpoint + drop, and the mailbox is pumped explicitly — a tokio task-per-hot-actor is a later
//! runtime ADAPTER over this core, never a second coding. The registry composes journals and owns
//! NO new authority: every queued request still passes the journal's full admission fence.
//!
//! HONEST BOUNDARIES (claude2 #4854 rulings): (1) a mailbox is MEMORY, not a journal — a crash
//! loses queued-but-unprocessed requests with the process; only the append RECEIPT is durable, and
//! callers needing durability wait for it (acceptance into a mailbox is not a receipt). (2) A
//! ROTATED journal's hydrate always takes the full manifest-walk (O(history)) — the stale sidecar
//! self-discards structurally; fast hydrate on rotated journals awaits the
//! checkpoint-fast-path-over-sealed-history increment (the named clause-4 completion dependency).

use crate::journal_chirho::{
    AppendReceiptChirho, AppendRequestChirho, JournalErrorChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use crate::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use std::collections::{BTreeMap, VecDeque};

/// Why the registry refused — DISTINCT from every journal/admission error: "retry later" must
/// never be confusable with "your request is illegal" (claude2 #4854 pin i).
#[derive(Debug)]
pub enum RegistryErrorChirho {
    /// The actor's bounded mailbox is full: the NEWEST request is refused at the door
    /// (refuse-newest law — backpressure visible at the source, FIFO fairness preserved, and
    /// nothing already queued is ever shed). Nothing was enqueued and no state changed.
    BackpressureChirho { cluster_chirho: ClusterIdChirho },
    /// The registry is at capacity and EVERY resident actor is non-idle (non-empty mailbox):
    /// hydrating another cluster would evict accepted work by another name, so the hydrate is
    /// refused instead (a hot actor is NEVER evicted).
    CapacityChirho { cluster_chirho: ClusterIdChirho },
    /// A non-idle actor (queued work in its mailbox) was asked to passivate — refused with the
    /// actor untouched (passivating it would shed accepted work by another name).
    NonIdleChirho { cluster_chirho: ClusterIdChirho },
    /// The underlying journal refused (open/checkpoint/append) — the journal's law, passed through.
    JournalChirho { error_chirho: JournalErrorChirho },
}

impl From<JournalErrorChirho> for RegistryErrorChirho {
    fn from(error_chirho: JournalErrorChirho) -> Self {
        RegistryErrorChirho::JournalChirho { error_chirho }
    }
}

struct ActorChirho<'ports_chirho> {
    journal_chirho: LedgerJournalChirho<'ports_chirho>,
    mailbox_chirho: VecDeque<AppendRequestChirho>,
    /// Logical LRU stamp (monotonic registry tick — never wall-clock).
    last_touch_chirho: u64,
}

/// The bounded registry of hydrated cluster journals.
pub struct LedgerActorRegistryChirho<'ports_chirho> {
    ports_chirho: JournalPortsChirho<'ports_chirho>,
    path_fn_chirho: fn(&ClusterIdChirho) -> StoragePathChirho,
    capacity_chirho: usize,
    mailbox_capacity_chirho: usize,
    tick_chirho: u64,
    active_chirho: BTreeMap<ClusterIdChirho, ActorChirho<'ports_chirho>>,
}

impl<'ports_chirho> LedgerActorRegistryChirho<'ports_chirho> {
    /// `capacity` bounds resident actors (the O(active) memory law, enforced structurally);
    /// `mailbox_capacity` bounds each actor's queue (refuse-newest past it). Both must be ≥ 1.
    pub fn new_chirho(
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        path_fn_chirho: fn(&ClusterIdChirho) -> StoragePathChirho,
        capacity_chirho: usize,
        mailbox_capacity_chirho: usize,
    ) -> Self {
        assert!(capacity_chirho >= 1, "registry capacity must be at least 1");
        assert!(
            mailbox_capacity_chirho >= 1,
            "mailbox capacity must be at least 1"
        );
        LedgerActorRegistryChirho {
            ports_chirho,
            path_fn_chirho,
            capacity_chirho,
            mailbox_capacity_chirho,
            tick_chirho: 0,
            active_chirho: BTreeMap::new(),
        }
    }

    /// How many actors are resident right now (always ≤ capacity — the scaling twin's guard).
    pub fn active_len_chirho(&self) -> usize {
        self.active_chirho.len()
    }

    /// Enqueue one append request for a cluster, hydrating its journal on demand. Refuse-newest:
    /// a full mailbox refuses THIS request before any state effect (no idempotency registration,
    /// no receipt, nothing to compensate). A cold cluster at registry capacity passivates the
    /// least-recently-touched IDLE actor first; if every resident actor is non-idle the hydrate
    /// is refused (hot actors are never evicted).
    pub fn submit_chirho(
        &mut self,
        cluster_chirho: &ClusterIdChirho,
        request_chirho: AppendRequestChirho,
    ) -> Result<(), RegistryErrorChirho> {
        self.tick_chirho += 1;
        let tick_chirho = self.tick_chirho;
        if let Some(actor_chirho) = self.active_chirho.get_mut(cluster_chirho) {
            if actor_chirho.mailbox_chirho.len() >= self.mailbox_capacity_chirho {
                return Err(RegistryErrorChirho::BackpressureChirho {
                    cluster_chirho: cluster_chirho.clone(),
                });
            }
            actor_chirho.mailbox_chirho.push_back(request_chirho);
            actor_chirho.last_touch_chirho = tick_chirho;
            return Ok(());
        }
        self.ensure_room_chirho(cluster_chirho)?;
        let journal_chirho = LedgerJournalChirho::open_chirho(
            self.ports_chirho,
            (self.path_fn_chirho)(cluster_chirho),
            cluster_chirho,
        )?;
        let mut mailbox_chirho = VecDeque::with_capacity(self.mailbox_capacity_chirho.min(16));
        mailbox_chirho.push_back(request_chirho);
        self.active_chirho.insert(
            cluster_chirho.clone(),
            ActorChirho {
                journal_chirho,
                mailbox_chirho,
                last_touch_chirho: tick_chirho,
            },
        );
        Ok(())
    }

    /// Pump one actor's mailbox FIFO through its journal's full admission fence, returning the
    /// receipts. On a journal/admission refusal the failed request is consumed (it was REFUSED,
    /// not lost — re-submitting the identical illegal request would refuse again), the error
    /// returns, and the REMAINDER stays queued.
    pub fn process_all_chirho(
        &mut self,
        cluster_chirho: &ClusterIdChirho,
    ) -> Result<Vec<AppendReceiptChirho>, RegistryErrorChirho> {
        self.tick_chirho += 1;
        let tick_chirho = self.tick_chirho;
        let Some(actor_chirho) = self.active_chirho.get_mut(cluster_chirho) else {
            return Ok(Vec::new());
        };
        actor_chirho.last_touch_chirho = tick_chirho;
        let mut receipts_chirho = Vec::new();
        while let Some(request_chirho) = actor_chirho.mailbox_chirho.pop_front() {
            let receipt_chirho = actor_chirho.journal_chirho.append_chirho(request_chirho)?;
            receipts_chirho.push(receipt_chirho);
        }
        Ok(receipts_chirho)
    }

    /// Explicitly passivate one IDLE actor: durable head checkpoint, then drop from residency.
    /// A NON-idle actor (queued work) refuses with the actor untouched — passivating it would
    /// shed accepted work by another name. Returns `false` when the cluster was not resident.
    pub fn passivate_chirho(
        &mut self,
        cluster_chirho: &ClusterIdChirho,
    ) -> Result<bool, RegistryErrorChirho> {
        let Some(actor_chirho) = self.active_chirho.get(cluster_chirho) else {
            return Ok(false);
        };
        if !actor_chirho.mailbox_chirho.is_empty() {
            return Err(RegistryErrorChirho::NonIdleChirho {
                cluster_chirho: cluster_chirho.clone(),
            });
        }
        actor_chirho.journal_chirho.write_head_checkpoint_chirho()?;
        self.active_chirho.remove(cluster_chirho);
        Ok(true)
    }

    /// Make room for one more resident actor: passivate the least-recently-touched IDLE actor,
    /// or refuse if the registry is full of non-idle actors.
    fn ensure_room_chirho(
        &mut self,
        incoming_chirho: &ClusterIdChirho,
    ) -> Result<(), RegistryErrorChirho> {
        if self.active_chirho.len() < self.capacity_chirho {
            return Ok(());
        }
        let victim_chirho = self
            .active_chirho
            .iter()
            .filter(|(_, actor_chirho)| actor_chirho.mailbox_chirho.is_empty())
            .min_by_key(|(_, actor_chirho)| actor_chirho.last_touch_chirho)
            .map(|(cluster_chirho, _)| cluster_chirho.clone());
        let Some(victim_chirho) = victim_chirho else {
            return Err(RegistryErrorChirho::CapacityChirho {
                cluster_chirho: incoming_chirho.clone(),
            });
        };
        let passivated_chirho = self.passivate_chirho(&victim_chirho)?;
        debug_assert!(passivated_chirho, "the LRU victim was selected as resident");
        Ok(())
    }
}
