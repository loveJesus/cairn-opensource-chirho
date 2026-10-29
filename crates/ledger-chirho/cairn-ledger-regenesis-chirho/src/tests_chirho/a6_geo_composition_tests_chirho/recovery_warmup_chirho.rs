// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The recovery warm-up: tick the two survivors until the adopter leads with a warm, live lease.

use super::*;
use cairn_writer_elector_chirho::raft_elector_chirho::election_timeout_upper_bound_chirho;

/// How many election rounds this helper tries before it gives up: a chosen give-up budget, not a
/// Raft worst case (gpt #29802). A round ends inside raft's largest election timeout, and each split
/// vote costs one more round. After a split both survivors reset in the same drain, so another split
/// needs both randomized timeouts to land in the same tick: about 1 in 10 per round, if the draws
/// are independent and uniform over raft's range (claude2 #29804). That figure is a conditional
/// estimate, not a measured failure probability. The budget allows that many election rounds plus
/// the warm-up, and exhausting it is diagnosed by the panic below, not proof of that many splits: a
/// real monotonic lease can also stay invalid under prolonged scheduling or I/O delay (gpt #29808).
/// It bounds how long the helper tries; it does not make failure impossible or guarantee that an
/// election converges.
pub(super) const RECOVERY_WARMUP_ELECTION_ROUNDS_CHIRHO: usize = 5;

/// What the recovery warm-up did, so an arm can pin HOW leadership reached the adopter.
#[derive(Debug)]
pub(super) struct RecoveryWarmupReportChirho {
    pub(super) ticks_chirho: usize,
    pub(super) transfers_chirho: Vec<RecoveryWarmupTransferChirho>,
}

/// One preferred-owner transfer the warm-up started from the other survivor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecoveryWarmupTransferChirho {
    from_term_chirho: u64,
    /// Whether the outgoing leader's own lease was already warm. The warm-up never waits for it.
    from_lease_valid_chirho: bool,
}

/// The most ticks the warm-up may take: its election rounds, plus one more election window for the
/// adopter's own warm-up. That warm-up lasts one election timeout, so it fits inside the window.
pub(super) fn recovery_warmup_tick_bound_chirho() -> usize {
    let window_chirho = election_timeout_upper_bound_chirho(TEST_TICK_INTERVAL_CHIRHO)
        .expect("the fixture tick is a deployable interval");
    let window_ticks_chirho =
        usize::try_from(window_chirho.as_millis() / TEST_TICK_INTERVAL_CHIRHO.as_millis())
            .expect("one election window fits in usize ticks");
    (RECOVERY_WARMUP_ELECTION_ROUNDS_CHIRHO + 1) * window_ticks_chirho
}

/// Tick the two survivors, with the old leader and the held learner silent, until the ADOPTER leads
/// with a warm, live lease.
///
/// Either survivor may win the election. When the other one wins, leadership moves to the adopter at
/// once by preferred-owner transfer, which is election mechanics only and does not wait for the
/// outgoing leader's lease. This helper used to wait for that lease. That spent a whole warm-up on a
/// leader about to hand over, and after one split vote it ran past the old 60-tick bound (Agy #29645,
/// gpt #29654). The exit is still the adopter's own warm lease.
pub(super) fn drive_recovery_until_adopter_warm_without_old_leader_chirho(
    nodes_chirho: &[ClusterNodeChirho],
) -> RecoveryWarmupReportChirho {
    let max_ticks_chirho = recovery_warmup_tick_bound_chirho();
    let mut transfers_chirho = Vec::new();
    for tick_chirho in 0..max_ticks_chirho {
        std::thread::sleep(TEST_TICK_INTERVAL_CHIRHO);
        let mut messages_chirho = nodes_chirho[1..]
            .iter()
            .flat_map(|node_chirho| node_chirho.elector_chirho().tick_chirho())
            .collect::<Vec<_>>();
        for _round_chirho in 0..1_000 {
            if messages_chirho.is_empty() {
                break;
            }
            let mut next_chirho = Vec::new();
            for message_chirho in messages_chirho.drain(..) {
                if matches!(message_chirho.to, 1 | 4) {
                    continue;
                }
                let target_chirho = nodes_chirho
                    .iter()
                    .find(|node_chirho| {
                        node_chirho.elector_chirho().local_raft_id_chirho() == message_chirho.to
                    })
                    .expect("every surviving warmup target is present");
                next_chirho.extend(
                    target_chirho
                        .elector_chirho()
                        .step_chirho(message_chirho)
                        .expect("surviving target accepts warmup traffic"),
                );
            }
            messages_chirho = next_chirho;
        }
        assert!(messages_chirho.is_empty());
        let adopter_leadership_chirho =
            nodes_chirho[1].elector_chirho().current_leadership_chirho();
        if adopter_leadership_chirho.is_leader_chirho
            && adopter_leadership_chirho.lease_valid_chirho
        {
            return RecoveryWarmupReportChirho {
                ticks_chirho: tick_chirho + 1,
                transfers_chirho,
            };
        }
        let other_survivor_leadership_chirho =
            nodes_chirho[2].elector_chirho().current_leadership_chirho();
        // Once per term the other survivor leads: a transfer that did not take is retried only
        // after a later election. That relies on this helper's traffic being reliable and fully
        // drained over a common log cut, so a transfer completes inside its own drain. Under message
        // loss a transfer could fail while the leader stays stable, and this would spend the budget
        // with no new election. No same-term retry is claimed (gpt #29802).
        if other_survivor_leadership_chirho.is_leader_chirho
            && !transfers_chirho
                .iter()
                .any(|transfer_chirho: &RecoveryWarmupTransferChirho| {
                    transfer_chirho.from_term_chirho == other_survivor_leadership_chirho.term_chirho
                })
        {
            transfers_chirho.push(RecoveryWarmupTransferChirho {
                from_term_chirho: other_survivor_leadership_chirho.term_chirho,
                from_lease_valid_chirho: other_survivor_leadership_chirho.lease_valid_chirho,
            });
            drive_recovery_transfer_without_old_leader_chirho(nodes_chirho, 2, 2);
        }
    }
    let adopter_leadership_chirho = nodes_chirho[1].elector_chirho().current_leadership_chirho();
    let other_survivor_leadership_chirho =
        nodes_chirho[2].elector_chirho().current_leadership_chirho();
    panic!(
        "adopter did not become a warmed leader within {max_ticks_chirho} ticks \
         ({RECOVERY_WARMUP_ELECTION_ROUNDS_CHIRHO} election rounds plus a warm-up window); \
         adopter leader={} lease={} term={}, other leader={} lease={} term={}, transfers={:?}",
        adopter_leadership_chirho.is_leader_chirho,
        adopter_leadership_chirho.lease_valid_chirho,
        adopter_leadership_chirho.term_chirho,
        other_survivor_leadership_chirho.is_leader_chirho,
        other_survivor_leadership_chirho.lease_valid_chirho,
        other_survivor_leadership_chirho.term_chirho,
        transfers_chirho,
    );
}

#[path = "recovery_warmup_tests_chirho.rs"]
mod recovery_warmup_tests_chirho;
