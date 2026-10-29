// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exits a relay-only voter that wins its election, and keeps a starting voter from settling under a
//! remote winner that is about to do the same.
//!
//! A voter that starts as a follower has no resident actor for the life of its process. If it later
//! wins, every local write refuses as definitely not executed. The watcher here notices that win and
//! stops the process with a fixed identity, so its supervisor restarts it into the startup path, which
//! opens the one resident actor in a fresh process. It reads leadership and sets two flags; it opens
//! nothing, writes nothing to the root, and changes no write path.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/promotion-restart-design-chirho.md`.

use super::voter_startup_chirho::{
    is_warm_local_leader_chirho, GeoNonResidentVoterRoleChirho, GeoVoterStartupRoleChirho,
};
use anyhow::{anyhow, Context, Result};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::{
    election_timeout_upper_bound_chirho, RaftWriterElectorChirho,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The fixed identity a promoted relay-only voter logs and exits with.
pub(crate) const PROMOTION_EXIT_IDENTITY_CHIRHO: &str = "GeoVoterPromotedWhileNonResidentChirho";

/// Driver ticks after the watcher starts before any observation counts, so a leadership blip in
/// the first moments of serving cannot spend a supervisor restart.
const WATCHER_ARMING_TICKS_CHIRHO: u32 = 4;
/// Driver ticks of continuous warm local leadership before the watcher fires.
const WATCHER_CONFIRM_TICKS_CHIRHO: u32 = 4;
/// Driver ticks a firing process has to stop serving and exit before the watcher forces the exit.
const EXIT_BUDGET_TICKS_CHIRHO: u32 = 8;
/// The exit status of a forced exit, after a graceful stop overran its budget (EX_TEMPFAIL).
const FORCED_EXIT_STATUS_CHIRHO: i32 = 75;

/// The watcher's timing and the startup stability window, all derived from one driver tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PromotionExitTimingChirho {
    pub(crate) arming_chirho: Duration,
    pub(crate) confirm_chirho: Duration,
    /// How long a firing process may take to stop gracefully before the watcher forces the exit.
    /// The bound matters: it caps how long a doomed winner stays leader.
    pub(crate) exit_budget_chirho: Duration,
    /// How long a starting voter must see one unchanged remote owner before it serves relay-only.
    ///
    /// A follower keeps naming a dead leader until its own election timeout fires, so a doomed
    /// winner stays visible for its arming, confirmation and bounded exit, plus up to one longest
    /// election timeout after its last heartbeat. The window is that sum plus one more longest
    /// election timeout as margin. A relay-only remote owner is therefore gone, and replaced in a
    /// new term, before a starting voter would settle under it, while that voter is still inside its
    /// own startup window to win as the resident owner. Without this, two survivors hand the win
    /// back and forth, each settling under the other just before the other exits.
    pub(crate) remote_owner_stability_chirho: Duration,
}

impl PromotionExitTimingChirho {
    pub(crate) fn from_driver_tick_chirho(tick_interval_chirho: Duration) -> Result<Self> {
        let ticks_chirho = |count_chirho: u32| {
            tick_interval_chirho
                .checked_mul(count_chirho)
                .ok_or_else(|| anyhow!("promotion-exit timing overflows Duration"))
        };
        let arming_chirho = ticks_chirho(WATCHER_ARMING_TICKS_CHIRHO)?;
        let confirm_chirho = ticks_chirho(WATCHER_CONFIRM_TICKS_CHIRHO)?;
        let exit_budget_chirho = ticks_chirho(EXIT_BUDGET_TICKS_CHIRHO)?;
        let election_upper_bound_chirho = election_timeout_upper_bound_chirho(tick_interval_chirho)
            .context("derive the longest election timeout for the startup stability window")?;
        let remote_owner_stability_chirho = arming_chirho
            .checked_add(confirm_chirho)
            .and_then(|sum_chirho| sum_chirho.checked_add(exit_budget_chirho))
            .and_then(|sum_chirho| sum_chirho.checked_add(election_upper_bound_chirho))
            .and_then(|sum_chirho| sum_chirho.checked_add(election_upper_bound_chirho))
            .ok_or_else(|| anyhow!("promotion-exit stability window overflows Duration"))?;
        Ok(Self {
            arming_chirho,
            confirm_chirho,
            exit_budget_chirho,
            remote_owner_stability_chirho,
        })
    }
}

/// Whether a process that started in `role_chirho` runs the watcher.
///
/// Only a relay-only follower does. A local owner already holds the resident actor. A retiring,
/// transport-only voter is outside placement, so a restart would not make it resident; whether it
/// should hand leadership away is C4 placement's question.
pub(crate) fn watches_startup_role_chirho(role_chirho: GeoVoterStartupRoleChirho) -> bool {
    matches!(
        role_chirho,
        GeoVoterStartupRoleChirho::NonResidentChirho(
            GeoNonResidentVoterRoleChirho::RemoteOwnerChirho
        )
    )
}

/// Decides, from successive leadership observations, when a relay-only voter has won.
#[derive(Debug)]
pub(crate) struct PromotionExitDetectorChirho {
    armed_at_chirho: Instant,
    confirm_chirho: Duration,
    warm_since_chirho: Option<Instant>,
}

impl PromotionExitDetectorChirho {
    pub(crate) fn new_chirho(
        started_at_chirho: Instant,
        timing_chirho: PromotionExitTimingChirho,
    ) -> Self {
        Self {
            armed_at_chirho: started_at_chirho + timing_chirho.arming_chirho,
            confirm_chirho: timing_chirho.confirm_chirho,
            warm_since_chirho: None,
        }
    }

    /// True once warm local leadership has held without a break for the confirmation window,
    /// counted only from arming. Any observation that is not warm local leadership restarts it.
    pub(crate) fn observe_chirho(
        &mut self,
        now_chirho: Instant,
        leadership_chirho: &LeadershipChirho,
        local_node_chirho: &NodeIdChirho,
    ) -> bool {
        if now_chirho < self.armed_at_chirho
            || !is_warm_local_leader_chirho(leadership_chirho, local_node_chirho)
        {
            self.warm_since_chirho = None;
            return false;
        }
        let warm_since_chirho = *self.warm_since_chirho.get_or_insert(now_chirho);
        now_chirho.duration_since(warm_since_chirho) >= self.confirm_chirho
    }
}

/// Holds a starting voter back from serving relay-only until one remote owner, at one term, has
/// stayed in place for the stability window.
#[derive(Debug, Default)]
pub(crate) struct RemoteOwnerStabilityChirho {
    observed_chirho: Option<(NodeIdChirho, u64, Instant)>,
}

impl RemoteOwnerStabilityChirho {
    /// True once `owner_chirho` at `term_chirho` has been observed continuously for `window_chirho`.
    /// A different owner or term starts the window again.
    pub(crate) fn observe_chirho(
        &mut self,
        now_chirho: Instant,
        owner_chirho: &NodeIdChirho,
        term_chirho: u64,
        window_chirho: Duration,
    ) -> bool {
        match &self.observed_chirho {
            Some((observed_owner_chirho, observed_term_chirho, since_chirho))
                if observed_owner_chirho == owner_chirho
                    && *observed_term_chirho == term_chirho =>
            {
                now_chirho.duration_since(*since_chirho) >= window_chirho
            }
            _ => {
                self.observed_chirho = Some((owner_chirho.clone(), term_chirho, now_chirho));
                window_chirho.is_zero()
            }
        }
    }

    /// When the owner now being observed would settle, if one is being observed.
    pub(crate) fn settles_at_chirho(&self, window_chirho: Duration) -> Option<Instant> {
        self.observed_chirho
            .as_ref()
            .map(|(_owner_chirho, _term_chirho, since_chirho)| *since_chirho + window_chirho)
    }

    /// Forget the observed owner, as when no leader, or a cold local leader, is seen.
    pub(crate) fn reset_chirho(&mut self) {
        self.observed_chirho = None;
    }
}

/// The watcher a voter composition runs for the life of its serve loop, with the two flags the exit
/// needs. It is inert unless the startup role is watched.
pub(crate) struct PromotionExitWatchChirho {
    thread_chirho: Option<JoinHandle<()>>,
    fired_chirho: Arc<AtomicBool>,
    shutdown_complete_chirho: Arc<AtomicBool>,
}

impl PromotionExitWatchChirho {
    /// Start the watcher when `role_chirho` is a relay-only follower; otherwise return an inert watch.
    pub(crate) fn start_for_role_chirho(
        role_chirho: GeoVoterStartupRoleChirho,
        elector_chirho: Arc<RaftWriterElectorChirho>,
        local_node_chirho: NodeIdChirho,
        tick_interval_chirho: Duration,
        stop_chirho: Arc<AtomicBool>,
    ) -> Result<Self> {
        let fired_chirho = Arc::new(AtomicBool::new(false));
        let shutdown_complete_chirho = Arc::new(AtomicBool::new(false));
        let thread_chirho = if watches_startup_role_chirho(role_chirho) {
            Some(spawn_promotion_exit_watcher_chirho(
                elector_chirho,
                local_node_chirho,
                PromotionExitTimingChirho::from_driver_tick_chirho(tick_interval_chirho)?,
                tick_interval_chirho.min(Duration::from_millis(100)),
                stop_chirho,
                Arc::clone(&fired_chirho),
                Arc::clone(&shutdown_complete_chirho),
            )?)
        } else {
            None
        };
        Ok(Self {
            thread_chirho,
            fired_chirho,
            shutdown_complete_chirho,
        })
    }

    /// Call once the composition's whole stop is done. It releases a fired watcher's forced-exit
    /// wait, joins it, and turns a fired watch into the fixed identity error.
    pub(crate) fn finish_chirho(self) -> Result<()> {
        self.shutdown_complete_chirho.store(true, Ordering::Release);
        if let Some(thread_chirho) = self.thread_chirho {
            thread_chirho
                .join()
                .map_err(|_panic_chirho| anyhow!("promotion-exit watcher panicked"))?;
        }
        if self.fired_chirho.load(Ordering::Acquire) {
            return Err(anyhow!("{PROMOTION_EXIT_IDENTITY_CHIRHO}"));
        }
        Ok(())
    }
}

/// The startup deadline while a remote owner may be settling.
///
/// An owner first observed late in the bounded startup interval still gets its whole stability
/// window. Without this, a round in which the first winner was a doomed relay-only node uses up
/// half the interval, and the starting voter bails just before the resident winner of the next
/// round would have settled. That costs a supervisor restart (Claude2 #28856). The interval grows
/// by at most one window, so startup stays bounded. An owner first seen AFTER the base deadline
/// cannot settle inside that cap, so it gets no extension at all (Agy R-C1-2c).
pub(crate) fn startup_deadline_chirho(
    base_deadline_chirho: Instant,
    settles_at_chirho: Option<Instant>,
    window_chirho: Duration,
) -> Instant {
    match settles_at_chirho {
        Some(settles_at_chirho) if settles_at_chirho <= base_deadline_chirho + window_chirho => {
            settles_at_chirho.max(base_deadline_chirho)
        }
        _ => base_deadline_chirho,
    }
}

/// Run the detector on its own thread for a relay-only voter. On firing it logs the fixed identity,
/// records the reason in `fired_chirho` and sets the shared stop flag, so the serve loop and the
/// transport wind down exactly as they do on a signal. If the composition has not set
/// `shutdown_complete_chirho` within the exit budget, the watcher forces the exit, because a hung
/// stop would keep a relay-only winner as leader, refusing every write.
fn spawn_promotion_exit_watcher_chirho(
    elector_chirho: Arc<RaftWriterElectorChirho>,
    local_node_chirho: NodeIdChirho,
    timing_chirho: PromotionExitTimingChirho,
    poll_interval_chirho: Duration,
    stop_chirho: Arc<AtomicBool>,
    fired_chirho: Arc<AtomicBool>,
    shutdown_complete_chirho: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("gd7-promotion-exit-chirho".to_owned())
        .spawn(move || {
            let mut detector_chirho =
                PromotionExitDetectorChirho::new_chirho(Instant::now(), timing_chirho);
            while !stop_chirho.load(Ordering::Acquire) {
                let leadership_chirho = elector_chirho.current_leadership_chirho();
                if detector_chirho.observe_chirho(
                    Instant::now(),
                    &leadership_chirho,
                    &local_node_chirho,
                ) {
                    eprintln!(
                        "{PROMOTION_EXIT_IDENTITY_CHIRHO}: this relay-only voter is the warm elected \
                         leader at term {}; exiting so its supervisor restarts it into the resident path",
                        leadership_chirho.term_chirho
                    );
                    fired_chirho.store(true, Ordering::Release);
                    stop_chirho.store(true, Ordering::Release);
                    force_exit_after_budget_chirho(
                        &shutdown_complete_chirho,
                        timing_chirho.exit_budget_chirho,
                        poll_interval_chirho,
                    );
                    return;
                }
                std::thread::sleep(poll_interval_chirho);
            }
        })
        .context("spawn the promotion-exit watcher")
}

/// Wait up to `budget_chirho` for the composition to finish its graceful stop; past it, exit the
/// process. The relay-only process holds no resident actor, so a forced exit is no worse than the
/// crash every durable store here already survives.
fn force_exit_after_budget_chirho(
    shutdown_complete_chirho: &AtomicBool,
    budget_chirho: Duration,
    poll_interval_chirho: Duration,
) {
    let deadline_chirho = Instant::now() + budget_chirho;
    while Instant::now() < deadline_chirho {
        if shutdown_complete_chirho.load(Ordering::Acquire) {
            return;
        }
        std::thread::sleep(poll_interval_chirho);
    }
    if !shutdown_complete_chirho.load(Ordering::Acquire) {
        eprintln!(
            "{PROMOTION_EXIT_IDENTITY_CHIRHO}: the graceful stop overran its {budget_chirho:?} budget; \
             forcing the exit"
        );
        std::process::exit(FORCED_EXIT_STATUS_CHIRHO);
    }
}

#[cfg(test)]
#[path = "promotion_exit_tests_chirho.rs"]
mod tests_chirho;
