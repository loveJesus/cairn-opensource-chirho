// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! In-memory `LedgerRuntimePortChirho` adapter — a single-threaded deterministic scheduler over
//! VIRTUAL time (no real sleeping), the scheduling half of the sim.
//!
//! `sleep_until_ms` advances a virtual clock to the deadline so the durable-timer sweep runs
//! deterministically and instantly instead of blocking a test for real milliseconds. An optional
//! constant `extra_delay_ms` models a slow-wakeup fault — the sleep overshoots its deadline — and
//! virtual time never moves backward.

use std::cell::Cell;

use cairn_ledger_log_chirho::ports_chirho::LedgerRuntimePortChirho;

/// A deterministic virtual-time scheduler.
pub struct SimRuntimeChirho {
    virtual_now_ms_chirho: Cell<u64>,
    extra_delay_ms_chirho: u64,
}

impl SimRuntimeChirho {
    /// A scheduler whose virtual clock starts at `start_ms`.
    pub fn new_chirho(start_ms_chirho: u64) -> Self {
        Self {
            virtual_now_ms_chirho: Cell::new(start_ms_chirho),
            extra_delay_ms_chirho: 0,
        }
    }

    /// A scheduler that overshoots every sleep by `extra_delay_ms` — a slow-wakeup fault.
    pub fn with_delay_chirho(start_ms_chirho: u64, extra_delay_ms_chirho: u64) -> Self {
        Self {
            virtual_now_ms_chirho: Cell::new(start_ms_chirho),
            extra_delay_ms_chirho,
        }
    }

    /// The current virtual time.
    pub fn virtual_now_ms_chirho(&self) -> u64 {
        self.virtual_now_ms_chirho.get()
    }
}

impl LedgerRuntimePortChirho for SimRuntimeChirho {
    fn sleep_until_ms_chirho(&self, deadline_ms_chirho: u64) {
        let now_chirho = self.virtual_now_ms_chirho.get();
        // The slow-wakeup fault (extra_delay > 0) is added to max(deadline, now), NOT gated on
        // deadline > now: a real timer-sweep wakeup costs latency even when the deadline has already
        // passed, so even an already-satisfied sleep consumes the delay. Intended (claude2 O-4203).
        let target_chirho = deadline_ms_chirho
            .max(now_chirho)
            .saturating_add(self.extra_delay_ms_chirho);
        // Never move virtual time backward.
        if target_chirho > now_chirho {
            self.virtual_now_ms_chirho.set(target_chirho);
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn sleep_advances_virtual_time_to_deadline_chirho() {
        let runtime_chirho = SimRuntimeChirho::new_chirho(100);
        runtime_chirho.sleep_until_ms_chirho(500);
        assert_eq!(runtime_chirho.virtual_now_ms_chirho(), 500);
    }

    #[test]
    fn sleep_past_deadline_does_not_move_backward_chirho() {
        let runtime_chirho = SimRuntimeChirho::new_chirho(500);
        runtime_chirho.sleep_until_ms_chirho(100); // already passed
        assert_eq!(runtime_chirho.virtual_now_ms_chirho(), 500); // unchanged
    }

    #[test]
    fn delay_overshoots_the_deadline_chirho() {
        let runtime_chirho = SimRuntimeChirho::with_delay_chirho(100, 30);
        runtime_chirho.sleep_until_ms_chirho(500);
        assert_eq!(runtime_chirho.virtual_now_ms_chirho(), 530); // 500 + 30 slow wakeup
    }

    #[test]
    fn virtual_time_is_monotone_across_sleeps_chirho() {
        let runtime_chirho = SimRuntimeChirho::new_chirho(0);
        runtime_chirho.sleep_until_ms_chirho(200);
        runtime_chirho.sleep_until_ms_chirho(150); // past
        runtime_chirho.sleep_until_ms_chirho(400);
        assert_eq!(runtime_chirho.virtual_now_ms_chirho(), 400);
    }
}
