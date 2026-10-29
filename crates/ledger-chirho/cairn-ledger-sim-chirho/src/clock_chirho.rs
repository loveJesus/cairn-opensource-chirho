// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! In-memory `LedgerClockPortChirho` adapter — a scripted physical clock, the time half of the sim.
//!
//! The port only reports what the clock says; the HLC monotonic guard lives in ledger code, not
//! here. So the sim clock is a scripted ORACLE: a test hands it an exact sequence of physical-ms
//! readings — including regressions (a reading smaller than its predecessor) and skews (a large
//! jump) — and the toy log's HLC logic must stay monotone across them. When the script is exhausted
//! the clock holds its final reading.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use cairn_ledger_log_chirho::ports_chirho::LedgerClockPortChirho;

/// A scripted physical clock.
pub struct SimClockChirho {
    readings_chirho: RefCell<VecDeque<u64>>,
    last_chirho: Cell<u64>,
}

impl SimClockChirho {
    /// A clock that returns `readings` in order, then holds the final value forever.
    pub fn scripted_chirho(readings_chirho: impl IntoIterator<Item = u64>) -> Self {
        let readings_chirho: VecDeque<u64> = readings_chirho.into_iter().collect();
        let last_chirho = readings_chirho.back().copied().unwrap_or(0);
        Self {
            readings_chirho: RefCell::new(readings_chirho),
            last_chirho: Cell::new(last_chirho),
        }
    }

    /// A clock that always returns `value`.
    pub fn fixed_chirho(value_chirho: u64) -> Self {
        Self {
            readings_chirho: RefCell::new(VecDeque::new()),
            last_chirho: Cell::new(value_chirho),
        }
    }

    /// A monotone clock: `count` readings starting at `start`, advancing by `step` each call.
    pub fn advancing_chirho(start_chirho: u64, step_chirho: u64, count_chirho: usize) -> Self {
        let readings_chirho = (0..count_chirho as u64)
            .map(|i_chirho| start_chirho.saturating_add(i_chirho * step_chirho));
        Self::scripted_chirho(readings_chirho)
    }
}

impl LedgerClockPortChirho for SimClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        if let Some(next_chirho) = self.readings_chirho.borrow_mut().pop_front() {
            self.last_chirho.set(next_chirho);
            next_chirho
        } else {
            self.last_chirho.get()
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn scripted_returns_in_order_then_holds_last_chirho() {
        let clock_chirho = SimClockChirho::scripted_chirho([100, 200, 300]);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 100);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 200);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 300);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 300); // held
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 300);
    }

    #[test]
    fn fixed_always_returns_the_same_value_chirho() {
        let clock_chirho = SimClockChirho::fixed_chirho(42);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 42);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 42);
    }

    #[test]
    fn advancing_is_monotone_chirho() {
        let clock_chirho = SimClockChirho::advancing_chirho(1000, 5, 3);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 1000);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 1005);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 1010);
    }

    #[test]
    fn regression_is_reported_faithfully_chirho() {
        // The clock port does not hide a backward jump; the ledger HLC guard must handle it.
        let clock_chirho = SimClockChirho::scripted_chirho([100, 50]);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 100);
        assert_eq!(clock_chirho.physical_now_ms_chirho(), 50);
    }
}
