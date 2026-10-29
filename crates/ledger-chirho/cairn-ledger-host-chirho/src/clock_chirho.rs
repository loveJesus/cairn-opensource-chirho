// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! System-clock adapter. HLC monotonicity remains ledger-core law.

use cairn_ledger_log_chirho::ports_chirho::LedgerClockPortChirho;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The production wall-clock source for ledger HLC observations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemLedgerClockChirho;

impl LedgerClockPortChirho for SystemLedgerClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration_chirho| u64::try_from(duration_chirho.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// Exact concrete clock retained by a resident ledger.
///
/// Serving uses the system form. Operator-only regenesis uses the reviewed form so the signed plan
/// determines genesis and activation HLCs without opening the resident port bundle to an arbitrary
/// trait-object clock.
#[derive(Debug)]
pub struct ResidentLedgerClockChirho {
    reviewed_now_ms_chirho: Option<AtomicU64>,
}

impl ResidentLedgerClockChirho {
    pub fn system_chirho() -> Self {
        Self {
            reviewed_now_ms_chirho: None,
        }
    }

    pub fn reviewed_chirho(now_ms_chirho: u64) -> Self {
        Self {
            reviewed_now_ms_chirho: Some(AtomicU64::new(now_ms_chirho)),
        }
    }

    pub(crate) fn set_reviewed_chirho(&self, now_ms_chirho: u64) -> bool {
        let Some(reviewed_now_ms_chirho) = &self.reviewed_now_ms_chirho else {
            return false;
        };
        let mut current_chirho = reviewed_now_ms_chirho.load(Ordering::Acquire);
        loop {
            if now_ms_chirho < current_chirho {
                return false;
            }
            if now_ms_chirho == current_chirho {
                return true;
            }
            match reviewed_now_ms_chirho.compare_exchange_weak(
                current_chirho,
                now_ms_chirho,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed_chirho) => current_chirho = observed_chirho,
            }
        }
    }
}

impl LedgerClockPortChirho for ResidentLedgerClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.reviewed_now_ms_chirho
            .as_ref()
            .map(|now_ms_chirho| now_ms_chirho.load(Ordering::Acquire))
            .unwrap_or_else(|| SystemLedgerClockChirho.physical_now_ms_chirho())
    }
}
