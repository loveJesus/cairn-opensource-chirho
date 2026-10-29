// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Constructor-only timing policy for the deployable tier-1 local-liveness lease.

use crate::monotonic_clock_chirho::MonotonicClockChirho;
use anyhow::{anyhow, bail, Result};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

/// The Raft election timeout in ticks, shared by `raft::Config` and deployable lease derivation.
pub(crate) const ELECTION_TICK_CHIRHO: usize = 10;

pub(crate) struct MonotonicLeaseChirho {
    pub(crate) clock_chirho: Arc<dyn MonotonicClockChirho>,
    pub(crate) warmup_millis_chirho: u64,
    pub(crate) expiry_millis_chirho: u64,
}

fn election_timeout_millis_from_driver_tick_chirho(
    driver_tick_interval_chirho: Duration,
) -> Result<(u64, u64)> {
    if driver_tick_interval_chirho.is_zero()
        || !driver_tick_interval_chirho
            .subsec_nanos()
            .is_multiple_of(1_000_000)
    {
        bail!("deployable Raft tick interval must be a positive whole number of milliseconds");
    }
    let driver_tick_millis_chirho = u64::try_from(driver_tick_interval_chirho.as_millis())
        .map_err(|_| anyhow!("Raft driver tick exceeds monotonic lease representation"))?;
    let election_tick_count_chirho = u32::try_from(ELECTION_TICK_CHIRHO)
        .map_err(|_| anyhow!("Raft election tick count exceeds Duration multiplier"))?;
    let election_timeout_chirho = driver_tick_interval_chirho
        .checked_mul(election_tick_count_chirho)
        .ok_or_else(|| anyhow!("Raft election timeout overflows Duration"))?;
    let election_timeout_millis_chirho = u64::try_from(election_timeout_chirho.as_millis())
        .map_err(|_| anyhow!("Raft election timeout exceeds monotonic lease representation"))?;
    Ok((driver_tick_millis_chirho, election_timeout_millis_chirho))
}

pub(crate) fn election_timeout_monotonic_lease_chirho(
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    driver_tick_interval_chirho: Duration,
) -> Result<MonotonicLeaseChirho> {
    let (_driver_tick_millis_chirho, election_timeout_millis_chirho) =
        election_timeout_millis_from_driver_tick_chirho(driver_tick_interval_chirho)?;
    Ok(MonotonicLeaseChirho {
        clock_chirho,
        warmup_millis_chirho: election_timeout_millis_chirho,
        expiry_millis_chirho: election_timeout_millis_chirho,
    })
}

/// The exclusive upper bound on how long a follower waits before it campaigns.
///
/// raft draws each randomized election timeout below `max_election_tick` driver ticks, and the
/// deployable config leaves that at raft's default for `ELECTION_TICK_CHIRHO`, so the bound is
/// derived from raft's own `Config` rather than restated here. It is a timing input for a caller
/// that must outlast one election, never authority evidence.
pub fn election_timeout_upper_bound_chirho(
    driver_tick_interval_chirho: Duration,
) -> Result<Duration> {
    election_timeout_millis_from_driver_tick_chirho(driver_tick_interval_chirho)?;
    let max_election_ticks_chirho = raft::Config {
        election_tick: ELECTION_TICK_CHIRHO,
        ..Default::default()
    }
    .max_election_tick();
    let max_election_ticks_chirho = u32::try_from(max_election_ticks_chirho)
        .map_err(|_| anyhow!("Raft maximum election tick count exceeds Duration multiplier"))?;
    driver_tick_interval_chirho
        .checked_mul(max_election_ticks_chirho)
        .ok_or_else(|| anyhow!("Raft election timeout upper bound overflows Duration"))
}

/// Refuse a relay composition whose healthy-tick lease cannot survive its full transit deduction.
///
/// This is a configuration compatibility check, not authority evidence. The elector keeps the
/// election-tick constant private and checks the relation against the same constructor-only
/// derivation that mints the tier-1 lease and local append-authority pair together.
pub fn validate_election_timeout_relay_margin_chirho(
    driver_tick_interval_chirho: Duration,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<()> {
    let (driver_tick_millis_chirho, election_timeout_millis_chirho) =
        election_timeout_millis_from_driver_tick_chirho(driver_tick_interval_chirho)?;
    let minimum_healthy_remaining_millis_chirho = election_timeout_millis_chirho
        .checked_sub(driver_tick_millis_chirho)
        .ok_or_else(|| anyhow!("RelayLeaseTransitBudgetIncompatibleChirho"))?;
    if minimum_healthy_remaining_millis_chirho <= transit_budget_millis_chirho.get() {
        bail!(
            "RelayLeaseTransitBudgetIncompatibleChirho: one healthy confirmation interval leaves \
             {minimum_healthy_remaining_millis_chirho}ms before a {}ms transit deduction",
            transit_budget_millis_chirho.get()
        );
    }
    Ok(())
}
