// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Runs synchronous sign-in work (log verification, Argon2id, signing, the locked append) on tokio's blocking pool,
//! a few at a time, so a sign-in never occupies an async worker that every other request needs; and warms the
//! sign-in attempt view at startup, so no sign-in pays the first load of the whole log.
//!
//! Why (PFE #1243, confirmed at the bytes in #1244/#1247): the auth handlers are `async fn`s that called the whole
//! synchronous identity path directly on a tokio worker. cax11 runs 2 workers, so two concurrent sign-ins blocked
//! every request; PFE also measured an unrelated GET waiting behind ONE sign-in with 18 workers free, which this
//! removes if its cause is sync-on-worker (the LIFO-slot hypothesis) and which PFE's probe re-measures either way.
//! The permit cap bounds how much CPU sign-ins can take at once: a flood WAITS asynchronously for a permit instead
//! of burning the blocking pool on Argon2. Each task holds its permit until its work is done, so a client that hangs
//! up mid-request cannot free a slot while its work still computes (R11.1; PFE #26081). Workflow:
//! spec-chirho/tasklists-chirho/26-10-01_16-40-tasklist-signin_cost_engine_fix-chirho.md.

use super::sign_in_gate_chirho::SignInMeterChirho;
use cairn_chirho::identity_chirho::PublicAuthRefusalChirho;
use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

/// Half the available parallelism, at least one: on a 2-vCPU host one sign-in computes at a time and a core stays
/// free for everything else.
fn default_auth_permits_chirho() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism_chirho| (parallelism_chirho.get() / 2).max(1))
        .unwrap_or(1)
}

fn auth_permits_chirho() -> &'static Arc<Semaphore> {
    &auth_pool_chirho().0
}

fn auth_pool_chirho() -> &'static (Arc<Semaphore>, usize) {
    static PERMITS_CHIRHO: OnceLock<(Arc<Semaphore>, usize)> = OnceLock::new();
    PERMITS_CHIRHO.get_or_init(|| {
        let capacity_chirho = default_auth_permits_chirho();
        (Arc::new(Semaphore::new(capacity_chirho)), capacity_chirho)
    })
}

// Observed only after the fixture's HTTP handlers have drained, so none can enqueue new auth work.
// Do not close this process-wide pool: normal serving and tests retain its existing admission law.
#[cfg(feature = "dev-transient-review-fixture-chirho")]
pub(super) fn fixture_auth_custody_chirho() -> (Arc<Semaphore>, usize) {
    let (permits_chirho, capacity_chirho) = auth_pool_chirho();
    (Arc::clone(permits_chirho), *capacity_chirho)
}

/// The blocking pool did not complete a sign-in's work: its task panicked, or the runtime cancelled it at shutdown. The
/// work may have stopped anywhere, after a write included, so a road that writes answers it as not known (K4 Part 3's
/// connection road, PFE #26813). Its text is the one this error always had, so every other road's answer is unchanged.
#[derive(Debug)]
pub(super) struct SignInWorkIncompleteChirho;

impl std::fmt::Display for SignInWorkIncompleteChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str("sign-in work did not complete")
    }
}

impl std::error::Error for SignInWorkIncompleteChirho {}

/// Run `task_chirho` off the async workers once one of `permits_chirho` is free. Waiting for a permit is
/// asynchronous, so a queue of sign-ins never holds a worker; the work itself runs on the blocking pool. The TASK holds
/// its permit until its work is done (R11.1; PFE #26081): when a client hangs up mid-request the server drops the
/// handler awaiting here while the work runs on, so a permit held by the handler would free a slot with the Argon2id
/// still computing.
pub(super) async fn run_blocking_auth_with_permits_chirho<OutputChirho>(
    permits_chirho: &Arc<Semaphore>,
    task_chirho: impl FnOnce() -> anyhow::Result<OutputChirho> + Send + 'static,
) -> anyhow::Result<OutputChirho>
where
    OutputChirho: Send + 'static,
{
    let permit_chirho = Arc::clone(permits_chirho)
        .acquire_owned()
        .await
        .map_err(|_closed_chirho| anyhow::anyhow!("sign-in work permits are closed"))?;
    tokio::task::spawn_blocking(move || {
        let _permit_chirho = permit_chirho;
        task_chirho()
    })
    .await
    .map_err(|_join_chirho| anyhow::Error::new(SignInWorkIncompleteChirho))?
}

/// The production entry point: every synchronous sign-in call from an async handler goes through here.
pub(super) async fn run_blocking_auth_chirho<OutputChirho>(
    task_chirho: impl FnOnce() -> anyhow::Result<OutputChirho> + Send + 'static,
) -> anyhow::Result<OutputChirho>
where
    OutputChirho: Send + 'static,
{
    run_blocking_auth_with_permits_chirho(auth_permits_chirho(), task_chirho).await
}

/// A public auth road (login, token or recover) off the async workers, metered by the sign-in gate in the SAME
/// blocking task (R12): the meter's admission is checked and its slots reserved right before the work, so a burst queued
/// behind the permit cannot overrun a source's limit, and the slots are settled right after it. When a client hangs up
/// mid-request the server drops the handler awaiting here, but the work and its settling run on. A refused admission
/// runs no work and records nothing. A pool failure comes back as a refusal for which the runner appends no row, but
/// the failed task may already have appended rows of its own: K4 Part 3's join arm shows a success row (PFE #26821).
/// Closed permits ran no work and reserved nothing; a task that panics after its admission never settles, so both
/// slots it reserved stay charged until they leave their windows. A panic is a bug, and keeping is the conservative
/// error (PFE #26814).
pub(super) async fn run_blocking_public_auth_chirho<OutputChirho>(
    meter_chirho: SignInMeterChirho,
    task_chirho: impl FnOnce() -> Result<OutputChirho, PublicAuthRefusalChirho> + Send + 'static,
) -> Result<OutputChirho, PublicAuthRefusalChirho>
where
    OutputChirho: Send + 'static,
{
    run_blocking_public_auth_with_permits_chirho(auth_permits_chirho(), meter_chirho, task_chirho)
        .await
}

/// `run_blocking_public_auth_chirho` under the given permits, which the hold-and-release arms supply.
pub(super) async fn run_blocking_public_auth_with_permits_chirho<OutputChirho>(
    permits_chirho: &Arc<Semaphore>,
    meter_chirho: SignInMeterChirho,
    task_chirho: impl FnOnce() -> Result<OutputChirho, PublicAuthRefusalChirho> + Send + 'static,
) -> Result<OutputChirho, PublicAuthRefusalChirho>
where
    OutputChirho: Send + 'static,
{
    run_blocking_auth_with_permits_chirho(permits_chirho, move || {
        let admission_chirho = match meter_chirho.admit_chirho() {
            Ok(admission_chirho) => admission_chirho,
            Err(error_chirho) => {
                return Ok(Err(PublicAuthRefusalChirho::not_recorded_chirho(
                    error_chirho,
                )))
            }
        };
        let outcome_chirho = task_chirho();
        meter_chirho.settle_chirho(admission_chirho, &outcome_chirho);
        Ok(outcome_chirho)
    })
    .await
    .unwrap_or_else(|error_chirho| Err(PublicAuthRefusalChirho::not_recorded_chirho(error_chirho)))
}

/// Build the sign-in attempt view before the listener accepts traffic, so a process's first load (proportional to
/// the whole log) lands on startup, not on a sign-in (the bounded-auth-history charter's property 1). Read-only. A
/// log that does not verify is not fatal here: sign-ins refuse on their own until it does.
pub(super) async fn warm_sign_in_view_chirho(root_chirho: &std::path::Path) {
    let root_chirho = root_chirho.to_path_buf();
    let warmed_chirho = tokio::task::spawn_blocking(move || {
        cairn_chirho::identity_chirho::warm_auth_attempt_view_chirho(&root_chirho)
    })
    .await;
    if let Ok(Err(error_chirho)) = warmed_chirho {
        eprintln!(
            "cairn-chirho: the sign-in attempt log did not verify at startup; sign-ins refuse until it does: {error_chirho:#}"
        );
    }
}
