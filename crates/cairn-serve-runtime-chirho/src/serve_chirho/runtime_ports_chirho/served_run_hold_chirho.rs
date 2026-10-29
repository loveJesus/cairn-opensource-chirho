// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-only hold points that park, fail or panic served work where it executes, keyed by root so tests running in
//! parallel never reach each other's work.
//!
//! Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long parked work waits for its test before resuming on its own. Work that parks an async worker stops the
/// test's own requests from being served, so it can only resume by timing out, and the arm reads that as its failure.
const HOLD_TIMEOUT_CHIRHO: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum HoldSiteChirho {
    /// The start of a served or preview run, wherever it executes.
    RunChirho,
    /// The start of the named app route's after-write projection refresh.
    RefreshChirho,
    /// The invoke critical section, after its run and before its final version observation.
    InvokeAfterRunChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HoldModeChirho {
    /// Wait until the test releases the hold.
    ParkChirho,
    /// Return an injected error, as a failing step would.
    FailChirho,
    /// Panic, as a defect in the work would.
    PanicChirho,
}

#[derive(Default)]
struct HoldStateChirho {
    entered_chirho: usize,
    left_chirho: usize,
    released_chirho: bool,
    timed_out_chirho: usize,
}

pub(crate) struct ServedRunHoldChirho {
    mode_chirho: HoldModeChirho,
    state_chirho: Mutex<HoldStateChirho>,
    changed_chirho: Condvar,
}

type HoldKeyChirho = (PathBuf, HoldSiteChirho);
type HoldMapChirho = HashMap<HoldKeyChirho, Arc<ServedRunHoldChirho>>;

fn holds_chirho() -> &'static Mutex<HoldMapChirho> {
    static HOLDS_CHIRHO: OnceLock<Mutex<HoldMapChirho>> = OnceLock::new();
    HOLDS_CHIRHO.get_or_init(Default::default)
}

/// An armed hold. Dropping it releases any parked work and disarms the site, so a failing arm never leaves work parked.
pub(crate) struct ArmedHoldChirho {
    key_chirho: HoldKeyChirho,
    hold_chirho: Arc<ServedRunHoldChirho>,
}

/// Arm one root's hold at one site: every piece of work on that root that reaches the site meets `mode_chirho`.
pub(crate) fn arm_chirho(
    root_chirho: &Path,
    site_chirho: HoldSiteChirho,
    mode_chirho: HoldModeChirho,
) -> ArmedHoldChirho {
    let key_chirho = (root_chirho.to_path_buf(), site_chirho);
    let hold_chirho = Arc::new(ServedRunHoldChirho {
        mode_chirho,
        state_chirho: Mutex::new(HoldStateChirho::default()),
        changed_chirho: Condvar::new(),
    });
    holds_chirho()
        .lock()
        .expect("served run holds")
        .insert(key_chirho.clone(), hold_chirho.clone());
    ArmedHoldChirho {
        key_chirho,
        hold_chirho,
    }
}

fn armed_chirho(
    root_chirho: &Path,
    site_chirho: HoldSiteChirho,
) -> Option<Arc<ServedRunHoldChirho>> {
    holds_chirho()
        .lock()
        .expect("served run holds")
        .get(&(root_chirho.to_path_buf(), site_chirho))
        .cloned()
}

/// Called where served work reaches `site_chirho`, on whatever thread runs it. A no-op unless a test armed this root
/// at this site. A parked caller BLOCKS its thread, which is the point: on an async worker that is the defect an arm
/// exists to catch.
pub(crate) fn wait_if_armed_chirho(root_chirho: &Path, site_chirho: HoldSiteChirho) -> Result<()> {
    let Some(hold_chirho) = armed_chirho(root_chirho, site_chirho) else {
        return Ok(());
    };
    hold_chirho.enter_chirho()?;
    let state_chirho = hold_chirho.state_chirho.lock().expect("hold state");
    let (mut state_chirho, wait_chirho) = hold_chirho
        .changed_chirho
        .wait_timeout_while(state_chirho, HOLD_TIMEOUT_CHIRHO, |state_chirho| {
            !state_chirho.released_chirho
        })
        .expect("hold wait");
    if wait_chirho.timed_out() {
        state_chirho.timed_out_chirho += 1;
    }
    state_chirho.left_chirho += 1;
    Ok(())
}

/// The same hold for a site inside async work: it waits without blocking the worker it runs on.
pub(crate) async fn wait_if_armed_async_chirho(
    root_chirho: &Path,
    site_chirho: HoldSiteChirho,
) -> Result<()> {
    let Some(hold_chirho) = armed_chirho(root_chirho, site_chirho) else {
        return Ok(());
    };
    hold_chirho.enter_chirho()?;
    let deadline_chirho = Instant::now() + HOLD_TIMEOUT_CHIRHO;
    while !hold_chirho.released_chirho() {
        if Instant::now() >= deadline_chirho {
            hold_chirho
                .state_chirho
                .lock()
                .expect("hold state")
                .timed_out_chirho += 1;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    hold_chirho
        .state_chirho
        .lock()
        .expect("hold state")
        .left_chirho += 1;
    Ok(())
}

impl ServedRunHoldChirho {
    /// Count the arrival, then apply a fail or panic mode before any wait.
    fn enter_chirho(&self) -> Result<()> {
        self.state_chirho.lock().expect("hold state").entered_chirho += 1;
        self.changed_chirho.notify_all();
        match self.mode_chirho {
            HoldModeChirho::ParkChirho => Ok(()),
            HoldModeChirho::FailChirho => Err(anyhow::anyhow!("injected served-work failure")),
            HoldModeChirho::PanicChirho => panic!("injected served-work panic"),
        }
    }

    fn released_chirho(&self) -> bool {
        self.state_chirho
            .lock()
            .expect("hold state")
            .released_chirho
    }
}

impl ArmedHoldChirho {
    pub(crate) fn entered_chirho(&self) -> usize {
        self.hold_chirho
            .state_chirho
            .lock()
            .expect("hold state")
            .entered_chirho
    }

    pub(crate) fn timed_out_chirho(&self) -> usize {
        self.hold_chirho
            .state_chirho
            .lock()
            .expect("hold state")
            .timed_out_chirho
    }

    /// How many pieces of work have passed the hold after parking.
    pub(crate) fn left_chirho(&self) -> usize {
        self.hold_chirho
            .state_chirho
            .lock()
            .expect("hold state")
            .left_chirho
    }

    /// Wait until `count_chirho` pieces of work have arrived, or the deadline passes; true when they arrived.
    pub(crate) fn wait_entered_chirho(
        &self,
        count_chirho: usize,
        deadline_chirho: Duration,
    ) -> bool {
        let state_chirho = self.hold_chirho.state_chirho.lock().expect("hold state");
        let (state_chirho, _wait_chirho) = self
            .hold_chirho
            .changed_chirho
            .wait_timeout_while(state_chirho, deadline_chirho, |state_chirho| {
                state_chirho.entered_chirho < count_chirho
            })
            .expect("hold wait");
        state_chirho.entered_chirho >= count_chirho
    }

    pub(crate) fn release_chirho(&self) {
        self.hold_chirho
            .state_chirho
            .lock()
            .expect("hold state")
            .released_chirho = true;
        self.hold_chirho.changed_chirho.notify_all();
    }
}

impl Drop for ArmedHoldChirho {
    fn drop(&mut self) {
        self.release_chirho();
        if let Ok(mut holds_chirho) = holds_chirho().lock() {
            holds_chirho.remove(&self.key_chirho);
        }
    }
}
