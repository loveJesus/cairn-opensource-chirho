// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Test-only hold points on the public error roads: a hook an arm sets runs once, where the road reaches its point,
//! so a real failure can be caused exactly at the boundary under test (public-error-bodies arms, PFE #26451).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Where an arm's hook can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HoldPointChirho {
    /// Right before the app road's refs read, where the measured leak was.
    BeforeAppRefsReadChirho,
    /// Right before the SSR road starts its run.
    BeforeSsrRunChirho,
    /// Right before a road reads the app's request-access policy.
    BeforeRequestAccessPolicyReadChirho,
}

type HookChirho = Box<dyn FnOnce() + Send>;

/// A hook, the point it waits for, and the root it is scoped to: `None` fires for any request reaching the point, which
/// a concurrently running arm can take; `Some(root)` fires only for a request on that root.
static HOOKS_CHIRHO: Mutex<Vec<(HoldPointChirho, Option<PathBuf>, HookChirho)>> =
    Mutex::new(Vec::new());

/// Sets a hook to run once, the next time a road reaches `point_chirho`.
pub(crate) fn set_hold_chirho(
    point_chirho: HoldPointChirho,
    hook_chirho: impl FnOnce() + Send + 'static,
) {
    HOOKS_CHIRHO
        .lock()
        .expect("hold points")
        .push((point_chirho, None, Box::new(hook_chirho)));
}

/// Sets a hook to run once, the next time a road reaches `point_chirho` for a request on `root_chirho`, so arms running
/// in parallel on other roots cannot take it.
pub(crate) fn set_hold_for_root_chirho(
    point_chirho: HoldPointChirho,
    root_chirho: &Path,
    hook_chirho: impl FnOnce() + Send + 'static,
) {
    HOOKS_CHIRHO.lock().expect("hold points").push((
        point_chirho,
        Some(root_chirho.to_path_buf()),
        Box::new(hook_chirho),
    ));
}

/// Runs and removes the first unscoped hook set for `point_chirho`; with none set, nothing happens.
pub(crate) fn reach_chirho(point_chirho: HoldPointChirho) {
    reach_scoped_chirho(point_chirho, None);
}

/// Runs and removes the first hook set for `point_chirho` that is unscoped or scoped to `root_chirho`.
pub(crate) fn reach_for_root_chirho(point_chirho: HoldPointChirho, root_chirho: &Path) {
    reach_scoped_chirho(point_chirho, Some(root_chirho));
}

fn reach_scoped_chirho(point_chirho: HoldPointChirho, root_chirho: Option<&Path>) {
    let hook_chirho = {
        let mut hooks_chirho = HOOKS_CHIRHO.lock().expect("hold points");
        hooks_chirho
            .iter()
            .position(|(set_point_chirho, scope_chirho, _)| {
                *set_point_chirho == point_chirho
                    && scope_chirho
                        .as_deref()
                        .is_none_or(|scope_chirho| Some(scope_chirho) == root_chirho)
            })
            .map(|index_chirho| hooks_chirho.remove(index_chirho).2)
    };
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}
