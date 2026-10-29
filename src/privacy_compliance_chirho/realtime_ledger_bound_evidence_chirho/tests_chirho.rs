// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pins that these three doors still BIND against the ledger, rather than merely still compiling.
//!
//! The failure this exists to catch is silent and cheap to cause. Every door here is five lines —
//! build the view, pass `Some(&view)` — and the kept evidence bodies accept `None` just as happily,
//! skipping the ledger cross-check with no error and no warning. So the whole difference between a
//! bound verification and a thinned one is one argument that nothing else checks.
//!
//! Slice 2 documented `None` as the intended post-wave-1 state, which stopped being reachable when
//! (a2-1) repointed the view onto a read that survives the spine deletion. A future reader meeting
//! that stale sentence has every reason to "simplify" these wrappers to `None` — and every test on
//! an intact corpus would stay green while a subject export quietly lost a verified source.
//!
//! These arms fail if that happens, and they do it without needing realtime fixtures: the view is
//! built BEFORE any realtime record is read, so its gate fires on an empty root. That makes the
//! probe refusal usable as a live-wire test for the binding itself.

use super::{
    reveal_realtime_transcript_chirho, verify_realtime_chirho, verify_realtime_epilogues_chirho,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-realtime-ledger-bound-{n_chirho}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d_chirho| d_chirho.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&root_chirho).expect("create temp root");
    root_chirho
}

/// Give a root a Gate-1 authority-mode branch, matching the ledger characterization fixture: the
/// hash is arbitrary because a PRESENCE-only probe never dereferences it.
fn add_gate1_authority_branch_chirho(root_chirho: &Path) {
    let mut refs_chirho = crate::refs_chirho::load_refs_chirho(root_chirho).expect("load refs");
    refs_chirho.branches_chirho.insert(
        cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO.to_string(),
        crate::model_chirho::HashChirho("0".repeat(64)),
    );
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        serde_json::to_vec_pretty(&refs_chirho).expect("encode refs"),
    )
    .expect("write refs fixture");
}

/// All three doors reach the ledger, proven by inheriting the read's gate rather than by reading
/// the source.
///
/// **If this goes red because a door now RETURNS on a branched root, the binding was dropped** —
/// that is the regression, and the fix is to restore `Some(&view)`, not to relax the arm. If it
/// goes red because the refusal no longer names the branch, the probe's message changed and the
/// assertion should follow it through the constant.
#[test]
fn every_ledger_bound_door_inherits_the_single_road_refusal_chirho() {
    let root_chirho = temp_root_chirho();

    // POSITIVE CONTROL FIRST. Without it, a door that errors for an unrelated reason -- a missing
    // directory, an unreadable log -- would look like a working gate, and the arm would pass while
    // proving nothing about the ledger at all.
    assert_eq!(
        verify_realtime_chirho(&root_chirho).expect("a clean empty root verifies"),
        (0, 0),
        "the control must pass cleanly, or the refusal below is not attributable to the branch"
    );

    add_gate1_authority_branch_chirho(&root_chirho);

    let branch_chirho = cairn_model_gate1_chirho::GATE1_AUTHORITY_MODE_BRANCH_CHIRHO;
    for (name_chirho, error_chirho) in [
        (
            "verify_realtime_chirho",
            verify_realtime_chirho(&root_chirho).err(),
        ),
        (
            "verify_realtime_epilogues_chirho",
            verify_realtime_epilogues_chirho(&root_chirho).err(),
        ),
        (
            "reveal_realtime_transcript_chirho",
            reveal_realtime_transcript_chirho(&root_chirho, "session-chirho", "op-chirho", "audit")
                .err(),
        ),
    ] {
        let text_chirho = error_chirho
            .unwrap_or_else(|| {
                panic!("{name_chirho} answered a branched root instead of refusing it -- the ledger binding is gone")
            })
            .to_string();

        // ASSERT THE REASON, not merely that it failed. `reveal_realtime_transcript_chirho` on this
        // root would fail anyway for a missing session, so "it errored" is satisfied by the wrong
        // cause -- the fixture must be unable to pass for a reason other than the one under test.
        assert!(
            text_chirho.contains(branch_chirho),
            "{name_chirho} must refuse THROUGH the ledger read, naming the branch to inspect: {text_chirho}"
        );
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}
