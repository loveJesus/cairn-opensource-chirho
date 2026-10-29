// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A node that cannot tick must not look like a node that is merely idle.
//!
//! `tick_once_chirho` deliberately contains a failing tick so the timer thread cannot die. The cost of
//! that containment is that the failure is invisible: the node keeps serving, dials nobody, persists
//! nothing, and its `/leader-chirho` output is identical to a healthy node that simply has no work.
//! This was measured the expensive way — a three-host cluster sat at term 0 indefinitely with no log
//! line, no panic and no error output anywhere, and the absence of outbound sockets was the only
//! signal available.
//!
//! So the containment stays and the silence goes: failures are counted, and this pins that the count
//! is real rather than decorative.

use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::driver_chirho::RaftDriverChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::sync::Arc;
use std::time::Duration;

fn temp_dir_chirho(tag_chirho: &str) -> std::path::PathBuf {
    let base_chirho = std::env::temp_dir().join(format!(
        "cairn-tick-visibility-{tag_chirho}-{}-chirho",
        std::process::id()
    ));
    std::fs::create_dir_all(&base_chirho).expect("create temp dir");
    base_chirho
}

fn driver_over_durable_elector_chirho(dir_chirho: std::path::PathBuf) -> Arc<RaftDriverChirho> {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-tick-visibility-chirho".to_string(),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho,
            NodeIdChirho("1".repeat(64)),
            group_chirho,
        )
        .expect("build a durable single-node elector"),
    );
    Arc::new(
        RaftDriverChirho::new_chirho(elector_chirho, Vec::new(), Duration::from_secs(2))
            .expect("build a driver with no peers"),
    )
}

#[test]
fn a_healthy_driver_reports_no_tick_failures_chirho() {
    // The positive control. Without it, a counter stuck at zero would pass the test below by being
    // broken rather than by the node being healthy.
    let driver_chirho = driver_over_durable_elector_chirho(temp_dir_chirho("healthy"));
    for _tick_chirho in 0..20 {
        driver_chirho.tick_once_chirho();
    }
    assert_eq!(
        driver_chirho.tick_failures_chirho(),
        0,
        "a driver over a healthy elector must report zero tick failures"
    );
}

#[test]
fn losing_the_durable_directory_is_not_promptly_detected_chirho() {
    // CHARACTERISATION of a SECOND blind spot, written after the obvious test turned out vacuous.
    //
    // The intuitive way to force a tick failure is to delete the elector's durable directory and
    // watch the counter climb. It does not climb: measured, forty ticks after `remove_dir_all` still
    // report zero failures, because raft only persists on state change and an idle single node has
    // none. So storage loss is NOT promptly detected — the node keeps ticking, keeps serving, and
    // keeps reporting itself healthy while its durable home no longer exists.
    //
    // That is recorded rather than asserted away, because it is exactly the class of thing that
    // makes a hosted node look fine while it is not. **If this test ever fails, that is good news**:
    // it means storage loss became detectable, and it should be replaced by an assertion that the
    // failure is counted rather than reverted.
    let dir_chirho = temp_dir_chirho("storage-loss");
    let driver_chirho = driver_over_durable_elector_chirho(dir_chirho.clone());

    driver_chirho.tick_once_chirho();
    let baseline_chirho = driver_chirho.tick_failures_chirho();
    assert_eq!(baseline_chirho, 0, "a fresh healthy driver starts clean");

    std::fs::remove_dir_all(&dir_chirho).expect("remove the elector's durable directory");
    for _tick_chirho in 0..40 {
        driver_chirho.tick_once_chirho();
    }

    assert_eq!(
        driver_chirho.tick_failures_chirho(),
        0,
        "TODAY losing the durable directory is not detected by ticking; if this now reports \
         failures, storage loss became observable and this characterisation should be replaced by \
         the stronger assertion rather than reverted"
    );
}
