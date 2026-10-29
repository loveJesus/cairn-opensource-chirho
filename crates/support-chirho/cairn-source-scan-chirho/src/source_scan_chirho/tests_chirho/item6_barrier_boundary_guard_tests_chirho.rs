// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::*;

const BARRIER_CONTROLLER_PATH_CHIRHO: &str =
    "crates/stores-chirho/cairn-writer-elector-http-chirho/tests/barrier_controller_chirho.rs";
const BARRIER_CONTROLLER_NEEDLE_CHIRHO: &str = "TcpBarrierControllerChirho";
const BARRIER_CONTROLLER_OWNER_PATH_CHIRHO: &str =
    "crates/stores-chirho/cairn-writer-elector-http-chirho/tests/failback_election_chirho.rs";
const BARRIER_CONTROLLER_GUARD_PATH_CHIRHO: &str =
    "crates/support-chirho/cairn-source-scan-chirho/src/source_scan_chirho/tests_chirho/item6_barrier_boundary_guard_tests_chirho.rs";

fn barrier_controller_needle_files_chirho() -> Vec<String> {
    let root_chirho = workspace_root_chirho();
    let mut needle_files_chirho = Vec::new();
    for file_chirho in workspace_all_rs_files_chirho() {
        let relative_file_chirho = file_chirho
            .strip_prefix(&root_chirho)
            .expect("workspace Rust file is under the workspace root");
        let file_text_chirho = relative_file_chirho.to_string_lossy();
        let source_chirho = std::fs::read_to_string(root_chirho.join(&*file_text_chirho))
            .expect("read workspace Rust source");
        if source_chirho.contains(BARRIER_CONTROLLER_NEEDLE_CHIRHO) {
            needle_files_chirho.push(file_text_chirho.to_string());
        }
    }
    needle_files_chirho.sort();
    needle_files_chirho
}

#[test]
fn item6_barrier_controller_needle_population_is_nonempty_chirho() {
    assert_eq!(
        barrier_controller_needle_files_chirho(),
        vec![
            BARRIER_CONTROLLER_PATH_CHIRHO.to_string(),
            BARRIER_CONTROLLER_OWNER_PATH_CHIRHO.to_string(),
            BARRIER_CONTROLLER_GUARD_PATH_CHIRHO.to_string(),
        ]
    );
}

#[test]
fn item6_barrier_controller_stays_in_harness_test_support_chirho() {
    let root_chirho = workspace_root_chirho();
    let controller_path_chirho = root_chirho.join(BARRIER_CONTROLLER_PATH_CHIRHO);
    assert!(
        controller_path_chirho.is_file(),
        "item 6.1 controller must remain at its harness-only path: {}",
        controller_path_chirho.display()
    );
    assert!(
        BARRIER_CONTROLLER_PATH_CHIRHO.contains("/tests/"),
        "the controller path must stay outside app/DAG production source"
    );

    let production_mentions_chirho = barrier_controller_needle_files_chirho()
        .into_iter()
        .filter(|file_text_chirho| {
            file_text_chirho != BARRIER_CONTROLLER_PATH_CHIRHO
                && file_text_chirho != BARRIER_CONTROLLER_OWNER_PATH_CHIRHO
                && file_text_chirho != BARRIER_CONTROLLER_GUARD_PATH_CHIRHO
        })
        .collect::<Vec<_>>();
    assert!(
        production_mentions_chirho.is_empty(),
        "item 6.1 controller must not be reachable from app/DAG or production Rust: {production_mentions_chirho:?}"
    );
}
