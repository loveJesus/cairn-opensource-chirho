// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Virtual-actor registry proofs (CF1 clause 4): refuse-newest backpressure, hot-actors-never-
//! evicted, LRU passivate/hydrate state preservation, and the O(active) registry scaling twin.
//! Reuses the journal test harness (one memory storage, same ports) — the registry adds no
//! authority, so these tests assert LIFECYCLE law; admission law is the journal suite's.

use crate::journal_chirho::LedgerJournalChirho;
use crate::journal_tests_chirho::{mint_request_chirho, transfer_request_chirho, HarnessChirho};
use crate::ports_chirho::StoragePathChirho;
use crate::registry_chirho::{LedgerActorRegistryChirho, RegistryErrorChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;

fn registry_path_chirho(cluster_chirho: &ClusterIdChirho) -> StoragePathChirho {
    StoragePathChirho(format!("journals/{}.jsonl", cluster_chirho.0))
}

fn cluster_n_chirho(n_chirho: usize) -> ClusterIdChirho {
    ClusterIdChirho(format!("cluster-reg-{n_chirho}-chirho"))
}

/// Create a journal for a cluster directly (registries hydrate EXISTING journals; creation is an
/// explicit act).
fn create_cluster_chirho(harness_chirho: &HarnessChirho, cluster_chirho: &ClusterIdChirho) {
    LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        registry_path_chirho(cluster_chirho),
        cluster_chirho.clone(),
        1,
    )
    .unwrap();
}

#[test]
fn mailbox_refuses_newest_before_any_state_effect_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_chirho = harness_chirho.cluster_chirho();
    create_cluster_chirho(&harness_chirho, &cluster_chirho);
    let mut registry_chirho = LedgerActorRegistryChirho::new_chirho(
        harness_chirho.ports_chirho(),
        registry_path_chirho,
        4,
        2,
    );
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    registry_chirho
        .submit_chirho(
            &cluster_chirho,
            mint_request_chirho("issuer-chirho", 100, "idem-bp-1"),
        )
        .unwrap();
    registry_chirho
        .submit_chirho(
            &cluster_chirho,
            transfer_request_chirho("issuer-chirho", "alice-chirho", 10, "idem-bp-2"),
        )
        .unwrap();
    // The THIRD request refuses at the door — typed backpressure, nothing enqueued, no receipt,
    // no idempotency registration (its key remains usable after the queue drains).
    match registry_chirho.submit_chirho(
        &cluster_chirho,
        transfer_request_chirho("issuer-chirho", "alice-chirho", 5, "idem-bp-3"),
    ) {
        Err(RegistryErrorChirho::BackpressureChirho { .. }) => {}
        other_chirho => {
            panic!("a full mailbox must refuse the newest request, got {other_chirho:?}")
        }
    }
    let receipts_chirho = registry_chirho.process_all_chirho(&cluster_chirho).unwrap();
    assert_eq!(
        receipts_chirho
            .iter()
            .map(|r_chirho| r_chirho.seq_chirho)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "the two ACCEPTED requests process FIFO; the shed one left no trace"
    );
    // The shed request's idempotency key was never registered: re-submitting it now succeeds.
    registry_chirho
        .submit_chirho(
            &cluster_chirho,
            transfer_request_chirho("issuer-chirho", "alice-chirho", 5, "idem-bp-3"),
        )
        .unwrap();
    let retry_chirho = registry_chirho.process_all_chirho(&cluster_chirho).unwrap();
    assert_eq!(retry_chirho.len(), 1);
    assert_eq!(retry_chirho[0].seq_chirho, 3);
}

#[test]
fn hot_actors_are_never_evicted_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_a_chirho = cluster_n_chirho(1);
    let cluster_b_chirho = cluster_n_chirho(2);
    create_cluster_chirho(&harness_chirho, &cluster_a_chirho);
    create_cluster_chirho(&harness_chirho, &cluster_b_chirho);
    let mut registry_chirho = LedgerActorRegistryChirho::new_chirho(
        harness_chirho.ports_chirho(),
        registry_path_chirho,
        1,
        4,
    );
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    // A is resident and NON-idle (queued work).
    registry_chirho
        .submit_chirho(
            &cluster_a_chirho,
            mint_request_chirho("issuer-chirho", 100, "idem-hot-a"),
        )
        .unwrap();
    // Hydrating B would require evicting hot A — refused with a DISTINCT capacity error.
    match registry_chirho.submit_chirho(
        &cluster_b_chirho,
        mint_request_chirho("issuer-chirho", 50, "idem-hot-b"),
    ) {
        Err(RegistryErrorChirho::CapacityChirho { .. }) => {}
        other_chirho => panic!("a hot actor must never be evicted, got {other_chirho:?}"),
    }
    // A's queued work is intact and processes normally.
    let receipts_chirho = registry_chirho
        .process_all_chirho(&cluster_a_chirho)
        .unwrap();
    assert_eq!(receipts_chirho.len(), 1);
    // Once A is idle, B hydrates (A passivates via LRU with a durable checkpoint).
    registry_chirho
        .submit_chirho(
            &cluster_b_chirho,
            mint_request_chirho("issuer-chirho", 50, "idem-hot-b"),
        )
        .unwrap();
    assert_eq!(registry_chirho.active_len_chirho(), 1);
    assert_eq!(
        registry_chirho
            .process_all_chirho(&cluster_b_chirho)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn passivate_refuses_non_idle_and_roundtrips_state_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let cluster_chirho = harness_chirho.cluster_chirho();
    create_cluster_chirho(&harness_chirho, &cluster_chirho);
    let mut registry_chirho = LedgerActorRegistryChirho::new_chirho(
        harness_chirho.ports_chirho(),
        registry_path_chirho,
        2,
        4,
    );
    harness_chirho.clock_chirho.now_ms_chirho.set(1_100);
    registry_chirho
        .submit_chirho(
            &cluster_chirho,
            mint_request_chirho("issuer-chirho", 500, "idem-pp-mint"),
        )
        .unwrap();
    match registry_chirho.passivate_chirho(&cluster_chirho) {
        Err(RegistryErrorChirho::NonIdleChirho { .. }) => {}
        other_chirho => panic!("passivating a non-idle actor must refuse, got {other_chirho:?}"),
    }
    registry_chirho.process_all_chirho(&cluster_chirho).unwrap();
    assert!(registry_chirho.passivate_chirho(&cluster_chirho).unwrap());
    assert_eq!(registry_chirho.active_len_chirho(), 0);
    // Rehydrate: the money state is exactly what was passivated (checkpoint + reopen).
    harness_chirho.clock_chirho.now_ms_chirho.set(1_200);
    registry_chirho
        .submit_chirho(
            &cluster_chirho,
            transfer_request_chirho("issuer-chirho", "alice-chirho", 120, "idem-pp-t1"),
        )
        .unwrap();
    let receipts_chirho = registry_chirho.process_all_chirho(&cluster_chirho).unwrap();
    assert_eq!(
        receipts_chirho[0].seq_chirho, 2,
        "seq continues across passivate/hydrate"
    );
}

#[test]
fn registry_memory_stays_o_active_across_many_clusters_twin_chirho() {
    // CF1 clause 4, the ACTOR-REGISTRY scaling twin: 40 clusters funnel through a capacity-4
    // registry; residency NEVER exceeds 4 (memory O(active), never O(total)), and every cluster's
    // request lands correctly (seq 1 on its own journal). HONEST SCOPE (claude2 #4854): these are
    // UNROTATED journals, where hydrate = fast/full open on a small active; rotated-journal
    // hydrate is O(history) until the checkpoint-fast-path-over-sealed-history increment (the
    // named clause-4 completion dependency).
    let harness_chirho = HarnessChirho::new_chirho();
    let clusters_chirho: Vec<ClusterIdChirho> = (0..40).map(cluster_n_chirho).collect();
    for cluster_chirho in &clusters_chirho {
        create_cluster_chirho(&harness_chirho, cluster_chirho);
    }
    let mut registry_chirho = LedgerActorRegistryChirho::new_chirho(
        harness_chirho.ports_chirho(),
        registry_path_chirho,
        4,
        2,
    );
    for (index_chirho, cluster_chirho) in clusters_chirho.iter().enumerate() {
        harness_chirho
            .clock_chirho
            .now_ms_chirho
            .set(1_100 + index_chirho as u64 * 10);
        registry_chirho
            .submit_chirho(
                cluster_chirho,
                mint_request_chirho("issuer-chirho", 100, &format!("idem-twin-{index_chirho}")),
            )
            .unwrap();
        let receipts_chirho = registry_chirho.process_all_chirho(cluster_chirho).unwrap();
        assert_eq!(receipts_chirho.len(), 1);
        assert_eq!(receipts_chirho[0].seq_chirho, 1);
        assert!(
            registry_chirho.active_len_chirho() <= 4,
            "residency must never exceed capacity (O(active) law), saw {}",
            registry_chirho.active_len_chirho()
        );
    }
    assert_eq!(registry_chirho.active_len_chirho(), 4);
}
