// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Non-mutating fast-open proofs for standing readers and projection observers.

use crate::checkpoint_chirho::MAX_HEAD_CHECKPOINT_BYTES_CHIRHO;
use crate::journal_chirho::{JournalErrorChirho, LedgerJournalChirho};
use crate::journal_tests_chirho::{mint_request_chirho, HarnessChirho, MONEY_KIND_CHIRHO};
use crate::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;

#[test]
fn read_only_fast_open_replays_only_the_checkpoint_suffix_without_writes_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            500,
            "idem-read-fast-prefix-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            25,
            "idem-read-fast-suffix-chirho",
        ))
        .unwrap();
    drop(engine_chirho);

    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    let opened_chirho = LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();

    assert!(opened_chirho.last_open_was_fast_chirho());
    assert_eq!(opened_chirho.tail_seq_chirho(), 2);
    assert_eq!(
        opened_chirho.supply_chirho(&AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned())),
        525
    );
    assert!(
        reads_after_chirho[1] > reads_before_chirho[1],
        "fast read-only open must use bounded exact-range reads"
    );
    assert_eq!(
        reads_after_chirho[2] - reads_before_chirho[2],
        0,
        "fast read-only open must not full-read either the sidecar or journal"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "suffix replay must not acquire repair authority"
    );
}

#[test]
fn read_only_invalid_checkpoint_falls_back_to_full_verification_without_writes_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "idem-read-full-fallback-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);

    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&sidecar_path_chirho, b"invalid-checkpoint-chirho")
        .unwrap();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let opened_chirho = LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert!(!opened_chirho.last_open_was_fast_chirho());
    assert_eq!(opened_chirho.tail_seq_chirho(), 1);
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "advisory-sidecar rejection must not rewrite either object"
    );
}

#[test]
fn read_only_oversized_checkpoint_falls_back_without_loading_sidecar_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    drop(engine_chirho);

    let sidecar_path_chirho = StoragePathChirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().0
    ));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &sidecar_path_chirho,
            &vec![b'x'; MAX_HEAD_CHECKPOINT_BYTES_CHIRHO + 1],
        )
        .unwrap();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    let opened_chirho = LedgerJournalChirho::open_read_only_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();

    assert!(!opened_chirho.last_open_was_fast_chirho());
    assert_eq!(opened_chirho.tail_seq_chirho(), 0);
    assert_eq!(
        reads_after_chirho[2] - reads_before_chirho[2],
        1,
        "only the full verifier reads a complete object; the oversized sidecar is length-refused"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "oversized advisory state must not grant repair authority"
    );
}

#[test]
fn exact_checkpoint_open_refuses_suffix_replay_and_full_fallback_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "idem-exact-prefix-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            25,
            "idem-exact-suffix-chirho",
        ))
        .unwrap();
    drop(engine_chirho);
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();

    assert!(matches!(
        LedgerJournalChirho::open_read_only_exact_head_checkpoint_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &harness_chirho.cluster_chirho(),
        ),
        Err(JournalErrorChirho::ReadOnlyExactCheckpointRequiredChirho)
    ));
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    assert_eq!(
        reads_after_chirho[2] - reads_before_chirho[2],
        0,
        "strict held startup never falls back to a full journal read"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "strict held startup never repairs or advances its checkpoint"
    );
}

#[test]
fn exact_checkpoint_open_revalidates_the_current_physical_tail_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "idem-exact-tail-chirho",
        ))
        .unwrap();
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    drop(engine_chirho);

    let opened_chirho = LedgerJournalChirho::open_read_only_exact_head_checkpoint_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .unwrap();
    assert_eq!(
        opened_chirho
            .revalidate_current_losing_tail_chirho()
            .unwrap()
            .coordinate_chirho()
            .seq_chirho(),
        1
    );

    let journal_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    let tampered_chirho = String::from_utf8(journal_bytes_chirho).unwrap().replacen(
        "idem-exact-tail-chirho",
        "idem-exact-fail-chirho",
        1,
    );
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), tampered_chirho.as_bytes())
        .unwrap();
    assert!(
        opened_chirho
            .revalidate_current_losing_tail_chirho()
            .is_err(),
        "same-length physical-tail tamper must invalidate the cached held coordinate"
    );
}
