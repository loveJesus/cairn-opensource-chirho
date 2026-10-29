// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

#[test]
fn torn_manifest_tail_fails_closed_at_open_chirho() {
    // RC.1(b) / deviation-#4 obligation (iii): the MANIFEST's recovery is the OPPOSITE of the
    // active's — a torn manifest tail is NEVER repaired; every open fails closed (operator
    // decision, not silent truncation of the seal history's authority).
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(500, "idem-manifest-torn-mint"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    drop(engine_chirho);
    let manifest_path_chirho =
        StoragePathChirho(format!("{}.segment-manifest-chirho", path_chirho().0));
    storage_chirho
        .append_durable_chirho(&manifest_path_chirho, b"{\"generation_chirho\":1,\"torn")
        .unwrap();
    let views2_chirho = ViewsChirho::new_chirho();
    views2_chirho.clock_chirho.now_ms_chirho.set(5_000);
    match LedgerJournalChirho::open_chirho(
        views2_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("segment base-seq derivation failed"),
            "torn manifest must fail base-seq derivation closed: {detail_chirho}"
        ),
        _ => panic!("a torn manifest tail must fail the open closed"),
    }
}

#[test]
fn truncated_manifest_breaks_the_seam_and_fails_closed_chirho() {
    // B2 (claude2 #4834 follow-up), the EXPLICIT truncated-manifest RC: dropping the LAST manifest
    // line leaves an internally-consistent signed prefix (count == base′, bind passes) — but the
    // active's first record then continues from the TRUE seal, so the dense law breaks at the seam
    // and the open fails closed. (Truncating manifest AND active to a wholly-older consistent
    // state is whole-record rollback — out of CF1 scope by the pinned line.)
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(500, "idem-b2-mint"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(transfer_chirho("alice-chirho", 5, "idem-b2-t1"))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(transfer_chirho("alice-chirho", 3, "idem-b2-t2"))
        .unwrap();
    drop(engine_chirho);
    // Truncate the manifest to its FIRST line only (drop the second seal's entry).
    let manifest_path_chirho =
        StoragePathChirho(format!("{}.segment-manifest-chirho", path_chirho().0));
    let manifest_bytes_chirho = storage_chirho
        .read_all_chirho(&manifest_path_chirho)
        .unwrap()
        .unwrap();
    let manifest_text_chirho = String::from_utf8(manifest_bytes_chirho).unwrap();
    let mut manifest_lines_chirho = manifest_text_chirho.lines();
    let first_line_chirho = manifest_lines_chirho.next().unwrap();
    assert!(
        manifest_lines_chirho.next().is_some(),
        "two rotations must have produced two manifest entries"
    );
    storage_chirho
        .atomic_write_chirho(
            &manifest_path_chirho,
            format!("{first_line_chirho}\n").as_bytes(),
        )
        .unwrap();
    let views2_chirho = ViewsChirho::new_chirho();
    views2_chirho.clock_chirho.now_ms_chirho.set(9_000);
    match LedgerJournalChirho::open_chirho(
        views2_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    ) {
        Err(JournalErrorChirho::ChainChirho { detail_chirho }) => assert!(
            detail_chirho.contains("dense law") || detail_chirho.contains("prev mismatch"),
            "a truncated manifest must break the seam chain law: {detail_chirho}"
        ),
        _ => panic!("a truncated manifest must fail the open closed at the seam"),
    }
}

#[test]
fn sidecar_crash_interaction_recovers_correctly_chirho() {
    // op indices in the checkpointed scenario: 0 genesis, 1 mint, 2 CHECKPOINT (atomic_write),
    // 3 transfer->alice, 4 transfer->bob. A crash at each cut, each fault, must recover to the
    // right clean prefix AND take the right path (fast when a valid sidecar covers a prefix).
    let fault_shapes_chirho: Vec<(FaultKindChirho, bool)> = vec![
        (FaultKindChirho::CrashBeforeChirho, false),
        (
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 30,
            },
            false,
        ),
        (
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: usize::MAX,
            },
            true,
        ),
    ];
    for op_index_chirho in 1..=4u64 {
        for (fault_chirho, full_line_chirho) in &fault_shapes_chirho {
            // A tear/full-line only makes sense on APPENDs; the checkpoint (op2) is an atomic write
            // that has no partial state, so on op2 a tear degrades to crash-before (no sidecar).
            let views_chirho = ViewsChirho::new_chirho();
            let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
                op_index_chirho,
                fault_chirho.clone(),
            ));
            let acked_chirho = drive_checkpointed_scenario_chirho(&views_chirho, &storage_chirho);
            assert!(
                storage_chirho.is_crashed_chirho(),
                "the fault latched at op {op_index_chirho}"
            );

            let recovered_storage_chirho = SimStorageChirho::restore_chirho(
                storage_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let recovery_views_chirho = ViewsChirho::new_chirho();
            recovery_views_chirho.clock_chirho.now_ms_chirho.set(9_000);
            let mut recovered_chirho = LedgerJournalChirho::open_chirho(
                recovery_views_chirho.ports_chirho(&recovered_storage_chirho),
                path_chirho(),
                &cluster_chirho(),
            )
            .unwrap();

            // Expected records: acked appends, +1 if the faulted append landed a full durable line.
            let is_append_cut_chirho = op_index_chirho != 2;
            let expected_records_chirho = if *full_line_chirho && is_append_cut_chirho {
                acked_chirho + 1
            } else {
                acked_chirho
            };
            assert_state_chirho(&recovered_chirho, expected_records_chirho);

            // A valid signed sidecar exists once the checkpoint (op2) has completed — i.e. the
            // crash was at op 3 or 4 (after the checkpoint). Then recovery MUST take the fast path
            // (covering seq 1, replaying the durable suffix). A crash at/ before the checkpoint
            // leaves no sidecar -> full rebuild.
            if op_index_chirho >= 3 {
                assert!(
                    recovered_chirho.last_open_was_fast_chirho(),
                    "op {op_index_chirho}: a completed checkpoint yields a fast recovery"
                );
            } else {
                assert!(
                    !recovered_chirho.last_open_was_fast_chirho(),
                    "op {op_index_chirho}: no completed checkpoint -> full rebuild"
                );
            }

            // Continuity: the recovered journal accepts new work after every sidecar-crash cut.
            recovery_views_chirho.clock_chirho.tick_chirho();
            let receipt_chirho = recovered_chirho
                .append_chirho(mint_chirho(3, "idem-post-sidecar-crash-chirho"))
                .unwrap();
            assert_eq!(receipt_chirho.seq_chirho, expected_records_chirho + 1);
        }
    }
}
