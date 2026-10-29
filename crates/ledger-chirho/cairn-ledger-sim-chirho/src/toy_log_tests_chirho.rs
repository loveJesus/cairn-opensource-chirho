// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Toy-log behavioral tests driven through the sim storage adapter — the F1 (seq) and R-3a-1
//! lease-bound epoch (`e == E`) fence under no faults, and the rotation crash matrix (a crash
//! injected at every cut, then recovery) proving R1 (no seq lost or duplicated), R2 (recovery is
//! idempotent), and R3 (an impossible durable state is refused, not silently accepted).

use cairn_ledger_log_chirho::toy_log_chirho::{
    AppendOutcomeChirho, RecoveryOutcomeChirho, RotationOutcomeChirho, ToyLogChirho,
};
use cairn_ledger_model_chirho::LedgerToyRecordChirho;

use crate::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use crate::storage_chirho::SimStorageChirho;

const BASE_CHIRHO: &str = "log-chirho";

fn record_chirho(seq_chirho: u64, epoch_chirho: u64) -> LedgerToyRecordChirho {
    LedgerToyRecordChirho::new_chirho(
        seq_chirho,
        epoch_chirho,
        format!("payload-{seq_chirho}-{epoch_chirho}").as_bytes(),
    )
}

// ---- F1 seq / R-3a-1 lease-bound epoch fence (no faults, no rotation) ------------------------

#[test]
fn appends_a_monotone_sequence_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    for seq_chirho in 0..3u64 {
        assert_eq!(
            log_chirho
                .append_chirho(record_chirho(seq_chirho, 0), 0)
                .unwrap(),
            AppendOutcomeChirho::AppendedChirho
        );
    }
    let records_chirho = log_chirho.records_chirho().unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[2].seq_chirho, 2);
}

#[test]
fn rejects_a_seq_gap_or_duplicate_f1_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    log_chirho.append_chirho(record_chirho(0, 0), 0).unwrap();
    assert_eq!(
        log_chirho.append_chirho(record_chirho(0, 0), 0).unwrap(),
        AppendOutcomeChirho::RejectedSeqChirho {
            expected_chirho: 1,
            got_chirho: 0
        }
    );
    assert_eq!(
        log_chirho.append_chirho(record_chirho(2, 0), 0).unwrap(),
        AppendOutcomeChirho::RejectedSeqChirho {
            expected_chirho: 1,
            got_chirho: 2
        }
    );
    assert_eq!(log_chirho.records_chirho().unwrap().len(), 1);
}

#[test]
fn append_law_is_lease_bound_e_equals_e_r3a1_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    // Genesis at lease 5.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(0, 5), 5).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    // A newly granted lease (7) advances the epoch.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(1, 7), 7).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    // R-3a-1 CORE: a record claiming a FUTURE never-granted epoch (9) while the handed lease is 7 is
    // REJECTED. The old `e >= chain-fence` law would have ACCEPTED it (9 >= 7) — the split-brain hole.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(2, 9), 7).unwrap(),
        AppendOutcomeChirho::RejectedEpochChirho {
            record_epoch_chirho: 9,
            lease_epoch_chirho: 7,
            chain_fence_chirho: 7
        }
    );
    // A stale lease (5, below the chain tail 7) is rejected even though record.epoch == lease.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(2, 5), 5).unwrap(),
        AppendOutcomeChirho::RejectedEpochChirho {
            record_epoch_chirho: 5,
            lease_epoch_chirho: 5,
            chain_fence_chirho: 7
        }
    );
    // A record NOT stamped with the handed lease (epoch 7 but lease 8) is rejected — e must equal E.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(2, 7), 8).unwrap(),
        AppendOutcomeChirho::RejectedEpochChirho {
            record_epoch_chirho: 7,
            lease_epoch_chirho: 8,
            chain_fence_chirho: 7
        }
    );
    // The current lease (7) with a matching record is accepted.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(2, 7), 7).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    assert_eq!(log_chirho.records_chirho().unwrap().len(), 3);
}

#[test]
fn empty_log_has_no_tail_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    assert!(log_chirho.overall_tail_chirho().unwrap().is_none());
    assert_eq!(log_chirho.all_records_chirho().unwrap().len(), 0);
}

// ---- Rotation: clean path + crash matrix -----------------------------------------------------

#[test]
fn clean_rotation_seals_and_continues_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    for seq_chirho in 0..3u64 {
        log_chirho
            .append_chirho(record_chirho(seq_chirho, 0), 0)
            .unwrap();
    }
    assert_eq!(
        log_chirho.rotate_chirho().unwrap(),
        RotationOutcomeChirho::RotatedChirho
    );
    // Active empty; segment-0 holds the 3 records; the whole log is intact.
    assert_eq!(log_chirho.records_chirho().unwrap().len(), 0);
    assert_eq!(log_chirho.sealed_segments_chirho().unwrap().len(), 1);
    assert_eq!(log_chirho.all_records_chirho().unwrap().len(), 3);
    // The sequence CONTINUES across the rotation: next append is seq 3.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(3, 0), 0).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    // A second rotation seals segment-1.
    assert_eq!(
        log_chirho.rotate_chirho().unwrap(),
        RotationOutcomeChirho::RotatedChirho
    );
    assert_eq!(log_chirho.sealed_segments_chirho().unwrap().len(), 2);
    assert_eq!(log_chirho.all_records_chirho().unwrap().len(), 4);
    // recover on a clean log is a no-op.
    assert_eq!(
        log_chirho.recover_chirho().unwrap(),
        RecoveryOutcomeChirho::CleanChirho
    );
}

/// Crash the rotate at exactly one cut (mutating-op index), restart, recover, and prove R1/R2 plus
/// that the log is usable afterward. Three appends are ops 0,1,2; the rotate's cuts are op 3 (marker),
/// 4 (seal rename), 5 (fresh active), 6 (clear marker).
fn assert_rotation_recovers_chirho(crash_op_chirho: u64, expected_chirho: RecoveryOutcomeChirho) {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
        crash_op_chirho,
        FaultKindChirho::CrashBeforeChirho,
    ));
    {
        let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
        for seq_chirho in 0..3u64 {
            assert_eq!(
                log_chirho
                    .append_chirho(record_chirho(seq_chirho, 0), 0)
                    .unwrap(),
                AppendOutcomeChirho::AppendedChirho
            );
        }
        assert!(log_chirho.rotate_chirho().is_err()); // crashes at the scheduled cut
        assert!(storage_chirho.is_crashed_chirho());
    }
    // Restart: restore the durable snapshot into a fresh no-fault machine, then recover.
    let recovered_storage_chirho = SimStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let recovered_log_chirho = ToyLogChirho::new_chirho(&recovered_storage_chirho, BASE_CHIRHO);
    assert_eq!(
        recovered_log_chirho.recover_chirho().unwrap(),
        expected_chirho
    );
    // R1: exactly the 3 original records survive, once each, in seq order.
    let all_chirho = recovered_log_chirho.all_records_chirho().unwrap();
    assert_eq!(all_chirho.len(), 3);
    for (index_chirho, record_ref_chirho) in all_chirho.iter().enumerate() {
        assert_eq!(record_ref_chirho.seq_chirho, index_chirho as u64);
    }
    // R2: recovery is idempotent — re-running finds nothing to do.
    assert_eq!(
        recovered_log_chirho.recover_chirho().unwrap(),
        RecoveryOutcomeChirho::CleanChirho
    );
    // The log is usable again: the next append continues the sequence at seq 3.
    assert_eq!(
        recovered_log_chirho
            .append_chirho(record_chirho(3, 0), 0)
            .unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    assert_eq!(recovered_log_chirho.all_records_chirho().unwrap().len(), 4);
}

#[test]
fn crash_before_marker_recovers_clean_chirho() {
    assert_rotation_recovers_chirho(3, RecoveryOutcomeChirho::CleanChirho);
}

#[test]
fn crash_before_seal_finishes_seal_chirho() {
    assert_rotation_recovers_chirho(4, RecoveryOutcomeChirho::FinishedSealChirho);
}

#[test]
fn crash_before_fresh_active_finishes_active_chirho() {
    assert_rotation_recovers_chirho(5, RecoveryOutcomeChirho::FinishedActiveChirho);
}

#[test]
fn crash_before_clear_finishes_clear_chirho() {
    assert_rotation_recovers_chirho(6, RecoveryOutcomeChirho::FinishedClearChirho);
}

#[test]
fn pending_rotation_blocks_append_until_recovered_chirho() {
    // Crash the seal rename (op 4) — the marker is durable, so a rotation is in flight.
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
        4,
        FaultKindChirho::CrashBeforeChirho,
    ));
    {
        let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
        for seq_chirho in 0..3u64 {
            log_chirho
                .append_chirho(record_chirho(seq_chirho, 0), 0)
                .unwrap();
        }
        assert!(log_chirho.rotate_chirho().is_err());
    }
    let recovered_storage_chirho = SimStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let log_chirho = ToyLogChirho::new_chirho(&recovered_storage_chirho, BASE_CHIRHO);
    // The marker is still present — append and rotate both refuse until recovery clears it.
    assert!(log_chirho.append_chirho(record_chirho(3, 0), 0).is_err());
    assert!(log_chirho.rotate_chirho().is_err());
    // Recover, then the log accepts appends again.
    log_chirho.recover_chirho().unwrap();
    assert_eq!(
        log_chirho.append_chirho(record_chirho(3, 0), 0).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
}

// ---- R-3b-1: no empty segment is ever constructed --------------------------------------------

#[test]
fn rotate_on_fresh_log_is_nothing_to_rotate_r3b1_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    // Rotating a never-written log seals nothing and writes NO marker — no ENOENT wedge.
    assert_eq!(
        log_chirho.rotate_chirho().unwrap(),
        RotationOutcomeChirho::NothingToRotateChirho
    );
    assert_eq!(log_chirho.sealed_segments_chirho().unwrap().len(), 0);
    // recover is Clean (no marker was left behind), and the log is usable from seq 0.
    assert_eq!(
        log_chirho.recover_chirho().unwrap(),
        RecoveryOutcomeChirho::CleanChirho
    );
    assert_eq!(
        log_chirho.append_chirho(record_chirho(0, 0), 0).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
}

#[test]
fn double_rotate_does_not_resurrect_seq_r3b1_chirho() {
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let log_chirho = ToyLogChirho::new_chirho(&storage_chirho, BASE_CHIRHO);
    for seq_chirho in 0..3u64 {
        log_chirho
            .append_chirho(record_chirho(seq_chirho, 0), 0)
            .unwrap();
    }
    // First rotate seals segment-0 (seqs 0..2).
    assert_eq!(
        log_chirho.rotate_chirho().unwrap(),
        RotationOutcomeChirho::RotatedChirho
    );
    // Second rotate on the now-EMPTY active must NOT seal an empty segment (the F1-resurrection door).
    assert_eq!(
        log_chirho.rotate_chirho().unwrap(),
        RotationOutcomeChirho::NothingToRotateChirho
    );
    assert_eq!(log_chirho.sealed_segments_chirho().unwrap().len(), 1); // still just segment-0
                                                                       // F1 preserved across the whole log: the next append continues at seq 3, NOT reset to 0.
    assert_eq!(
        log_chirho.append_chirho(record_chirho(0, 0), 0).unwrap(),
        AppendOutcomeChirho::RejectedSeqChirho {
            expected_chirho: 3,
            got_chirho: 0
        }
    );
    assert_eq!(
        log_chirho.append_chirho(record_chirho(3, 0), 0).unwrap(),
        AppendOutcomeChirho::AppendedChirho
    );
    // The whole log is 0,1,2,3 — each exactly once.
    let all_chirho = log_chirho.all_records_chirho().unwrap();
    assert_eq!(all_chirho.len(), 4);
    for (index_chirho, record_ref_chirho) in all_chirho.iter().enumerate() {
        assert_eq!(record_ref_chirho.seq_chirho, index_chirho as u64);
    }
}
