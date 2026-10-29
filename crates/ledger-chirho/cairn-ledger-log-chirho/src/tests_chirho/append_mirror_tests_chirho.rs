// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::admission_chirho::AdmissionRejectChirho;
use crate::append_mirror_chirho::{
    LedgerAppendMirrorCandidateChirho, LedgerAppendMirrorPortChirho,
    LedgerAppendMirrorPortErrorChirho, LedgerAppendMirrorTailChirho,
};
use crate::journal_chirho::{JournalErrorChirho, LedgerJournalChirho};
use crate::journal_tests_chirho::{mint_request_chirho, HarnessChirho};
use cairn_ledger_model_chirho::wire_chirho::stored_line_digest_chirho;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct RecordingMirrorPortChirho {
    events_chirho: Mutex<Vec<String>>,
    fail_prepare_chirho: AtomicBool,
    fail_finalize_chirho: AtomicBool,
}

impl RecordingMirrorPortChirho {
    fn events_chirho(&self) -> Vec<String> {
        self.events_chirho
            .lock()
            .expect("mirror event lock")
            .clone()
    }

    fn record_chirho(&self, event_chirho: String) {
        self.events_chirho
            .lock()
            .expect("mirror event lock")
            .push(event_chirho);
    }
}

impl LedgerAppendMirrorPortChirho for RecordingMirrorPortChirho {
    fn require_no_unreconciled_pending_append_chirho(
        &self,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn reconcile_before_append_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        self.record_chirho(format!("reconcile:{}", local_tail_chirho.tail_seq_chirho()));
        Ok(())
    }

    fn prepare_append_chirho(
        &self,
        candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        assert_eq!(
            stored_line_digest_chirho(candidate_chirho.canonical_record_line_chirho()),
            *candidate_chirho.record_digest_chirho(),
            "the F1 port must receive the exact canonical line bound by its digest"
        );
        assert_eq!(
            candidate_chirho.predecessor_seq_chirho() + 1,
            candidate_chirho.record_seq_chirho()
        );
        self.record_chirho(format!("prepare:{}", candidate_chirho.record_seq_chirho()));
        if self.fail_prepare_chirho.load(Ordering::Acquire) {
            return Err(LedgerAppendMirrorPortErrorChirho::new_chirho(
                "injected prepare refusal",
            ));
        }
        Ok(())
    }

    fn finalize_append_chirho(
        &self,
        committed_candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        self.record_chirho(format!(
            "finalize:{}",
            committed_candidate_chirho.record_seq_chirho()
        ));
        if self.fail_finalize_chirho.load(Ordering::Acquire) {
            return Err(LedgerAppendMirrorPortErrorChirho::new_chirho(
                "injected finalize refusal",
            ));
        }
        Ok(())
    }
}

fn mirrored_journal_chirho(
    harness_chirho: &HarnessChirho,
    mirror_chirho: Arc<RecordingMirrorPortChirho>,
) -> LedgerJournalChirho<'_> {
    LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .expect("create mirror-gated journal")
    .with_append_mirror_chirho(mirror_chirho)
}

#[test]
fn failed_prepare_blocks_the_local_durable_append_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mirror_chirho = Arc::new(RecordingMirrorPortChirho::default());
    mirror_chirho
        .fail_prepare_chirho
        .store(true, Ordering::Release);
    let mut journal_chirho = mirrored_journal_chirho(&harness_chirho, Arc::clone(&mirror_chirho));

    let error_chirho = journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            7,
            "mirror-prepare-fail",
        ))
        .expect_err("failed mirror prepare must refuse before local commit");

    assert!(matches!(
        error_chirho,
        JournalErrorChirho::MirrorPrepareRefusedChirho { .. }
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), 0);
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho()[1],
        0
    );
    assert_eq!(mirror_chirho.events_chirho(), ["reconcile:0", "prepare:1"]);
}

#[test]
fn failed_finalize_reports_the_exact_committed_receipt_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mirror_chirho = Arc::new(RecordingMirrorPortChirho::default());
    mirror_chirho
        .fail_finalize_chirho
        .store(true, Ordering::Release);
    let mut journal_chirho = mirrored_journal_chirho(&harness_chirho, Arc::clone(&mirror_chirho));

    let error_chirho = journal_chirho
        .append_chirho(mint_request_chirho(
            "alice-chirho",
            7,
            "mirror-finalize-fail",
        ))
        .expect_err("failed finalize must carry committed evidence");
    let JournalErrorChirho::MirrorCommittedEvidencePendingChirho { receipt_chirho, .. } =
        error_chirho
    else {
        panic!("finalize failure lost its committed identity");
    };

    assert_eq!(receipt_chirho.seq_chirho, 1);
    assert_eq!(
        receipt_chirho.record_digest_chirho,
        *journal_chirho.tail_line_digest_chirho()
    );
    assert_eq!(journal_chirho.tail_seq_chirho(), 1);
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho()[1],
        1
    );
    assert_eq!(
        mirror_chirho.events_chirho(),
        ["reconcile:0", "prepare:1", "finalize:1"]
    );
}

#[test]
fn pending_reconciliation_precedes_duplicate_admission_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mirror_chirho = Arc::new(RecordingMirrorPortChirho::default());
    mirror_chirho
        .fail_finalize_chirho
        .store(true, Ordering::Release);
    let mut journal_chirho = mirrored_journal_chirho(&harness_chirho, Arc::clone(&mirror_chirho));
    let request_chirho = mint_request_chirho("alice-chirho", 7, "mirror-retry");
    assert!(matches!(
        journal_chirho.append_chirho(request_chirho.clone()),
        Err(JournalErrorChirho::MirrorCommittedEvidencePendingChirho { .. })
    ));
    mirror_chirho
        .fail_finalize_chirho
        .store(false, Ordering::Release);

    let error_chirho = journal_chirho
        .append_chirho(request_chirho)
        .expect_err("the landed idempotency key remains a duplicate after reconciliation");
    assert!(matches!(
        error_chirho,
        JournalErrorChirho::AdmissionChirho {
            reject_chirho: AdmissionRejectChirho::IdempotencyDuplicateChirho
        }
    ));
    assert_eq!(
        mirror_chirho.events_chirho(),
        ["reconcile:0", "prepare:1", "finalize:1", "reconcile:1"]
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho()[1],
        1
    );
}
