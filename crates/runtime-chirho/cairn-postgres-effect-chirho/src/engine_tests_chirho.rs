// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::crypto_chirho::{row_fingerprint_chirho, AdapterEvidenceKeyChirho};
use crate::engine_chirho::{
    apply_reversible_postgres_chirho as apply_reversible_postgres_coordinate_chirho,
    compensate_reversible_postgres_chirho, preview_reversible_postgres_compensation_chirho,
    query_reversible_postgres_by_key_chirho, query_reversible_postgres_compensation_by_key_chirho,
    PostgresCompensationPreviewChirho, PostgresCompensationQueryResultChirho,
    PostgresForwardQueryResultChirho, PostgresForwardResultChirho, ReversiblePostgresErrorChirho,
};
use crate::model_chirho::{
    canonical_absence_witness_bytes_chirho, canonical_committed_decision_bytes_chirho,
    canonical_request_bytes_chirho, parse_canonical_absence_witness_chirho,
    parse_canonical_committed_decision_chirho, DesiredPostgresStateChirho,
    ExpectedPostgresStateChirho, PostgresCompensationOutcomeChirho,
    ReversiblePostgresEffectCoordinateChirho, ReversiblePostgresRequestChirho,
    REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO,
};
use crate::ports_chirho::{
    AuthenticatedCompensationReceiptRowChirho, AuthenticatedForwardDecisionRowChirho,
    DatabasePortErrorChirho, DatabaseValueChirho, OriginalEffectEvidenceErrorChirho,
    PostgresOriginalEffectEvidencePortChirho, PostgresPrivateEvidencePortChirho,
    PrivateEvidencePortErrorChirho, ReversiblePostgresDatabasePortChirho,
    ReversiblePostgresTransactionPortChirho, SensitiveBytesChirho,
    VerifiedOriginalPostgresEffectChirho,
};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LawEventChirho(&'static str);

impl LawEventChirho {
    const LOAD_PRIVATE_CHIRHO: Self = Self("load-private-chirho");
    const STORE_PRIVATE_CHIRHO: Self = Self("store-private-chirho");
    const BEGIN_CHIRHO: Self = Self("begin-chirho");
    const LOCK_FORWARD_CHIRHO: Self = Self("lock-forward-chirho");
    const LOCK_COMPENSATION_CHIRHO: Self = Self("lock-compensation-chirho");
    const LOCK_ORIGINAL_CHIRHO: Self = Self("lock-original-chirho");
    const LOCK_ROW_CHIRHO: Self = Self("lock-row-chirho");
    const LOAD_FORWARD_CHIRHO: Self = Self("load-forward-chirho");
    const LOAD_COMPENSATION_CHIRHO: Self = Self("load-compensation-chirho");
    const LOAD_COMPENSATION_BY_ORIGINAL_CHIRHO: Self = Self("load-compensation-by-original-chirho");
    const LOAD_ROW_CHIRHO: Self = Self("load-row-chirho");
    const UPSERT_ROW_CHIRHO: Self = Self("upsert-row-chirho");
    const DELETE_ROW_CHIRHO: Self = Self("delete-row-chirho");
    const INSERT_FORWARD_CHIRHO: Self = Self("insert-forward-chirho");
    const INSERT_COMPENSATION_CHIRHO: Self = Self("insert-compensation-chirho");
    const COMMIT_CHIRHO: Self = Self("commit-chirho");
}

#[test]
fn query_commits_negative_before_answer_and_execute_can_never_reopen_it_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho);
    let evidence_key_chirho = evidence_key_chirho();
    let effect_key_chirho = hash_chirho('e');
    let coordinate_chirho = effect_coordinate_chirho(&effect_key_chirho);

    let first_chirho = query_reversible_postgres_by_key_chirho(
        &mut database_chirho,
        &evidence_key_chirho,
        &coordinate_chirho,
    )
    .unwrap();
    let (first_witness_bytes_chirho, first_replayed_chirho) = match first_chirho {
        PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
            witness_bytes_chirho,
            replayed_chirho,
            ..
        } => (witness_bytes_chirho, replayed_chirho),
        PostgresForwardQueryResultChirho::CommittedChirho { .. } => {
            panic!("empty coordinate cannot resolve committed")
        }
    };
    assert!(!first_replayed_chirho);
    assert!(database_chirho
        .forward_decisions_chirho
        .contains_key(coordinate_chirho.effect_intent_key_chirho()));

    let replay_chirho = query_reversible_postgres_by_key_chirho(
        &mut database_chirho,
        &evidence_key_chirho,
        &coordinate_chirho,
    )
    .unwrap();
    assert!(matches!(
        replay_chirho,
        PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
            witness_bytes_chirho,
            replayed_chirho: true,
            ..
        } if witness_bytes_chirho == first_witness_bytes_chirho
    ));

    let request_bytes_chirho = canonical_request_bytes_chirho(&build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    ))
    .unwrap();
    assert_eq!(
        apply_reversible_postgres_coordinate_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &evidence_key_chirho,
            &coordinate_chirho,
            &request_bytes_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::EffectAlreadyDecidedAbsentChirho)
    );
    assert!(database_chirho.rows_chirho.is_empty());
}

#[test]
fn execute_commit_is_the_only_decision_and_query_replays_it_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho);
    let evidence_key_chirho = evidence_key_chirho();
    let effect_key_chirho = hash_chirho('e');
    let coordinate_chirho = effect_coordinate_chirho(&effect_key_chirho);
    let request_bytes_chirho = canonical_request_bytes_chirho(&build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    ))
    .unwrap();
    let committed_chirho = apply_reversible_postgres_coordinate_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &evidence_key_chirho,
        &coordinate_chirho,
        &request_bytes_chirho,
    )
    .unwrap();

    let queried_chirho = query_reversible_postgres_by_key_chirho(
        &mut database_chirho,
        &evidence_key_chirho,
        &coordinate_chirho,
    )
    .unwrap();
    assert!(matches!(
        queried_chirho,
        PostgresForwardQueryResultChirho::CommittedChirho {
            receipt_chirho,
            decision_bytes_chirho,
        } if receipt_chirho == committed_chirho.receipt_chirho
            && decision_bytes_chirho == committed_chirho.decision_bytes_chirho
    ));
    assert_eq!(database_chirho.forward_decisions_chirho.len(), 1);
}

#[test]
fn tampered_negative_decision_fails_closed_on_query_and_execute_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho);
    let evidence_key_chirho = evidence_key_chirho();
    let coordinate_chirho = effect_coordinate_chirho(&hash_chirho('e'));
    query_reversible_postgres_by_key_chirho(
        &mut database_chirho,
        &evidence_key_chirho,
        &coordinate_chirho,
    )
    .unwrap();
    let row_chirho = database_chirho
        .forward_decisions_chirho
        .get_mut(coordinate_chirho.effect_intent_key_chirho())
        .unwrap();
    let mut witness_chirho =
        parse_canonical_absence_witness_chirho(&row_chirho.decision_bytes_chirho).unwrap();
    witness_chirho.witness_mac_chirho = hash_chirho('0');
    row_chirho.decision_bytes_chirho =
        canonical_absence_witness_bytes_chirho(&witness_chirho).unwrap();

    assert!(matches!(
        query_reversible_postgres_by_key_chirho(
            &mut database_chirho,
            &evidence_key_chirho,
            &coordinate_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::StoredEvidenceInvalidChirho { .. })
    ));
    let request_bytes_chirho = canonical_request_bytes_chirho(&build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    ))
    .unwrap();
    assert!(matches!(
        apply_reversible_postgres_coordinate_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &evidence_key_chirho,
            &coordinate_chirho,
            &request_bytes_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::StoredEvidenceInvalidChirho { .. })
    ));
    assert!(database_chirho.rows_chirho.is_empty());
}

#[test]
fn negative_decision_commit_failure_never_answers_or_persists_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho);
    database_chirho.fail_commit_chirho = true;
    let evidence_key_chirho = evidence_key_chirho();
    let coordinate_chirho = effect_coordinate_chirho(&hash_chirho('e'));
    assert!(matches!(
        query_reversible_postgres_by_key_chirho(
            &mut database_chirho,
            &evidence_key_chirho,
            &coordinate_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::DatabaseChirho(
            DatabasePortErrorChirho::PermanentChirho { .. }
        ))
    ));
    assert!(database_chirho.forward_decisions_chirho.is_empty());
}

type EventLedgerChirho = Rc<RefCell<Vec<LawEventChirho>>>;
type RowCoordinateChirho = (HashChirho, HashChirho);

fn record_event_chirho(events_chirho: &EventLedgerChirho, event_chirho: LawEventChirho) {
    events_chirho.borrow_mut().push(event_chirho);
}

fn event_position_chirho(events_chirho: &[LawEventChirho], event_chirho: LawEventChirho) -> usize {
    events_chirho
        .iter()
        .position(|candidate_chirho| *candidate_chirho == event_chirho)
        .unwrap_or_else(|| panic!("missing event {event_chirho:?}"))
}

fn event_count_chirho(events_chirho: &[LawEventChirho], event_chirho: LawEventChirho) -> usize {
    events_chirho
        .iter()
        .filter(|candidate_chirho| **candidate_chirho == event_chirho)
        .count()
}

fn effect_coordinate_chirho(
    effect_idem_key_chirho: &HashChirho,
) -> ReversiblePostgresEffectCoordinateChirho {
    ReversiblePostgresEffectCoordinateChirho::new_chirho(
        format!(
            "{}{}",
            cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO,
            effect_idem_key_chirho.0
        ),
        hash_chirho('c'),
        hash_chirho('d'),
    )
    .unwrap()
}

fn apply_reversible_postgres_chirho<DatabaseChirho, EvidenceChirho>(
    database_chirho: &mut DatabaseChirho,
    private_evidence_chirho: &mut EvidenceChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    effect_idem_key_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
) -> Result<PostgresForwardResultChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    EvidenceChirho: PostgresPrivateEvidencePortChirho,
{
    apply_reversible_postgres_coordinate_chirho(
        database_chirho,
        private_evidence_chirho,
        evidence_key_chirho,
        &effect_coordinate_chirho(effect_idem_key_chirho),
        request_bytes_chirho,
    )
}

struct PrivateBlobFixtureChirho {
    subject_chirho: HashChirho,
    bytes_chirho: Vec<u8>,
}

pub(super) struct FakePrivateEvidenceChirho {
    blobs_chirho: BTreeMap<String, PrivateBlobFixtureChirho>,
    events_chirho: EventLedgerChirho,
}

impl FakePrivateEvidenceChirho {
    pub(super) fn new_quiet_chirho() -> Self {
        Self::new_chirho(EventLedgerChirho::default())
    }

    fn new_chirho(events_chirho: EventLedgerChirho) -> Self {
        Self {
            blobs_chirho: BTreeMap::new(),
            events_chirho,
        }
    }

    fn insert_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> PrivateBlobRefChirho {
        let blob_ref_chirho = private_ref_for_chirho(subject_chirho, bytes_chirho);
        self.blobs_chirho.insert(
            blob_ref_chirho.ciphertext_chirho.0.clone(),
            PrivateBlobFixtureChirho {
                subject_chirho: subject_chirho.clone(),
                bytes_chirho: bytes_chirho.to_vec(),
            },
        );
        blob_ref_chirho
    }

    fn tamper_blob_chirho(&mut self, blob_ref_chirho: &PrivateBlobRefChirho, bytes_chirho: &[u8]) {
        self.blobs_chirho
            .get_mut(&blob_ref_chirho.ciphertext_chirho.0)
            .expect("blob exists")
            .bytes_chirho = bytes_chirho.to_vec();
    }
}

impl PostgresPrivateEvidencePortChirho for FakePrivateEvidenceChirho {
    fn load_subject_blob_chirho(
        &self,
        subject_chirho: &HashChirho,
        blob_ref_chirho: &PrivateBlobRefChirho,
    ) -> Result<SensitiveBytesChirho, PrivateEvidencePortErrorChirho> {
        record_event_chirho(&self.events_chirho, LawEventChirho::LOAD_PRIVATE_CHIRHO);
        let fixture_chirho = self
            .blobs_chirho
            .get(&blob_ref_chirho.ciphertext_chirho.0)
            .ok_or_else(|| PrivateEvidencePortErrorChirho::UnavailableChirho {
                detail_chirho: "private blob missing".to_string(),
            })?;
        if fixture_chirho.subject_chirho != *subject_chirho {
            return Err(PrivateEvidencePortErrorChirho::SubjectMismatchChirho);
        }
        Ok(SensitiveBytesChirho::new_chirho(
            fixture_chirho.bytes_chirho.clone(),
        ))
    }

    fn store_subject_blob_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> Result<PrivateBlobRefChirho, PrivateEvidencePortErrorChirho> {
        record_event_chirho(&self.events_chirho, LawEventChirho::STORE_PRIVATE_CHIRHO);
        Ok(self.insert_blob_chirho(subject_chirho, bytes_chirho))
    }
}

pub(super) struct FakeDatabaseChirho {
    rows_chirho: BTreeMap<RowCoordinateChirho, Vec<u8>>,
    forward_decisions_chirho: BTreeMap<String, AuthenticatedForwardDecisionRowChirho>,
    compensation_receipts_chirho: BTreeMap<HashChirho, AuthenticatedCompensationReceiptRowChirho>,
    compensation_by_original_chirho: BTreeMap<HashChirho, HashChirho>,
    events_chirho: EventLedgerChirho,
    fail_commit_chirho: bool,
}

impl FakeDatabaseChirho {
    pub(super) fn new_quiet_chirho() -> Self {
        Self::new_chirho(EventLedgerChirho::default())
    }

    pub(super) fn forward_decision_count_chirho(&self) -> usize {
        self.forward_decisions_chirho.len()
    }

    pub(super) fn row_count_chirho(&self) -> usize {
        self.rows_chirho.len()
    }

    fn new_chirho(events_chirho: EventLedgerChirho) -> Self {
        Self {
            rows_chirho: BTreeMap::new(),
            forward_decisions_chirho: BTreeMap::new(),
            compensation_receipts_chirho: BTreeMap::new(),
            compensation_by_original_chirho: BTreeMap::new(),
            events_chirho,
            fail_commit_chirho: false,
        }
    }

    fn set_row_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) {
        self.rows_chirho.insert(
            (subject_chirho.clone(), row_key_chirho.clone()),
            bytes_chirho.to_vec(),
        );
    }

    fn row_chirho(
        &self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Option<&[u8]> {
        self.rows_chirho
            .get(&(subject_chirho.clone(), row_key_chirho.clone()))
            .map(Vec::as_slice)
    }
}

pub(super) struct FakeTransactionChirho<'database_chirho> {
    database_chirho: &'database_chirho mut FakeDatabaseChirho,
    rows_chirho: BTreeMap<RowCoordinateChirho, Vec<u8>>,
    forward_decisions_chirho: BTreeMap<String, AuthenticatedForwardDecisionRowChirho>,
    compensation_receipts_chirho: BTreeMap<HashChirho, AuthenticatedCompensationReceiptRowChirho>,
    compensation_by_original_chirho: BTreeMap<HashChirho, HashChirho>,
}

impl ReversiblePostgresDatabasePortChirho for FakeDatabaseChirho {
    type TransactionChirho<'database_chirho>
        = FakeTransactionChirho<'database_chirho>
    where
        Self: 'database_chirho;

    fn verify_schema_ready_chirho(&mut self) -> Result<(), DatabasePortErrorChirho> {
        Ok(())
    }

    fn begin_serializable_transaction_chirho(
        &mut self,
    ) -> Result<Self::TransactionChirho<'_>, DatabasePortErrorChirho> {
        record_event_chirho(&self.events_chirho, LawEventChirho::BEGIN_CHIRHO);
        Ok(FakeTransactionChirho {
            rows_chirho: self.rows_chirho.clone(),
            forward_decisions_chirho: self.forward_decisions_chirho.clone(),
            compensation_receipts_chirho: self.compensation_receipts_chirho.clone(),
            compensation_by_original_chirho: self.compensation_by_original_chirho.clone(),
            database_chirho: self,
        })
    }
}

impl ReversiblePostgresTransactionPortChirho for FakeTransactionChirho<'_> {
    fn lock_forward_idempotency_key_chirho(
        &mut self,
        _effect_intent_key_chirho: &str,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOCK_FORWARD_CHIRHO,
        );
        Ok(())
    }

    fn lock_compensation_idempotency_key_chirho(
        &mut self,
        _compensation_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOCK_COMPENSATION_CHIRHO,
        );
        Ok(())
    }

    fn lock_original_effect_compensation_chirho(
        &mut self,
        _original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOCK_ORIGINAL_CHIRHO,
        );
        Ok(())
    }

    fn lock_row_chirho(
        &mut self,
        _subject_chirho: &HashChirho,
        _row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOCK_ROW_CHIRHO,
        );
        Ok(())
    }

    fn load_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOAD_FORWARD_CHIRHO,
        );
        Ok(self
            .forward_decisions_chirho
            .get(effect_intent_key_chirho)
            .cloned())
    }

    fn load_forward_decision_by_idem_key_chirho(
        &mut self,
        effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedForwardDecisionRowChirho>, DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOAD_FORWARD_CHIRHO,
        );
        Ok(self
            .forward_decisions_chirho
            .values()
            .find(|row_chirho| row_chirho.effect_idem_key_chirho == *effect_idem_key_chirho)
            .cloned())
    }

    fn load_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOAD_COMPENSATION_CHIRHO,
        );
        Ok(self
            .compensation_receipts_chirho
            .get(compensation_idem_key_chirho)
            .cloned())
    }

    fn load_compensation_receipt_by_original_effect_chirho(
        &mut self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<Option<AuthenticatedCompensationReceiptRowChirho>, DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOAD_COMPENSATION_BY_ORIGINAL_CHIRHO,
        );
        Ok(self
            .compensation_by_original_chirho
            .get(original_effect_idem_key_chirho)
            .and_then(|compensation_key_chirho| {
                self.compensation_receipts_chirho
                    .get(compensation_key_chirho)
            })
            .cloned())
    }

    fn load_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<Option<DatabaseValueChirho>, DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::LOAD_ROW_CHIRHO,
        );
        Ok(self
            .rows_chirho
            .get(&(subject_chirho.clone(), row_key_chirho.clone()))
            .cloned()
            .map(|bytes_chirho| DatabaseValueChirho {
                value_chirho: SensitiveBytesChirho::new_chirho(bytes_chirho),
            }))
    }

    fn upsert_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
        value_chirho: &[u8],
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::UPSERT_ROW_CHIRHO,
        );
        self.rows_chirho.insert(
            (subject_chirho.clone(), row_key_chirho.clone()),
            value_chirho.to_vec(),
        );
        Ok(())
    }

    fn delete_value_chirho(
        &mut self,
        subject_chirho: &HashChirho,
        row_key_chirho: &HashChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::DELETE_ROW_CHIRHO,
        );
        self.rows_chirho
            .remove(&(subject_chirho.clone(), row_key_chirho.clone()));
        Ok(())
    }

    fn insert_forward_decision_chirho(
        &mut self,
        effect_intent_key_chirho: &str,
        row_chirho: &AuthenticatedForwardDecisionRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::INSERT_FORWARD_CHIRHO,
        );
        if self
            .forward_decisions_chirho
            .contains_key(effect_intent_key_chirho)
            || self.forward_decisions_chirho.values().any(|stored_chirho| {
                stored_chirho.effect_idem_key_chirho == row_chirho.effect_idem_key_chirho
            })
        {
            return Err(permanent_error_chirho("duplicate forward decision"));
        }
        self.forward_decisions_chirho
            .insert(effect_intent_key_chirho.to_string(), row_chirho.clone());
        Ok(())
    }

    fn insert_compensation_receipt_chirho(
        &mut self,
        compensation_idem_key_chirho: &HashChirho,
        row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    ) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::INSERT_COMPENSATION_CHIRHO,
        );
        if self
            .compensation_receipts_chirho
            .contains_key(compensation_idem_key_chirho)
            || self
                .compensation_by_original_chirho
                .contains_key(&row_chirho.original_effect_idem_key_chirho)
        {
            return Err(permanent_error_chirho("duplicate compensation receipt"));
        }
        self.compensation_by_original_chirho.insert(
            row_chirho.original_effect_idem_key_chirho.clone(),
            compensation_idem_key_chirho.clone(),
        );
        self.compensation_receipts_chirho
            .insert(compensation_idem_key_chirho.clone(), row_chirho.clone());
        Ok(())
    }

    fn commit_chirho(self) -> Result<(), DatabasePortErrorChirho> {
        record_event_chirho(
            &self.database_chirho.events_chirho,
            LawEventChirho::COMMIT_CHIRHO,
        );
        if self.database_chirho.fail_commit_chirho {
            return Err(permanent_error_chirho("injected commit failure"));
        }
        self.database_chirho.rows_chirho = self.rows_chirho;
        self.database_chirho.forward_decisions_chirho = self.forward_decisions_chirho;
        self.database_chirho.compensation_receipts_chirho = self.compensation_receipts_chirho;
        self.database_chirho.compensation_by_original_chirho = self.compensation_by_original_chirho;
        Ok(())
    }
}

#[derive(Default)]
struct FakeOriginalEffectsChirho {
    effects_chirho: BTreeMap<HashChirho, VerifiedOriginalPostgresEffectChirho>,
}

impl PostgresOriginalEffectEvidencePortChirho for FakeOriginalEffectsChirho {
    fn load_verified_original_effect_chirho(
        &self,
        original_effect_idem_key_chirho: &HashChirho,
    ) -> Result<VerifiedOriginalPostgresEffectChirho, OriginalEffectEvidenceErrorChirho> {
        self.effects_chirho
            .get(original_effect_idem_key_chirho)
            .cloned()
            .ok_or(OriginalEffectEvidenceErrorChirho::MissingChirho)
    }
}

fn hash_chirho(marker_chirho: char) -> HashChirho {
    HashChirho(marker_chirho.to_string().repeat(64))
}

pub(super) fn evidence_key_chirho() -> AdapterEvidenceKeyChirho {
    AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap()
}

fn private_ref_for_chirho(
    subject_chirho: &HashChirho,
    bytes_chirho: &[u8],
) -> PrivateBlobRefChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(subject_chirho.0.as_bytes());
    hasher_chirho.update(bytes_chirho);
    PrivateBlobRefChirho {
        ciphertext_chirho: HashChirho(hasher_chirho.finalize().to_hex().to_string()),
        key_id_chirho: "fake-subject-key-chirho".to_string(),
        nonce_chirho: "fake-nonce-chirho".to_string(),
        mac_chirho: "fake-mac-chirho".to_string(),
        alg_chirho: "fake-private-evidence-v1-chirho".to_string(),
    }
}

pub(super) fn build_request_chirho(
    expected_before_chirho: ExpectedPostgresStateChirho,
    desired_chirho: DesiredPostgresStateChirho,
) -> ReversiblePostgresRequestChirho {
    ReversiblePostgresRequestChirho {
        schema_chirho: REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO.to_string(),
        subject_chirho: hash_chirho('a'),
        row_key_chirho: hash_chirho('b'),
        expected_before_chirho,
        desired_chirho,
    }
}

fn original_effects_chirho(
    effect_idem_key_chirho: &HashChirho,
    request_bytes_chirho: &[u8],
    forward_receipt_bytes_chirho: &[u8],
) -> FakeOriginalEffectsChirho {
    FakeOriginalEffectsChirho {
        effects_chirho: [(
            effect_idem_key_chirho.clone(),
            VerifiedOriginalPostgresEffectChirho {
                original_effect_idem_key_chirho: effect_idem_key_chirho.clone(),
                request_bytes_chirho: request_bytes_chirho.to_vec(),
                forward_receipt_bytes_chirho: forward_receipt_bytes_chirho.to_vec(),
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn permanent_error_chirho(detail_chirho: &str) -> DatabasePortErrorChirho {
    DatabasePortErrorChirho::PermanentChirho {
        detail_chirho: detail_chirho.to_string(),
    }
}

#[path = "engine_tests_chirho/forward_tests_chirho.rs"]
mod forward_tests_chirho;

#[path = "engine_tests_chirho/compensation_tests_chirho.rs"]
mod compensation_tests_chirho;
