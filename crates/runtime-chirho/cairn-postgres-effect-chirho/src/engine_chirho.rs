// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Transaction-ordering law for the dormant reversible PostgreSQL effect.

use crate::crypto_chirho::{
    absence_witness_mac_chirho, compensation_receipt_mac_chirho, forward_receipt_mac_chirho,
    request_digest_chirho, row_fingerprint_chirho, verify_absence_witness_mac_chirho,
    verify_compensation_receipt_mac_chirho, verify_forward_receipt_mac_chirho,
    AdapterEvidenceKeyChirho,
};
use crate::model_chirho::{
    canonical_absence_witness_bytes_chirho, canonical_committed_decision_bytes_chirho,
    canonical_compensation_receipt_bytes_chirho, canonical_forward_receipt_bytes_chirho,
    parse_canonical_absence_witness_chirho, parse_canonical_committed_decision_chirho,
    parse_canonical_compensation_receipt_chirho, parse_canonical_forward_receipt_chirho,
    parse_canonical_request_chirho, validate_digest_chirho, DesiredPostgresStateChirho,
    EffectAbsenceDecisionChirho, ExpectedPostgresStateChirho, PostgresCompensationOutcomeChirho,
    PostgresWireErrorChirho, ReversiblePostgresAbsenceWitnessChirho,
    ReversiblePostgresCommittedDecisionChirho, ReversiblePostgresCompensationReceiptChirho,
    ReversiblePostgresEffectCoordinateChirho, ReversiblePostgresForwardReceiptChirho,
    ReversiblePostgresRequestChirho, EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO,
    REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO,
    REVERSIBLE_POSTGRES_COMPENSATION_RECEIPT_SCHEMA_CHIRHO,
    REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO,
};
use crate::ports_chirho::{
    AuthenticatedCompensationReceiptRowChirho, AuthenticatedForwardDecisionRowChirho,
    DatabasePortErrorChirho, DatabaseValueChirho, OriginalEffectEvidenceErrorChirho,
    PostgresForwardDecisionKindChirho, PostgresOriginalEffectEvidencePortChirho,
    PostgresPrivateEvidencePortChirho, PrivateEvidencePortErrorChirho,
    ReversiblePostgresDatabasePortChirho, ReversiblePostgresTransactionPortChirho,
    SensitiveBytesChirho,
};
use cairn_core_chirho::model_chirho::HashChirho;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresForwardResultChirho {
    pub receipt_chirho: ReversiblePostgresForwardReceiptChirho,
    pub receipt_bytes_chirho: Vec<u8>,
    pub decision_bytes_chirho: Vec<u8>,
    pub replayed_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgresForwardQueryResultChirho {
    CommittedChirho {
        receipt_chirho: ReversiblePostgresForwardReceiptChirho,
        decision_bytes_chirho: Vec<u8>,
    },
    DefiniteNoEffectChirho {
        witness_chirho: ReversiblePostgresAbsenceWitnessChirho,
        witness_bytes_chirho: Vec<u8>,
        replayed_chirho: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostgresCompensationResultChirho {
    pub receipt_chirho: ReversiblePostgresCompensationReceiptChirho,
    pub receipt_bytes_chirho: Vec<u8>,
    pub replayed_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgresCompensationPreviewChirho {
    ExecutableChirho,
    MustNotExecuteChirho {
        observed_state_chirho: ExpectedPostgresStateChirho,
    },
    CompletedReplayChirho {
        receipt_chirho: ReversiblePostgresCompensationReceiptChirho,
        receipt_bytes_chirho: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgresCompensationQueryResultChirho {
    CommittedChirho {
        receipt_chirho: ReversiblePostgresCompensationReceiptChirho,
        receipt_bytes_chirho: Vec<u8>,
    },
    InDoubtChirho,
}

struct VerifiedOriginalPostgresBindingChirho {
    request_chirho: ReversiblePostgresRequestChirho,
    request_digest_chirho: HashChirho,
    forward_receipt_chirho: ReversiblePostgresForwardReceiptChirho,
    forward_receipt_bytes_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReversiblePostgresErrorChirho {
    WireChirho(PostgresWireErrorChirho),
    PrivateEvidenceChirho(PrivateEvidencePortErrorChirho),
    OriginalEffectEvidenceChirho(OriginalEffectEvidenceErrorChirho),
    DatabaseChirho(DatabasePortErrorChirho),
    IdempotencyConflictChirho,
    ExpectedBeforeMismatchChirho {
        expected_chirho: ExpectedPostgresStateChirho,
        observed_chirho: ExpectedPostgresStateChirho,
    },
    StoredEvidenceInvalidChirho {
        detail_chirho: String,
    },
    OriginalEffectBindingInvalidChirho {
        detail_chirho: String,
    },
    BeforeImageMismatchChirho,
    CompensationAlreadyRecordedChirho,
    EffectAlreadyDecidedAbsentChirho,
}

impl std::fmt::Display for ReversiblePostgresErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireChirho(error_chirho) => write!(formatter_chirho, "{error_chirho}"),
            Self::PrivateEvidenceChirho(error_chirho) => {
                write!(formatter_chirho, "{error_chirho}")
            }
            Self::OriginalEffectEvidenceChirho(error_chirho) => {
                write!(formatter_chirho, "{error_chirho}")
            }
            Self::DatabaseChirho(error_chirho) => write!(formatter_chirho, "{error_chirho}"),
            Self::IdempotencyConflictChirho => {
                formatter_chirho.write_str("reversible-Postgres idempotency key request mismatch")
            }
            Self::ExpectedBeforeMismatchChirho { .. } => {
                formatter_chirho.write_str("reversible-Postgres expected-before state mismatch")
            }
            Self::StoredEvidenceInvalidChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "invalid stored reversible-Postgres evidence: {detail_chirho}"
                )
            }
            Self::OriginalEffectBindingInvalidChirho { detail_chirho } => write!(
                formatter_chirho,
                "invalid signed original reversible-Postgres effect binding: {detail_chirho}"
            ),
            Self::BeforeImageMismatchChirho => {
                formatter_chirho.write_str("reversible-Postgres private before-image mismatch")
            }
            Self::CompensationAlreadyRecordedChirho => formatter_chirho
                .write_str("a compensation already exists for this reversible-Postgres effect"),
            Self::EffectAlreadyDecidedAbsentChirho => formatter_chirho
                .write_str("reversible-Postgres effect is durably closed as definite no-effect"),
        }
    }
}

impl std::error::Error for ReversiblePostgresErrorChirho {}

impl From<PostgresWireErrorChirho> for ReversiblePostgresErrorChirho {
    fn from(error_chirho: PostgresWireErrorChirho) -> Self {
        Self::WireChirho(error_chirho)
    }
}

impl From<PrivateEvidencePortErrorChirho> for ReversiblePostgresErrorChirho {
    fn from(error_chirho: PrivateEvidencePortErrorChirho) -> Self {
        Self::PrivateEvidenceChirho(error_chirho)
    }
}

impl From<OriginalEffectEvidenceErrorChirho> for ReversiblePostgresErrorChirho {
    fn from(error_chirho: OriginalEffectEvidenceErrorChirho) -> Self {
        Self::OriginalEffectEvidenceChirho(error_chirho)
    }
}

impl From<DatabasePortErrorChirho> for ReversiblePostgresErrorChirho {
    fn from(error_chirho: DatabasePortErrorChirho) -> Self {
        Self::DatabaseChirho(error_chirho)
    }
}

/// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
pub fn apply_reversible_postgres_chirho<DatabaseChirho, EvidenceChirho>(
    database_chirho: &mut DatabaseChirho,
    private_evidence_chirho: &mut EvidenceChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    coordinate_chirho: &ReversiblePostgresEffectCoordinateChirho,
    request_bytes_chirho: &[u8],
) -> Result<PostgresForwardResultChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    EvidenceChirho: PostgresPrivateEvidencePortChirho,
{
    let request_chirho = parse_canonical_request_chirho(request_bytes_chirho)?;
    let request_digest_chirho = request_digest_chirho(&request_chirho)?;

    // A subject mismatch must fail before any database state or idempotency row can change.
    let desired_value_chirho = load_desired_value_chirho(private_evidence_chirho, &request_chirho)?;

    let mut transaction_chirho = database_chirho.begin_serializable_transaction_chirho()?;
    transaction_chirho
        .lock_forward_idempotency_key_chirho(coordinate_chirho.effect_intent_key_chirho())?;
    if let Some(row_chirho) = transaction_chirho
        .load_forward_decision_chirho(coordinate_chirho.effect_intent_key_chirho())?
    {
        if row_chirho.decision_kind_chirho
            == PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho
        {
            verify_absence_decision_row_chirho(
                evidence_key_chirho,
                &row_chirho,
                coordinate_chirho,
            )?;
            return Err(ReversiblePostgresErrorChirho::EffectAlreadyDecidedAbsentChirho);
        }
        let (decision_chirho, decision_bytes_chirho, receipt_bytes_chirho) =
            verify_committed_decision_row_chirho(evidence_key_chirho, &row_chirho)?;
        verify_decision_coordinate_chirho(&decision_chirho, coordinate_chirho)?;
        verify_forward_request_binding_chirho(
            &decision_chirho.forward_receipt_chirho,
            coordinate_chirho.effect_idem_key_chirho(),
            &request_digest_chirho,
            &request_chirho,
        )?;
        return Ok(PostgresForwardResultChirho {
            receipt_chirho: decision_chirho.forward_receipt_chirho,
            receipt_bytes_chirho,
            decision_bytes_chirho,
            replayed_chirho: true,
        });
    }

    transaction_chirho.lock_row_chirho(
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
    )?;
    let before_value_chirho = transaction_chirho.load_value_chirho(
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
    )?;
    let before_state_chirho = state_for_value_chirho(
        evidence_key_chirho,
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
        before_value_chirho.as_ref(),
    );
    if before_state_chirho != request_chirho.expected_before_chirho {
        return Err(
            ReversiblePostgresErrorChirho::ExpectedBeforeMismatchChirho {
                expected_chirho: request_chirho.expected_before_chirho,
                observed_chirho: before_state_chirho,
            },
        );
    }

    // This external write deliberately precedes the database mutation and commit. A later rollback
    // may leave an unreachable private blob; the opposite ordering could commit without evidence.
    let before_image_ref_chirho = match before_value_chirho.as_ref() {
        Some(value_chirho) => Some(private_evidence_chirho.store_subject_blob_chirho(
            &request_chirho.subject_chirho,
            value_chirho.value_chirho.as_slice_chirho(),
        )?),
        None => None,
    };

    let post_state_chirho = match desired_value_chirho.as_ref() {
        Some(value_chirho) => {
            transaction_chirho.upsert_value_chirho(
                &request_chirho.subject_chirho,
                &request_chirho.row_key_chirho,
                value_chirho.as_slice_chirho(),
            )?;
            ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: row_fingerprint_chirho(
                    evidence_key_chirho,
                    &request_chirho.subject_chirho,
                    &request_chirho.row_key_chirho,
                    value_chirho.as_slice_chirho(),
                ),
            }
        }
        None => {
            transaction_chirho.delete_value_chirho(
                &request_chirho.subject_chirho,
                &request_chirho.row_key_chirho,
            )?;
            ExpectedPostgresStateChirho::AbsentChirho
        }
    };

    let receipt_chirho = ReversiblePostgresForwardReceiptChirho {
        schema_chirho: REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO.to_string(),
        effect_idem_key_chirho: coordinate_chirho.effect_idem_key_chirho().clone(),
        request_digest_chirho,
        subject_chirho: request_chirho.subject_chirho,
        row_key_chirho: request_chirho.row_key_chirho,
        before_state_chirho,
        before_image_ref_chirho,
        post_state_chirho,
    };
    let receipt_bytes_chirho = canonical_forward_receipt_bytes_chirho(&receipt_chirho)?;
    let receipt_mac_chirho = forward_receipt_mac_chirho(evidence_key_chirho, &receipt_chirho)?;
    let decision_chirho = ReversiblePostgresCommittedDecisionChirho {
        schema_chirho: REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO.to_string(),
        k_chirho: coordinate_chirho.effect_intent_key_chirho().to_string(),
        contract_digest_chirho: coordinate_chirho.contract_digest_chirho().clone(),
        journal_binding_chirho: coordinate_chirho.journal_binding_chirho().clone(),
        forward_receipt_chirho: receipt_chirho.clone(),
        receipt_mac_chirho,
    };
    let decision_bytes_chirho = canonical_committed_decision_bytes_chirho(&decision_chirho)?;
    transaction_chirho.insert_forward_decision_chirho(
        coordinate_chirho.effect_intent_key_chirho(),
        &AuthenticatedForwardDecisionRowChirho {
            effect_idem_key_chirho: coordinate_chirho.effect_idem_key_chirho().clone(),
            decision_kind_chirho: PostgresForwardDecisionKindChirho::CommittedChirho,
            decision_bytes_chirho: decision_bytes_chirho.clone(),
        },
    )?;
    transaction_chirho.commit_chirho()?;

    Ok(PostgresForwardResultChirho {
        receipt_chirho,
        receipt_bytes_chirho,
        decision_bytes_chirho,
        replayed_chirho: false,
    })
}

/// Resolve the provider's exact signed-intent K under the SAME SERIALIZABLE decision coordinate as
/// execution. A negative answer becomes authoritative only after its authenticated witness commits;
/// a later execute observes that durable decision and cannot mutate the external world.
pub fn query_reversible_postgres_by_key_chirho<DatabaseChirho>(
    database_chirho: &mut DatabaseChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    coordinate_chirho: &ReversiblePostgresEffectCoordinateChirho,
) -> Result<PostgresForwardQueryResultChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    let mut transaction_chirho = database_chirho.begin_serializable_transaction_chirho()?;
    transaction_chirho
        .lock_forward_idempotency_key_chirho(coordinate_chirho.effect_intent_key_chirho())?;
    if let Some(row_chirho) = transaction_chirho
        .load_forward_decision_chirho(coordinate_chirho.effect_intent_key_chirho())?
    {
        return match row_chirho.decision_kind_chirho {
            PostgresForwardDecisionKindChirho::CommittedChirho => {
                let (decision_chirho, decision_bytes_chirho, _) =
                    verify_committed_decision_row_chirho(evidence_key_chirho, &row_chirho)?;
                verify_decision_coordinate_chirho(&decision_chirho, coordinate_chirho)?;
                Ok(PostgresForwardQueryResultChirho::CommittedChirho {
                    receipt_chirho: decision_chirho.forward_receipt_chirho,
                    decision_bytes_chirho,
                })
            }
            PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho => {
                let (witness_chirho, witness_bytes_chirho) = verify_absence_decision_row_chirho(
                    evidence_key_chirho,
                    &row_chirho,
                    coordinate_chirho,
                )?;
                Ok(PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
                    witness_chirho,
                    witness_bytes_chirho,
                    replayed_chirho: true,
                })
            }
        };
    }

    let witness_chirho = ReversiblePostgresAbsenceWitnessChirho {
        schema_chirho: EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO.to_string(),
        k_chirho: coordinate_chirho.effect_intent_key_chirho().to_string(),
        decision_chirho: EffectAbsenceDecisionChirho::DefiniteNoEffectChirho,
        contract_digest_chirho: coordinate_chirho.contract_digest_chirho().clone(),
        journal_binding_chirho: coordinate_chirho.journal_binding_chirho().clone(),
        witness_mac_chirho: absence_witness_mac_chirho(evidence_key_chirho, coordinate_chirho),
    };
    let witness_bytes_chirho = canonical_absence_witness_bytes_chirho(&witness_chirho)?;
    transaction_chirho.insert_forward_decision_chirho(
        coordinate_chirho.effect_intent_key_chirho(),
        &AuthenticatedForwardDecisionRowChirho {
            effect_idem_key_chirho: coordinate_chirho.effect_idem_key_chirho().clone(),
            decision_kind_chirho: PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho,
            decision_bytes_chirho: witness_bytes_chirho.clone(),
        },
    )?;
    // A Hold may release only after this commit succeeds. Insert/commit failure remains in-doubt.
    transaction_chirho.commit_chirho()?;
    Ok(PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
        witness_chirho,
        witness_bytes_chirho,
        replayed_chirho: false,
    })
}

/// Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/README-chirho.md`.
pub fn compensate_reversible_postgres_chirho<DatabaseChirho, EvidenceChirho, OriginalChirho>(
    database_chirho: &mut DatabaseChirho,
    private_evidence_chirho: &mut EvidenceChirho,
    original_effects_chirho: &OriginalChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    compensation_idem_key_chirho: &HashChirho,
    original_effect_idem_key_chirho: &HashChirho,
) -> Result<PostgresCompensationResultChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    EvidenceChirho: PostgresPrivateEvidencePortChirho,
    OriginalChirho: PostgresOriginalEffectEvidencePortChirho + ?Sized,
{
    validate_digest_chirho("compensation_idem_key_chirho", compensation_idem_key_chirho)?;
    validate_digest_chirho(
        "original_effect_idem_key_chirho",
        original_effect_idem_key_chirho,
    )?;
    let original_chirho = load_verified_original_binding_chirho(
        original_effects_chirho,
        original_effect_idem_key_chirho,
    )?;
    let request_chirho = original_chirho.request_chirho;
    let request_digest_chirho = original_chirho.request_digest_chirho;
    let signed_forward_receipt_chirho = original_chirho.forward_receipt_chirho;

    let mut transaction_chirho = database_chirho.begin_serializable_transaction_chirho()?;
    transaction_chirho.lock_compensation_idempotency_key_chirho(compensation_idem_key_chirho)?;
    transaction_chirho.lock_original_effect_compensation_chirho(original_effect_idem_key_chirho)?;

    if let Some(row_chirho) =
        transaction_chirho.load_compensation_receipt_chirho(compensation_idem_key_chirho)?
    {
        let (receipt_chirho, receipt_bytes_chirho) = verify_compensation_row_chirho(
            evidence_key_chirho,
            &row_chirho,
            compensation_idem_key_chirho,
            original_effect_idem_key_chirho,
            &request_digest_chirho,
            &request_chirho,
        )?;
        return Ok(PostgresCompensationResultChirho {
            receipt_chirho,
            receipt_bytes_chirho,
            replayed_chirho: true,
        });
    }
    if transaction_chirho
        .load_compensation_receipt_by_original_effect_chirho(original_effect_idem_key_chirho)?
        .is_some()
    {
        return Err(ReversiblePostgresErrorChirho::CompensationAlreadyRecordedChirho);
    }

    let stored_forward_row_chirho = transaction_chirho
        .load_forward_decision_by_idem_key_chirho(original_effect_idem_key_chirho)?
        .ok_or_else(|| stored_evidence_error_chirho("committed forward decision is missing"))?;
    let (stored_decision_chirho, _, stored_forward_bytes_chirho) =
        verify_committed_decision_row_chirho(evidence_key_chirho, &stored_forward_row_chirho)?;
    verify_original_forward_binding_chirho(
        &stored_decision_chirho.forward_receipt_chirho,
        original_effect_idem_key_chirho,
        &request_digest_chirho,
        &request_chirho,
    )?;
    if stored_forward_bytes_chirho != original_chirho.forward_receipt_bytes_chirho {
        return Err(stored_evidence_error_chirho(
            "database receipt does not byte-match the signed original effect",
        ));
    }

    transaction_chirho.lock_row_chirho(
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
    )?;
    let current_value_chirho = transaction_chirho.load_value_chirho(
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
    )?;
    let observed_state_chirho = state_for_value_chirho(
        evidence_key_chirho,
        &request_chirho.subject_chirho,
        &request_chirho.row_key_chirho,
        current_value_chirho.as_ref(),
    );

    let outcome_chirho = if observed_state_chirho != signed_forward_receipt_chirho.post_state_chirho
    {
        PostgresCompensationOutcomeChirho::SupersededChirho {
            observed_state_chirho,
        }
    } else {
        restore_before_state_chirho(
            &mut transaction_chirho,
            private_evidence_chirho,
            evidence_key_chirho,
            &signed_forward_receipt_chirho,
        )?;
        PostgresCompensationOutcomeChirho::RestoredChirho {
            restored_state_chirho: signed_forward_receipt_chirho.before_state_chirho.clone(),
        }
    };

    let receipt_chirho = ReversiblePostgresCompensationReceiptChirho {
        schema_chirho: REVERSIBLE_POSTGRES_COMPENSATION_RECEIPT_SCHEMA_CHIRHO.to_string(),
        compensation_idem_key_chirho: compensation_idem_key_chirho.clone(),
        original_effect_idem_key_chirho: original_effect_idem_key_chirho.clone(),
        original_request_digest_chirho: request_digest_chirho,
        subject_chirho: request_chirho.subject_chirho,
        row_key_chirho: request_chirho.row_key_chirho,
        outcome_chirho,
    };
    let receipt_bytes_chirho = canonical_compensation_receipt_bytes_chirho(&receipt_chirho)?;
    let receipt_mac_chirho = compensation_receipt_mac_chirho(evidence_key_chirho, &receipt_chirho)?;
    transaction_chirho.insert_compensation_receipt_chirho(
        compensation_idem_key_chirho,
        &AuthenticatedCompensationReceiptRowChirho {
            original_effect_idem_key_chirho: original_effect_idem_key_chirho.clone(),
            receipt_bytes_chirho: receipt_bytes_chirho.clone(),
            receipt_mac_chirho,
        },
    )?;
    transaction_chirho.commit_chirho()?;

    Ok(PostgresCompensationResultChirho {
        receipt_chirho,
        receipt_bytes_chirho,
        replayed_chirho: false,
    })
}

/// Read-only provider preview for one root-verified forward effect. The transaction is deliberately
/// dropped without commit, and this door has no private-evidence or row-mutation capability.
/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub fn preview_reversible_postgres_compensation_chirho<DatabaseChirho, OriginalChirho>(
    database_chirho: &mut DatabaseChirho,
    original_effects_chirho: &OriginalChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    original_effect_idem_key_chirho: &HashChirho,
) -> Result<PostgresCompensationPreviewChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    OriginalChirho: PostgresOriginalEffectEvidencePortChirho,
{
    validate_digest_chirho(
        "original_effect_idem_key_chirho",
        original_effect_idem_key_chirho,
    )?;
    let original_chirho = load_verified_original_binding_chirho(
        original_effects_chirho,
        original_effect_idem_key_chirho,
    )?;
    let mut transaction_chirho = database_chirho.begin_serializable_transaction_chirho()?;
    transaction_chirho.lock_original_effect_compensation_chirho(original_effect_idem_key_chirho)?;

    if let Some(row_chirho) = transaction_chirho
        .load_compensation_receipt_by_original_effect_chirho(original_effect_idem_key_chirho)?
    {
        let parsed_chirho =
            parse_canonical_compensation_receipt_chirho(&row_chirho.receipt_bytes_chirho)
                .map_err(|error_chirho| stored_evidence_error_chirho(&error_chirho.to_string()))?;
        let (receipt_chirho, receipt_bytes_chirho) = verify_compensation_row_chirho(
            evidence_key_chirho,
            &row_chirho,
            &parsed_chirho.compensation_idem_key_chirho,
            original_effect_idem_key_chirho,
            &original_chirho.request_digest_chirho,
            &original_chirho.request_chirho,
        )?;
        return Ok(PostgresCompensationPreviewChirho::CompletedReplayChirho {
            receipt_chirho,
            receipt_bytes_chirho,
        });
    }

    let stored_forward_row_chirho = transaction_chirho
        .load_forward_decision_by_idem_key_chirho(original_effect_idem_key_chirho)?
        .ok_or_else(|| stored_evidence_error_chirho("committed forward decision is missing"))?;
    let (stored_decision_chirho, _, stored_forward_bytes_chirho) =
        verify_committed_decision_row_chirho(evidence_key_chirho, &stored_forward_row_chirho)?;
    verify_original_forward_binding_chirho(
        &stored_decision_chirho.forward_receipt_chirho,
        original_effect_idem_key_chirho,
        &original_chirho.request_digest_chirho,
        &original_chirho.request_chirho,
    )?;
    if stored_forward_bytes_chirho != original_chirho.forward_receipt_bytes_chirho {
        return Err(stored_evidence_error_chirho(
            "database receipt does not byte-match the signed original effect",
        ));
    }

    transaction_chirho.lock_row_chirho(
        &original_chirho.request_chirho.subject_chirho,
        &original_chirho.request_chirho.row_key_chirho,
    )?;
    let current_value_chirho = transaction_chirho.load_value_chirho(
        &original_chirho.request_chirho.subject_chirho,
        &original_chirho.request_chirho.row_key_chirho,
    )?;
    let observed_state_chirho = state_for_value_chirho(
        evidence_key_chirho,
        &original_chirho.request_chirho.subject_chirho,
        &original_chirho.request_chirho.row_key_chirho,
        current_value_chirho.as_ref(),
    );
    if observed_state_chirho == original_chirho.forward_receipt_chirho.post_state_chirho {
        Ok(PostgresCompensationPreviewChirho::ExecutableChirho)
    } else {
        Ok(PostgresCompensationPreviewChirho::MustNotExecuteChirho {
            observed_state_chirho,
        })
    }
}

/// Query one compensation coordinate without creating a durable negative witness. An absent
/// receipt remains in-doubt because the reviewed operator door may still execute the restoration;
/// only an authenticated committed receipt can close the journal Hold.
/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub fn query_reversible_postgres_compensation_by_key_chirho<DatabaseChirho, OriginalChirho>(
    database_chirho: &mut DatabaseChirho,
    original_effects_chirho: &OriginalChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    compensation_idem_key_chirho: &HashChirho,
    original_effect_idem_key_chirho: &HashChirho,
) -> Result<PostgresCompensationQueryResultChirho, ReversiblePostgresErrorChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    OriginalChirho: PostgresOriginalEffectEvidencePortChirho + ?Sized,
{
    validate_digest_chirho("compensation_idem_key_chirho", compensation_idem_key_chirho)?;
    validate_digest_chirho(
        "original_effect_idem_key_chirho",
        original_effect_idem_key_chirho,
    )?;
    let original_chirho = load_verified_original_binding_chirho(
        original_effects_chirho,
        original_effect_idem_key_chirho,
    )?;
    let mut transaction_chirho = database_chirho.begin_serializable_transaction_chirho()?;
    transaction_chirho.lock_compensation_idempotency_key_chirho(compensation_idem_key_chirho)?;
    transaction_chirho.lock_original_effect_compensation_chirho(original_effect_idem_key_chirho)?;

    let row_chirho =
        match transaction_chirho.load_compensation_receipt_chirho(compensation_idem_key_chirho)? {
            Some(row_chirho) => row_chirho,
            None => {
                let Some(row_chirho) = transaction_chirho
                    .load_compensation_receipt_by_original_effect_chirho(
                        original_effect_idem_key_chirho,
                    )?
                else {
                    return Ok(PostgresCompensationQueryResultChirho::InDoubtChirho);
                };
                let parsed_chirho =
                    parse_canonical_compensation_receipt_chirho(&row_chirho.receipt_bytes_chirho)
                        .map_err(|error_chirho| {
                        stored_evidence_error_chirho(&error_chirho.to_string())
                    })?;
                if parsed_chirho.compensation_idem_key_chirho != *compensation_idem_key_chirho {
                    return Err(ReversiblePostgresErrorChirho::CompensationAlreadyRecordedChirho);
                }
                row_chirho
            }
        };
    let (receipt_chirho, receipt_bytes_chirho) = verify_compensation_row_chirho(
        evidence_key_chirho,
        &row_chirho,
        compensation_idem_key_chirho,
        original_effect_idem_key_chirho,
        &original_chirho.request_digest_chirho,
        &original_chirho.request_chirho,
    )?;
    Ok(PostgresCompensationQueryResultChirho::CommittedChirho {
        receipt_chirho,
        receipt_bytes_chirho,
    })
}

fn load_verified_original_binding_chirho<OriginalChirho>(
    original_effects_chirho: &OriginalChirho,
    original_effect_idem_key_chirho: &HashChirho,
) -> Result<VerifiedOriginalPostgresBindingChirho, ReversiblePostgresErrorChirho>
where
    OriginalChirho: PostgresOriginalEffectEvidencePortChirho + ?Sized,
{
    let original_chirho = original_effects_chirho
        .load_verified_original_effect_chirho(original_effect_idem_key_chirho)?;
    if original_chirho.original_effect_idem_key_chirho != *original_effect_idem_key_chirho {
        return Err(original_binding_error_chirho(
            "original effect key mismatch",
        ));
    }
    let request_chirho = parse_canonical_request_chirho(&original_chirho.request_bytes_chirho)
        .map_err(|error_chirho| original_binding_error_chirho(&error_chirho.to_string()))?;
    let request_digest_chirho = request_digest_chirho(&request_chirho)
        .map_err(|error_chirho| original_binding_error_chirho(&error_chirho.to_string()))?;
    let forward_receipt_chirho =
        parse_canonical_forward_receipt_chirho(&original_chirho.forward_receipt_bytes_chirho)
            .map_err(|error_chirho| original_binding_error_chirho(&error_chirho.to_string()))?;
    verify_original_forward_binding_chirho(
        &forward_receipt_chirho,
        original_effect_idem_key_chirho,
        &request_digest_chirho,
        &request_chirho,
    )?;
    Ok(VerifiedOriginalPostgresBindingChirho {
        request_chirho,
        request_digest_chirho,
        forward_receipt_chirho,
        forward_receipt_bytes_chirho: original_chirho.forward_receipt_bytes_chirho,
    })
}

fn load_desired_value_chirho<EvidenceChirho: PostgresPrivateEvidencePortChirho>(
    private_evidence_chirho: &EvidenceChirho,
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<Option<SensitiveBytesChirho>, ReversiblePostgresErrorChirho> {
    match &request_chirho.desired_chirho {
        DesiredPostgresStateChirho::PresentChirho { value_ref_chirho } => private_evidence_chirho
            .load_subject_blob_chirho(&request_chirho.subject_chirho, value_ref_chirho)
            .map(Some)
            .map_err(Into::into),
        DesiredPostgresStateChirho::AbsentChirho => Ok(None),
    }
}

fn state_for_value_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    subject_chirho: &HashChirho,
    row_key_chirho: &HashChirho,
    value_chirho: Option<&DatabaseValueChirho>,
) -> ExpectedPostgresStateChirho {
    value_chirho.map_or(ExpectedPostgresStateChirho::AbsentChirho, |value_chirho| {
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: row_fingerprint_chirho(
                evidence_key_chirho,
                subject_chirho,
                row_key_chirho,
                value_chirho.value_chirho.as_slice_chirho(),
            ),
        }
    })
}

pub(crate) fn verify_committed_decision_row_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    row_chirho: &AuthenticatedForwardDecisionRowChirho,
) -> Result<
    (ReversiblePostgresCommittedDecisionChirho, Vec<u8>, Vec<u8>),
    ReversiblePostgresErrorChirho,
> {
    if row_chirho.decision_kind_chirho != PostgresForwardDecisionKindChirho::CommittedChirho {
        return Err(stored_evidence_error_chirho(
            "forward decision dispatch kind is not committed",
        ));
    }
    let decision_chirho =
        parse_canonical_committed_decision_chirho(&row_chirho.decision_bytes_chirho)
            .map_err(|error_chirho| stored_evidence_error_chirho(&error_chirho.to_string()))?;
    let receipt_chirho = &decision_chirho.forward_receipt_chirho;
    if !verify_forward_receipt_mac_chirho(
        evidence_key_chirho,
        receipt_chirho,
        &decision_chirho.receipt_mac_chirho,
    ) {
        return Err(stored_evidence_error_chirho("forward receipt MAC mismatch"));
    }
    if receipt_chirho.effect_idem_key_chirho != row_chirho.effect_idem_key_chirho {
        return Err(stored_evidence_error_chirho(
            "forward decision row and receipt idempotency bindings differ",
        ));
    }
    let receipt_bytes_chirho = canonical_forward_receipt_bytes_chirho(receipt_chirho)
        .map_err(|error_chirho| stored_evidence_error_chirho(&error_chirho.to_string()))?;
    Ok((
        decision_chirho,
        row_chirho.decision_bytes_chirho.clone(),
        receipt_bytes_chirho,
    ))
}

fn verify_decision_coordinate_chirho(
    decision_chirho: &ReversiblePostgresCommittedDecisionChirho,
    coordinate_chirho: &ReversiblePostgresEffectCoordinateChirho,
) -> Result<(), ReversiblePostgresErrorChirho> {
    if decision_chirho.k_chirho != coordinate_chirho.effect_intent_key_chirho()
        || decision_chirho.contract_digest_chirho != *coordinate_chirho.contract_digest_chirho()
        || decision_chirho.journal_binding_chirho != *coordinate_chirho.journal_binding_chirho()
        || decision_chirho
            .forward_receipt_chirho
            .effect_idem_key_chirho
            != *coordinate_chirho.effect_idem_key_chirho()
    {
        return Err(stored_evidence_error_chirho(
            "committed decision coordinate binding mismatch",
        ));
    }
    Ok(())
}

fn verify_absence_decision_row_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    row_chirho: &AuthenticatedForwardDecisionRowChirho,
    coordinate_chirho: &ReversiblePostgresEffectCoordinateChirho,
) -> Result<(ReversiblePostgresAbsenceWitnessChirho, Vec<u8>), ReversiblePostgresErrorChirho> {
    if row_chirho.decision_kind_chirho != PostgresForwardDecisionKindChirho::DefiniteNoEffectChirho
    {
        return Err(stored_evidence_error_chirho(
            "forward decision dispatch kind is not definite no-effect",
        ));
    }
    let witness_chirho = parse_canonical_absence_witness_chirho(&row_chirho.decision_bytes_chirho)
        .map_err(|error_chirho| stored_evidence_error_chirho(&error_chirho.to_string()))?;
    if !verify_absence_witness_mac_chirho(evidence_key_chirho, &witness_chirho) {
        return Err(stored_evidence_error_chirho(
            "definite-no-effect witness MAC mismatch",
        ));
    }
    if row_chirho.effect_idem_key_chirho != *coordinate_chirho.effect_idem_key_chirho()
        || witness_chirho.k_chirho != coordinate_chirho.effect_intent_key_chirho()
        || witness_chirho.contract_digest_chirho != *coordinate_chirho.contract_digest_chirho()
        || witness_chirho.journal_binding_chirho != *coordinate_chirho.journal_binding_chirho()
    {
        return Err(stored_evidence_error_chirho(
            "definite-no-effect witness coordinate binding mismatch",
        ));
    }
    Ok((witness_chirho, row_chirho.decision_bytes_chirho.clone()))
}

fn verify_forward_request_binding_chirho(
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
    effect_idem_key_chirho: &HashChirho,
    request_digest_chirho: &HashChirho,
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<(), ReversiblePostgresErrorChirho> {
    if receipt_chirho.effect_idem_key_chirho != *effect_idem_key_chirho {
        return Err(stored_evidence_error_chirho(
            "forward receipt idempotency binding mismatch",
        ));
    }
    if receipt_chirho.request_digest_chirho != *request_digest_chirho {
        return Err(ReversiblePostgresErrorChirho::IdempotencyConflictChirho);
    }
    if receipt_chirho.subject_chirho != request_chirho.subject_chirho
        || receipt_chirho.row_key_chirho != request_chirho.row_key_chirho
    {
        return Err(stored_evidence_error_chirho(
            "forward receipt coordinate binding mismatch",
        ));
    }
    Ok(())
}

fn verify_original_forward_binding_chirho(
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
    effect_idem_key_chirho: &HashChirho,
    request_digest_chirho: &HashChirho,
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<(), ReversiblePostgresErrorChirho> {
    if receipt_chirho.effect_idem_key_chirho != *effect_idem_key_chirho
        || receipt_chirho.request_digest_chirho != *request_digest_chirho
        || receipt_chirho.subject_chirho != request_chirho.subject_chirho
        || receipt_chirho.row_key_chirho != request_chirho.row_key_chirho
    {
        return Err(original_binding_error_chirho(
            "signed request and forward receipt do not bind exactly",
        ));
    }
    Ok(())
}

fn verify_compensation_row_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    row_chirho: &AuthenticatedCompensationReceiptRowChirho,
    compensation_idem_key_chirho: &HashChirho,
    original_effect_idem_key_chirho: &HashChirho,
    request_digest_chirho: &HashChirho,
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<(ReversiblePostgresCompensationReceiptChirho, Vec<u8>), ReversiblePostgresErrorChirho> {
    let receipt_chirho =
        parse_canonical_compensation_receipt_chirho(&row_chirho.receipt_bytes_chirho)
            .map_err(|error_chirho| stored_evidence_error_chirho(&error_chirho.to_string()))?;
    if !verify_compensation_receipt_mac_chirho(
        evidence_key_chirho,
        &receipt_chirho,
        &row_chirho.receipt_mac_chirho,
    ) {
        return Err(stored_evidence_error_chirho(
            "compensation receipt MAC mismatch",
        ));
    }
    if row_chirho.original_effect_idem_key_chirho != *original_effect_idem_key_chirho
        || receipt_chirho.compensation_idem_key_chirho != *compensation_idem_key_chirho
        || receipt_chirho.original_effect_idem_key_chirho != *original_effect_idem_key_chirho
        || receipt_chirho.original_request_digest_chirho != *request_digest_chirho
        || receipt_chirho.subject_chirho != request_chirho.subject_chirho
        || receipt_chirho.row_key_chirho != request_chirho.row_key_chirho
    {
        return Err(stored_evidence_error_chirho(
            "compensation receipt binding mismatch",
        ));
    }
    Ok((receipt_chirho, row_chirho.receipt_bytes_chirho.clone()))
}

fn restore_before_state_chirho<TransactionChirho, EvidenceChirho>(
    transaction_chirho: &mut TransactionChirho,
    private_evidence_chirho: &EvidenceChirho,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
) -> Result<(), ReversiblePostgresErrorChirho>
where
    TransactionChirho: ReversiblePostgresTransactionPortChirho,
    EvidenceChirho: PostgresPrivateEvidencePortChirho,
{
    match &receipt_chirho.before_state_chirho {
        ExpectedPostgresStateChirho::AbsentChirho => transaction_chirho
            .delete_value_chirho(
                &receipt_chirho.subject_chirho,
                &receipt_chirho.row_key_chirho,
            )
            .map_err(Into::into),
        ExpectedPostgresStateChirho::KeyedFingerprintChirho { fingerprint_chirho } => {
            let before_ref_chirho =
                receipt_chirho
                    .before_image_ref_chirho
                    .as_ref()
                    .ok_or_else(|| {
                        stored_evidence_error_chirho(
                            "present before-state has no private before-image ref",
                        )
                    })?;
            let before_bytes_chirho = private_evidence_chirho
                .load_subject_blob_chirho(&receipt_chirho.subject_chirho, before_ref_chirho)?;
            let actual_fingerprint_chirho = row_fingerprint_chirho(
                evidence_key_chirho,
                &receipt_chirho.subject_chirho,
                &receipt_chirho.row_key_chirho,
                before_bytes_chirho.as_slice_chirho(),
            );
            if actual_fingerprint_chirho != *fingerprint_chirho {
                return Err(ReversiblePostgresErrorChirho::BeforeImageMismatchChirho);
            }
            transaction_chirho.upsert_value_chirho(
                &receipt_chirho.subject_chirho,
                &receipt_chirho.row_key_chirho,
                before_bytes_chirho.as_slice_chirho(),
            )?;
            Ok(())
        }
    }
}

fn stored_evidence_error_chirho(detail_chirho: &str) -> ReversiblePostgresErrorChirho {
    ReversiblePostgresErrorChirho::StoredEvidenceInvalidChirho {
        detail_chirho: detail_chirho.to_string(),
    }
}

fn original_binding_error_chirho(detail_chirho: &str) -> ReversiblePostgresErrorChirho {
    ReversiblePostgresErrorChirho::OriginalEffectBindingInvalidChirho {
        detail_chirho: detail_chirho.to_string(),
    }
}
