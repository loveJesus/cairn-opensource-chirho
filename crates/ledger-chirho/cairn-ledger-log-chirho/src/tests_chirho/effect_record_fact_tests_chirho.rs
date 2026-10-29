// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::admission_tests_chirho::record_chirho;
use crate::effect_record_fact_chirho::{
    classify_effect_record_fact_chirho, EffectHoldLineageChirho, EffectRecordFactChirho,
    EffectRecordFactRefusalReasonChirho, EffectRecordFamilyChirho,
    EffectTerminalFactDispositionChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO, EFFECT_INTENT_KEY_PREFIX_CHIRHO,
};
use cairn_effect_commit_chirho::terminal_chirho::EFFECT_TERMINAL_KEY_PREFIX_CHIRHO;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::{
    EscrowControlChirho, LedgerOpChirho, LedgerRecordChirho,
};

const INTENT_REF_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONTROL_REF_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OUTCOME_REF_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn digest_chirho(value_chirho: &str) -> DigestChirho {
    DigestChirho(value_chirho.to_owned())
}

fn control_chirho(value_chirho: &str) -> EscrowControlChirho {
    EscrowControlChirho {
        saga_id_chirho: digest_chirho(value_chirho),
        step_chirho: 7,
    }
}

fn forward_hold_chirho() -> LedgerRecordChirho {
    let mut record_chirho = record_chirho(
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: control_chirho(INTENT_REF_CHIRHO),
        },
        Vec::new(),
    );
    record_chirho.idempotency_key_chirho =
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{INTENT_REF_CHIRHO}");
    record_chirho.provenance_chirho = Some(digest_chirho(INTENT_REF_CHIRHO));
    record_chirho
}

fn compensation_hold_chirho() -> LedgerRecordChirho {
    let mut record_chirho = forward_hold_chirho();
    record_chirho.idempotency_key_chirho =
        format!("{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}{CONTROL_REF_CHIRHO}");
    record_chirho.op_chirho = LedgerOpChirho::EscrowHoldChirho {
        control_chirho: control_chirho(CONTROL_REF_CHIRHO),
    };
    record_chirho
}

fn terminal_chirho(finalize_chirho: bool) -> LedgerRecordChirho {
    let terminal_op_chirho = if finalize_chirho {
        LedgerOpChirho::EscrowFinalizeChirho {
            control_chirho: control_chirho(CONTROL_REF_CHIRHO),
        }
    } else {
        LedgerOpChirho::EscrowReleaseChirho {
            control_chirho: control_chirho(CONTROL_REF_CHIRHO),
        }
    };
    let mut record_chirho = record_chirho(terminal_op_chirho, Vec::new());
    record_chirho.idempotency_key_chirho =
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}{INTENT_REF_CHIRHO}");
    record_chirho.provenance_chirho = Some(digest_chirho(OUTCOME_REF_CHIRHO));
    record_chirho
}

#[test]
fn classifier_emits_only_record_local_effect_facts_chirho() {
    let ordinary_chirho = record_chirho(LedgerOpChirho::TransferChirho, Vec::new());
    assert_eq!(
        classify_effect_record_fact_chirho(&ordinary_chirho).unwrap(),
        EffectRecordFactChirho::LedgerOnlyChirho
    );
    assert_eq!(
        classify_effect_record_fact_chirho(&forward_hold_chirho()).unwrap(),
        EffectRecordFactChirho::EffectHoldChirho {
            lineage_chirho: EffectHoldLineageChirho::ForwardChirho,
            intent_ref_chirho: digest_chirho(INTENT_REF_CHIRHO),
            control_chirho: control_chirho(INTENT_REF_CHIRHO),
        }
    );
    assert_eq!(
        classify_effect_record_fact_chirho(&compensation_hold_chirho()).unwrap(),
        EffectRecordFactChirho::EffectHoldChirho {
            lineage_chirho: EffectHoldLineageChirho::CompensationChirho,
            intent_ref_chirho: digest_chirho(INTENT_REF_CHIRHO),
            control_chirho: control_chirho(CONTROL_REF_CHIRHO),
        }
    );
    assert_eq!(
        classify_effect_record_fact_chirho(&terminal_chirho(true)).unwrap(),
        EffectRecordFactChirho::EffectTerminalChirho {
            intent_ref_chirho: digest_chirho(INTENT_REF_CHIRHO),
            outcome_ref_chirho: digest_chirho(OUTCOME_REF_CHIRHO),
            control_chirho: control_chirho(CONTROL_REF_CHIRHO),
            disposition_chirho: EffectTerminalFactDispositionChirho::CommittedFinalizeChirho,
        }
    );
    assert_eq!(
        classify_effect_record_fact_chirho(&terminal_chirho(false)).unwrap(),
        EffectRecordFactChirho::EffectTerminalChirho {
            intent_ref_chirho: digest_chirho(INTENT_REF_CHIRHO),
            outcome_ref_chirho: digest_chirho(OUTCOME_REF_CHIRHO),
            control_chirho: control_chirho(CONTROL_REF_CHIRHO),
            disposition_chirho: EffectTerminalFactDispositionChirho::DefiniteNoEffectReleaseChirho,
        }
    );
}

#[test]
fn ordinary_escrow_shape_without_a_reserved_key_stays_ledger_only_chirho() {
    let record_chirho = record_chirho(
        LedgerOpChirho::EscrowHoldChirho {
            control_chirho: control_chirho("not-a-digest-chirho"),
        },
        Vec::new(),
    );
    assert_eq!(
        classify_effect_record_fact_chirho(&record_chirho).unwrap(),
        EffectRecordFactChirho::LedgerOnlyChirho
    );
}

#[test]
fn reserved_effect_records_fail_closed_on_every_binding_axis_chirho() {
    let mut cases_chirho = Vec::new();

    let mut malformed_forward_key_chirho = forward_hold_chirho();
    malformed_forward_key_chirho.idempotency_key_chirho =
        format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}broken-chirho");
    cases_chirho.push((
        malformed_forward_key_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
    ));

    let mut missing_forward_provenance_chirho = forward_hold_chirho();
    missing_forward_provenance_chirho.provenance_chirho = None;
    cases_chirho.push((
        missing_forward_provenance_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::MissingProvenanceChirho,
    ));

    let mut malformed_forward_provenance_chirho = forward_hold_chirho();
    malformed_forward_provenance_chirho.provenance_chirho = Some(digest_chirho("broken-chirho"));
    cases_chirho.push((
        malformed_forward_provenance_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::MalformedProvenanceChirho,
    ));

    let mut wrong_forward_provenance_chirho = forward_hold_chirho();
    wrong_forward_provenance_chirho.provenance_chirho = Some(digest_chirho(OUTCOME_REF_CHIRHO));
    cases_chirho.push((
        wrong_forward_provenance_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho,
    ));

    let mut wrong_forward_control_chirho = forward_hold_chirho();
    wrong_forward_control_chirho.op_chirho = LedgerOpChirho::EscrowHoldChirho {
        control_chirho: control_chirho(CONTROL_REF_CHIRHO),
    };
    cases_chirho.push((
        wrong_forward_control_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho,
    ));

    let mut wrong_forward_op_chirho = forward_hold_chirho();
    wrong_forward_op_chirho.op_chirho = LedgerOpChirho::TransferChirho;
    cases_chirho.push((
        wrong_forward_op_chirho,
        EffectRecordFamilyChirho::ForwardIntentChirho,
        EffectRecordFactRefusalReasonChirho::WrongOperationChirho,
    ));

    let mut malformed_compensation_key_chirho = compensation_hold_chirho();
    malformed_compensation_key_chirho.idempotency_key_chirho =
        format!("{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}broken-chirho");
    cases_chirho.push((
        malformed_compensation_key_chirho,
        EffectRecordFamilyChirho::CompensationIntentChirho,
        EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
    ));

    let mut wrong_compensation_control_chirho = compensation_hold_chirho();
    wrong_compensation_control_chirho.op_chirho = LedgerOpChirho::EscrowHoldChirho {
        control_chirho: control_chirho(OUTCOME_REF_CHIRHO),
    };
    cases_chirho.push((
        wrong_compensation_control_chirho,
        EffectRecordFamilyChirho::CompensationIntentChirho,
        EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho,
    ));

    let mut malformed_terminal_key_chirho = terminal_chirho(true);
    malformed_terminal_key_chirho.idempotency_key_chirho =
        format!("{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}broken-chirho");
    cases_chirho.push((
        malformed_terminal_key_chirho,
        EffectRecordFamilyChirho::TerminalChirho,
        EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
    ));

    let mut missing_terminal_outcome_chirho = terminal_chirho(true);
    missing_terminal_outcome_chirho.provenance_chirho = None;
    cases_chirho.push((
        missing_terminal_outcome_chirho,
        EffectRecordFamilyChirho::TerminalChirho,
        EffectRecordFactRefusalReasonChirho::MissingProvenanceChirho,
    ));

    let mut malformed_terminal_outcome_chirho = terminal_chirho(true);
    malformed_terminal_outcome_chirho.provenance_chirho = Some(digest_chirho("broken-chirho"));
    cases_chirho.push((
        malformed_terminal_outcome_chirho,
        EffectRecordFamilyChirho::TerminalChirho,
        EffectRecordFactRefusalReasonChirho::MalformedProvenanceChirho,
    ));

    let mut malformed_terminal_control_chirho = terminal_chirho(true);
    malformed_terminal_control_chirho.op_chirho = LedgerOpChirho::EscrowFinalizeChirho {
        control_chirho: control_chirho("broken-chirho"),
    };
    cases_chirho.push((
        malformed_terminal_control_chirho,
        EffectRecordFamilyChirho::TerminalChirho,
        EffectRecordFactRefusalReasonChirho::MalformedControlChirho,
    ));

    let mut wrong_terminal_op_chirho = terminal_chirho(true);
    wrong_terminal_op_chirho.op_chirho = LedgerOpChirho::TransferChirho;
    cases_chirho.push((
        wrong_terminal_op_chirho,
        EffectRecordFamilyChirho::TerminalChirho,
        EffectRecordFactRefusalReasonChirho::WrongOperationChirho,
    ));

    for (record_chirho, family_chirho, reason_chirho) in cases_chirho {
        let refusal_chirho = classify_effect_record_fact_chirho(&record_chirho).unwrap_err();
        assert_eq!(refusal_chirho.family_chirho, family_chirho);
        assert_eq!(refusal_chirho.reason_chirho, reason_chirho);
    }
}
