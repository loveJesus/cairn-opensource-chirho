// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure CF3 record classification shared by journal replay and GD7 reconciliation.
//!
//! This module classifies only what one verified ledger record proves. In particular, a terminal
//! record does not identify forward-versus-compensation lineage by itself; the bounded
//! reconciliation reducer derives that lineage from the terminal's verified signed intent.

use cairn_effect_commit_chirho::intent_chirho::{
    is_reserved_effect_compensation_key_chirho, is_reserved_effect_intent_key_chirho,
    parse_effect_compensation_key_chirho, parse_effect_intent_key_chirho,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    is_reserved_effect_terminal_key_chirho, parse_effect_terminal_key_chirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::{
    EscrowControlChirho, LedgerOpChirho, LedgerRecordChirho,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectRecordFamilyChirho {
    ForwardIntentChirho,
    CompensationIntentChirho,
    TerminalChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectRecordFactRefusalReasonChirho {
    MalformedReservedKeyChirho,
    MissingProvenanceChirho,
    MalformedProvenanceChirho,
    WrongOperationChirho,
    CoordinateMismatchChirho,
    MalformedControlChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRecordFactRefusalChirho {
    pub seq_chirho: u64,
    pub family_chirho: EffectRecordFamilyChirho,
    pub reason_chirho: EffectRecordFactRefusalReasonChirho,
}

impl std::fmt::Display for EffectRecordFactRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let family_chirho = match self.family_chirho {
            EffectRecordFamilyChirho::ForwardIntentChirho => "intent",
            EffectRecordFamilyChirho::CompensationIntentChirho => "compensation",
            EffectRecordFamilyChirho::TerminalChirho => "terminal",
        };
        match self.reason_chirho {
            EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho => write!(
                formatter_chirho,
                "malformed reserved CF3 {family_chirho} key at seq {}",
                self.seq_chirho
            ),
            EffectRecordFactRefusalReasonChirho::MissingProvenanceChirho => write!(
                formatter_chirho,
                "reserved CF3 {family_chirho} at seq {} lacks required provenance",
                self.seq_chirho
            ),
            EffectRecordFactRefusalReasonChirho::MalformedProvenanceChirho => write!(
                formatter_chirho,
                "reserved CF3 {family_chirho} at seq {} carries malformed provenance",
                self.seq_chirho
            ),
            EffectRecordFactRefusalReasonChirho::WrongOperationChirho => write!(
                formatter_chirho,
                "reserved CF3 {family_chirho} at seq {} has the wrong ledger operation",
                self.seq_chirho
            ),
            EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho => write!(
                formatter_chirho,
                "reserved CF3 {family_chirho} record binding is malformed at seq {}",
                self.seq_chirho
            ),
            EffectRecordFactRefusalReasonChirho::MalformedControlChirho => write!(
                formatter_chirho,
                "reserved CF3 {family_chirho} at seq {} carries malformed control",
                self.seq_chirho
            ),
        }
    }
}

impl std::error::Error for EffectRecordFactRefusalChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectHoldLineageChirho {
    ForwardChirho,
    CompensationChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectTerminalFactDispositionChirho {
    CommittedFinalizeChirho,
    DefiniteNoEffectReleaseChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectRecordFactChirho {
    LedgerOnlyChirho,
    EffectHoldChirho {
        lineage_chirho: EffectHoldLineageChirho,
        intent_ref_chirho: DigestChirho,
        control_chirho: EscrowControlChirho,
    },
    EffectTerminalChirho {
        intent_ref_chirho: DigestChirho,
        outcome_ref_chirho: DigestChirho,
        control_chirho: EscrowControlChirho,
        disposition_chirho: EffectTerminalFactDispositionChirho,
    },
}

/// Classify only the authority fact carried by one record. Reserved namespaces fail closed; an
/// ordinary record remains ledger-only even when its operation is escrow-shaped.
///
/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
pub fn classify_effect_record_fact_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<EffectRecordFactChirho, EffectRecordFactRefusalChirho> {
    if is_reserved_effect_compensation_key_chirho(&record_chirho.idempotency_key_chirho) {
        return classify_compensation_hold_chirho(record_chirho);
    }
    if is_reserved_effect_intent_key_chirho(&record_chirho.idempotency_key_chirho) {
        return classify_forward_hold_chirho(record_chirho);
    }
    if is_reserved_effect_terminal_key_chirho(&record_chirho.idempotency_key_chirho) {
        return classify_terminal_chirho(record_chirho);
    }
    Ok(EffectRecordFactChirho::LedgerOnlyChirho)
}

fn classify_forward_hold_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<EffectRecordFactChirho, EffectRecordFactRefusalChirho> {
    let family_chirho = EffectRecordFamilyChirho::ForwardIntentChirho;
    let intent_ref_chirho = parse_effect_intent_key_chirho(&record_chirho.idempotency_key_chirho)
        .map_err(|_| {
        refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
        )
    })?;
    let provenance_chirho = required_provenance_chirho(record_chirho, family_chirho)?;
    let LedgerOpChirho::EscrowHoldChirho { control_chirho } = &record_chirho.op_chirho else {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::WrongOperationChirho,
        ));
    };
    validate_control_chirho(record_chirho, family_chirho, control_chirho)?;
    if provenance_chirho != intent_ref_chirho || control_chirho.saga_id_chirho != intent_ref_chirho
    {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho,
        ));
    }
    Ok(EffectRecordFactChirho::EffectHoldChirho {
        lineage_chirho: EffectHoldLineageChirho::ForwardChirho,
        intent_ref_chirho,
        control_chirho: control_chirho.clone(),
    })
}

fn classify_compensation_hold_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<EffectRecordFactChirho, EffectRecordFactRefusalChirho> {
    let family_chirho = EffectRecordFamilyChirho::CompensationIntentChirho;
    let compensation_control_chirho = parse_effect_compensation_key_chirho(
        &record_chirho.idempotency_key_chirho,
    )
    .map_err(|_| {
        refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
        )
    })?;
    let intent_ref_chirho = required_provenance_chirho(record_chirho, family_chirho)?;
    let LedgerOpChirho::EscrowHoldChirho { control_chirho } = &record_chirho.op_chirho else {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::WrongOperationChirho,
        ));
    };
    validate_control_chirho(record_chirho, family_chirho, control_chirho)?;
    if control_chirho.saga_id_chirho != compensation_control_chirho {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::CoordinateMismatchChirho,
        ));
    }
    Ok(EffectRecordFactChirho::EffectHoldChirho {
        lineage_chirho: EffectHoldLineageChirho::CompensationChirho,
        intent_ref_chirho,
        control_chirho: control_chirho.clone(),
    })
}

fn classify_terminal_chirho(
    record_chirho: &LedgerRecordChirho,
) -> Result<EffectRecordFactChirho, EffectRecordFactRefusalChirho> {
    let family_chirho = EffectRecordFamilyChirho::TerminalChirho;
    let intent_ref_chirho = parse_effect_terminal_key_chirho(&record_chirho.idempotency_key_chirho)
        .map_err(|_| {
            refusal_chirho(
                record_chirho,
                family_chirho,
                EffectRecordFactRefusalReasonChirho::MalformedReservedKeyChirho,
            )
        })?;
    let outcome_ref_chirho = required_provenance_chirho(record_chirho, family_chirho)?;
    let (control_chirho, disposition_chirho) = match &record_chirho.op_chirho {
        LedgerOpChirho::EscrowFinalizeChirho { control_chirho } => (
            control_chirho,
            EffectTerminalFactDispositionChirho::CommittedFinalizeChirho,
        ),
        LedgerOpChirho::EscrowReleaseChirho { control_chirho } => (
            control_chirho,
            EffectTerminalFactDispositionChirho::DefiniteNoEffectReleaseChirho,
        ),
        _ => {
            return Err(refusal_chirho(
                record_chirho,
                family_chirho,
                EffectRecordFactRefusalReasonChirho::WrongOperationChirho,
            ));
        }
    };
    validate_control_chirho(record_chirho, family_chirho, control_chirho)?;
    Ok(EffectRecordFactChirho::EffectTerminalChirho {
        intent_ref_chirho,
        outcome_ref_chirho,
        control_chirho: control_chirho.clone(),
        disposition_chirho,
    })
}

fn required_provenance_chirho(
    record_chirho: &LedgerRecordChirho,
    family_chirho: EffectRecordFamilyChirho,
) -> Result<DigestChirho, EffectRecordFactRefusalChirho> {
    let provenance_chirho = record_chirho.provenance_chirho.clone().ok_or_else(|| {
        refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::MissingProvenanceChirho,
        )
    })?;
    if !is_lower_hex_digest_chirho(&provenance_chirho.0) {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::MalformedProvenanceChirho,
        ));
    }
    Ok(provenance_chirho)
}

fn validate_control_chirho(
    record_chirho: &LedgerRecordChirho,
    family_chirho: EffectRecordFamilyChirho,
    control_chirho: &EscrowControlChirho,
) -> Result<(), EffectRecordFactRefusalChirho> {
    if !is_lower_hex_digest_chirho(&control_chirho.saga_id_chirho.0) {
        return Err(refusal_chirho(
            record_chirho,
            family_chirho,
            EffectRecordFactRefusalReasonChirho::MalformedControlChirho,
        ));
    }
    Ok(())
}

fn refusal_chirho(
    record_chirho: &LedgerRecordChirho,
    family_chirho: EffectRecordFamilyChirho,
    reason_chirho: EffectRecordFactRefusalReasonChirho,
) -> EffectRecordFactRefusalChirho {
    EffectRecordFactRefusalChirho {
        seq_chirho: record_chirho.seq_chirho,
        family_chirho,
        reason_chirho,
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}
