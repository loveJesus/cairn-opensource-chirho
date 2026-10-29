// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Held-side import of a winner's SIGNED compensation ledger record into a held-signed convergence row.
//!
//! Ruled (a) lands the compensated `CompletedChirho` obligation-processing row on the WINNER root, so
//! the held convergence classifier never sees it and refuses `UnconvergedObligationChirho`. This
//! module is the held-side mover (Shape A′) that closes that gap WITHOUT trusting an unsigned winner
//! row (Shape E, forbidden): it re-verifies the winner's own signed compensation ledger record —
//! deterministic-K-bound to the exact original effect, under the adopted winner term, ledger-signature
//! checked by a verifier holding NO winner signing power — and persists a HELD-SIGNED
//! `Gd7ConvergedImportRowChirho`. The classifier consults that row on a native `MissingState`.
//!
//! Trust chain: the mover verifies the winner's money-moving receipt; the held node signs a row
//! binding `{mint identity, canonical obligation, verified receipt digest, winner term, compensated}`;
//! the classifier re-checks the held signature and the subject binding before it certifies. An
//! obligation whose winner receipt does not verify stays OPEN → `UnconvergedObligationChirho`
//! (fail-closed, unchanged refusal).
//!
//! Workflow:
//! `spec-chirho/workstream-state-chirho/gd7-converged-import-mover-decision-chirho.md`.

use super::authority_chirho::{
    enumerate_gd7_sealed_plan_obligations_chirho, VerifiedGd7SealedPlanProofChirho,
};
use super::contract_chirho::Gd7PlanRefusalChirho;
use super::obligation_mint_chirho::gd7_mint_identity_for_verified_obligation_chirho;
use super::reducer_chirho::Gd7EffectProofPortsChirho;
use crate::reconciliation_chirho::contract_chirho::{
    is_lower_hex_digest_chirho, Gd7LedgerRecordVerifierPortChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho;
use cairn_effect_commit_chirho::intent_chirho::{
    effect_compensation_key_chirho, parse_effect_compensation_key_chirho,
    EFFECT_INTENT_KEY_PREFIX_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::record_chirho::{LedgerOpChirho, LedgerRecordChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::split_writer_epoch_chirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub(crate) const GD7_CONVERGED_IMPORT_ROW_SCHEMA_V1_CHIRHO: &str =
    "gd7-converged-import-row-v1-chirho";
const MAX_GD7_CONVERGED_IMPORT_ROW_BYTES_CHIRHO: usize = 16 * 1024;
const MAX_GD7_WINNER_COMPENSATION_RECORD_LINE_BYTES_CHIRHO: usize = 256 * 1024;

/// The one terminal the import path admits: a verified winner compensation.
///
/// The type carries no other variant on purpose — the mover only ever attests to a verified
/// compensation receipt, so a row that deserialized to anything else is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Gd7ConvergedImportTerminalChirho {
    CompensatedChirho,
}

/// A HELD-SIGNED attestation that this node verified the winner's compensation receipt for one
/// obligation. The classifier trusts THIS row (held signature + subject binding), never the winner's
/// unsigned processing row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Gd7ConvergedImportRowChirho {
    schema_chirho: String,
    mint_identity_digest_chirho: String,
    canonical_obligation_digest_chirho: String,
    verified_receipt_digest_chirho: String,
    winner_term_chirho: u64,
    terminal_chirho: Gd7ConvergedImportTerminalChirho,
    key_id_chirho: String,
    sig_chirho: String,
}

impl Gd7ConvergedImportRowChirho {
    pub fn verified_receipt_digest_chirho(&self) -> &str {
        &self.verified_receipt_digest_chirho
    }

    fn canonical_unsigned_bytes_chirho(&self) -> Result<Vec<u8>, Gd7ConvergedImportRefusalChirho> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.sig_chirho.clear();
        serde_json::to_vec(&unsigned_chirho)
            .map_err(|_| Gd7ConvergedImportRefusalChirho::SerializationChirho)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum Gd7ConvergedImportRefusalChirho {
    InvalidReferenceChirho,
    OversizedRecordChirho,
    MalformedRecordChirho,
    NonCanonicalRecordChirho,
    InvalidLedgerSignatureChirho,
    NotCompensationHoldChirho,
    EffectKeyMismatchChirho,
    WrongWinnerTermChirho,
    CompensationKeyChirho,
    MalformedRowChirho,
    NonCanonicalRowChirho,
    OversizedRowChirho,
    InvalidRowSignatureChirho,
    RowSubjectMismatchChirho,
    SubjectMismatchChirho,
    StateCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7ConvergedImportRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidReferenceChirho => "GD7 converged import reference is invalid",
            Self::OversizedRecordChirho => {
                "GD7 winner compensation record line exceeds its fixed bound"
            }
            Self::MalformedRecordChirho => "GD7 winner compensation record is malformed",
            Self::NonCanonicalRecordChirho => "GD7 winner compensation record is not canonical",
            Self::InvalidLedgerSignatureChirho => {
                "GD7 winner compensation record ledger signature is invalid"
            }
            Self::NotCompensationHoldChirho => {
                "GD7 winner compensation record is not an escrow-hold"
            }
            Self::EffectKeyMismatchChirho => {
                "GD7 winner compensation record does not bind the expected compensation coordinate"
            }
            Self::WrongWinnerTermChirho => {
                "GD7 winner compensation record is not under the adopted winner term"
            }
            Self::CompensationKeyChirho => {
                "GD7 original effect key does not derive a compensation coordinate"
            }
            Self::MalformedRowChirho => "GD7 converged import row is malformed",
            Self::NonCanonicalRowChirho => "GD7 converged import row is not canonical",
            Self::OversizedRowChirho => "GD7 converged import row exceeds its fixed bound",
            Self::InvalidRowSignatureChirho => "GD7 converged import row held signature is invalid",
            Self::RowSubjectMismatchChirho => {
                "GD7 converged import row is filed under a different mint identity"
            }
            Self::SubjectMismatchChirho => {
                "GD7 converged import row does not bind this obligation's subject"
            }
            Self::StateCollisionChirho => {
                "GD7 converged import row collided with different durable bytes"
            }
            Self::SerializationChirho => "GD7 converged import serialization failed",
            Self::SigningChirho => "GD7 converged import row signing failed",
            Self::StorageChirho => "GD7 converged import storage operation failed",
        })
    }
}

impl Error for Gd7ConvergedImportRefusalChirho {}

pub(crate) fn gd7_converged_import_row_path_chirho(
    mint_identity_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ConvergedImportRefusalChirho> {
    if !is_lower_hex_digest_chirho(mint_identity_digest_chirho) {
        return Err(Gd7ConvergedImportRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/converged-import-rows-chirho/{}/{}/{mint_identity_digest_chirho}.json",
        &mint_identity_digest_chirho[..2],
        &mint_identity_digest_chirho[2..4],
    )))
}

/// Re-verify the winner's signed compensation ledger record and return its stored-line digest.
///
/// The record must: canonically re-serialize to the exact imported bytes; carry a valid winner
/// ledger signature; be an `EscrowHoldChirho` whose control saga id equals
/// `parse_effect_compensation_key(effect_compensation_key(original_effect_key))` — the deterministic
/// K coordinate the compensation append bound; and sit under the adopted winner term (the record's
/// epoch geo-term). Any failure is fail-closed. The returned digest is the receipt the held row binds.
fn verify_winner_compensation_record_chirho(
    winner_compensation_record_line_chirho: &str,
    winner_ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    original_effect_key_chirho: &str,
    adopted_winner_term_chirho: u64,
) -> Result<String, Gd7ConvergedImportRefusalChirho> {
    if winner_compensation_record_line_chirho.len()
        > MAX_GD7_WINNER_COMPENSATION_RECORD_LINE_BYTES_CHIRHO
    {
        return Err(Gd7ConvergedImportRefusalChirho::OversizedRecordChirho);
    }
    let record_chirho: LedgerRecordChirho =
        serde_json::from_str(winner_compensation_record_line_chirho)
            .map_err(|_| Gd7ConvergedImportRefusalChirho::MalformedRecordChirho)?;
    // Canonical re-serialization must reproduce the imported bytes exactly — a non-canonical or
    // sig-tampered line is refused before it can be trusted, and the digest below is bound to the
    // canonical form the winner journal actually stored.
    let canonical_line_chirho = canonical_ledger_record_line_chirho(&record_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::MalformedRecordChirho)?;
    if canonical_line_chirho != winner_compensation_record_line_chirho {
        return Err(Gd7ConvergedImportRefusalChirho::NonCanonicalRecordChirho);
    }
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::MalformedRecordChirho)?;
    if !winner_ledger_verifier_chirho
        .verify_chirho(&signed_content_chirho, &record_chirho.sig_chirho)
    {
        return Err(Gd7ConvergedImportRefusalChirho::InvalidLedgerSignatureChirho);
    }
    let compensation_key_chirho = effect_compensation_key_chirho(original_effect_key_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::CompensationKeyChirho)?;
    let expected_saga_id_chirho = parse_effect_compensation_key_chirho(&compensation_key_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::CompensationKeyChirho)?;
    match &record_chirho.op_chirho {
        LedgerOpChirho::EscrowHoldChirho { control_chirho } => {
            if control_chirho.saga_id_chirho != expected_saga_id_chirho {
                return Err(Gd7ConvergedImportRefusalChirho::EffectKeyMismatchChirho);
            }
        }
        _ => return Err(Gd7ConvergedImportRefusalChirho::NotCompensationHoldChirho),
    }
    if u64::from(split_writer_epoch_chirho(record_chirho.epoch_chirho).geo_term_chirho)
        != adopted_winner_term_chirho
    {
        return Err(Gd7ConvergedImportRefusalChirho::WrongWinnerTermChirho);
    }
    Ok(stored_line_digest_chirho(&canonical_line_chirho).0)
}

/// Verify a winner compensation receipt and persist a HELD-SIGNED import row keyed by mint identity.
///
/// The caller supplies the coordinates of ONE enumerated obligation — its mint identity, canonical
/// obligation digest, and original effect key — plus the adopted winner term and the imported winner
/// compensation record line. All coordinates must describe the same obligation; the production caller
/// derives them together from one verified obligation. Create-only and immutable-collision-checked:
/// re-importing the same receipt is idempotent, a DIFFERENT receipt under the same mint identity is a
/// `StateCollisionChirho`.
#[allow(
    clippy::too_many_arguments,
    reason = "the import verifies one complete compensation-receipt authority coordinate"
)]
pub(crate) fn import_verified_gd7_compensation_receipt_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    mint_identity_digest_chirho: &str,
    canonical_obligation_digest_chirho: &str,
    original_effect_key_chirho: &str,
    adopted_winner_term_chirho: u64,
    winner_compensation_record_line_chirho: &str,
) -> Result<Gd7ConvergedImportRowChirho, Gd7ConvergedImportRefusalChirho> {
    if !is_lower_hex_digest_chirho(mint_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(canonical_obligation_digest_chirho)
        || adopted_winner_term_chirho == 0
    {
        return Err(Gd7ConvergedImportRefusalChirho::InvalidReferenceChirho);
    }
    let verified_receipt_digest_chirho = verify_winner_compensation_record_chirho(
        winner_compensation_record_line_chirho,
        winner_ledger_verifier_chirho,
        original_effect_key_chirho,
        adopted_winner_term_chirho,
    )?;
    let row_chirho = sign_converged_import_row_chirho(
        held_signer_chirho,
        mint_identity_digest_chirho,
        canonical_obligation_digest_chirho,
        &verified_receipt_digest_chirho,
        adopted_winner_term_chirho,
    )?;
    let path_chirho = gd7_converged_import_row_path_chirho(mint_identity_digest_chirho)?;
    let bytes_chirho = serialize_row_chirho(&row_chirho)?;
    match storage_chirho
        .create_durable_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(row_chirho),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_verified_row_bytes_chirho(
                storage_chirho,
                &path_chirho,
                held_signer_chirho,
                mint_identity_digest_chirho,
            )?
            .ok_or(Gd7ConvergedImportRefusalChirho::StorageChirho)?;
            require_same_row_identity_chirho(&existing_chirho, &row_chirho)?;
            Ok(existing_chirho)
        }
    }
}

/// PRODUCTION write-side driver for Shape A': persist the held-signed converged-import row that
/// `verify_gd7_convergence_chirho`'s classifier consults on a native `MissingState`.
///
/// The classifier READS a persisted held-signed row; this driver is what PERSISTS one, closing the
/// gap where a deposed compensated obligation always classified OPEN because nothing wrote the row.
///
/// The winner compensation record line is a TRANSFERRED object — the held node re-verifies it here
/// and never gains live winner-journal access. Trust rests on the same held-side authority the rest
/// of convergence uses: `winner_ledger_verifier_chirho` is the config-pinned journal verifier (the
/// SAME ledger trust root the winner fork witness uses — a compromised label cannot select it), the
/// adopted winner term comes from the verified sealed-plan proof, and the deterministic compensation
/// coordinate binds the record to one exact original effect. The obligation SUBJECT is derived from
/// the held root's own enumerated population — never from the transferred line — using the identical
/// coordinates `classify_gd7_convergence_terminal_outcomes_chirho` derives, so a transferred line
/// cannot forge which obligation it satisfies and the persisted row is exactly the one classify will
/// look up. Fail-closed: a line whose compensation coordinate matches no enumerated obligation, or
/// which fails re-verification (bad ledger signature, wrong winner term), persists nothing.
///
/// Returns the verified receipt digest (= the winner record's stored-line digest) the held-signed row
/// binds. Workflow: `spec-chirho/workstream-state-chirho/gd7-converged-import-mover-decision-chirho.md`.
#[allow(
    clippy::too_many_arguments,
    reason = "the population driver carries one fixed verified convergence bundle"
)]
pub(crate) fn import_converged_compensation_receipt_over_population_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    adopted_checkpoint_ref_chirho: &str,
    winner_compensation_record_line_chirho: &str,
) -> Result<String, Gd7PlanRefusalChirho> {
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        storage_chirho,
        held_signer_chirho,
        winner_ledger_verifier_chirho,
        effect_proof_ports_chirho,
        plan_checkpoint_chirho,
    )?;
    for obligation_chirho in &population_chirho {
        // The exact coordinates the classifier derives — so the persisted row's mint identity,
        // obligation digest, and winner term are the ones the classifier will look up.
        let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
            gd7_mint_identity_for_verified_obligation_chirho(
                adopted_checkpoint_ref_chirho,
                proof_chirho.checkpoint_ref_chirho(),
                proof_chirho.sealed_plan_ref_chirho(),
                proof_chirho.reconciliation_identity_digest_chirho(),
                proof_chirho.winner_term_chirho(),
                obligation_chirho,
            )
            .map_err(|_| Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho)?;
        let original_effect_key_chirho = format!(
            "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
            obligation_chirho.obligation_chirho().intent_ref_chirho.0
        );
        match import_verified_gd7_compensation_receipt_chirho(
            storage_chirho,
            held_signer_chirho,
            winner_ledger_verifier_chirho,
            &mint_identity_digest_chirho,
            &canonical_obligation_digest_chirho,
            &original_effect_key_chirho,
            proof_chirho.winner_term_chirho(),
            winner_compensation_record_line_chirho,
        ) {
            Ok(row_chirho) => return Ok(row_chirho.verified_receipt_digest_chirho().to_owned()),
            // The record's deterministic coordinate is for a DIFFERENT obligation (or it is not a
            // compensation hold at all): keep looking. A real forgery — a bad ledger signature or a
            // record under the wrong winner term — is NOT skipped; the mover checks the signature
            // before the coordinate, so it fails closed at the arm below.
            Err(Gd7ConvergedImportRefusalChirho::EffectKeyMismatchChirho)
            | Err(Gd7ConvergedImportRefusalChirho::NotCompensationHoldChirho) => continue,
            Err(_other_chirho) => return Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho),
        }
    }
    // No enumerated obligation is compensated by this transferred record — persist nothing.
    Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho)
}

/// Load and verify the held-signed import row for one obligation, if present.
///
/// Fail-closed: a malformed, non-canonical, oversized, or wrongly-signed row is refused rather than
/// treated as absent. A row filed under a different mint identity is `RowSubjectMismatchChirho`.
pub(crate) fn load_verified_gd7_converged_import_row_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    mint_identity_digest_chirho: &str,
) -> Result<Option<Gd7ConvergedImportRowChirho>, Gd7ConvergedImportRefusalChirho> {
    let path_chirho = gd7_converged_import_row_path_chirho(mint_identity_digest_chirho)?;
    read_verified_row_bytes_chirho(
        storage_chirho,
        &path_chirho,
        held_verifier_chirho,
        mint_identity_digest_chirho,
    )
}

/// The classifier entry point: the verified compensated receipt for a MISSING native row, if the
/// held-signed import row is present and binds this exact obligation subject and winner term.
///
/// `Ok(None)` means no import evidence exists → the obligation stays OPEN. A present-but-invalid or
/// wrong-subject row is a hard refusal so a tampered held root cannot silently certify.
pub(super) fn imported_compensated_receipt_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    mint_identity_digest_chirho: &str,
    canonical_obligation_digest_chirho: &str,
    winner_term_chirho: u64,
) -> Result<Option<String>, Gd7ConvergedImportRefusalChirho> {
    let Some(row_chirho) = load_verified_gd7_converged_import_row_chirho(
        storage_chirho,
        held_verifier_chirho,
        mint_identity_digest_chirho,
    )?
    else {
        return Ok(None);
    };
    // Subject binding mirrors the native row-subject check: the held-signed row must describe THIS
    // obligation (mint identity is bound at load; canonical obligation and winner term here) and it
    // must be a compensated terminal, or a misfiled/replayed row could satisfy the wrong obligation.
    if row_chirho.canonical_obligation_digest_chirho != canonical_obligation_digest_chirho
        || row_chirho.winner_term_chirho != winner_term_chirho
        || row_chirho.terminal_chirho != Gd7ConvergedImportTerminalChirho::CompensatedChirho
    {
        return Err(Gd7ConvergedImportRefusalChirho::SubjectMismatchChirho);
    }
    Ok(Some(row_chirho.verified_receipt_digest_chirho.clone()))
}

fn read_verified_row_bytes_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    expected_mint_identity_digest_chirho: &str,
) -> Result<Option<Gd7ConvergedImportRowChirho>, Gd7ConvergedImportRefusalChirho> {
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    let row_chirho = verify_row_bytes_chirho(
        &bytes_chirho,
        held_verifier_chirho,
        expected_mint_identity_digest_chirho,
    )?;
    Ok(Some(row_chirho))
}

fn verify_row_bytes_chirho(
    bytes_chirho: &[u8],
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    expected_mint_identity_digest_chirho: &str,
) -> Result<Gd7ConvergedImportRowChirho, Gd7ConvergedImportRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_CONVERGED_IMPORT_ROW_BYTES_CHIRHO {
        return Err(Gd7ConvergedImportRefusalChirho::OversizedRowChirho);
    }
    let row_chirho: Gd7ConvergedImportRowChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::MalformedRowChirho)?;
    if serialize_row_chirho(&row_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7ConvergedImportRefusalChirho::NonCanonicalRowChirho);
    }
    validate_row_shape_chirho(&row_chirho)?;
    if row_chirho.mint_identity_digest_chirho != expected_mint_identity_digest_chirho {
        return Err(Gd7ConvergedImportRefusalChirho::RowSubjectMismatchChirho);
    }
    if row_chirho.key_id_chirho != held_verifier_chirho.key_id_chirho() {
        return Err(Gd7ConvergedImportRefusalChirho::InvalidRowSignatureChirho);
    }
    let unsigned_bytes_chirho = row_chirho.canonical_unsigned_bytes_chirho()?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::SerializationChirho)?;
    if !held_verifier_chirho.verify_chirho(unsigned_line_chirho, &row_chirho.sig_chirho) {
        return Err(Gd7ConvergedImportRefusalChirho::InvalidRowSignatureChirho);
    }
    Ok(row_chirho)
}

fn sign_converged_import_row_chirho(
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    mint_identity_digest_chirho: &str,
    canonical_obligation_digest_chirho: &str,
    verified_receipt_digest_chirho: &str,
    winner_term_chirho: u64,
) -> Result<Gd7ConvergedImportRowChirho, Gd7ConvergedImportRefusalChirho> {
    let mut row_chirho = Gd7ConvergedImportRowChirho {
        schema_chirho: GD7_CONVERGED_IMPORT_ROW_SCHEMA_V1_CHIRHO.to_owned(),
        mint_identity_digest_chirho: mint_identity_digest_chirho.to_owned(),
        canonical_obligation_digest_chirho: canonical_obligation_digest_chirho.to_owned(),
        verified_receipt_digest_chirho: verified_receipt_digest_chirho.to_owned(),
        winner_term_chirho,
        terminal_chirho: Gd7ConvergedImportTerminalChirho::CompensatedChirho,
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_row_shape_chirho(&row_chirho)?;
    let unsigned_bytes_chirho = row_chirho.canonical_unsigned_bytes_chirho()?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::SerializationChirho)?;
    row_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7ConvergedImportRefusalChirho::SigningChirho)?;
    Ok(row_chirho)
}

fn validate_row_shape_chirho(
    row_chirho: &Gd7ConvergedImportRowChirho,
) -> Result<(), Gd7ConvergedImportRefusalChirho> {
    if row_chirho.schema_chirho != GD7_CONVERGED_IMPORT_ROW_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&row_chirho.mint_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&row_chirho.canonical_obligation_digest_chirho)
        || !is_lower_hex_digest_chirho(&row_chirho.verified_receipt_digest_chirho)
        || row_chirho.winner_term_chirho == 0
    {
        return Err(Gd7ConvergedImportRefusalChirho::MalformedRowChirho);
    }
    Ok(())
}

fn serialize_row_chirho(
    row_chirho: &Gd7ConvergedImportRowChirho,
) -> Result<Vec<u8>, Gd7ConvergedImportRefusalChirho> {
    serde_json::to_vec(row_chirho).map_err(|_| Gd7ConvergedImportRefusalChirho::SerializationChirho)
}

fn require_same_row_identity_chirho(
    actual_chirho: &Gd7ConvergedImportRowChirho,
    expected_chirho: &Gd7ConvergedImportRowChirho,
) -> Result<(), Gd7ConvergedImportRefusalChirho> {
    let mut actual_unsigned_chirho = actual_chirho.clone();
    actual_unsigned_chirho.sig_chirho.clear();
    let mut expected_unsigned_chirho = expected_chirho.clone();
    expected_unsigned_chirho.sig_chirho.clear();
    if actual_unsigned_chirho != expected_unsigned_chirho {
        return Err(Gd7ConvergedImportRefusalChirho::StateCollisionChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::FsLedgerStorageChirho;
    use cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO;
    use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, DigestChirho};
    use cairn_ledger_model_chirho::record_chirho::{
        AttributionChirho, EscrowControlChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho,
        LedgerRecordChirho, LegDeltaChirho, LegPostStateChirho,
    };
    use cairn_ledger_model_chirho::wire_chirho::LEDGER_RECORD_SCHEMA_V1_CHIRHO;
    use cairn_ledger_model_chirho::LogIdChirho;
    use cairn_writer_head_chirho::writer_head_chirho::compose_writer_epoch_chirho;
    use std::fs;
    use std::path::PathBuf;

    const MINT_CHIRHO: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OBLIGATION_CHIRHO: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const WINNER_TERM_CHIRHO: u64 = 2;

    fn original_effect_key_chirho(seed_chirho: char) -> String {
        format!(
            "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
            seed_chirho.to_string().repeat(64)
        )
    }

    struct TestHeldSignerChirho {
        key_id_chirho: String,
    }

    impl Gd7ReconciliationVerifierPortChirho for TestHeldSignerChirho {
        fn key_id_chirho(&self) -> String {
            self.key_id_chirho.clone()
        }
        fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
            sig_chirho == held_test_sig_chirho(canonical_unsigned_chirho)
        }
    }

    impl Gd7ReconciliationSignerPortChirho for TestHeldSignerChirho {
        fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
            Ok(held_test_sig_chirho(canonical_unsigned_chirho))
        }
    }

    fn held_test_sig_chirho(content_chirho: &str) -> String {
        format!(
            "held-sig-{}",
            blake3::hash(content_chirho.as_bytes()).to_hex()
        )
    }

    struct TestWinnerLedgerVerifierChirho {
        key_id_chirho: String,
    }

    impl TestWinnerLedgerVerifierChirho {
        fn sign_chirho(&self, content_chirho: &str) -> String {
            format!(
                "winner-ledger-sig-{}",
                blake3::hash(content_chirho.as_bytes()).to_hex()
            )
        }
    }

    impl Gd7LedgerRecordVerifierPortChirho for TestWinnerLedgerVerifierChirho {
        fn key_id_chirho(&self) -> String {
            self.key_id_chirho.clone()
        }
        fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
            sig_chirho == self.sign_chirho(signed_content_line_chirho)
        }
    }

    /// A winner ledger verifier whose signature scheme BINDS to its key id: a record signed by one
    /// winner's key does not verify under another's root. `TestWinnerLedgerVerifierChirho`'s scheme
    /// ignores the key id, which cannot exercise the winner-pinning the mover relies on — in
    /// production the config-pinned journal verifier authenticates a record only under the exact
    /// pinned key, and this double is what lets an arm prove the mover honours that binding.
    struct KeyBindingWinnerLedgerVerifierChirho {
        key_id_chirho: String,
    }

    impl KeyBindingWinnerLedgerVerifierChirho {
        fn sign_chirho(&self, content_chirho: &str) -> String {
            format!(
                "winner-ledger-sig-{}-{}",
                self.key_id_chirho,
                blake3::hash(content_chirho.as_bytes()).to_hex()
            )
        }
    }

    impl Gd7LedgerRecordVerifierPortChirho for KeyBindingWinnerLedgerVerifierChirho {
        fn key_id_chirho(&self) -> String {
            self.key_id_chirho.clone()
        }
        fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
            sig_chirho == self.sign_chirho(signed_content_line_chirho)
        }
    }

    /// A winner-signed compensation Hold record for `original_effect_key` under `winner_term`,
    /// canonically serialized, exactly as the winner journal would store it.
    fn signed_winner_compensation_record_line_chirho(
        winner_ledger_chirho: &TestWinnerLedgerVerifierChirho,
        original_effect_key_chirho: &str,
        winner_term_chirho: u64,
    ) -> String {
        signed_winner_compensation_line_chirho(
            &winner_ledger_chirho.key_id_chirho,
            &|content_chirho| winner_ledger_chirho.sign_chirho(content_chirho),
            original_effect_key_chirho,
            winner_term_chirho,
        )
    }

    /// A compensation Hold line signed by an arbitrary ledger key id + signature closure, so an arm
    /// can prove the mover binds to the INJECTED winner verifier's key rather than the record's
    /// self-declared label: a record signed by one key verifies only under that key's root.
    fn signed_winner_compensation_line_chirho(
        winner_ledger_key_id_chirho: &str,
        sign_chirho: &dyn Fn(&str) -> String,
        original_effect_key_chirho: &str,
        winner_term_chirho: u64,
    ) -> String {
        let compensation_key_chirho =
            effect_compensation_key_chirho(original_effect_key_chirho).expect("valid original key");
        let saga_id_chirho =
            parse_effect_compensation_key_chirho(&compensation_key_chirho).expect("parses");
        winner_record_line_chirho(
            winner_ledger_key_id_chirho,
            sign_chirho,
            LedgerOpChirho::EscrowHoldChirho {
                control_chirho: EscrowControlChirho {
                    saga_id_chirho,
                    step_chirho: 1,
                },
            },
            winner_term_chirho,
        )
    }

    fn winner_record_line_chirho(
        winner_ledger_key_id_chirho: &str,
        sign_chirho: &dyn Fn(&str) -> String,
        op_chirho: LedgerOpChirho,
        winner_term_chirho: u64,
    ) -> String {
        let epoch_chirho =
            compose_writer_epoch_chirho(winner_term_chirho, 0).expect("winner term composes");
        let mut record_chirho = LedgerRecordChirho {
            schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
            format_version_chirho: 1,
            seq_chirho: 7,
            prev_chirho: DigestChirho("aa".repeat(32)),
            epoch_chirho,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 1234,
                logical_chirho: 0,
            },
            legs_chirho: vec![LedgerLegChirho {
                account_chirho: LogIdChirho::new_chirho("payer-chirho", "money-chirho"),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    "policy-digest-chirho".into(),
                )),
                delta_chirho: LegDeltaChirho::HoldChirho,
                amount_chirho: 1,
                post_chirho: LegPostStateChirho {
                    credits_total_chirho: 0,
                    debits_total_chirho: 0,
                    held_chirho: 1,
                },
                counterpart_chirho: None,
            }],
            op_chirho,
            idempotency_key_chirho: "gd7-compensation-idem-chirho".to_owned(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::CauserChirho {
                principal_chirho: "payer-chirho".to_owned(),
            },
            anchor_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: winner_ledger_key_id_chirho.to_owned(),
        };
        let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho)
            .expect("signed content encodes");
        record_chirho.sig_chirho = sign_chirho(&signed_content_chirho);
        canonical_ledger_record_line_chirho(&record_chirho).expect("canonical record line")
    }

    fn temp_storage_chirho(label_chirho: &str) -> (PathBuf, FsLedgerStorageChirho) {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-converged-import-{}-{}-chirho",
            std::process::id(),
            label_chirho
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("temp storage");
        let storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&directory_chirho).expect("open storage");
        (directory_chirho, storage_chirho)
    }

    fn held_signer_chirho() -> TestHeldSignerChirho {
        TestHeldSignerChirho {
            key_id_chirho: "held-node-key-chirho".to_owned(),
        }
    }

    fn winner_ledger_chirho() -> TestWinnerLedgerVerifierChirho {
        TestWinnerLedgerVerifierChirho {
            key_id_chirho: "winner-journal-key-chirho".to_owned(),
        }
    }

    #[test]
    fn import_persists_a_held_signed_row_binding_the_exact_receipt_digest_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("roundtrip");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        let expected_digest_chirho = stored_line_digest_chirho(&line_chirho).0;

        let row_chirho = import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("a valid winner compensation receipt imports");

        // DIGEST-EXACT: the row binds the winner record's stored-line digest (= journal_receipt_ref).
        assert_eq!(
            row_chirho.verified_receipt_digest_chirho(),
            expected_digest_chirho
        );
        assert_eq!(row_chirho.winner_term_chirho, WINNER_TERM_CHIRHO);
        assert_eq!(
            row_chirho.terminal_chirho,
            Gd7ConvergedImportTerminalChirho::CompensatedChirho
        );

        // The classifier's consumption path returns the same receipt for the matching subject.
        assert_eq!(
            imported_compensated_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                WINNER_TERM_CHIRHO,
            )
            .expect("load succeeds"),
            Some(expected_digest_chirho)
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_forged_winner_ledger_signature_refuses_and_persists_nothing_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("forged-sig");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let mut line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        // Corrupt the signature token in place; the record stays canonical-shaped but unverifiable.
        line_chirho = line_chirho.replace("winner-ledger-sig-", "winner-ledger-sig-0");

        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &key_chirho,
                WINNER_TERM_CHIRHO,
                &line_chirho,
            )
            .expect_err("a forged winner signature must refuse"),
            Gd7ConvergedImportRefusalChirho::InvalidLedgerSignatureChirho
        );
        assert!(
            imported_compensated_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                WINNER_TERM_CHIRHO,
            )
            .expect("no row exists")
            .is_none(),
            "a refused import must persist no row"
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_sibling_receipt_for_a_different_effect_refuses_resolve_not_match_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("sibling");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        // A genuine, validly-signed winner receipt — but for a DIFFERENT original effect.
        let sibling_key_chirho = original_effect_key_chirho('b');
        let sibling_line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &sibling_key_chirho,
            WINNER_TERM_CHIRHO,
        );
        // Import it while claiming it satisfies obligation A (original effect 'a').
        let our_key_chirho = original_effect_key_chirho('a');
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &our_key_chirho,
                WINNER_TERM_CHIRHO,
                &sibling_line_chirho,
            )
            .expect_err("a receipt for a different obligation must not satisfy this one"),
            Gd7ConvergedImportRefusalChirho::EffectKeyMismatchChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_receipt_under_the_wrong_winner_term_refuses_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("wrong-term");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        // A valid receipt, but appended under winner term 3 while the adopted checkpoint names 2.
        let line_chirho =
            signed_winner_compensation_record_line_chirho(&winner_chirho, &key_chirho, 3);
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &key_chirho,
                WINNER_TERM_CHIRHO,
                &line_chirho,
            )
            .expect_err("a receipt under a different winner term must refuse"),
            Gd7ConvergedImportRefusalChirho::WrongWinnerTermChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_non_hold_record_refuses_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("non-hold");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        // A validly-signed winner record that is a plain transfer, not an escrow-hold.
        let line_chirho = winner_record_line_chirho(
            &winner_chirho.key_id_chirho,
            &|content_chirho| winner_chirho.sign_chirho(content_chirho),
            LedgerOpChirho::TransferChirho,
            WINNER_TERM_CHIRHO,
        );
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &key_chirho,
                WINNER_TERM_CHIRHO,
                &line_chirho,
            )
            .expect_err("a non-hold record is not a compensation receipt"),
            Gd7ConvergedImportRefusalChirho::NotCompensationHoldChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_non_canonical_record_line_refuses_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("non-canonical");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        // A trailing space makes the bytes differ from the canonical re-serialization.
        let padded_chirho = format!("{line_chirho} ");
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &key_chirho,
                WINNER_TERM_CHIRHO,
                &padded_chirho,
            )
            .expect_err("a non-canonical record line must refuse"),
            Gd7ConvergedImportRefusalChirho::NonCanonicalRecordChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_tampered_held_signature_on_the_row_refuses_at_load_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("row-tamper");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("import succeeds");

        // Overwrite the persisted row with one carrying a different bound receipt but the OLD sig.
        let path_chirho = gd7_converged_import_row_path_chirho(MINT_CHIRHO).unwrap();
        let bytes_chirho = storage_chirho
            .read_all_chirho(&path_chirho)
            .unwrap()
            .unwrap();
        let mut row_chirho: Gd7ConvergedImportRowChirho =
            serde_json::from_slice(&bytes_chirho).unwrap();
        row_chirho.verified_receipt_digest_chirho = "3".repeat(64);
        storage_chirho
            .atomic_write_chirho(&path_chirho, &serde_json::to_vec(&row_chirho).unwrap())
            .unwrap();

        assert_eq!(
            load_verified_gd7_converged_import_row_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO
            )
            .expect_err("a tampered held signature must refuse"),
            Gd7ConvergedImportRefusalChirho::InvalidRowSignatureChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_row_bound_to_a_different_subject_refuses_at_classify_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("subject");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("import succeeds");

        // A different canonical-obligation digest must not be satisfied by this row.
        assert_eq!(
            imported_compensated_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO,
                &"9".repeat(64),
                WINNER_TERM_CHIRHO,
            )
            .expect_err("a wrong obligation subject must refuse"),
            Gd7ConvergedImportRefusalChirho::SubjectMismatchChirho
        );
        // A different winner term must not be satisfied either.
        assert_eq!(
            imported_compensated_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                WINNER_TERM_CHIRHO + 1,
            )
            .expect_err("a wrong winner term must refuse"),
            Gd7ConvergedImportRefusalChirho::SubjectMismatchChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn reimport_is_idempotent_and_a_different_receipt_collides_chirho() {
        let (directory_chirho, storage_chirho) = temp_storage_chirho("idempotent");
        let held_chirho = held_signer_chirho();
        let winner_chirho = winner_ledger_chirho();
        let key_chirho = original_effect_key_chirho('a');
        let line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );
        let first_chirho = import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("first import");
        let second_chirho = import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("exact re-import is idempotent");
        assert_eq!(first_chirho, second_chirho);

        // A DIFFERENT valid receipt (different original effect => different saga => different bytes)
        // filed under the SAME mint identity must collide rather than silently rebind.
        let other_key_chirho = original_effect_key_chirho('c');
        let other_line_chirho = signed_winner_compensation_record_line_chirho(
            &winner_chirho,
            &other_key_chirho,
            WINNER_TERM_CHIRHO,
        );
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &other_key_chirho,
                WINNER_TERM_CHIRHO,
                &other_line_chirho,
            )
            .expect_err("a different receipt under the same mint must collide"),
            Gd7ConvergedImportRefusalChirho::StateCollisionChirho
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }

    #[test]
    fn a_winner_receipt_signed_by_a_different_key_refuses_at_import_chirho() {
        // Two winners whose signatures BIND to their key id: winner A's genuine receipt must verify
        // only under winner A's root. This is what the key-agnostic doubles above cannot exercise —
        // they verify any well-formed signature regardless of which winner produced it.
        let (directory_chirho, storage_chirho) = temp_storage_chirho("different-winner-key");
        let held_chirho = held_signer_chirho();
        let winner_a_chirho = KeyBindingWinnerLedgerVerifierChirho {
            key_id_chirho: "winner-a-journal-key-chirho".to_owned(),
        };
        let winner_b_chirho = KeyBindingWinnerLedgerVerifierChirho {
            key_id_chirho: "winner-b-journal-key-chirho".to_owned(),
        };
        let key_chirho = original_effect_key_chirho('a');
        // A genuine, validly-signed compensation receipt — signed by WINNER A's key.
        let line_chirho = signed_winner_compensation_line_chirho(
            &winner_a_chirho.key_id_chirho,
            &|content_chirho| winner_a_chirho.sign_chirho(content_chirho),
            &key_chirho,
            WINNER_TERM_CHIRHO,
        );

        // Verified against WINNER B's pinned root, A's receipt fails the ledger signature and
        // persists nothing: the mover binds to the injected verifier's key, not the record's label.
        assert_eq!(
            import_verified_gd7_compensation_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                &winner_b_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                &key_chirho,
                WINNER_TERM_CHIRHO,
                &line_chirho,
            )
            .expect_err("a receipt signed by a different winner key must refuse"),
            Gd7ConvergedImportRefusalChirho::InvalidLedgerSignatureChirho
        );
        assert!(
            imported_compensated_receipt_chirho(
                &storage_chirho,
                &held_chirho,
                MINT_CHIRHO,
                OBLIGATION_CHIRHO,
                WINNER_TERM_CHIRHO,
            )
            .expect("no row exists")
            .is_none(),
            "a cross-key refusal must persist no row"
        );

        // POSITIVE CONTROL: the SAME record verifies and imports under WINNER A's own root, so the
        // refusal above is the winner-key binding — not the record being malformed.
        let row_chirho = import_verified_gd7_compensation_receipt_chirho(
            &storage_chirho,
            &held_chirho,
            &winner_a_chirho,
            MINT_CHIRHO,
            OBLIGATION_CHIRHO,
            &key_chirho,
            WINNER_TERM_CHIRHO,
            &line_chirho,
        )
        .expect("a receipt verifies under its own winner's root");
        assert_eq!(
            row_chirho.verified_receipt_digest_chirho(),
            stored_line_digest_chirho(&line_chirho).0
        );
        fs::remove_dir_all(directory_chirho).expect("cleanup");
    }
}
