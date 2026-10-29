// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only whole-plan verification before any GD7 adoption authority exists.
//!
//! Convergence is certified over the population this module enumerates and classifies itself. The
//! only satisfying terminal outcome is a `CompletedChirho` processing row carrying its journal
//! receipt; **every `HeldManualChirho` is OPEN and blocks certification.** The ratified clause also
//! names a disposed-with-operator-reference terminal, but the durable R2/R3 schema carries no such
//! variant, so that branch is UNREACHABLE here and is deliberately unwritten — the split, and the
//! schema change it requires, belong to D3.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::conservation_chirho::{
    verify_gd7_conservation_snapshot_chirho, Gd7ConservationProofPortsChirho,
};
use super::contract_chirho::Gd7PlanRefusalChirho;
use super::converged_import_chirho::{
    imported_compensated_receipt_chirho, Gd7ConvergedImportRefusalChirho,
};
use super::obligation_mint_chirho::{
    gd7_mint_identity_for_verified_obligation_chirho, verified_gd7_sealed_plan_obligation_chirho,
    Gd7LosingEffectObligationSelectorChirho, VerifiedGd7SealedPlanObligationChirho,
};
use super::obligation_processing_chirho::{
    load_gd7_obligation_processing_state_chirho, Gd7ObligationProcessingRefusalChirho,
    Gd7ObligationTerminalProgressChirho,
};
use super::operator_roster_chirho::load_verified_gd7_operator_roster_chirho;
use super::reducer_chirho::{
    load_verified_gd7_reconciliation_plan_page_chirho, reverify_record_inputs_read_only_chirho,
    validate_sealed_plan_head_chirho, Gd7EffectProofPortsChirho,
};
use crate::reconciliation_chirho::contract_chirho::{
    is_lower_hex_digest_chirho, Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use crate::reconciliation_chirho::manifest_chirho::load_verified_gd7_losing_manifest_page_chirho;
use crate::reconciliation_chirho::store_chirho::{
    gd7_reconciliation_identity_digest_chirho, ActiveGd7ReconciliationChirho,
    Gd7ReconciliationStoreChirho,
};
use crate::reconciliation_chirho::winner_witness_chirho::AuthenticatedGd7DeposedForkObservationChirho;
use crate::reconciliation_chirho::Gd7ReconciliationCheckpointChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::wire_chirho::ledger_record_signed_content_line_chirho;

/// Opaque proof that one exact `PlanSealedChirho` checkpoint's complete linked plan and manifest
/// chains were re-evaluated against current signed effect evidence.
///
/// This is a prerequisite for later winner-held adoption. It is not compensation authority and
/// cannot move a ref, append a journal record, or re-enable a writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7SealedPlanProofChirho {
    reconciliation_identity_digest_chirho: String,
    checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    winner_fork_witness_object_digest_chirho: String,
    winner_term_chirho: u64,
    plan_page_count_chirho: u64,
    manifest_record_count_chirho: u64,
    effect_obligation_count_chirho: u64,
}

pub const GD7_CONVERGED_READ_REPLICA_SCHEMA_V1_CHIRHO: &str =
    "gd7-converged-read-replica-v1-chirho";
pub const GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO: &str =
    "gd7-converged-read-replica-v2-chirho";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConvergedReadReplicaChirho {
    schema_chirho: String,
    reconciliation_identity_digest_chirho: String,
    checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    winner_fork_witness_object_digest_chirho: String,
    winner_term_chirho: u64,
    adopted_checkpoint_ref_chirho: String,
    losing_population_identity_chirho: String,
    losing_population_digest_chirho: String,
    terminal_outcome_identity_chirho: String,
    terminal_outcome_digest_chirho: String,
    /// Digest of the signature-verified conservation snapshot the CF4 checker passed for this cut.
    conservation_snapshot_digest_chirho: String,
    retained_refs_chirho: Vec<String>,
    population_count_chirho: u64,
    #[serde(default)]
    completed_count_chirho: u64,
    #[serde(default)]
    disposed_count_chirho: u64,
    certificate_key_id_chirho: String,
    certificate_sig_chirho: String,
}

impl ConvergedReadReplicaChirho {
    pub fn schema_chirho(&self) -> &str {
        &self.schema_chirho
    }
    pub fn reconciliation_identity_digest_chirho(&self) -> &str {
        &self.reconciliation_identity_digest_chirho
    }
    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }
    pub fn sealed_plan_ref_chirho(&self) -> &str {
        &self.sealed_plan_ref_chirho
    }
    pub fn winner_fork_witness_object_digest_chirho(&self) -> &str {
        &self.winner_fork_witness_object_digest_chirho
    }
    pub fn winner_term_chirho(&self) -> u64 {
        self.winner_term_chirho
    }
    pub fn adopted_checkpoint_ref_chirho(&self) -> &str {
        &self.adopted_checkpoint_ref_chirho
    }
    pub fn losing_population_identity_chirho(&self) -> &str {
        &self.losing_population_identity_chirho
    }
    pub fn losing_population_digest_chirho(&self) -> &str {
        &self.losing_population_digest_chirho
    }
    pub fn terminal_outcome_identity_chirho(&self) -> &str {
        &self.terminal_outcome_identity_chirho
    }
    pub fn terminal_outcome_digest_chirho(&self) -> &str {
        &self.terminal_outcome_digest_chirho
    }
    pub fn conservation_snapshot_digest_chirho(&self) -> &str {
        &self.conservation_snapshot_digest_chirho
    }
    pub fn population_count_chirho(&self) -> u64 {
        self.population_count_chirho
    }
    pub fn retained_refs_chirho(&self) -> &[String] {
        &self.retained_refs_chirho
    }

    /// Authority consumers may use the separated outcome counts only from v2 certificates.
    /// Legacy v1 rows remain readable for display and migration, but their defaulted zeros are
    /// not measured evidence.
    pub fn verified_v2_counts_chirho(&self) -> Result<(u64, u64), Gd7PlanRefusalChirho> {
        if self.schema_chirho != GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO {
            return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
        }
        Ok((self.completed_count_chirho, self.disposed_count_chirho))
    }

    pub fn certificate_key_id_chirho(&self) -> &str {
        &self.certificate_key_id_chirho
    }

    pub fn certificate_sig_chirho(&self) -> &str {
        &self.certificate_sig_chirho
    }
}

fn canonical_converged_certificate_bytes_chirho(
    certificate_chirho: &ConvergedReadReplicaChirho,
) -> Result<Vec<u8>, Gd7PlanRefusalChirho> {
    serde_json::to_vec(certificate_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)
}

/// Re-verify a v2 certificate at the authority read boundary. Unsigned and legacy certificates
/// remain display-readable but cannot authorize D4.
pub fn verify_signed_gd7_converged_read_replica_chirho(
    certificate_chirho: &ConvergedReadReplicaChirho,
    verifier_chirho: &dyn crate::reconciliation_chirho::Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7PlanRefusalChirho> {
    if certificate_chirho.schema_chirho != GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    if certificate_chirho.certificate_key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    let mut unsigned_chirho = certificate_chirho.clone();
    unsigned_chirho.certificate_sig_chirho.clear();
    let bytes_chirho = canonical_converged_certificate_bytes_chirho(&unsigned_chirho)?;
    let line_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(line_chirho, &certificate_chirho.certificate_sig_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

pub fn load_verified_gd7_converged_read_replica_chirho(
    bytes_chirho: &[u8],
    verifier_chirho: &dyn crate::reconciliation_chirho::Gd7ReconciliationVerifierPortChirho,
) -> Result<ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    let certificate_chirho: ConvergedReadReplicaChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    let canonical_chirho = canonical_converged_certificate_bytes_chirho(&certificate_chirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(Gd7PlanRefusalChirho::SerializationChirho);
    }
    verify_signed_gd7_converged_read_replica_chirho(&certificate_chirho, verifier_chirho)?;
    Ok(certificate_chirho)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedGd7ConvergenceReleaseWitnessChirho {
    certificate_digest_chirho: String,
}

/// Terminal evidence MEASURED from the durable R2/R3 rows of an enumerated population.
///
/// Every field is produced by [`classify_gd7_convergence_terminal_outcomes_chirho`] from rows it
/// read. The fields are private and there is no public constructor, so a caller cannot hand the
/// converger an assertion about outcomes it did not measure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7ConvergenceTerminalEvidenceChirho {
    terminal_outcome_identity_chirho: String,
    terminal_outcome_digest_chirho: String,
    terminal_outcome_count_chirho: u64,
    completed_count_chirho: u64,
    disposed_count_chirho: u64,
    open_held_manual_count_chirho: u64,
    measured_population_count_chirho: u64,
    /// Mint identity of the first obligation classified OPEN, so a refusal can name one.
    first_open_mint_identity_chirho: Option<String>,
}

impl Gd7ConvergenceTerminalEvidenceChirho {
    pub fn terminal_outcome_count_chirho(&self) -> u64 {
        self.terminal_outcome_count_chirho
    }

    pub fn open_held_manual_count_chirho(&self) -> u64 {
        self.open_held_manual_count_chirho
    }

    pub fn measured_population_count_chirho(&self) -> u64 {
        self.measured_population_count_chirho
    }
    pub fn completed_count_chirho(&self) -> u64 {
        self.completed_count_chirho
    }
    pub fn disposed_count_chirho(&self) -> u64 {
        self.disposed_count_chirho
    }
}

/// The ONE clause-3 predicate this brick still does not measure, kept separate so it cannot be
/// mistaken for measured evidence.
///
/// The conservation fold LEFT this struct: it is now measured from a signature-verified snapshot
/// through the CF4 checker ([`super::conservation_chirho`]), and the certificate binds that
/// snapshot's digest. The local-winner-view comparison is still a caller assertion, and it stays
/// visibly asserted here rather than being folded into
/// [`Gd7ConvergenceTerminalEvidenceChirho`] — laundering it into a value whose type says "measured"
/// would be worse than naming it.
///
/// Why this one survived, measured rather than assumed: the winner-view evidence already exists,
/// in `current_view_chirho::adoption_chirho` — `VerifiedGd7HeldWinnerViewChainChirho` and its
/// fresh, elector-rechecked freshness evidence. So the work left is not deriving that view; it is
/// a SECOND port-shaped wiring exactly like the conservation one, binding that module's evidence
/// into the certificate. That is its own brick, and leaving the predicate visibly asserted is the
/// honest interim state — the adopted view is the cut, and the adoption module owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7ConvergenceUnmeasuredPredicatesChirho {
    pub winner_view_matches_chirho: bool,
}

/// The one coordinate the caller legitimately names: WHICH adopted cut is being certified.
///
/// The losing-population digests and retained refs USED to live here as caller-supplied strings that
/// `verify_gd7_convergence_chirho` only shape-checked before signing them into the certificate — and
/// `losing_population_digest_chirho` flowed on into the signed D4 write-restoration confirmation as
/// `closed_population_digest_chirho`. A signed field named `closed_population_digest` must carry a
/// MEASURED value, so those fields left the caller's hands: the converger now folds the population
/// digests over the obligations it itself enumerates ([`measure_gd7_losing_population_chirho`]) and
/// binds `retained_refs` from the verified sealed-plan proof. `adopted_checkpoint_ref_chirho` stays a
/// caller coordinate because it is self-validating — a wrong value derives mint identities that match
/// no row, so every obligation classifies OPEN and the certificate refuses (it can block convergence,
/// never manufacture one).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7ConvergenceBindingInputChirho {
    pub adopted_checkpoint_ref_chirho: String,
}

/// Classify every enumerated obligation against its durable R2/R3 processing row.
///
/// Exactly one progress value satisfies convergence: `CompletedChirho`. It is the only state the
/// R2/R3 machine locks — `mark_gd7_obligation_held_manual_chirho` refuses from it, while
/// `JournalRecordedChirho` can still become `HeldManualChirho`, so a recorded receipt is not yet a
/// terminal outcome.
///
/// **Every `HeldManualChirho` is OPEN and blocks certification.** The ratified clause names a
/// disposed-with-operator-reference terminal, but the durable schema carries no such variant: a
/// held obligation is held, full stop. The disposed branch is therefore UNREACHABLE here and is
/// deliberately not written — introducing the split is D3's, along with the schema change it needs.
/// A classifier that guessed the split would silently certify held work as disposed.
///
/// A missing row is OPEN, not absent: an obligation the plan names and processing never began is
/// exactly the unfinished case convergence exists to catch.
pub(super) fn classify_gd7_convergence_terminal_outcomes_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    adopted_checkpoint_ref_chirho: &str,
    population_chirho: &[VerifiedGd7SealedPlanObligationChirho],
    roster_context_chirho: Option<(
        &str,
        &dyn crate::reconciliation_chirho::Gd7ReconciliationVerifierPortChirho,
    )>,
) -> Result<Gd7ConvergenceTerminalEvidenceChirho, Gd7PlanRefusalChirho> {
    let mut identity_rows_chirho: Vec<String> = Vec::with_capacity(population_chirho.len());
    let mut outcome_rows_chirho: Vec<(String, &str, Option<String>)> =
        Vec::with_capacity(population_chirho.len());
    let mut terminal_outcome_count_chirho: u64 = 0;
    let mut open_count_chirho: u64 = 0;
    let mut completed_count_chirho: u64 = 0;
    let mut disposed_count_chirho: u64 = 0;
    let mut first_open_mint_identity_chirho: Option<String> = None;

    for obligation_chirho in population_chirho {
        let (mint_identity_digest_chirho, canonical_obligation_digest_chirho) =
            gd7_mint_identity_for_verified_obligation_chirho(
                adopted_checkpoint_ref_chirho,
                &proof_chirho.checkpoint_ref_chirho,
                &proof_chirho.sealed_plan_ref_chirho,
                &proof_chirho.reconciliation_identity_digest_chirho,
                proof_chirho.winner_term_chirho,
                obligation_chirho,
            )
            .map_err(|_| Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho)?;

        let state_chirho = match load_gd7_obligation_processing_state_chirho(
            storage_chirho,
            &mint_identity_digest_chirho,
        ) {
            Ok(state_chirho) => Some(state_chirho),
            Err(Gd7ObligationProcessingRefusalChirho::MissingStateChirho) => None,
            Err(_) => return Err(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho),
        };

        // Row-subject binding: a row filed under this mint identity must describe this exact
        // obligation. Without it a misfiled or replayed row could satisfy the wrong obligation.
        if let Some(state_chirho) = state_chirho.as_ref() {
            if state_chirho.mint_identity_digest_chirho() != mint_identity_digest_chirho
                || state_chirho.canonical_obligation_digest_chirho()
                    != canonical_obligation_digest_chirho
            {
                return Err(Gd7PlanRefusalChirho::ObligationStateSubjectMismatchChirho(
                    mint_identity_digest_chirho,
                ));
            }
        }

        let disposed_operator_chirho = state_chirho.as_ref().and_then(|state_chirho| {
            state_chirho
                .held_manual_disposition_chirho()
                .map(|disposition_chirho| disposition_chirho.operator_key_id_chirho().to_owned())
        });
        if let Some(state_row_chirho) = state_chirho.as_ref() {
            if state_row_chirho.terminal_progress_chirho()
                == Gd7ObligationTerminalProgressChirho::HeldManualChirho
            {
                if let Some(operator_key_id_chirho) = disposed_operator_chirho.as_deref() {
                    let (group_chirho, verifier_chirho) = roster_context_chirho
                        .ok_or(Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho)?;
                    load_verified_gd7_operator_roster_chirho(
                        storage_chirho,
                        group_chirho,
                        verifier_chirho,
                        operator_key_id_chirho,
                    )
                    .map_err(|error_chirho| {
                        Gd7PlanRefusalChirho::OperatorRosterRefusalChirho(error_chirho.to_string())
                    })?;
                }
            }
        }
        let native_compensated_receipt_chirho = state_chirho.as_ref().and_then(|state_chirho| {
            match state_chirho.terminal_progress_chirho() {
                Gd7ObligationTerminalProgressChirho::CompletedChirho => {
                    state_chirho.journal_receipt_ref_chirho().map(str::to_owned)
                }
                Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho
                | Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
                | Gd7ObligationTerminalProgressChirho::ProviderObservedChirho
                | Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
                | Gd7ObligationTerminalProgressChirho::HeldManualChirho => None,
            }
        });
        // Converged-read import path (Shape A'). Ruled (a) lands the compensated obligation row on
        // the WINNER root, so a native `MissingState` here is the deposed root's normal state for a
        // compensated obligation. On that miss ONLY, the held converger consults the held-signed
        // import row a prior mover persisted after re-verifying the winner's own signed compensation
        // receipt. A present-but-invalid held signature fails closed (`InvalidTerminalEvidence`); a
        // present row bound to a different obligation subject or winner term refuses like the native
        // row-subject mismatch; an ABSENT row leaves the obligation OPEN, unchanged from before this
        // brick. When no held verifier is available the import path is not consulted.
        //
        // Forbidden Shape E (trusting the winner's UNSIGNED processing row) is structurally impossible
        // here: this classifier reads only held-root native rows and the held-signed import row, never
        // the winner's row. Native held-root rows are trusted on local storage integrity (only the
        // local R2/R3 machine writes them), so a deposed-context "planted native Completed" is not
        // separately guarded — anyone who could plant one could forge the held-signed certificate
        // directly. That deposed-context native guard is an optional follow-up, not a gap this leaves.
        let compensated_receipt_chirho = match native_compensated_receipt_chirho {
            Some(receipt_chirho) => Some(receipt_chirho),
            None => match (state_chirho.is_none(), roster_context_chirho) {
                (true, Some((_group_chirho, held_verifier_chirho))) => {
                    imported_compensated_receipt_chirho(
                        storage_chirho,
                        held_verifier_chirho,
                        &mint_identity_digest_chirho,
                        &canonical_obligation_digest_chirho,
                        proof_chirho.winner_term_chirho,
                    )
                    .map_err(|error_chirho| match error_chirho {
                        Gd7ConvergedImportRefusalChirho::SubjectMismatchChirho => {
                            Gd7PlanRefusalChirho::ObligationStateSubjectMismatchChirho(
                                mint_identity_digest_chirho.clone(),
                            )
                        }
                        _ => Gd7PlanRefusalChirho::InvalidTerminalEvidenceChirho,
                    })?
                }
                _ => None,
            },
        };

        let disposed_chirho = disposed_operator_chirho.is_some();
        let outcome_label_chirho = if compensated_receipt_chirho.is_some() {
            completed_count_chirho = completed_count_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
            terminal_outcome_count_chirho = terminal_outcome_count_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
            "compensated-chirho"
        } else if disposed_chirho {
            disposed_count_chirho = disposed_count_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
            terminal_outcome_count_chirho = terminal_outcome_count_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
            "disposed-chirho"
        } else {
            open_count_chirho = open_count_chirho
                .checked_add(1)
                .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
            first_open_mint_identity_chirho
                .get_or_insert_with(|| mint_identity_digest_chirho.clone());
            "open-chirho"
        };
        identity_rows_chirho.push(mint_identity_digest_chirho.clone());
        outcome_rows_chirho.push((
            mint_identity_digest_chirho,
            outcome_label_chirho,
            compensated_receipt_chirho,
        ));
    }

    let measured_population_count_chirho = u64::try_from(population_chirho.len())
        .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
    Ok(Gd7ConvergenceTerminalEvidenceChirho {
        terminal_outcome_identity_chirho: canonical_digest_chirho(&identity_rows_chirho)?,
        terminal_outcome_digest_chirho: canonical_digest_chirho(&outcome_rows_chirho)?,
        terminal_outcome_count_chirho,
        completed_count_chirho,
        disposed_count_chirho,
        open_held_manual_count_chirho: open_count_chirho,
        measured_population_count_chirho,
        first_open_mint_identity_chirho,
    })
}

/// Hash a serializable value through JSON, whose escaping keeps the encoding injective for the
/// bounded free-form receipt references that appear in outcome rows.
fn canonical_digest_chirho<T: serde::Serialize>(
    value_chirho: &T,
) -> Result<String, Gd7PlanRefusalChirho> {
    let bytes_chirho =
        serde_json::to_vec(value_chirho).map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

/// The losing population, MEASURED from the obligations the converger itself enumerated.
///
/// `verify_gd7_convergence_chirho` once signed a caller-supplied `losing_population_digest` — only
/// shape-checked, never measured — into the certificate, whence it flowed into the signed D4
/// write-restoration confirmation as `closed_population_digest_chirho`. A signed field named
/// `closed_population_digest` must carry a measured value. Both digests here are folded over the exact
/// `population_chirho` the converger walks (no extra reads): `identity` over each obligation's
/// canonical content digest, `digest` over the full ordered population — page ref, page index,
/// obligation index, and content digest. Any change to a losing member moves both, so the certificate
/// can no longer echo a caller assertion about the population it closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gd7LosingPopulationMeasurementChirho {
    pub(crate) losing_population_identity_chirho: String,
    pub(crate) losing_population_digest_chirho: String,
}

pub(crate) fn measure_gd7_losing_population_chirho(
    population_chirho: &[VerifiedGd7SealedPlanObligationChirho],
) -> Result<Gd7LosingPopulationMeasurementChirho, Gd7PlanRefusalChirho> {
    let mut identity_rows_chirho: Vec<String> = Vec::with_capacity(population_chirho.len());
    let mut content_rows_chirho: Vec<(String, u64, u64, String)> =
        Vec::with_capacity(population_chirho.len());
    for obligation_chirho in population_chirho {
        // The obligation's OWN content identity — independent of the adopted coordinate, so this
        // measures the losing set itself rather than the outcome-and-adoption view the terminal
        // digests already carry.
        let canonical_obligation_digest_chirho =
            canonical_digest_chirho(obligation_chirho.obligation_chirho())?;
        content_rows_chirho.push((
            obligation_chirho.plan_page_ref_chirho().to_owned(),
            obligation_chirho.plan_page_index_chirho(),
            obligation_chirho.obligation_index_chirho(),
            canonical_obligation_digest_chirho.clone(),
        ));
        identity_rows_chirho.push(canonical_obligation_digest_chirho);
    }
    Ok(Gd7LosingPopulationMeasurementChirho {
        losing_population_identity_chirho: canonical_digest_chirho(&identity_rows_chirho)?,
        losing_population_digest_chirho: canonical_digest_chirho(&content_rows_chirho)?,
    })
}

/// Certify convergence over the population this function itself enumerates and classifies.
///
/// The caller supplies coordinates and the two unmeasured predicates; it does not supply outcomes.
/// A wrong `adopted_checkpoint_ref_chirho` derives mint identities that match no row, so every
/// obligation classifies OPEN and the certificate refuses — a bad coordinate can block convergence
/// but cannot manufacture one.
#[allow(
    clippy::too_many_arguments,
    reason = "the converger consumes each verification port directly rather than accepting a forgeable aggregate"
)]
pub fn verify_gd7_convergence_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    losing_record_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    conservation_ports_chirho: &Gd7ConservationProofPortsChirho<'_>,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    proof_chirho: &VerifiedGd7SealedPlanProofChirho,
    binding_chirho: Gd7ConvergenceBindingInputChirho,
    unmeasured_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
) -> Result<ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(&binding_chirho.adopted_checkpoint_ref_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    // Conservation is MEASURED, not asserted: the snapshot's signature is checked here and its
    // equations are checked by the single CF4 checker. A tampered-and-honestly-re-signed snapshot
    // still refuses, at the conservation law rather than at the signature.
    let conservation_chirho = verify_gd7_conservation_snapshot_chirho(conservation_ports_chirho)?;
    let population_chirho = enumerate_gd7_sealed_plan_obligations_chirho(
        storage_chirho,
        held_signer_chirho,
        losing_record_verifier_chirho,
        effect_proof_ports_chirho,
        plan_checkpoint_chirho,
    )?;
    // MEASURE the losing population from the obligations just enumerated — the caller no longer
    // supplies these digests. The measured `losing_population_digest_chirho` is what the certificate,
    // and then the signed D4 confirmation, binds as the closed population.
    let losing_population_chirho = measure_gd7_losing_population_chirho(&population_chirho)?;
    // BIND retained refs from the verified sealed-plan proof rather than a caller literal: these are
    // the content-addressed objects the converged cut retains — the adopted cut, its plan checkpoint,
    // the sealed-plan chain root, and the winner fork witness — each already content-address verified
    // by `proof_chirho`. Preferred over quarantine because the values are in scope AND verified; a
    // future consumer that defines `retained_refs` more narrowly retargets this one construction.
    let retained_refs_chirho = vec![
        binding_chirho.adopted_checkpoint_ref_chirho.clone(),
        proof_chirho.checkpoint_ref_chirho.clone(),
        proof_chirho.sealed_plan_ref_chirho.clone(),
        proof_chirho
            .winner_fork_witness_object_digest_chirho
            .clone(),
    ];
    let evidence_chirho = classify_gd7_convergence_terminal_outcomes_chirho(
        storage_chirho,
        proof_chirho,
        &binding_chirho.adopted_checkpoint_ref_chirho,
        &population_chirho,
        Some((
            &plan_checkpoint_chirho
                .identity_chirho
                .consistency_group_digest_chirho,
            held_signer_chirho,
        )),
    )?;
    // The population count is cross-checked against the signed proof rather than self-reported:
    // a walk that certified a subset would otherwise bind its own tally and be unfalsifiable.
    if evidence_chirho.measured_population_count_chirho
        != proof_chirho.effect_obligation_count_chirho
    {
        return Err(Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho);
    }
    if evidence_chirho.open_held_manual_count_chirho != 0 {
        return Err(Gd7PlanRefusalChirho::UnconvergedObligationChirho(
            evidence_chirho
                .first_open_mint_identity_chirho
                .unwrap_or_default(),
        ));
    }
    if proof_chirho.effect_obligation_count_chirho != evidence_chirho.terminal_outcome_count_chirho
        || evidence_chirho
            .completed_count_chirho
            .checked_add(evidence_chirho.disposed_count_chirho)
            != Some(evidence_chirho.measured_population_count_chirho)
        || !unmeasured_chirho.winner_view_matches_chirho
        || !is_lower_hex_digest_chirho(&evidence_chirho.terminal_outcome_identity_chirho)
        || !is_lower_hex_digest_chirho(&evidence_chirho.terminal_outcome_digest_chirho)
        || !is_lower_hex_digest_chirho(&losing_population_chirho.losing_population_identity_chirho)
        || !is_lower_hex_digest_chirho(&losing_population_chirho.losing_population_digest_chirho)
        || retained_refs_chirho.is_empty()
        || retained_refs_chirho
            .iter()
            .any(|reference_chirho| !is_lower_hex_digest_chirho(reference_chirho))
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    let certificate_chirho = ConvergedReadReplicaChirho {
        schema_chirho: GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: proof_chirho
            .reconciliation_identity_digest_chirho
            .clone(),
        checkpoint_ref_chirho: proof_chirho.checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho: proof_chirho.sealed_plan_ref_chirho.clone(),
        winner_fork_witness_object_digest_chirho: proof_chirho
            .winner_fork_witness_object_digest_chirho
            .clone(),
        winner_term_chirho: proof_chirho.winner_term_chirho,
        adopted_checkpoint_ref_chirho: binding_chirho.adopted_checkpoint_ref_chirho,
        losing_population_identity_chirho: losing_population_chirho
            .losing_population_identity_chirho,
        losing_population_digest_chirho: losing_population_chirho.losing_population_digest_chirho,
        terminal_outcome_identity_chirho: evidence_chirho.terminal_outcome_identity_chirho,
        terminal_outcome_digest_chirho: evidence_chirho.terminal_outcome_digest_chirho,
        conservation_snapshot_digest_chirho: conservation_chirho
            .snapshot_digest_chirho()
            .to_owned(),
        retained_refs_chirho,
        population_count_chirho: proof_chirho.effect_obligation_count_chirho,
        completed_count_chirho: evidence_chirho.completed_count_chirho,
        disposed_count_chirho: evidence_chirho.disposed_count_chirho,
        certificate_key_id_chirho: held_signer_chirho.key_id_chirho(),
        certificate_sig_chirho: String::new(),
    };
    let signing_bytes_chirho = canonical_converged_certificate_bytes_chirho(&certificate_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    let mut certificate_chirho = certificate_chirho;
    certificate_chirho.certificate_sig_chirho = held_signer_chirho
        .sign_chirho(signing_line_chirho)
        .map_err(|_| Gd7PlanRefusalChirho::SerializationChirho)?;
    Ok(certificate_chirho)
}

// The barrier-release brick (`release_converged_reconciliation_hold_chirho`) already binds the
// certificate it receives by adopted-checkpoint identity; consuming THIS digest witness as the
// release authorization would add certificate-signature verification to that separate money-authority
// brick, a reviewed change out of the converged-import mover's scope. Kept (guard-pinned to one
// construction) as the honest seam for that future binding rather than wired with a discard-only call.
#[allow(
    dead_code,
    reason = "certificate-digest witness for a future reviewed release-authorization binding in the barrier-release brick"
)]
fn release_witness_for_converged_replica_chirho(
    certificate_chirho: &ConvergedReadReplicaChirho,
) -> VerifiedGd7ConvergenceReleaseWitnessChirho {
    let bytes_chirho = serde_json::to_vec(certificate_chirho)
        .expect("convergence certificate has a bounded serializable shape");
    VerifiedGd7ConvergenceReleaseWitnessChirho {
        certificate_digest_chirho: blake3::hash(&bytes_chirho).to_hex().to_string(),
    }
}

impl VerifiedGd7SealedPlanProofChirho {
    pub fn reconciliation_identity_digest_chirho(&self) -> &str {
        &self.reconciliation_identity_digest_chirho
    }

    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }

    pub fn sealed_plan_ref_chirho(&self) -> &str {
        &self.sealed_plan_ref_chirho
    }

    pub fn winner_fork_witness_object_digest_chirho(&self) -> &str {
        &self.winner_fork_witness_object_digest_chirho
    }

    pub fn winner_term_chirho(&self) -> u64 {
        self.winner_term_chirho
    }

    pub fn plan_page_count_chirho(&self) -> u64 {
        self.plan_page_count_chirho
    }

    pub fn manifest_record_count_chirho(&self) -> u64 {
        self.manifest_record_count_chirho
    }

    pub fn effect_obligation_count_chirho(&self) -> u64 {
        self.effect_obligation_count_chirho
    }
}

/// Verify the complete linked plan and manifest chains named by one exact ACTIVE checkpoint, at
/// either lawful phase — `PlanSealedChirho` before adoption or `AdoptedHeldChirho` after it.
///
/// The proof is about ONE checkpoint's plan chain, not about where the reconciliation has since
/// travelled; the sealed-only wording this carried was fixture lineage rather than the authority
/// contract, and it made nonzero convergence structurally unreachable (see the phase gate's own
/// comment). The checkpoint must still be the ACTIVE one — a stale ref refuses.
///
/// Work is O(plan pages + manifest records), memory is O(page), and the loop is bounded by the
/// signed checkpoint's exact page count. Every page is content-address verified, every manifest
/// record is reclassified against current signed effect evidence, and terminal markers are loaded
/// read-only. The returned proof cannot authorize compensation, move a ref, or re-enable writes.
pub(crate) fn verify_sealed_gd7_reconciliation_plan_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    losing_record_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    expected_checkpoint_ref_chirho: &str,
) -> Result<VerifiedGd7SealedPlanProofChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(expected_checkpoint_ref_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    let identity_chirho = observation_chirho.identity_chirho();
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        storage_chirho,
        held_signer_chirho,
        identity_chirho.clone(),
        observation_chirho
            .winner_fork_witness_chirho()
            .object_digest_chirho()
            .to_owned(),
    )?;
    let active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(Gd7PlanRefusalChirho::NoActiveReconciliationChirho)?;
    if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho {
        return Err(Gd7PlanRefusalChirho::StaleCheckpointChirho);
    }
    // BOTH LAWFUL PHASES, and the second one is a fix rather than a widening.
    //
    // This gate admitted `PlanSealedChirho` alone, and that made NONZERO convergence unreachable:
    // a nonzero population needs minted obligations, the mint requires an active reconciliation in
    // `AdoptedHeldChirho`, and one active record carries one phase. So a sealed-only converger could
    // only ever certify ZERO-obligation worlds — which is exactly what every fixture predating the
    // success ladder was, and why the limitation never surfaced. The gate encoded the only phase its
    // test world had ever held.
    //
    // The contract it belongs to says adopted plainly: the certificate this proof feeds binds
    // `adopted_checkpoint_ref_chirho`, and the convergence verifier derives every mint identity from
    // that binding before classifying rows. A converger that names an adopted cut while refusing the
    // adopted phase contradicts its own output type. D3 requires verified adoption AND convergence
    // together, which is only satisfiable if convergence is evaluable in an adopted world.
    //
    // NOTHING ELSE MOVES. The staleness check above still requires the caller to name the ACTIVE
    // checkpoint, and every signature, identity, manifest, population, and terminal-row check below
    // runs unchanged. Zero-obligation certification stays lawful at either phase. Admitting the
    // phase does NOT imply an obligation may be minted before adoption: that remains the mint's own
    // gate, and this proof still refuses a plan whose required obligation evidence is absent.
    // THE TWO-COORDINATE CONTRACT (ruled), stated where a reader meets it:
    //
    //   S — the SEALED plan checkpoint — drives obligation population and mint-identity derivation.
    //   A — the ACTIVE adopted cut — is the certificate's `adopted_checkpoint_ref` coordinate.
    //   S is resolved from the ACTOR-VERIFIED adoption binding's retained `plan_checkpoint_ref`,
    //     NEVER from caller input — so no-forged-subject is preserved BY CONSTRUCTION.
    //   A must authenticate its predecessor: `A.previous_checkpoint_ref == S`, checked before use.
    //   The plan proof is taken at S through the ref-only content-addressed authenticated loader.
    //
    // RESOLVE THE PLAN CHECKPOINT, which after adoption is NOT the active one.
    //
    // Admitting the adopted phase is necessary but NOT sufficient, and the second half is why: the
    // mint binds an obligation's identity to `plan_checkpoint_ref = the adopted snapshot's PLAN
    // checkpoint` (adoption_commit_actor_chirho.rs:414), while the convergence classifier derives
    // that same coordinate from `proof.checkpoint_ref`. If the proof is taken at the ACTIVE
    // checkpoint, then after adoption those are two different checkpoints and the classifier derives
    // an identity no mint ever produced — so it finds no row, classifies OPEN, and refuses
    // `UnconvergedObligation` for a digest that cannot ever have one. Measured, not reasoned: with
    // the phase admitted and the proof still taken at the active checkpoint, the oracle refuses
    // naming a digest that differs from its own mint receipt's.
    //
    // So the plan proof is taken WHERE THE PLAN LIVES. At `PlanSealedChirho` that is the active
    // checkpoint itself. At `AdoptedHeldChirho` it is the checkpoint the adoption's OWN SIGNED
    // BINDING names — not a caller-supplied ref, so this widens no authority: the coordinate comes
    // from inside the authenticated active checkpoint.
    //
    // STALENESS IS UNCHANGED AND STILL BINDS THE ACTIVE RECORD: the caller must still name the
    // active checkpoint above, and the end-of-function re-read still compares against `active_chirho`
    // so a reconciliation that moves mid-verification is still refused.
    let plan_active_chirho = match active_chirho.checkpoint_chirho.state_chirho.phase_chirho {
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => active_chirho.clone(),
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            let binding_chirho = active_chirho
                .checkpoint_chirho
                .state_chirho
                .adoption_binding_chirho
                .as_ref()
                .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
            let plan_checkpoint_ref_chirho = binding_chirho.plan_checkpoint_ref_chirho.clone();
            let plan_checkpoint_chirho =
                crate::reconciliation_chirho::load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
                    storage_chirho,
                    held_signer_chirho,
                    &plan_checkpoint_ref_chirho,
                )
                .map_err(|_error_chirho| Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
            // A MUST AUTHENTICATE ITS PREDECESSOR. The adopted cut names the sealed cut it was
            // adopted FROM, and that relation is checked BEFORE the plan proof is taken from it.
            // Without this, `adoption_binding.plan_checkpoint_ref` would be a pointer the adopted
            // checkpoint merely carries; with it, the chain A -> S is the signed checkpoint's own
            // statement about its own history, so a binding that names some other reconciliation's
            // sealed cut cannot be followed.
            if active_chirho
                .checkpoint_chirho
                .state_chirho
                .previous_checkpoint_ref_chirho
                .as_deref()
                != Some(plan_checkpoint_ref_chirho.as_str())
            {
                return Err(Gd7PlanRefusalChirho::StaleCheckpointChirho);
            }
            // FAIL CLOSED ON BOTH: the adopted cut may only reach back to a checkpoint that is
            // genuinely sealed and genuinely this reconciliation's. Neither is implied by the load.
            if plan_checkpoint_chirho.state_chirho.phase_chirho
                != Gd7ReconciliationPhaseChirho::PlanSealedChirho
            {
                return Err(Gd7PlanRefusalChirho::InvalidPhaseChirho);
            }
            if plan_checkpoint_chirho.identity_chirho != *identity_chirho {
                return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
            }
            ActiveGd7ReconciliationChirho {
                checkpoint_ref_chirho: plan_checkpoint_ref_chirho,
                checkpoint_chirho: plan_checkpoint_chirho,
            }
        }
        _ => return Err(Gd7PlanRefusalChirho::InvalidPhaseChirho),
    };
    validate_sealed_plan_head_chirho(storage_chirho, identity_chirho, &plan_active_chirho)?;

    let state_chirho = &plan_active_chirho.checkpoint_chirho.state_chirho;
    let sealed_plan_ref_chirho = state_chirho
        .sealed_plan_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?
        .to_owned();
    let manifest_head_ref_chirho = state_chirho
        .manifest_head_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?
        .to_owned();
    let plan_page_count_chirho = state_chirho.plan_page_count_chirho;
    let manifest_record_count_chirho = state_chirho.manifest_record_count_chirho;
    let effect_obligation_count_chirho = state_chirho.effect_obligation_count_chirho;
    let (_selected_obligation_chirho, _enumerated_obligations_chirho) = verify_linked_plan_chirho(
        storage_chirho,
        held_signer_chirho,
        losing_record_verifier_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        &sealed_plan_ref_chirho,
        &manifest_head_ref_chirho,
        plan_page_count_chirho,
        manifest_record_count_chirho,
        effect_obligation_count_chirho,
        None,
    )?;
    let reloaded_active_chirho = store_chirho
        .load_active_chirho()?
        .ok_or(Gd7PlanRefusalChirho::NoActiveReconciliationChirho)?;
    if reloaded_active_chirho != active_chirho {
        return Err(Gd7PlanRefusalChirho::StaleCheckpointChirho);
    }

    Ok(VerifiedGd7SealedPlanProofChirho {
        reconciliation_identity_digest_chirho: gd7_reconciliation_identity_digest_chirho(
            identity_chirho,
        )?,
        // THE PLAN's ref, not the active one -- this is the coordinate the convergence classifier
        // feeds to the mint-identity derivation, and it must be the same cut the mint bound.
        checkpoint_ref_chirho: plan_active_chirho.checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho,
        winner_fork_witness_object_digest_chirho: active_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        winner_term_chirho: identity_chirho.winner_term_chirho,
        plan_page_count_chirho,
        manifest_record_count_chirho,
        effect_obligation_count_chirho,
    })
}

/// Reverify one exact immutable `PlanSealedChirho` checkpoint and retain only the selected
/// obligation after its page is proven inside the complete linked plan.
pub(crate) fn verify_gd7_sealed_plan_obligation_at_checkpoint_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    losing_record_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    plan_checkpoint_ref_chirho: &str,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    selector_chirho: &Gd7LosingEffectObligationSelectorChirho,
) -> Result<VerifiedGd7SealedPlanObligationChirho, Gd7PlanRefusalChirho> {
    if !is_lower_hex_digest_chirho(plan_checkpoint_ref_chirho) {
        return Err(Gd7PlanRefusalChirho::InvalidReferenceChirho);
    }
    if plan_checkpoint_chirho.state_chirho.phase_chirho
        != Gd7ReconciliationPhaseChirho::PlanSealedChirho
    {
        return Err(Gd7PlanRefusalChirho::InvalidPhaseChirho);
    }
    let identity_chirho = &plan_checkpoint_chirho.identity_chirho;
    let point_loaded_chirho = ActiveGd7ReconciliationChirho {
        checkpoint_ref_chirho: plan_checkpoint_ref_chirho.to_owned(),
        checkpoint_chirho: plan_checkpoint_chirho.clone(),
    };
    validate_sealed_plan_head_chirho(storage_chirho, identity_chirho, &point_loaded_chirho)?;
    let state_chirho = &plan_checkpoint_chirho.state_chirho;
    let sealed_plan_ref_chirho = state_chirho
        .sealed_plan_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    let manifest_head_ref_chirho = state_chirho
        .manifest_head_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    verify_linked_plan_chirho(
        storage_chirho,
        held_signer_chirho,
        losing_record_verifier_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        sealed_plan_ref_chirho,
        manifest_head_ref_chirho,
        state_chirho.plan_page_count_chirho,
        state_chirho.manifest_record_count_chirho,
        state_chirho.effect_obligation_count_chirho,
        Some(selector_chirho),
    )?
    .0
    .ok_or(Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho)
}

/// Enumerate the complete obligation population by walking the signed manifest chain.
///
/// This is deliberately separate from a count: callers receive each verified identity, so a
/// head-only traversal cannot satisfy the certificate merely by matching a chain-wide count.
/// VERIFIER ONLY, and this is the capability boundary the whole narrowing exists for.
///
/// This is the entry point a RESTORE PATH walks to learn a reconciliation's obligation population.
/// While it demanded a signer, any caller — including a winner re-opening under an active handoff —
/// had to hold a signing key to run an enumeration that never signs THROUGH THE CAPABILITY IT WAS
/// GIVEN. Scope that precisely: the parameter type excludes signing through the SUPPLIED closure, and
/// says nothing about a reachable function opening or constructing a signer internally. The guard
/// named in this module's tests is what covers that second door. That is authority
/// conferred by a TYPE rather than by a use, which is the one thing this engine's capability model
/// exists to forbid.
pub(crate) fn enumerate_gd7_sealed_plan_obligations_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    losing_record_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
) -> Result<Vec<VerifiedGd7SealedPlanObligationChirho>, Gd7PlanRefusalChirho> {
    let state_chirho = &plan_checkpoint_chirho.state_chirho;
    let identity_chirho = &plan_checkpoint_chirho.identity_chirho;
    let sealed_plan_ref_chirho = state_chirho
        .sealed_plan_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    let manifest_head_ref_chirho = state_chirho
        .manifest_head_ref_chirho
        .as_deref()
        .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
    Ok(verify_linked_plan_chirho(
        storage_chirho,
        held_verifier_chirho,
        losing_record_verifier_chirho,
        effect_proof_ports_chirho,
        identity_chirho,
        sealed_plan_ref_chirho,
        manifest_head_ref_chirho,
        state_chirho.plan_page_count_chirho,
        state_chirho.manifest_record_count_chirho,
        state_chirho.effect_obligation_count_chirho,
        None,
    )?
    .1)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the verifier binds every signed checkpoint count without assembling a second state object"
)]
/// VERIFIER ONLY — it verifies a linked plan, which is the whole of its job. Its three callers keep
/// whatever authority they legitimately hold; none of it is needed here.
fn verify_linked_plan_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    losing_record_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
    effect_proof_ports_chirho: &Gd7EffectProofPortsChirho<'_>,
    identity_chirho: &crate::reconciliation_chirho::Gd7ReconciliationIdentityChirho,
    sealed_plan_ref_chirho: &str,
    manifest_head_ref_chirho: &str,
    page_count_chirho: u64,
    manifest_record_count_chirho: u64,
    effect_obligation_count_chirho: u64,
    selector_chirho: Option<&Gd7LosingEffectObligationSelectorChirho>,
) -> Result<
    (
        Option<VerifiedGd7SealedPlanObligationChirho>,
        Vec<VerifiedGd7SealedPlanObligationChirho>,
    ),
    Gd7PlanRefusalChirho,
> {
    if page_count_chirho == 0 {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(identity_chirho)?;
    let mut remaining_page_count_chirho = page_count_chirho;
    let mut remaining_record_count_chirho = manifest_record_count_chirho;
    let mut remaining_obligation_count_chirho = effect_obligation_count_chirho;
    let mut current_plan_ref_chirho = Some(sealed_plan_ref_chirho.to_owned());
    let mut current_manifest_ref_chirho = Some(manifest_head_ref_chirho.to_owned());
    let mut prior_older_boundary_chirho: Option<(u64, String)> = None;
    let mut selected_obligation_chirho = None;
    let mut enumerated_obligations_chirho = Vec::new();

    while remaining_page_count_chirho > 0 {
        let expected_page_index_chirho = remaining_page_count_chirho
            .checked_sub(1)
            .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
        let plan_ref_chirho = current_plan_ref_chirho
            .as_deref()
            .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
        let expected_manifest_ref_chirho = current_manifest_ref_chirho
            .as_deref()
            .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
        let plan_page_chirho = load_verified_gd7_reconciliation_plan_page_chirho(
            storage_chirho,
            plan_ref_chirho,
            identity_chirho,
        )?;
        let manifest_page_chirho = load_verified_gd7_losing_manifest_page_chirho(
            storage_chirho,
            plan_page_chirho.page_chirho().manifest_page_ref_chirho(),
            identity_chirho,
        )?;
        let page_chirho = plan_page_chirho.page_chirho();
        let manifest_chirho = manifest_page_chirho.page_chirho();
        let local_record_count_chirho =
            u64::try_from(manifest_chirho.records_newest_first_chirho().len())
                .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
        let local_obligation_count_chirho =
            u64::try_from(page_chirho.obligations_newest_first_chirho().len())
                .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?;
        let expected_anchor_chirho =
            expected_page_index_chirho.checked_add(1) == Some(page_count_chirho);
        if page_chirho.page_index_chirho() != expected_page_index_chirho
            || manifest_chirho.page_index_chirho() != expected_page_index_chirho
            || page_chirho.manifest_page_ref_chirho() != expected_manifest_ref_chirho
            || manifest_page_chirho.object_digest_chirho() != expected_manifest_ref_chirho
            || page_chirho.reached_anchor_chirho() != expected_anchor_chirho
            || manifest_chirho.reached_anchor_chirho() != expected_anchor_chirho
            || page_chirho.manifest_record_count_chirho != local_record_count_chirho
        {
            return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
        }
        // Per-step cumulative invariant. Each page carries the chain-wide totals as of itself, so
        // a divergence is detected AT the page that introduced it and refuses naming that page,
        // rather than surfacing later as a mismatched grand total with no location.
        if page_chirho.cumulative_manifest_page_count_chirho != remaining_page_count_chirho
            || page_chirho.cumulative_manifest_record_count_chirho != remaining_record_count_chirho
            || page_chirho.cumulative_effect_obligation_count_chirho
                != remaining_obligation_count_chirho
        {
            return Err(Gd7PlanRefusalChirho::CumulativeDivergenceAtPlanPageChirho(
                plan_ref_chirho.to_owned(),
            ));
        }

        if let Some((older_seq_chirho, older_digest_chirho)) = prior_older_boundary_chirho.as_ref()
        {
            let newer_boundary_chirho = manifest_chirho
                .records_newest_first_chirho()
                .last()
                .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
            if newer_boundary_chirho.record_chirho().seq_chirho
                != older_seq_chirho
                    .checked_add(1)
                    .ok_or(Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?
                || newer_boundary_chirho.record_chirho().prev_chirho.0.as_str()
                    != older_digest_chirho.as_str()
            {
                return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
            }
        }
        let older_boundary_chirho = manifest_chirho
            .records_newest_first_chirho()
            .first()
            .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
        prior_older_boundary_chirho = Some((
            older_boundary_chirho.record_chirho().seq_chirho,
            older_boundary_chirho.record_digest_chirho().to_owned(),
        ));

        for record_chirho in manifest_chirho.records_newest_first_chirho() {
            let signed_content_chirho =
                ledger_record_signed_content_line_chirho(record_chirho.record_chirho())
                    .map_err(|_| Gd7PlanRefusalChirho::InvalidLosingRecordEncodingChirho)?;
            if !losing_record_verifier_chirho.verify_chirho(
                &signed_content_chirho,
                &record_chirho.record_chirho().sig_chirho,
            ) {
                return Err(Gd7PlanRefusalChirho::InvalidLosingRecordSignatureChirho);
            }
        }
        let reduced_chirho = reverify_record_inputs_read_only_chirho(
            storage_chirho,
            held_verifier_chirho,
            effect_proof_ports_chirho,
            identity_chirho,
            &identity_digest_chirho,
            manifest_chirho
                .records_newest_first_chirho()
                .iter()
                .map(|record_chirho| {
                    (
                        record_chirho.record_digest_chirho(),
                        record_chirho.record_chirho(),
                    )
                }),
        )?;
        if reduced_chirho.fact_counts_chirho != page_chirho.local_fact_counts_chirho
            || reduced_chirho.obligations_newest_first_chirho
                != page_chirho.obligations_newest_first_chirho
            || reduced_chirho.terminal_marker_object_digests_newest_first_chirho
                != page_chirho.terminal_marker_object_digests_newest_first_chirho
        {
            return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
        }
        if selector_chirho
            .is_some_and(|selector_chirho| selector_chirho.plan_page_ref_chirho == plan_ref_chirho)
        {
            let selector_chirho = selector_chirho.expect("selector checked above");
            let obligation_index_chirho = usize::try_from(selector_chirho.obligation_index_chirho)
                .map_err(|_| Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho)?;
            let obligation_chirho = page_chirho
                .obligations_newest_first_chirho()
                .get(obligation_index_chirho)
                .cloned()
                .ok_or(Gd7PlanRefusalChirho::ObligationNotInSealedPlanChirho)?;
            if selected_obligation_chirho.is_some() {
                return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
            }
            selected_obligation_chirho = Some(verified_gd7_sealed_plan_obligation_chirho(
                plan_ref_chirho.to_owned(),
                page_chirho.page_index_chirho(),
                selector_chirho.obligation_index_chirho,
                obligation_chirho,
            ));
        }
        for (obligation_index_chirho, obligation_chirho) in page_chirho
            .obligations_newest_first_chirho()
            .iter()
            .cloned()
            .enumerate()
        {
            enumerated_obligations_chirho.push(verified_gd7_sealed_plan_obligation_chirho(
                plan_ref_chirho.to_owned(),
                page_chirho.page_index_chirho(),
                u64::try_from(obligation_index_chirho)
                    .map_err(|_| Gd7PlanRefusalChirho::ArithmeticOverflowChirho)?,
                obligation_chirho,
            ));
        }

        remaining_page_count_chirho = expected_page_index_chirho;
        remaining_record_count_chirho = remaining_record_count_chirho
            .checked_sub(local_record_count_chirho)
            .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
        remaining_obligation_count_chirho = remaining_obligation_count_chirho
            .checked_sub(local_obligation_count_chirho)
            .ok_or(Gd7PlanRefusalChirho::InvalidPageShapeChirho)?;
        current_plan_ref_chirho = page_chirho.newer_plan_page_ref_chirho.clone();
        current_manifest_ref_chirho = manifest_chirho
            .newer_manifest_page_ref_chirho()
            .map(str::to_owned);
    }

    if current_plan_ref_chirho.is_some()
        || current_manifest_ref_chirho.is_some()
        || remaining_record_count_chirho != 0
        || remaining_obligation_count_chirho != 0
    {
        return Err(Gd7PlanRefusalChirho::InvalidPageShapeChirho);
    }
    Ok((selected_obligation_chirho, enumerated_obligations_chirho))
}

/// Exercise the private release witness from a sibling test without widening its production
/// surface: the witness fn and its field stay private, and the guard scans production text only.
#[cfg(test)]
pub(crate) fn release_witness_digest_for_test_chirho(
    certificate_chirho: &ConvergedReadReplicaChirho,
) -> String {
    release_witness_for_converged_replica_chirho(certificate_chirho).certificate_digest_chirho
}

/// Build the signed-proof coordinates for a convergence arm.
///
/// Proof *construction* is proven upstream by `verify_sealed_gd7_reconciliation_plan_chirho`'s own
/// tests. What the convergence arms must prove is that the converger consumes a real enumerated
/// population and real durable rows, so they supply the proof's coordinates and exercise everything
/// downstream against a genuine two-page chain.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn sealed_plan_proof_for_convergence_test_chirho(
    reconciliation_identity_digest_chirho: String,
    checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    winner_term_chirho: u64,
    plan_page_count_chirho: u64,
    manifest_record_count_chirho: u64,
    effect_obligation_count_chirho: u64,
) -> VerifiedGd7SealedPlanProofChirho {
    VerifiedGd7SealedPlanProofChirho {
        reconciliation_identity_digest_chirho,
        checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        winner_fork_witness_object_digest_chirho: "d".repeat(64),
        winner_term_chirho,
        plan_page_count_chirho,
        manifest_record_count_chirho,
        effect_obligation_count_chirho,
    }
}

/// The release door binds the certificate to the cut it supersedes by its `adopted_checkpoint_ref`
/// field, so this fixture sets both `checkpoint_ref` and `adopted_checkpoint_ref` to the caller's
/// adopted ref — it models a certificate already bound to that adopted cut. (A genuine converger
/// distinguishes the two: `checkpoint_ref` is the PlanSealed plan cut and `adopted_checkpoint_ref` is
/// the AdoptedHeld cut.)
#[cfg(test)]
pub(crate) fn converged_read_replica_for_release_test_chirho(
    checkpoint_ref_chirho: String,
) -> ConvergedReadReplicaChirho {
    ConvergedReadReplicaChirho {
        schema_chirho: GD7_CONVERGED_READ_REPLICA_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: "a".repeat(64),
        checkpoint_ref_chirho: checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho: "b".repeat(64),
        winner_fork_witness_object_digest_chirho: "c".repeat(64),
        winner_term_chirho: 1,
        adopted_checkpoint_ref_chirho: checkpoint_ref_chirho,
        losing_population_identity_chirho: "e".repeat(64),
        losing_population_digest_chirho: "f".repeat(64),
        terminal_outcome_identity_chirho: "1".repeat(64),
        terminal_outcome_digest_chirho: "2".repeat(64),
        conservation_snapshot_digest_chirho: "4".repeat(64),
        retained_refs_chirho: vec!["3".repeat(64)],
        population_count_chirho: 0,
        completed_count_chirho: 0,
        disposed_count_chirho: 0,
        certificate_key_id_chirho: String::new(),
        certificate_sig_chirho: String::new(),
    }
}

/// A v2 convergence certificate for the RELEASE door, signed by the given held signer.
///
/// The release door verifies the certificate now, so its release-success arms cannot use the v1
/// unsigned `converged_read_replica_for_release_test_chirho` helper (which stays v1 precisely so the
/// D4 gate arms can prove they reject v1). This carries the v2 schema and a real held signature over
/// the same coordinates. The release door binds the signature and the adopted-checkpoint identity,
/// not the population counts, so the defaulted zeros are immaterial here.
#[cfg(test)]
pub(crate) fn signed_converged_read_replica_for_release_test_chirho(
    checkpoint_ref_chirho: String,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> ConvergedReadReplicaChirho {
    let mut certificate_chirho =
        converged_read_replica_for_release_test_chirho(checkpoint_ref_chirho);
    certificate_chirho.schema_chirho = GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO.to_owned();
    sign_converged_read_replica_for_test_chirho(certificate_chirho, signer_chirho)
}

#[cfg(test)]
pub(crate) fn sign_converged_read_replica_for_test_chirho(
    mut certificate_chirho: ConvergedReadReplicaChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> ConvergedReadReplicaChirho {
    certificate_chirho.certificate_key_id_chirho = signer_chirho.key_id_chirho();
    certificate_chirho.certificate_sig_chirho.clear();
    let bytes_chirho = canonical_converged_certificate_bytes_chirho(&certificate_chirho)
        .expect("test certificate has a bounded serializable shape");
    let line_chirho = std::str::from_utf8(&bytes_chirho).expect("test certificate is utf8");
    certificate_chirho.certificate_sig_chirho = signer_chirho
        .sign_chirho(line_chirho)
        .expect("test signer signs certificate");
    certificate_chirho
}
