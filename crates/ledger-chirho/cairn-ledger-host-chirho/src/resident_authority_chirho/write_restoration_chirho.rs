// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The signed D4 confirmation that one released reconciliation instance restored ordinary writes.
//!
//! This artifact is CONFIRMATION AND AUDIT, never permission. The append funnel has no read path to
//! it (clause 7, guarded); what actually re-admits ordinary writes is the removal of the sibling
//! ordinary-write hold, and this artifact is the durable explanation that removal must never lack.
//! Hence the ordering in [`commit_write_restoration_chirho`]: artifact first, verified, and only
//! then the hold removal — so no crash can produce writable state with no durable explanation.

use crate::reconciliation_chirho::{
    consistency_group_digest_suffix_chirho, inspect_gd7_reconciliation_released_state_chirho,
    is_bounded_label_chirho, is_lower_hex_digest_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho,
    remove_gd7_ordinary_write_hold_chirho, validate_key_and_signature_chirho,
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
};
use crate::reconciliation_chirho::{
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    load_verified_gd7_converged_read_replica_chirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

pub const GD7_WRITE_RESTORATION_CONFIRMATION_SCHEMA_V1_CHIRHO: &str =
    "gd7-write-restoration-confirmation-v1-chirho";

const MAX_GD7_WRITE_RESTORATION_CONFIRMATION_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WriteRestorationRefusalChirho {
    InvalidIdentityChirho,
    MalformedConfirmationChirho,
    NonCanonicalConfirmationChirho,
    OversizedConfirmationChirho,
    WrongGroupChirho,
    ForeignGroupChirho,
    ForeignCheckpointCertificateChirho,
    ActiveReconciliationChirho,
    HeadPresentChirho,
    SiblingAbsentUnconfirmedChirho,
    WrongAdoptedCheckpointChirho,
    HeadNotMarkedAbsentChirho,
    SignerKeyMismatchChirho,
    InvalidConfirmationSignatureChirho,
    SigningChirho,
    SerializationChirho,
    StorageChirho,
    /// A confirmation already exists for this exact instance and does not match the one offered.
    /// Retry is idempotent only against a byte-identical artifact.
    ImmutableCollisionChirho,
    /// The artifact was written but did not reload and verify — the hold is NOT removed.
    ConfirmationUnreadableAfterWriteChirho,
    LaterElectorGrantRequiredChirho,
    V2CertificateRequiredChirho,
    ReleasedStateRequiredChirho,
}

impl fmt::Display for Gd7WriteRestorationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::InvalidIdentityChirho => "write-restoration identity is not a valid group cut",
            Self::MalformedConfirmationChirho => "write-restoration confirmation is malformed",
            Self::NonCanonicalConfirmationChirho => {
                "write-restoration confirmation bytes are not canonical"
            }
            Self::OversizedConfirmationChirho => "write-restoration confirmation exceeds its bound",
            Self::WrongGroupChirho => "write-restoration confirmation belongs to another group",
            Self::ForeignGroupChirho => "later elector observation belongs to another group",
            Self::ForeignCheckpointCertificateChirho => {
                "convergence certificate belongs to another checkpoint"
            }
            Self::ActiveReconciliationChirho => "reconciliation is still active",
            Self::HeadPresentChirho => "reconciliation head is still present",
            Self::SiblingAbsentUnconfirmedChirho => {
                "ordinary-write hold is absent without a matching confirmation"
            }
            Self::WrongAdoptedCheckpointChirho => {
                "write-restoration confirmation belongs to another adopted checkpoint"
            }
            Self::HeadNotMarkedAbsentChirho => {
                "write-restoration confirmation does not mark the superseded head absent"
            }
            Self::SignerKeyMismatchChirho => "write-restoration confirmation names a foreign key",
            Self::InvalidConfirmationSignatureChirho => {
                "write-restoration confirmation signature did not verify"
            }
            Self::SigningChirho => "write-restoration confirmation could not be signed",
            Self::SerializationChirho => "write-restoration confirmation could not be serialized",
            Self::StorageChirho => "write-restoration confirmation storage refused",
            Self::ImmutableCollisionChirho => {
                "a different write-restoration confirmation already exists for this instance"
            }
            Self::ConfirmationUnreadableAfterWriteChirho => {
                "write-restoration confirmation did not reload and verify after its write"
            }
            Self::LaterElectorGrantRequiredChirho => {
                "write restoration requires an authenticated elector grant later than the reconciliation winner"
            }
            Self::V2CertificateRequiredChirho => {
                "write restoration requires verified v2 convergence counts"
            }
            Self::ReleasedStateRequiredChirho => {
                "write restoration requires a released head and a standing ordinary-write hold"
            }
        };
        formatter_chirho.write_str(message_chirho)
    }
}

impl Error for Gd7WriteRestorationRefusalChirho {}

/// The clause-6 field list, bound into one signed object.
///
/// Fields are private with no public constructor: a caller cannot hand a consumer an assertion
/// about evidence it did not supply through [`Gd7WriteRestorationConfirmationInputChirho`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WriteRestorationConfirmationChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    retained_adopted_checkpoint_ref_chirho: String,
    superseded_head_checkpoint_ref_chirho: String,
    /// Clause 6's explicit absent-head marker. Verification REFUSES unless this is true, so the
    /// marker is load-bearing rather than decorative: an artifact can never describe a released
    /// instance whose head is still standing.
    head_absent_chirho: bool,
    accepted_winner_identity_chirho: String,
    accepted_winner_term_chirho: u64,
    convergence_certificate_digest_chirho: String,
    closed_population_digest_chirho: String,
    completed_count_chirho: u64,
    disposed_count_chirho: u64,
    elector_grant_identity_chirho: String,
    elector_grant_term_chirho: u64,
    key_id_chirho: String,
    sig_chirho: String,
}

impl Gd7WriteRestorationConfirmationChirho {
    pub fn schema_chirho(&self) -> &str {
        &self.schema_chirho
    }
    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }
    pub fn retained_adopted_checkpoint_ref_chirho(&self) -> &str {
        &self.retained_adopted_checkpoint_ref_chirho
    }
    pub fn superseded_head_checkpoint_ref_chirho(&self) -> &str {
        &self.superseded_head_checkpoint_ref_chirho
    }
    pub fn head_absent_chirho(&self) -> bool {
        self.head_absent_chirho
    }
    pub fn accepted_winner_identity_chirho(&self) -> &str {
        &self.accepted_winner_identity_chirho
    }
    pub fn accepted_winner_term_chirho(&self) -> u64 {
        self.accepted_winner_term_chirho
    }
    pub fn convergence_certificate_digest_chirho(&self) -> &str {
        &self.convergence_certificate_digest_chirho
    }
    pub fn closed_population_digest_chirho(&self) -> &str {
        &self.closed_population_digest_chirho
    }
    pub fn completed_count_chirho(&self) -> u64 {
        self.completed_count_chirho
    }
    pub fn disposed_count_chirho(&self) -> u64 {
        self.disposed_count_chirho
    }
    pub fn elector_grant_identity_chirho(&self) -> &str {
        &self.elector_grant_identity_chirho
    }
    pub fn elector_grant_term_chirho(&self) -> u64 {
        self.elector_grant_term_chirho
    }
    pub fn key_id_chirho(&self) -> &str {
        &self.key_id_chirho
    }

    /// The closed population this confirmation accounts for, refusing rather than wrapping.
    ///
    /// Derived, never stored: a stored total could disagree with its own parts, and the parts are
    /// what the certificate binds.
    pub fn verified_closed_population_total_chirho(
        &self,
    ) -> Result<u64, Gd7WriteRestorationRefusalChirho> {
        self.completed_count_chirho
            .checked_add(self.disposed_count_chirho)
            .ok_or(Gd7WriteRestorationRefusalChirho::MalformedConfirmationChirho)
    }
}

/// Caller-supplied evidence for one confirmation. Every field is bound into the signed artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7WriteRestorationConfirmationInputChirho {
    pub consistency_group_digest_chirho: String,
    pub retained_adopted_checkpoint_ref_chirho: String,
    pub superseded_head_checkpoint_ref_chirho: String,
    pub accepted_winner_identity_chirho: String,
    pub accepted_winner_term_chirho: u64,
    pub convergence_certificate_digest_chirho: String,
    pub closed_population_digest_chirho: String,
    pub completed_count_chirho: u64,
    pub disposed_count_chirho: u64,
    pub elector_grant_identity_chirho: String,
    pub elector_grant_term_chirho: u64,
}

/// Per-instance location beside the group's reconciliation refs, keyed by group AND adopted
/// checkpoint — so a confirmation for instance N can never be found while reading instance N+1.
pub fn gd7_write_restoration_confirmation_path_chirho(
    consistency_group_digest_chirho: &str,
    retained_adopted_checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7WriteRestorationRefusalChirho> {
    let digest_chirho = consistency_group_digest_suffix_chirho(consistency_group_digest_chirho)
        .ok_or(Gd7WriteRestorationRefusalChirho::InvalidIdentityChirho)?;
    if !is_lower_hex_digest_chirho(retained_adopted_checkpoint_ref_chirho) {
        return Err(Gd7WriteRestorationRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{}/{digest_chirho}/write-restoration-chirho/{retained_adopted_checkpoint_ref_chirho}.json",
        &digest_chirho[..2],
        &digest_chirho[2..4],
    )))
}

fn canonical_json_chirho(
    value_chirho: &impl serde::Serialize,
) -> Result<Vec<u8>, Gd7WriteRestorationRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::SerializationChirho)
}

fn canonical_signed_confirmation_chirho(
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    input_chirho: &Gd7WriteRestorationConfirmationInputChirho,
) -> Result<Vec<u8>, Gd7WriteRestorationRefusalChirho> {
    let mut confirmation_chirho = Gd7WriteRestorationConfirmationChirho {
        schema_chirho: GD7_WRITE_RESTORATION_CONFIRMATION_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho.clone(),
        retained_adopted_checkpoint_ref_chirho: input_chirho
            .retained_adopted_checkpoint_ref_chirho
            .clone(),
        superseded_head_checkpoint_ref_chirho: input_chirho
            .superseded_head_checkpoint_ref_chirho
            .clone(),
        head_absent_chirho: true,
        accepted_winner_identity_chirho: input_chirho.accepted_winner_identity_chirho.clone(),
        accepted_winner_term_chirho: input_chirho.accepted_winner_term_chirho,
        convergence_certificate_digest_chirho: input_chirho
            .convergence_certificate_digest_chirho
            .clone(),
        closed_population_digest_chirho: input_chirho.closed_population_digest_chirho.clone(),
        completed_count_chirho: input_chirho.completed_count_chirho,
        disposed_count_chirho: input_chirho.disposed_count_chirho,
        elector_grant_identity_chirho: input_chirho.elector_grant_identity_chirho.clone(),
        elector_grant_term_chirho: input_chirho.elector_grant_term_chirho,
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    if !confirmation_shape_valid_chirho(&confirmation_chirho) {
        return Err(Gd7WriteRestorationRefusalChirho::MalformedConfirmationChirho);
    }
    let signing_bytes_chirho = canonical_json_chirho(&confirmation_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::SerializationChirho)?;
    confirmation_chirho.sig_chirho = signer_chirho
        .sign_chirho(signing_line_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::SigningChirho)?;
    if !validate_key_and_signature_chirho(
        &confirmation_chirho.key_id_chirho,
        &confirmation_chirho.sig_chirho,
    ) {
        return Err(Gd7WriteRestorationRefusalChirho::SigningChirho);
    }
    let bytes_chirho = canonical_json_chirho(&confirmation_chirho)?;
    if bytes_chirho.len() > MAX_GD7_WRITE_RESTORATION_CONFIRMATION_BYTES_CHIRHO {
        return Err(Gd7WriteRestorationRefusalChirho::OversizedConfirmationChirho);
    }
    Ok(bytes_chirho)
}

fn confirmation_shape_valid_chirho(
    confirmation_chirho: &Gd7WriteRestorationConfirmationChirho,
) -> bool {
    confirmation_chirho.schema_chirho == GD7_WRITE_RESTORATION_CONFIRMATION_SCHEMA_V1_CHIRHO
        && consistency_group_digest_suffix_chirho(
            &confirmation_chirho.consistency_group_digest_chirho,
        )
        .is_some()
        && is_lower_hex_digest_chirho(&confirmation_chirho.retained_adopted_checkpoint_ref_chirho)
        && is_lower_hex_digest_chirho(&confirmation_chirho.superseded_head_checkpoint_ref_chirho)
        && is_lower_hex_digest_chirho(&confirmation_chirho.convergence_certificate_digest_chirho)
        && is_lower_hex_digest_chirho(&confirmation_chirho.closed_population_digest_chirho)
        && is_bounded_label_chirho(
            &confirmation_chirho.accepted_winner_identity_chirho,
            MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
        )
        && is_bounded_label_chirho(
            &confirmation_chirho.elector_grant_identity_chirho,
            MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
        )
}

/// Parse and fully verify one confirmation against the instance the caller is standing in.
///
/// Refuses non-canonical bytes, a foreign group, a foreign adopted checkpoint, a head not marked
/// absent, a foreign key, and a signature that does not cover these exact bytes. Altering ANY bound
/// field changes the signed line, so every clause-6 binding is enforced by this one call.
pub fn parse_and_verify_write_restoration_confirmation_chirho(
    bytes_chirho: &[u8],
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    expected_group_digest_chirho: &str,
    expected_adopted_checkpoint_ref_chirho: &str,
) -> Result<Gd7WriteRestorationConfirmationChirho, Gd7WriteRestorationRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_WRITE_RESTORATION_CONFIRMATION_BYTES_CHIRHO {
        return Err(Gd7WriteRestorationRefusalChirho::OversizedConfirmationChirho);
    }
    let confirmation_chirho: Gd7WriteRestorationConfirmationChirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_| Gd7WriteRestorationRefusalChirho::MalformedConfirmationChirho)?;
    if canonical_json_chirho(&confirmation_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WriteRestorationRefusalChirho::NonCanonicalConfirmationChirho);
    }
    if !confirmation_shape_valid_chirho(&confirmation_chirho)
        || !validate_key_and_signature_chirho(
            &confirmation_chirho.key_id_chirho,
            &confirmation_chirho.sig_chirho,
        )
    {
        return Err(Gd7WriteRestorationRefusalChirho::MalformedConfirmationChirho);
    }
    if !confirmation_chirho.head_absent_chirho {
        return Err(Gd7WriteRestorationRefusalChirho::HeadNotMarkedAbsentChirho);
    }
    if confirmation_chirho.consistency_group_digest_chirho != expected_group_digest_chirho {
        return Err(Gd7WriteRestorationRefusalChirho::WrongGroupChirho);
    }
    if confirmation_chirho.retained_adopted_checkpoint_ref_chirho
        != expected_adopted_checkpoint_ref_chirho
    {
        return Err(Gd7WriteRestorationRefusalChirho::WrongAdoptedCheckpointChirho);
    }
    if confirmation_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7WriteRestorationRefusalChirho::SignerKeyMismatchChirho);
    }
    let mut unsigned_chirho = confirmation_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    let signing_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(signing_line_chirho, &confirmation_chirho.sig_chirho) {
        return Err(Gd7WriteRestorationRefusalChirho::InvalidConfirmationSignatureChirho);
    }
    Ok(confirmation_chirho)
}

/// Reload one instance's confirmation, verified, or `None` when it was never written.
pub fn load_verified_write_restoration_confirmation_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    consistency_group_digest_chirho: &str,
    retained_adopted_checkpoint_ref_chirho: &str,
) -> Result<Option<Gd7WriteRestorationConfirmationChirho>, Gd7WriteRestorationRefusalChirho> {
    let path_chirho = gd7_write_restoration_confirmation_path_chirho(
        consistency_group_digest_chirho,
        retained_adopted_checkpoint_ref_chirho,
    )?;
    let Some(bytes_chirho) = storage_chirho
        .read_all_chirho(&path_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    parse_and_verify_write_restoration_confirmation_chirho(
        &bytes_chirho,
        verifier_chirho,
        consistency_group_digest_chirho,
        retained_adopted_checkpoint_ref_chirho,
    )
    .map(Some)
}

/// The outcome of one restoration attempt, so an idempotent retry is distinguishable from the
/// first success rather than collapsing into a bare `Ok(())`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gd7WriteRestorationOutcomeChirho {
    /// The confirmation was written and the ordinary-write hold removed.
    RestoredChirho,
    /// A byte-identical confirmation already existed; the hold removal was completed or confirmed.
    AlreadyRestoredChirho,
}

/// Verify the D4 gate's complete evidence set, then consume the parked artifact transaction.
///
/// The two observations are independently authenticated: the first names the reconciliation
/// winner being restored, while the second is the later elector observation. The confirmation
/// input is derived only after the v2 counts, released state, and standing sibling hold pass; no
/// caller can substitute fixture values for those coordinates. This is the gate's only production
/// caller of [`commit_write_restoration_chirho`].
pub fn restore_ordinary_writes_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    reconciliation_observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    later_elector_observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    convergence_chirho: &ConvergedReadReplicaChirho,
    adopted_checkpoint_ref_chirho: &str,
) -> Result<Gd7WriteRestorationOutcomeChirho, Gd7WriteRestorationRefusalChirho> {
    let reconciliation_identity_chirho = reconciliation_observation_chirho.identity_chirho();
    let later_identity_chirho = later_elector_observation_chirho.identity_chirho();
    if later_identity_chirho.consistency_group_digest_chirho
        != reconciliation_identity_chirho.consistency_group_digest_chirho
    {
        return Err(Gd7WriteRestorationRefusalChirho::ForeignGroupChirho);
    }
    if later_identity_chirho.winner_term_chirho <= reconciliation_identity_chirho.winner_term_chirho
    {
        return Err(Gd7WriteRestorationRefusalChirho::LaterElectorGrantRequiredChirho);
    }
    // BIND THE CERTIFICATE TO THE CUT BEING RESTORED by its `adopted_checkpoint_ref_chirho` field.
    // A genuine convergence certificate carries TWO refs: `checkpoint_ref_chirho` names the PlanSealed
    // plan cut where obligations were sealed, and `adopted_checkpoint_ref_chirho` names the AdoptedHeld
    // cut this gate restores writes over. They are never equal after a real adoption. This gate loads
    // the checkpoint at `adopted_checkpoint_ref_chirho` and identity-checks it against the certificate
    // below, so it must bind the certificate by that same field; binding by `checkpoint_ref_chirho`
    // (the plan cut) would reject every genuine certificate at this equality check — the same
    // mis-binding brick R fixed in the release door
    // (`sink_term_revoke_chirho.rs::release_converged_reconciliation_hold_chirho`). This is an
    // unauthenticated field getter — a fabricated certificate can assert any value here — which is why
    // the signature verification below is the actual authority gate; and because
    // `adopted_checkpoint_ref_chirho` is a signed field, re-aiming a genuine certificate at another cut
    // breaks that signature.
    if convergence_chirho.adopted_checkpoint_ref_chirho() != adopted_checkpoint_ref_chirho {
        return Err(Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho);
    }
    let convergence_bytes_chirho = serde_json::to_vec(convergence_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho)?;
    let convergence_chirho =
        load_verified_gd7_converged_read_replica_chirho(&convergence_bytes_chirho, verifier_chirho)
            .map_err(|_| Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho)?;
    let stored_checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
        storage_chirho,
        verifier_chirho,
        adopted_checkpoint_ref_chirho,
    )
    .map_err(|_| Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho)?;
    let stored_identity_digest_chirho =
        crate::reconciliation_chirho::gd7_reconciliation_identity_digest_chirho(
            &stored_checkpoint_chirho.identity_chirho,
        )
        .map_err(|_| Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho)?;
    if convergence_chirho.reconciliation_identity_digest_chirho() != stored_identity_digest_chirho
        || convergence_chirho.winner_term_chirho()
            != stored_checkpoint_chirho.identity_chirho.winner_term_chirho
    {
        return Err(Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho);
    }
    let (completed_count_chirho, disposed_count_chirho) = convergence_chirho
        .verified_v2_counts_chirho()
        .map_err(|_| Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho)?;
    let terminal_count_chirho = completed_count_chirho
        .checked_add(disposed_count_chirho)
        .ok_or(Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho)?;
    if terminal_count_chirho != convergence_chirho.population_count_chirho() {
        return Err(Gd7WriteRestorationRefusalChirho::V2CertificateRequiredChirho);
    }
    if load_authenticated_active_gd7_reconciliation_for_group_chirho(
        storage_chirho,
        verifier_chirho,
        &reconciliation_identity_chirho.consistency_group_digest_chirho,
    )
    .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?
    .is_some()
    {
        return Err(Gd7WriteRestorationRefusalChirho::ActiveReconciliationChirho);
    }
    let confirmation_path_chirho = gd7_write_restoration_confirmation_path_chirho(
        &reconciliation_identity_chirho.consistency_group_digest_chirho,
        adopted_checkpoint_ref_chirho,
    )
    .map_err(|_| Gd7WriteRestorationRefusalChirho::ForeignCheckpointCertificateChirho)?;
    let released_state_chirho = inspect_gd7_reconciliation_released_state_chirho(
        storage_chirho,
        &reconciliation_identity_chirho.consistency_group_digest_chirho,
        &confirmation_path_chirho,
    )
    .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?;
    if released_state_chirho.head_present_chirho {
        return Err(Gd7WriteRestorationRefusalChirho::HeadPresentChirho);
    }
    if !released_state_chirho.ordinary_write_hold_present_chirho {
        let matching_confirmation_chirho = released_state_chirho.confirmation_present_chirho
            && load_verified_write_restoration_confirmation_chirho(
                storage_chirho,
                verifier_chirho,
                &reconciliation_identity_chirho.consistency_group_digest_chirho,
                adopted_checkpoint_ref_chirho,
            )
            .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?
            .is_some();
        if !matching_confirmation_chirho {
            return Err(Gd7WriteRestorationRefusalChirho::SiblingAbsentUnconfirmedChirho);
        }
    }
    let superseded_head_checkpoint_ref_chirho =
        convergence_chirho.checkpoint_ref_chirho().to_owned();
    let input_chirho = Gd7WriteRestorationConfirmationInputChirho {
        consistency_group_digest_chirho: reconciliation_identity_chirho
            .consistency_group_digest_chirho
            .clone(),
        retained_adopted_checkpoint_ref_chirho: adopted_checkpoint_ref_chirho.to_owned(),
        superseded_head_checkpoint_ref_chirho,
        accepted_winner_identity_chirho: reconciliation_identity_chirho.winner_node_chirho.clone(),
        accepted_winner_term_chirho: reconciliation_identity_chirho.winner_term_chirho,
        convergence_certificate_digest_chirho: convergence_chirho
            .terminal_outcome_digest_chirho()
            .to_owned(),
        closed_population_digest_chirho: convergence_chirho
            .losing_population_digest_chirho()
            .to_owned(),
        completed_count_chirho,
        disposed_count_chirho,
        elector_grant_identity_chirho: later_identity_chirho.winner_node_chirho.clone(),
        elector_grant_term_chirho: later_identity_chirho.winner_term_chirho,
    };
    commit_write_restoration_chirho(
        storage_chirho,
        signer_chirho,
        verifier_chirho,
        &input_chirho,
    )
}

/// Clause 9 delivered as ORDERING, because the storage port has no multi-object transaction.
///
/// Write the confirmation, RELOAD AND VERIFY it, and only then remove the ordinary-write hold. A
/// crash at any point leaves either (no artifact, still withheld) or (artifact present, still
/// withheld) — both fail-closed and both in-doubt-recoverable by retry. There is no interleaving
/// that yields writable state without a durable, verified explanation, which is exactly what clause
/// 9 forbids. Retry is idempotent: an existing byte-identical artifact completes the removal.
pub fn commit_write_restoration_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    input_chirho: &Gd7WriteRestorationConfirmationInputChirho,
) -> Result<Gd7WriteRestorationOutcomeChirho, Gd7WriteRestorationRefusalChirho> {
    let path_chirho = gd7_write_restoration_confirmation_path_chirho(
        &input_chirho.consistency_group_digest_chirho,
        &input_chirho.retained_adopted_checkpoint_ref_chirho,
    )?;
    let bytes_chirho = canonical_signed_confirmation_chirho(signer_chirho, input_chirho)?;
    let mut already_present_chirho = false;
    match storage_chirho
        .create_durable_chirho(&path_chirho, &bytes_chirho)
        .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => {}
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = storage_chirho
                .read_all_chirho(&path_chirho)
                .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?
                .ok_or(Gd7WriteRestorationRefusalChirho::ImmutableCollisionChirho)?;
            if existing_chirho != bytes_chirho {
                return Err(Gd7WriteRestorationRefusalChirho::ImmutableCollisionChirho);
            }
            already_present_chirho = true;
        }
    }
    // The artifact must be readable and verifiable BEFORE the hold comes off. A write that landed
    // torn or unverifiable must leave ordinary writes withheld, not merely unexplained.
    if load_verified_write_restoration_confirmation_chirho(
        storage_chirho,
        verifier_chirho,
        &input_chirho.consistency_group_digest_chirho,
        &input_chirho.retained_adopted_checkpoint_ref_chirho,
    )?
    .is_none()
    {
        return Err(Gd7WriteRestorationRefusalChirho::ConfirmationUnreadableAfterWriteChirho);
    }
    remove_gd7_ordinary_write_hold_chirho(
        storage_chirho,
        &input_chirho.consistency_group_digest_chirho,
    )
    .map_err(|_| Gd7WriteRestorationRefusalChirho::StorageChirho)?;
    Ok(if already_present_chirho {
        Gd7WriteRestorationOutcomeChirho::AlreadyRestoredChirho
    } else {
        Gd7WriteRestorationOutcomeChirho::RestoredChirho
    })
}
