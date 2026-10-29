// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Create-only checkpoint persistence and the fixed per-group reconciliation hold head.

use super::contract_chirho::{
    consistency_group_digest_suffix_chirho, is_bounded_label_chirho, is_lower_hex_digest_chirho,
    validate_checkpoint_state_chirho, validate_identity_chirho, validate_key_and_signature_chirho,
    Gd7AdoptionCheckpointBindingChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationHeadChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO,
    MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO,
    MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7ReconciliationStoreRefusalChirho {
    InvalidIdentityChirho,
    InvalidCheckpointStateChirho,
    InvalidReferenceChirho,
    MalformedHeadChirho,
    MalformedCheckpointChirho,
    NonCanonicalHeadChirho,
    NonCanonicalCheckpointChirho,
    OversizedHeadChirho,
    OversizedCheckpointChirho,
    InvalidHeadSignatureChirho,
    InvalidCheckpointSignatureChirho,
    SignerKeyMismatchChirho,
    WrongIdentityChirho,
    MissingReferencedCheckpointChirho,
    WinnerWitnessMismatchChirho,
    CheckpointReferenceMismatchChirho,
    HeadCheckpointMismatchChirho,
    WrongExpectedPriorChirho,
    InvalidPhaseTransitionChirho,
    InvalidTransitionSequenceChirho,
    ManifestCountRegressionChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7ReconciliationStoreRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message_chirho = match self {
            Self::InvalidIdentityChirho => "GD7 reconciliation identity is invalid",
            Self::InvalidCheckpointStateChirho => "GD7 checkpoint state is invalid",
            Self::InvalidReferenceChirho => "GD7 object reference is invalid",
            Self::MalformedHeadChirho => "GD7 reconciliation head is malformed",
            Self::MalformedCheckpointChirho => "GD7 reconciliation checkpoint is malformed",
            Self::NonCanonicalHeadChirho => "GD7 reconciliation head is not canonical",
            Self::NonCanonicalCheckpointChirho => "GD7 checkpoint is not canonical",
            Self::OversizedHeadChirho => "GD7 reconciliation head exceeds its bound",
            Self::OversizedCheckpointChirho => "GD7 checkpoint exceeds its bound",
            Self::InvalidHeadSignatureChirho => "GD7 reconciliation head signature is invalid",
            Self::InvalidCheckpointSignatureChirho => "GD7 checkpoint signature is invalid",
            Self::SignerKeyMismatchChirho => "GD7 signer key label does not match",
            Self::WrongIdentityChirho => "GD7 reconciliation identity does not match",
            Self::MissingReferencedCheckpointChirho => "GD7 head references a missing checkpoint",
            Self::WinnerWitnessMismatchChirho => {
                "GD7 checkpoint winner witness differs from the authenticated observation"
            }
            Self::CheckpointReferenceMismatchChirho => {
                "GD7 checkpoint bytes do not match their reference"
            }
            Self::HeadCheckpointMismatchChirho => "GD7 head and checkpoint disagree",
            Self::WrongExpectedPriorChirho => "GD7 active prior checkpoint differs",
            Self::InvalidPhaseTransitionChirho => "GD7 checkpoint phase transition is invalid",
            Self::InvalidTransitionSequenceChirho => {
                "GD7 checkpoint transition sequence is invalid"
            }
            Self::ManifestCountRegressionChirho => "GD7 manifest counters regressed",
            Self::ImmutableCollisionChirho => "GD7 immutable checkpoint collision",
            Self::SerializationChirho => "GD7 reconciliation serialization failed",
            Self::SigningChirho => "GD7 reconciliation signing failed",
            Self::StorageChirho => "GD7 reconciliation storage operation failed",
        };
        formatter_chirho.write_str(message_chirho)
    }
}

impl Error for Gd7ReconciliationStoreRefusalChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGd7ReconciliationChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedGd7ReconciliationCheckpointChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7ObservedHeldOutcomeChirho {
    InstalledChirho(CommittedGd7ReconciliationCheckpointChirho),
    AlreadyObservedChirho(ActiveGd7ReconciliationChirho),
    AlreadyAdvancedChirho(ActiveGd7ReconciliationChirho),
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedGd7ReconciliationCheckpointChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    pub canonical_bytes_chirho: Vec<u8>,
}

pub struct Gd7ReconciliationStoreChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    identity_chirho: Gd7ReconciliationIdentityChirho,
    identity_digest_chirho: String,
    winner_fork_witness_object_digest_chirho: String,
    head_path_chirho: StoragePathChirho,
}

pub fn gd7_reconciliation_head_path_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<StoragePathChirho, Gd7ReconciliationStoreRefusalChirho> {
    if !validate_identity_chirho(identity_chirho) {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho);
    }
    gd7_reconciliation_group_head_path_chirho(&identity_chirho.consistency_group_digest_chirho)
}

pub fn gd7_reconciliation_group_head_path_chirho(
    consistency_group_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReconciliationStoreRefusalChirho> {
    let digest_chirho = consistency_group_digest_suffix_chirho(consistency_group_digest_chirho)
        .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho)?;
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{}/{digest_chirho}/active-head-chirho.json",
        &digest_chirho[..2],
        &digest_chirho[2..4],
    )))
}

/// The ORDINARY-WRITE hold: the second barrier, and the one D4 lifts.
///
/// Sibling of the active head, and the SAME SPECIES — presence WITHHOLDS, absence is merely the
/// absence of this barrier and never a grant. The two barriers come off at different moments and
/// that difference is the whole point: D3's release removes the head, which re-admits the fenced
/// compensation legs that finish the reconciliation; this object stays until D4 has verified a
/// later elector grant and written its signed confirmation, so ordinary writes cannot resume on
/// the strength of an old victory plus an absent head.
///
/// Its bytes are NEVER parsed by anything (see
/// [`gd7_reconciliation_group_ordinary_writes_withheld_chirho`]), so the content below is a
/// human-readable marker for an operator reading the tree, carrying no authority whatsoever.
const GD7_ORDINARY_WRITE_HOLD_MARKER_CHIRHO: &[u8] =
    b"gd7-ordinary-write-hold-chirho: ordinary resident writes are withheld until D4 confirms this reconciliation. Presence withholds; these bytes are never parsed.\n";

pub fn gd7_reconciliation_group_ordinary_write_hold_path_chirho(
    consistency_group_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReconciliationStoreRefusalChirho> {
    let digest_chirho = consistency_group_digest_suffix_chirho(consistency_group_digest_chirho)
        .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho)?;
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{}/{digest_chirho}/ordinary-write-hold-chirho.json",
        &digest_chirho[..2],
        &digest_chirho[2..4],
    )))
}

/// Fail closed on the ordinary-write barrier without ever reading its bytes.
///
/// `object_len` ONLY — deliberately the same instrument as the head's presence test, for the same
/// reason: a hot-path parse would make malformed or stale bytes decide whether a writer may write,
/// and the one-way doctrine exists precisely so they cannot. There is exactly ONE call site (the
/// resident append funnel) and a source guard pins that.
pub fn gd7_reconciliation_group_ordinary_writes_withheld_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    consistency_group_digest_chirho: &str,
) -> Result<bool, Gd7ReconciliationStoreRefusalChirho> {
    let hold_path_chirho =
        gd7_reconciliation_group_ordinary_write_hold_path_chirho(consistency_group_digest_chirho)?;
    storage_chirho
        .object_len_chirho(&hold_path_chirho)
        .map(|length_chirho| length_chirho.is_some())
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)
}

/// The composed state of both per-group reconciliation barriers plus D4's confirmation ref.
///
/// This is the only store-level read used by the D4 gate. The marker bytes remain opaque: only
/// presence is authority for the ordinary-write hold, while the confirmation is verified by its
/// owning module before the hold can be removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gd7ReconciliationReleasedStateChirho {
    pub head_present_chirho: bool,
    pub ordinary_write_hold_present_chirho: bool,
    pub confirmation_present_chirho: bool,
}

pub fn inspect_gd7_reconciliation_released_state_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    consistency_group_digest_chirho: &str,
    confirmation_path_chirho: &StoragePathChirho,
) -> Result<Gd7ReconciliationReleasedStateChirho, Gd7ReconciliationStoreRefusalChirho> {
    let head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(consistency_group_digest_chirho)?;
    let hold_path_chirho =
        gd7_reconciliation_group_ordinary_write_hold_path_chirho(consistency_group_digest_chirho)?;
    let head_present_chirho = storage_chirho
        .object_len_chirho(&head_path_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
        .is_some();
    let ordinary_write_hold_present_chirho = storage_chirho
        .object_len_chirho(&hold_path_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
        .is_some();
    let confirmation_present_chirho = storage_chirho
        .object_len_chirho(confirmation_path_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
        .is_some();
    Ok(Gd7ReconciliationReleasedStateChirho {
        head_present_chirho,
        ordinary_write_hold_present_chirho,
        confirmation_present_chirho,
    })
}

/// Plant the ordinary-write hold. Idempotent: a second call over an existing hold is a success
/// that leaves it byte-exact, so re-committing a checkpoint never disturbs a standing barrier.
pub fn plant_gd7_ordinary_write_hold_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    consistency_group_digest_chirho: &str,
) -> Result<(), Gd7ReconciliationStoreRefusalChirho> {
    let hold_path_chirho =
        gd7_reconciliation_group_ordinary_write_hold_path_chirho(consistency_group_digest_chirho)?;
    storage_chirho
        .create_durable_chirho(&hold_path_chirho, GD7_ORDINARY_WRITE_HOLD_MARKER_CHIRHO)
        .map(|_| ())
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)
}

/// Remove the ordinary-write hold. THE ONLY caller that may do this is D4's restoration
/// transaction, and only AFTER its signed confirmation is durable and re-verified — see
/// `resident_authority_chirho::write_restoration_chirho::commit_write_restoration_chirho`.
/// Idempotent (absent is Ok), so an interrupted restoration completes on retry.
pub fn remove_gd7_ordinary_write_hold_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    consistency_group_digest_chirho: &str,
) -> Result<(), Gd7ReconciliationStoreRefusalChirho> {
    let hold_path_chirho =
        gd7_reconciliation_group_ordinary_write_hold_path_chirho(consistency_group_digest_chirho)?;
    storage_chirho
        .remove_chirho(&hold_path_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)
}

/// Fail closed before a writer knows the exact reconciliation identity.
///
/// Any fixed-head object for the consistency group means the resident writer stays held. Parsing
/// and signature verification happen through `Gd7ReconciliationStoreChirho` after the exact
/// identity is known; malformed or stale bytes never turn presence into permission to write.
pub fn gd7_reconciliation_group_has_any_active_hold_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    consistency_group_digest_chirho: &str,
) -> Result<bool, Gd7ReconciliationStoreRefusalChirho> {
    let head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(consistency_group_digest_chirho)?;
    storage_chirho
        .object_len_chirho(&head_path_chirho)
        .map(|length_chirho| length_chirho.is_some())
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)
}

/// Reload one group's locally signed active reconciliation without requiring a caller to restate
/// the identity already bound into the fixed head and immutable checkpoint.
///
/// This is the restart seam for a held coordinator. It performs two bounded point reads, verifies
/// both signatures and their content-addressed binding, and never lists reconciliation history.
pub fn load_authenticated_active_gd7_reconciliation_for_group_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    consistency_group_digest_chirho: &str,
) -> Result<Option<ActiveGd7ReconciliationChirho>, Gd7ReconciliationStoreRefusalChirho> {
    let head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(consistency_group_digest_chirho)?;
    let Some(head_bytes_chirho) = read_bounded_chirho(
        storage_chirho,
        &head_path_chirho,
        MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO,
        Gd7ReconciliationStoreRefusalChirho::OversizedHeadChirho,
    )?
    else {
        return Ok(None);
    };
    let unverified_head_chirho: Gd7ReconciliationHeadChirho =
        serde_json::from_slice(&head_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::MalformedHeadChirho)?;
    let head_chirho = parse_and_verify_head_chirho(
        &head_bytes_chirho,
        held_verifier_chirho,
        consistency_group_digest_chirho,
        &unverified_head_chirho.reconciliation_identity_digest_chirho,
    )?;
    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&head_chirho.active_checkpoint_ref_chirho)?;
    let checkpoint_bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &checkpoint_path_chirho,
        MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
        Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho,
    )?
    .ok_or(Gd7ReconciliationStoreRefusalChirho::MissingReferencedCheckpointChirho)?;
    let unverified_checkpoint_chirho: Gd7ReconciliationCheckpointChirho =
        serde_json::from_slice(&checkpoint_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::MalformedCheckpointChirho)?;
    let checkpoint_chirho = parse_and_verify_checkpoint_chirho(
        &checkpoint_bytes_chirho,
        held_verifier_chirho,
        &unverified_checkpoint_chirho.identity_chirho,
        &unverified_checkpoint_chirho.winner_fork_witness_object_digest_chirho,
    )?;
    if checkpoint_chirho
        .identity_chirho
        .consistency_group_digest_chirho
        != consistency_group_digest_chirho
        || gd7_reconciliation_identity_digest_chirho(&checkpoint_chirho.identity_chirho)?
            != head_chirho.reconciliation_identity_digest_chirho
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho);
    }
    if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho);
    }
    if head_chirho.transition_seq_chirho != checkpoint_chirho.state_chirho.transition_seq_chirho
        || head_chirho.phase_chirho != checkpoint_chirho.state_chirho.phase_chirho
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::HeadCheckpointMismatchChirho);
    }
    Ok(Some(ActiveGd7ReconciliationChirho {
        checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
        checkpoint_chirho,
    }))
}

pub fn gd7_reconciliation_checkpoint_path_chirho(
    checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7ReconciliationStoreRefusalChirho> {
    if !is_lower_hex_digest_chirho(checkpoint_ref_chirho) {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/checkpoints-chirho/{}/{}/{checkpoint_ref_chirho}.json",
        &checkpoint_ref_chirho[..2],
        &checkpoint_ref_chirho[2..4],
    )))
}

/// Point-load one immutable held-signed checkpoint by its content digest.
///
/// Unlike the active sealed-plan verifier, this loader remains valid after the fixed head advances
/// to `AdoptedHeldChirho`. Callers must still bind the returned identity, witness, and state to the
/// active adoption checkpoint that named this exact reference.
pub(crate) fn load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    checkpoint_ref_chirho: &str,
) -> Result<Gd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho> {
    let checkpoint_bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &gd7_reconciliation_checkpoint_path_chirho(checkpoint_ref_chirho)?,
        MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
        Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho,
    )?
    .ok_or(Gd7ReconciliationStoreRefusalChirho::MissingReferencedCheckpointChirho)?;
    if digest_bytes_chirho(&checkpoint_bytes_chirho) != checkpoint_ref_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho);
    }
    let unverified_checkpoint_chirho: Gd7ReconciliationCheckpointChirho =
        serde_json::from_slice(&checkpoint_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::MalformedCheckpointChirho)?;
    parse_and_verify_checkpoint_chirho(
        &checkpoint_bytes_chirho,
        held_verifier_chirho,
        &unverified_checkpoint_chirho.identity_chirho,
        &unverified_checkpoint_chirho.winner_fork_witness_object_digest_chirho,
    )
}

/// Verify and retain one exact externally presented reconciliation checkpoint.
///
/// The caller supplies the verifier for the checkpoint's held-node signer and separately checks
/// the checkpoint identity against the operation being authorized. This function proves the
/// canonical object, digest, signature, and internal state shape before a create-only point write.
pub(crate) fn verify_and_retain_gd7_reconciliation_checkpoint_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    checkpoint_ref_chirho: &str,
    checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7ReconciliationStoreRefusalChirho> {
    let canonical_bytes_chirho = canonical_json_chirho(checkpoint_chirho)?;
    if canonical_bytes_chirho.len() > MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO {
        return Err(Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho);
    }
    if digest_bytes_chirho(&canonical_bytes_chirho) != checkpoint_ref_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho);
    }
    let verified_checkpoint_chirho = parse_and_verify_checkpoint_chirho(
        &canonical_bytes_chirho,
        verifier_chirho,
        &checkpoint_chirho.identity_chirho,
        &checkpoint_chirho.winner_fork_witness_object_digest_chirho,
    )?;
    if verified_checkpoint_chirho != *checkpoint_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::NonCanonicalCheckpointChirho);
    }
    let checkpoint_path_chirho = gd7_reconciliation_checkpoint_path_chirho(checkpoint_ref_chirho)?;
    match storage_chirho
        .create_durable_chirho(&checkpoint_path_chirho, &canonical_bytes_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                &checkpoint_path_chirho,
                MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
                Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho,
            )?
            .ok_or(Gd7ReconciliationStoreRefusalChirho::StorageChirho)?;
            if existing_chirho == canonical_bytes_chirho {
                Ok(())
            } else {
                Err(Gd7ReconciliationStoreRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

impl<'ports_chirho> Gd7ReconciliationStoreChirho<'ports_chirho> {
    pub(crate) fn new_authenticated_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        identity_chirho: Gd7ReconciliationIdentityChirho,
        winner_fork_witness_object_digest_chirho: String,
    ) -> Result<Self, Gd7ReconciliationStoreRefusalChirho> {
        if !validate_identity_chirho(&identity_chirho) {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho);
        }
        if !is_lower_hex_digest_chirho(&winner_fork_witness_object_digest_chirho) {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidReferenceChirho);
        }
        if signer_chirho.key_id_chirho() != identity_chirho.held_node_chirho {
            return Err(Gd7ReconciliationStoreRefusalChirho::SignerKeyMismatchChirho);
        }
        let head_path_chirho = gd7_reconciliation_head_path_chirho(&identity_chirho)?;
        let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(&identity_chirho)?;
        Ok(Self {
            storage_chirho,
            signer_chirho,
            identity_chirho,
            identity_digest_chirho,
            winner_fork_witness_object_digest_chirho,
            head_path_chirho,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        identity_chirho: Gd7ReconciliationIdentityChirho,
    ) -> Result<Self, Gd7ReconciliationStoreRefusalChirho> {
        Self::new_authenticated_chirho(
            storage_chirho,
            signer_chirho,
            identity_chirho,
            "9".repeat(64),
        )
    }

    pub fn identity_chirho(&self) -> &Gd7ReconciliationIdentityChirho {
        &self.identity_chirho
    }

    /// A bounded fail-closed actor interlock read. Every R1 phase is an active writer hold.
    pub fn has_active_hold_chirho(&self) -> Result<bool, Gd7ReconciliationStoreRefusalChirho> {
        Ok(self.load_active_chirho()?.is_some())
    }

    /// Install the one initial held checkpoint, retry it exactly, or report later progress.
    pub(crate) fn ensure_observed_held_chirho(
        &self,
    ) -> Result<Gd7ObservedHeldOutcomeChirho, Gd7ReconciliationStoreRefusalChirho> {
        if let Some(active_chirho) = self.load_active_chirho()? {
            return Ok(
                if active_chirho.checkpoint_chirho.state_chirho.phase_chirho
                    == Gd7ReconciliationPhaseChirho::ObservedHeldChirho
                {
                    Gd7ObservedHeldOutcomeChirho::AlreadyObservedChirho(active_chirho)
                } else {
                    Gd7ObservedHeldOutcomeChirho::AlreadyAdvancedChirho(active_chirho)
                },
            );
        }
        self.commit_checkpoint_internal_chirho(
            None,
            super::contract_chirho::observed_held_state_chirho(),
        )
        .map(Gd7ObservedHeldOutcomeChirho::InstalledChirho)
    }

    /// Load and verify the fixed head and its exact immutable checkpoint.
    pub fn load_active_chirho(
        &self,
    ) -> Result<Option<ActiveGd7ReconciliationChirho>, Gd7ReconciliationStoreRefusalChirho> {
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &self.head_path_chirho,
            MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO,
            Gd7ReconciliationStoreRefusalChirho::OversizedHeadChirho,
        )?
        else {
            return Ok(None);
        };
        let head_chirho = parse_and_verify_head_chirho(
            &head_bytes_chirho,
            self.signer_chirho,
            &self.identity_chirho.consistency_group_digest_chirho,
            &self.identity_digest_chirho,
        )?;
        let checkpoint_path_chirho =
            gd7_reconciliation_checkpoint_path_chirho(&head_chirho.active_checkpoint_ref_chirho)?;
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
            Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(Gd7ReconciliationStoreRefusalChirho::MissingReferencedCheckpointChirho)?;
        let checkpoint_chirho = parse_and_verify_checkpoint_chirho(
            &checkpoint_bytes_chirho,
            self.signer_chirho,
            &self.identity_chirho,
            &self.winner_fork_witness_object_digest_chirho,
        )?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho);
        }
        if head_chirho.transition_seq_chirho != checkpoint_chirho.state_chirho.transition_seq_chirho
            || head_chirho.phase_chirho != checkpoint_chirho.state_chirho.phase_chirho
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::HeadCheckpointMismatchChirho);
        }
        Ok(Some(ActiveGd7ReconciliationChirho {
            checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
            checkpoint_chirho,
        }))
    }

    pub(super) fn commit_manifest_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        manifest_page_chirho: &super::manifest_chirho::VerifiedGd7LosingManifestPageChirho,
    ) -> Result<CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho.state_chirho;
        let page_chirho = manifest_page_chirho.page_chirho();
        let page_record_count_chirho =
            u64::try_from(page_chirho.records_newest_first_chirho().len())
                .map_err(|_| Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?;
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho
            || page_chirho.page_index_chirho() != prior_chirho.manifest_page_count_chirho
            || page_chirho.newer_manifest_page_ref_chirho()
                != prior_chirho.manifest_head_ref_chirho.as_deref()
            || page_chirho.reached_anchor_chirho()
                != page_chirho.next_cursor_object_ref_chirho().is_none()
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho);
        }
        let state_chirho = Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::ManifestingChirho,
            transition_seq_chirho: prior_chirho
                .transition_seq_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidTransitionSequenceChirho)?,
            previous_checkpoint_ref_chirho: Some(expected_prior_ref_chirho.to_owned()),
            manifest_head_ref_chirho: Some(manifest_page_chirho.object_digest_chirho().to_owned()),
            manifest_page_count_chirho: prior_chirho
                .manifest_page_count_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?,
            manifest_record_count_chirho: prior_chirho
                .manifest_record_count_chirho
                .checked_add(page_record_count_chirho)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?,
            plan_head_ref_chirho: prior_chirho.plan_head_ref_chirho.clone(),
            plan_page_count_chirho: prior_chirho.plan_page_count_chirho,
            sealed_plan_ref_chirho: None,
            effect_obligation_count_chirho: prior_chirho.effect_obligation_count_chirho,
            cursor_object_ref_chirho: page_chirho
                .next_cursor_object_ref_chirho()
                .map(str::to_owned),
            adoption_binding_chirho: None,
        };
        self.commit_checkpoint_internal_chirho(Some(expected_prior_ref_chirho), state_chirho)
    }

    pub(super) fn commit_plan_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        plan_page_chirho: &super::plan_chirho::VerifiedGd7ReconciliationPlanPageChirho,
    ) -> Result<CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho.state_chirho;
        let page_chirho = plan_page_chirho.page_chirho();
        let manifest_page_chirho =
            super::manifest_chirho::load_verified_gd7_losing_manifest_page_chirho(
                self.storage_chirho,
                page_chirho.manifest_page_ref_chirho(),
                &self.identity_chirho,
            )
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho)?;
        let local_manifest_record_count_chirho = u64::try_from(
            manifest_page_chirho
                .page_chirho()
                .records_newest_first_chirho()
                .len(),
        )
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?;
        let local_effect_obligation_count_chirho =
            u64::try_from(page_chirho.obligations_newest_first_chirho().len())
                .map_err(|_| Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?;
        let (
            expected_cumulative_manifest_record_count_chirho,
            expected_cumulative_effect_obligation_count_chirho,
        ) = if let Some(prior_plan_ref_chirho) = prior_chirho.plan_head_ref_chirho.as_deref() {
            let prior_plan_page_chirho =
                super::plan_chirho::load_verified_gd7_reconciliation_plan_page_chirho(
                    self.storage_chirho,
                    prior_plan_ref_chirho,
                    &self.identity_chirho,
                )
                .map_err(|_| Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho)?;
            if prior_plan_page_chirho
                .page_chirho()
                .page_index_chirho()
                .checked_add(1)
                != Some(page_chirho.page_index_chirho())
                || prior_plan_page_chirho
                    .page_chirho()
                    .cumulative_manifest_page_count_chirho
                    != prior_chirho.plan_page_count_chirho
            {
                return Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho);
            }
            (
                prior_plan_page_chirho
                    .page_chirho()
                    .cumulative_manifest_record_count_chirho
                    .checked_add(local_manifest_record_count_chirho)
                    .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?,
                prior_plan_page_chirho
                    .page_chirho()
                    .cumulative_effect_obligation_count_chirho
                    .checked_add(local_effect_obligation_count_chirho)
                    .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?,
            )
        } else {
            if page_chirho.page_index_chirho() != 0 {
                return Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho);
            }
            (
                local_manifest_record_count_chirho,
                local_effect_obligation_count_chirho,
            )
        };
        let expected_phase_chirho = if page_chirho.reached_anchor_chirho {
            Gd7ReconciliationPhaseChirho::PlanSealedChirho
        } else {
            Gd7ReconciliationPhaseChirho::ManifestingChirho
        };
        let expected_effect_obligation_count_chirho = if page_chirho.reached_anchor_chirho {
            page_chirho.cumulative_effect_obligation_count_chirho
        } else {
            0
        };
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho
            || page_chirho.newer_plan_page_ref_chirho()
                != prior_chirho.plan_head_ref_chirho.as_deref()
            || prior_chirho.manifest_head_ref_chirho.as_deref()
                != Some(page_chirho.manifest_page_ref_chirho())
            || manifest_page_chirho.page_chirho().page_index_chirho()
                != page_chirho.page_index_chirho()
            || manifest_page_chirho.page_chirho().reached_anchor_chirho()
                != page_chirho.reached_anchor_chirho()
            || page_chirho.manifest_record_count_chirho != local_manifest_record_count_chirho
            || page_chirho.cumulative_manifest_page_count_chirho
                != prior_chirho.manifest_page_count_chirho
            || page_chirho.cumulative_manifest_record_count_chirho
                != expected_cumulative_manifest_record_count_chirho
            || page_chirho.cumulative_effect_obligation_count_chirho
                != expected_cumulative_effect_obligation_count_chirho
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho);
        }
        let state_chirho = Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: expected_phase_chirho,
            transition_seq_chirho: prior_chirho
                .transition_seq_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidTransitionSequenceChirho)?,
            previous_checkpoint_ref_chirho: Some(expected_prior_ref_chirho.to_owned()),
            manifest_head_ref_chirho: prior_chirho.manifest_head_ref_chirho.clone(),
            manifest_page_count_chirho: prior_chirho.manifest_page_count_chirho,
            manifest_record_count_chirho: prior_chirho.manifest_record_count_chirho,
            plan_head_ref_chirho: Some(plan_page_chirho.object_digest_chirho().to_owned()),
            plan_page_count_chirho: prior_chirho
                .plan_page_count_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?,
            sealed_plan_ref_chirho: page_chirho
                .reached_anchor_chirho
                .then(|| plan_page_chirho.object_digest_chirho().to_owned()),
            effect_obligation_count_chirho: expected_effect_obligation_count_chirho,
            cursor_object_ref_chirho: prior_chirho.cursor_object_ref_chirho.clone(),
            adoption_binding_chirho: None,
        };
        self.commit_checkpoint_internal_chirho(Some(expected_prior_ref_chirho), state_chirho)
    }

    /// Select the exact immutable Cut A pair while retaining the fixed reconciliation hold head.
    ///
    /// Creating the signed immutable checkpoint is not the commit. The active head is reloaded and
    /// required to still name `expected_prior_ref_chirho` immediately before the atomic head
    /// replacement, so this proves active-at-commit rather than assuming sealed-checkpoint
    /// uniqueness from today's call graph.
    pub(crate) fn commit_adopted_held_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        adoption_binding_chirho: Gd7AdoptionCheckpointBindingChirho,
    ) -> Result<CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho)?;
        let prior_chirho = &active_chirho.checkpoint_chirho.state_chirho;
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho
            || prior_chirho.phase_chirho != Gd7ReconciliationPhaseChirho::PlanSealedChirho
            || adoption_binding_chirho.plan_checkpoint_ref_chirho != expected_prior_ref_chirho
        {
            return Err(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        let state_chirho = Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
            transition_seq_chirho: prior_chirho
                .transition_seq_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidTransitionSequenceChirho)?,
            previous_checkpoint_ref_chirho: Some(expected_prior_ref_chirho.to_owned()),
            manifest_head_ref_chirho: prior_chirho.manifest_head_ref_chirho.clone(),
            manifest_page_count_chirho: prior_chirho.manifest_page_count_chirho,
            manifest_record_count_chirho: prior_chirho.manifest_record_count_chirho,
            plan_head_ref_chirho: prior_chirho.plan_head_ref_chirho.clone(),
            plan_page_count_chirho: prior_chirho.plan_page_count_chirho,
            sealed_plan_ref_chirho: prior_chirho.sealed_plan_ref_chirho.clone(),
            effect_obligation_count_chirho: prior_chirho.effect_obligation_count_chirho,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: Some(adoption_binding_chirho),
        };
        self.commit_checkpoint_internal_chirho(Some(expected_prior_ref_chirho), state_chirho)
    }

    /// Persist one deterministic immutable checkpoint, then move the fixed head atomically.
    ///
    /// The resident authority-generation barrier must serialize callers around this operation.
    /// The storage port supplies atomic whole-object replacement, while this method verifies the
    /// expected prior immediately before that replacement.
    fn commit_checkpoint_internal_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        state_chirho: Gd7ReconciliationCheckpointStateChirho,
    ) -> Result<CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        if state_chirho.previous_checkpoint_ref_chirho.as_deref() != expected_prior_ref_chirho {
            return Err(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        let prepared_chirho = self.prepare_checkpoint_chirho(state_chirho)?;
        let checkpoint_path_chirho =
            gd7_reconciliation_checkpoint_path_chirho(&prepared_chirho.checkpoint_ref_chirho)?;
        match self
            .storage_chirho
            .create_durable_chirho(
                &checkpoint_path_chirho,
                &prepared_chirho.canonical_bytes_chirho,
            )
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
        {
            CreateDurableOutcomeChirho::CreatedChirho => {}
            CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_chirho = read_bounded_chirho(
                    self.storage_chirho,
                    &checkpoint_path_chirho,
                    MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO,
                    Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho,
                )?
                .ok_or(Gd7ReconciliationStoreRefusalChirho::ImmutableCollisionChirho)?;
                if existing_chirho != prepared_chirho.canonical_bytes_chirho {
                    return Err(Gd7ReconciliationStoreRefusalChirho::ImmutableCollisionChirho);
                }
            }
        }

        // This reload-and-write pair is not a storage CAS; its indivisibility depends on the
        // resident actor mailbox remaining the sole production writer.
        let active_chirho = self.load_active_chirho()?;
        if active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            == Some(prepared_chirho.checkpoint_ref_chirho.as_str())
        {
            return Ok(committed_from_prepared_chirho(prepared_chirho));
        }
        let actual_prior_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str());
        if actual_prior_chirho != expected_prior_ref_chirho {
            return Err(Gd7ReconciliationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        validate_transition_chirho(
            active_chirho.as_ref(),
            &prepared_chirho.checkpoint_chirho.state_chirho,
        )?;

        let head_bytes_chirho = self.canonical_signed_head_chirho(
            &prepared_chirho.checkpoint_ref_chirho,
            &prepared_chirho.checkpoint_chirho.state_chirho,
        )?;
        // SIBLING FIRST, THEN HEAD — the strand-safe direction, and the ordering is the whole
        // safety argument. A crash between the two leaves the ordinary-write hold standing with no
        // active head: writes are withheld with no reconciliation in flight, which is recoverable
        // by an operator and costs only availability. The reverse order would leave a head with no
        // ordinary-write hold, so D3's release would re-admit ordinary writes with no D4
        // confirmation — the exact property this barrier exists to deny. Availability loss is the
        // survivable failure here; silent write admission is not.
        plant_gd7_ordinary_write_hold_chirho(
            self.storage_chirho,
            &self.identity_chirho.consistency_group_digest_chirho,
        )?;
        self.storage_chirho
            .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?;
        Ok(committed_from_prepared_chirho(prepared_chirho))
    }

    #[cfg(test)]
    pub(crate) fn commit_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        state_chirho: Gd7ReconciliationCheckpointStateChirho,
    ) -> Result<CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        self.commit_checkpoint_internal_chirho(expected_prior_ref_chirho, state_chirho)
    }

    pub(crate) fn prepare_checkpoint_chirho(
        &self,
        state_chirho: Gd7ReconciliationCheckpointStateChirho,
    ) -> Result<PreparedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho>
    {
        if !validate_checkpoint_state_chirho(&state_chirho) {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointStateChirho);
        }
        let key_id_chirho = self.signer_chirho.key_id_chirho();
        if !is_bounded_label_chirho(&key_id_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO) {
            return Err(Gd7ReconciliationStoreRefusalChirho::SigningChirho);
        }
        let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
            schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: self.identity_chirho.clone(),
            winner_fork_witness_object_digest_chirho: self
                .winner_fork_witness_object_digest_chirho
                .clone(),
            state_chirho,
            key_id_chirho,
            sig_chirho: String::new(),
        };
        let signing_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SerializationChirho)?;
        checkpoint_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(signing_line_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SigningChirho)?;
        if !validate_key_and_signature_chirho(
            &checkpoint_chirho.key_id_chirho,
            &checkpoint_chirho.sig_chirho,
        ) {
            return Err(Gd7ReconciliationStoreRefusalChirho::SigningChirho);
        }
        let canonical_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        if canonical_bytes_chirho.len() > MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO {
            return Err(Gd7ReconciliationStoreRefusalChirho::OversizedCheckpointChirho);
        }
        Ok(PreparedGd7ReconciliationCheckpointChirho {
            checkpoint_ref_chirho: digest_bytes_chirho(&canonical_bytes_chirho),
            checkpoint_chirho,
            canonical_bytes_chirho,
        })
    }

    fn canonical_signed_head_chirho(
        &self,
        checkpoint_ref_chirho: &str,
        state_chirho: &Gd7ReconciliationCheckpointStateChirho,
    ) -> Result<Vec<u8>, Gd7ReconciliationStoreRefusalChirho> {
        let mut head_chirho = Gd7ReconciliationHeadChirho {
            schema_chirho: GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self
                .identity_chirho
                .consistency_group_digest_chirho
                .clone(),
            reconciliation_identity_digest_chirho: self.identity_digest_chirho.clone(),
            active_checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            transition_seq_chirho: state_chirho.transition_seq_chirho,
            phase_chirho: state_chirho.phase_chirho,
            key_id_chirho: self.signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        let signing_bytes_chirho = canonical_json_chirho(&head_chirho)?;
        let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SerializationChirho)?;
        head_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(signing_line_chirho)
            .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SigningChirho)?;
        if !validate_key_and_signature_chirho(&head_chirho.key_id_chirho, &head_chirho.sig_chirho) {
            return Err(Gd7ReconciliationStoreRefusalChirho::SigningChirho);
        }
        let bytes_chirho = canonical_json_chirho(&head_chirho)?;
        if bytes_chirho.len() > MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO {
            return Err(Gd7ReconciliationStoreRefusalChirho::OversizedHeadChirho);
        }
        Ok(bytes_chirho)
    }
}

fn committed_from_prepared_chirho(
    prepared_chirho: PreparedGd7ReconciliationCheckpointChirho,
) -> CommittedGd7ReconciliationCheckpointChirho {
    CommittedGd7ReconciliationCheckpointChirho {
        checkpoint_ref_chirho: prepared_chirho.checkpoint_ref_chirho,
        checkpoint_chirho: prepared_chirho.checkpoint_chirho,
    }
}

fn validate_transition_chirho(
    active_chirho: Option<&ActiveGd7ReconciliationChirho>,
    next_chirho: &Gd7ReconciliationCheckpointStateChirho,
) -> Result<(), Gd7ReconciliationStoreRefusalChirho> {
    let Some(active_chirho) = active_chirho else {
        if next_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::ObservedHeldChirho
            && next_chirho.transition_seq_chirho == 0
        {
            return Ok(());
        }
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho);
    };
    let prior_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    if next_chirho.transition_seq_chirho
        != prior_chirho
            .transition_seq_chirho
            .checked_add(1)
            .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidTransitionSequenceChirho)?
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidTransitionSequenceChirho);
    }
    let phase_valid_chirho = matches!(
        (prior_chirho.phase_chirho, next_chirho.phase_chirho),
        (
            Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
            Gd7ReconciliationPhaseChirho::ManifestingChirho
        ) | (
            Gd7ReconciliationPhaseChirho::ManifestingChirho,
            Gd7ReconciliationPhaseChirho::ManifestingChirho
        ) | (
            Gd7ReconciliationPhaseChirho::ManifestingChirho,
            Gd7ReconciliationPhaseChirho::PlanSealedChirho
        ) | (
            Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
        )
    );
    if !phase_valid_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho);
    }
    if prior_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho
        && next_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
    {
        let exact_preservation_chirho = next_chirho.previous_checkpoint_ref_chirho.as_deref()
            == Some(active_chirho.checkpoint_ref_chirho.as_str())
            && next_chirho.manifest_head_ref_chirho == prior_chirho.manifest_head_ref_chirho
            && next_chirho.manifest_page_count_chirho == prior_chirho.manifest_page_count_chirho
            && next_chirho.manifest_record_count_chirho
                == prior_chirho.manifest_record_count_chirho
            && next_chirho.plan_head_ref_chirho == prior_chirho.plan_head_ref_chirho
            && next_chirho.plan_page_count_chirho == prior_chirho.plan_page_count_chirho
            && next_chirho.sealed_plan_ref_chirho == prior_chirho.sealed_plan_ref_chirho
            && next_chirho.effect_obligation_count_chirho
                == prior_chirho.effect_obligation_count_chirho
            && next_chirho.cursor_object_ref_chirho.is_none()
            && next_chirho
                .adoption_binding_chirho
                .as_ref()
                .is_some_and(|binding_chirho| {
                    binding_chirho.plan_checkpoint_ref_chirho == active_chirho.checkpoint_ref_chirho
                });
        return exact_preservation_chirho
            .then_some(())
            .ok_or(Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho);
    }
    if next_chirho.manifest_page_count_chirho < prior_chirho.manifest_page_count_chirho
        || next_chirho.manifest_record_count_chirho < prior_chirho.manifest_record_count_chirho
        || next_chirho.plan_page_count_chirho < prior_chirho.plan_page_count_chirho
        || next_chirho.effect_obligation_count_chirho < prior_chirho.effect_obligation_count_chirho
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho);
    }
    let manifest_advanced_chirho = next_chirho.manifest_page_count_chirho
        == prior_chirho
            .manifest_page_count_chirho
            .checked_add(1)
            .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?
        && next_chirho.manifest_head_ref_chirho != prior_chirho.manifest_head_ref_chirho
        && next_chirho.plan_page_count_chirho == prior_chirho.plan_page_count_chirho
        && next_chirho.plan_head_ref_chirho == prior_chirho.plan_head_ref_chirho
        && next_chirho.effect_obligation_count_chirho
            == prior_chirho.effect_obligation_count_chirho
        && next_chirho.manifest_record_count_chirho > prior_chirho.manifest_record_count_chirho;
    let plan_advanced_chirho = next_chirho.manifest_page_count_chirho
        == prior_chirho.manifest_page_count_chirho
        && next_chirho.manifest_record_count_chirho == prior_chirho.manifest_record_count_chirho
        && next_chirho.manifest_head_ref_chirho == prior_chirho.manifest_head_ref_chirho
        && next_chirho.cursor_object_ref_chirho == prior_chirho.cursor_object_ref_chirho
        && next_chirho.plan_page_count_chirho
            == prior_chirho
                .plan_page_count_chirho
                .checked_add(1)
                .ok_or(Gd7ReconciliationStoreRefusalChirho::ManifestCountRegressionChirho)?
        && next_chirho.plan_head_ref_chirho != prior_chirho.plan_head_ref_chirho
        && (next_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho
            || next_chirho.effect_obligation_count_chirho
                == prior_chirho.effect_obligation_count_chirho);
    if prior_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::ObservedHeldChirho {
        if !manifest_advanced_chirho {
            return Err(Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho);
        }
    } else if !(manifest_advanced_chirho || plan_advanced_chirho) {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidPhaseTransitionChirho);
    }
    Ok(())
}

fn parse_and_verify_head_chirho(
    bytes_chirho: &[u8],
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    expected_group_digest_chirho: &str,
    expected_identity_digest_chirho: &str,
) -> Result<Gd7ReconciliationHeadChirho, Gd7ReconciliationStoreRefusalChirho> {
    let head_chirho: Gd7ReconciliationHeadChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::MalformedHeadChirho)?;
    if canonical_json_chirho(&head_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::NonCanonicalHeadChirho);
    }
    if head_chirho.schema_chirho != GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO
        || consistency_group_digest_suffix_chirho(&head_chirho.consistency_group_digest_chirho)
            .is_none()
        || !is_lower_hex_digest_chirho(&head_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
        || !validate_key_and_signature_chirho(&head_chirho.key_id_chirho, &head_chirho.sig_chirho)
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::MalformedHeadChirho);
    }
    if head_chirho.consistency_group_digest_chirho != expected_group_digest_chirho
        || head_chirho.reconciliation_identity_digest_chirho != expected_identity_digest_chirho
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho);
    }
    verify_signature_chirho(
        verifier_chirho,
        &head_chirho.key_id_chirho,
        &head_chirho.sig_chirho,
        head_chirho.clone(),
        |unsigned_chirho| &mut unsigned_chirho.sig_chirho,
        Gd7ReconciliationStoreRefusalChirho::InvalidHeadSignatureChirho,
    )?;
    Ok(head_chirho)
}

fn parse_and_verify_checkpoint_chirho(
    bytes_chirho: &[u8],
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    expected_winner_fork_witness_object_digest_chirho: &str,
) -> Result<Gd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreRefusalChirho> {
    let checkpoint_chirho: Gd7ReconciliationCheckpointChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::MalformedCheckpointChirho)?;
    if canonical_json_chirho(&checkpoint_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::NonCanonicalCheckpointChirho);
    }
    if checkpoint_chirho.schema_chirho != GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO
        || !validate_identity_chirho(&checkpoint_chirho.identity_chirho)
        || !is_lower_hex_digest_chirho(&checkpoint_chirho.winner_fork_witness_object_digest_chirho)
        || !validate_checkpoint_state_chirho(&checkpoint_chirho.state_chirho)
        || !validate_key_and_signature_chirho(
            &checkpoint_chirho.key_id_chirho,
            &checkpoint_chirho.sig_chirho,
        )
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::MalformedCheckpointChirho);
    }
    if checkpoint_chirho.identity_chirho != *expected_identity_chirho {
        return Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho);
    }
    if checkpoint_chirho.winner_fork_witness_object_digest_chirho
        != expected_winner_fork_witness_object_digest_chirho
    {
        return Err(Gd7ReconciliationStoreRefusalChirho::WinnerWitnessMismatchChirho);
    }
    verify_signature_chirho(
        verifier_chirho,
        &checkpoint_chirho.key_id_chirho,
        &checkpoint_chirho.sig_chirho,
        checkpoint_chirho.clone(),
        |unsigned_chirho| &mut unsigned_chirho.sig_chirho,
        Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointSignatureChirho,
    )?;
    Ok(checkpoint_chirho)
}

fn verify_signature_chirho<RecordChirho>(
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    key_id_chirho: &str,
    signature_chirho: &str,
    mut unsigned_chirho: RecordChirho,
    signature_field_chirho: impl FnOnce(&mut RecordChirho) -> &mut String,
    invalid_signature_chirho: Gd7ReconciliationStoreRefusalChirho,
) -> Result<(), Gd7ReconciliationStoreRefusalChirho>
where
    RecordChirho: serde::Serialize,
{
    if key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7ReconciliationStoreRefusalChirho::SignerKeyMismatchChirho);
    }
    signature_field_chirho(&mut unsigned_chirho).clear();
    let signing_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(signing_line_chirho, signature_chirho) {
        return Err(invalid_signature_chirho);
    }
    Ok(())
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7ReconciliationStoreRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7ReconciliationStoreRefusalChirho> {
    let Some(len_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if len_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    if len_chirho == 0 {
        return Ok(Some(Vec::new()));
    }
    let bytes_chirho = storage_chirho
        .read_exact_range_chirho(path_chirho, 0, len_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != len_chirho as usize {
        return Err(Gd7ReconciliationStoreRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}

pub fn gd7_reconciliation_identity_digest_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<String, Gd7ReconciliationStoreRefusalChirho> {
    if !validate_identity_chirho(identity_chirho) {
        return Err(Gd7ReconciliationStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(digest_bytes_chirho(&canonical_json_chirho(
        identity_chirho,
    )?))
}

fn canonical_json_chirho(
    value_chirho: &impl serde::Serialize,
) -> Result<Vec<u8>, Gd7ReconciliationStoreRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| Gd7ReconciliationStoreRefusalChirho::SerializationChirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
