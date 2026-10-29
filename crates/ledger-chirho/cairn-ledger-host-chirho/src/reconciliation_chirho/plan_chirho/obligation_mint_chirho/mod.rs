// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Opaque runtime mint for one exact losing-effect obligation from an adopted GD7 sealed plan.
//!
//! This mechanism has no production call site until item 5b composes mint, current-winner
//! authorization, sink fencing, and compensation resume inside one persistent actor operation. A
//! durable receipt can outlive delivery of the runtime value; that is the inherent durable-record
//! versus caller-delivery window, not a terminal outcome. Item 5b may re-derive the affine value
//! from this receipt only after repeating the identical full verification. Opacity means callers
//! cannot mint from caller-supplied data; it does not forbid recovery from verified durable state.
//!
//! The historical winner term bound here is evidence provenance. It is deliberately not the
//! current elected winner term that item 5b must bind into `VerifiedEffectCompensationChirho` for
//! the sink fence. This module performs no provider call, journal append, ref movement, barrier
//! release, or write enablement.
//!
//! Receipt addressing binds the adopted reconciliation and canonical obligation content, not the
//! caller's selector or the verified plan position. The selector only locates a fully verified
//! obligation; its verified page/index coordinates remain signed receipt provenance. If a future
//! verifier ever duplicates one semantic obligation at two positions, both attempts therefore
//! converge on one receipt path and the provenance mismatch refuses rather than minting twice.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::contract_chirho::{
    Gd7EffectLineageChirho, Gd7EffectPlanObligationChirho, Gd7EffectPlanObligationKindChirho,
    Gd7PlanRefusalChirho,
};
use super::object_chirho::{digest_bytes_chirho, read_bounded_optional_chirho};
use crate::reconciliation_chirho::contract_chirho::{
    is_bounded_label_chirho, is_lower_hex_digest_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
    MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO,
};
use crate::reconciliation_chirho::Gd7ReconciliationSignerPortChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
const GD7_LOSING_EFFECT_OBLIGATION_BINDING_SCHEMA_V1_CHIRHO: &str =
    "gd7-losing-effect-obligation-binding-v1-chirho";
const GD7_LOSING_EFFECT_OBLIGATION_MINT_IDENTITY_SCHEMA_V1_CHIRHO: &str =
    "gd7-losing-effect-obligation-mint-identity-v1-chirho";
const GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_SCHEMA_V1_CHIRHO: &str =
    "gd7-losing-effect-obligation-mint-receipt-v1-chirho";
const MAX_GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_BYTES_CHIRHO: usize = 64 * 1024;

/// Plain read-only coordinate used to select an obligation from the complete verified plan.
///
/// This selector carries no authority. A page with a genuine digest is still refused unless the
/// whole-plan traversal reaches it through the exact adopted `PlanSealedChirho` chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7LosingEffectObligationSelectorChirho {
    pub(super) plan_page_ref_chirho: String,
    pub(super) obligation_index_chirho: u64,
}

impl Gd7LosingEffectObligationSelectorChirho {
    pub fn new_chirho(
        plan_page_ref_chirho: impl Into<String>,
        obligation_index_chirho: u64,
    ) -> Result<Self, Gd7LosingEffectObligationMintRefusalChirho> {
        let plan_page_ref_chirho = plan_page_ref_chirho.into();
        if !is_lower_hex_digest_chirho(&plan_page_ref_chirho) {
            return Err(Gd7LosingEffectObligationMintRefusalChirho::InvalidSelectorChirho);
        }
        Ok(Self {
            plan_page_ref_chirho,
            obligation_index_chirho,
        })
    }

    pub fn plan_page_ref_chirho(&self) -> &str {
        &self.plan_page_ref_chirho
    }

    pub fn obligation_index_chirho(&self) -> u64 {
        self.obligation_index_chirho
    }
}

/// Terminal coordinate carried by the opaque mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7LosingEffectObligationTerminalStateChirho {
    CommittedFinalizeChirho,
    InDoubtNoTerminalChirho,
}

/// Opaque affine proof that one exact adopted sealed-plan obligation was durably minted.
///
/// This deliberately differs from the reusable, `Clone`-capable
/// `VerifiedEffectCompensationChirho`: cloning a once-only historical obligation is itself the
/// exactly-one failure. Public accessors borrow coordinates; construction remains private.
///
/// The type cannot be deserialized:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::reconciliation_chirho::MintedGd7LosingEffectObligationChirho;
/// fn require_deserialize_chirho<T: serde::de::DeserializeOwned>() {}
/// require_deserialize_chirho::<MintedGd7LosingEffectObligationChirho>();
/// ```
///
/// It has no default value:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::reconciliation_chirho::MintedGd7LosingEffectObligationChirho;
/// let _forged_chirho = MintedGd7LosingEffectObligationChirho::default();
/// ```
///
/// It cannot be cloned:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::reconciliation_chirho::MintedGd7LosingEffectObligationChirho;
/// fn require_clone_chirho<T: Clone>() {}
/// require_clone_chirho::<MintedGd7LosingEffectObligationChirho>();
/// ```
///
/// Its fields cannot be named by a caller:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::reconciliation_chirho::MintedGd7LosingEffectObligationChirho;
/// fn inspect_private_chirho(value_chirho: &MintedGd7LosingEffectObligationChirho) -> &str {
///     &value_chirho.receipt_ref_chirho
/// }
/// ```
pub struct MintedGd7LosingEffectObligationChirho {
    receipt_ref_chirho: String,
    mint_identity_digest_chirho: String,
    binding_chirho: Gd7LosingEffectObligationBindingChirho,
    obligation_chirho: Gd7EffectPlanObligationChirho,
}

impl MintedGd7LosingEffectObligationChirho {
    pub fn receipt_ref_chirho(&self) -> &str {
        &self.receipt_ref_chirho
    }

    pub fn mint_identity_digest_chirho(&self) -> &str {
        &self.mint_identity_digest_chirho
    }

    pub fn reconciliation_identity_digest_chirho(&self) -> &str {
        &self.binding_chirho.reconciliation_identity_digest_chirho
    }

    pub fn adopted_checkpoint_ref_chirho(&self) -> &str {
        &self.binding_chirho.adopted_checkpoint_ref_chirho
    }

    pub fn plan_checkpoint_ref_chirho(&self) -> &str {
        &self.binding_chirho.plan_checkpoint_ref_chirho
    }

    pub fn sealed_plan_ref_chirho(&self) -> &str {
        &self.binding_chirho.sealed_plan_ref_chirho
    }

    pub fn historical_winner_term_chirho(&self) -> u64 {
        self.binding_chirho.historical_winner_term_chirho
    }

    pub fn kind_chirho(&self) -> Gd7EffectPlanObligationKindChirho {
        self.binding_chirho.kind_chirho
    }

    pub fn lineage_chirho(&self) -> Gd7EffectLineageChirho {
        self.binding_chirho.lineage_chirho
    }

    pub fn original_effect_key_chirho(&self) -> Option<&str> {
        self.binding_chirho.original_effect_key_chirho.as_deref()
    }

    pub fn terminal_state_chirho(&self) -> Gd7LosingEffectObligationTerminalStateChirho {
        self.binding_chirho.terminal_state_chirho
    }

    pub fn terminal_marker_object_digest_chirho(&self) -> Option<&str> {
        self.binding_chirho
            .terminal_marker_object_digest_chirho
            .as_deref()
    }

    pub fn source_seq_chirho(&self) -> u64 {
        self.binding_chirho.source_seq_chirho
    }

    pub fn source_record_digest_chirho(&self) -> &str {
        &self.binding_chirho.source_record_digest_chirho
    }

    pub fn canonical_obligation_digest_chirho(&self) -> &str {
        &self.binding_chirho.canonical_obligation_digest_chirho
    }

    pub fn plan_page_ref_chirho(&self) -> &str {
        &self.binding_chirho.plan_page_ref_chirho
    }

    pub fn plan_page_index_chirho(&self) -> u64 {
        self.binding_chirho.plan_page_index_chirho
    }

    pub fn obligation_index_chirho(&self) -> u64 {
        self.binding_chirho.obligation_index_chirho
    }

    pub fn obligation_chirho(&self) -> &Gd7EffectPlanObligationChirho {
        &self.obligation_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7LosingEffectObligationMintRefusalChirho {
    InvalidSelectorChirho,
    InvalidAdoptionBindingChirho,
    AdoptionChangedBeforeMintChirho,
    AdoptionChangedAfterMintChirho { receipt_ref_chirho: String },
    ObligationBindingMismatchChirho,
    MintedAwaitingConsumptionChirho { receipt_ref_chirho: String },
    MalformedMintReceiptChirho,
    NonCanonicalMintReceiptChirho,
    OversizedMintReceiptChirho,
    InvalidMintReceiptSignatureChirho,
    MintReceiptCollisionChirho,
    PlanChirho(Gd7PlanRefusalChirho),
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7LosingEffectObligationMintRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelectorChirho => {
                formatter_chirho.write_str("GD7 losing-effect obligation selector is invalid")
            }
            Self::InvalidAdoptionBindingChirho => formatter_chirho
                .write_str("GD7 losing-effect obligation does not match the adopted sealed plan"),
            Self::AdoptionChangedBeforeMintChirho => formatter_chirho
                .write_str("GD7 adopted selector changed before obligation mint"),
            Self::AdoptionChangedAfterMintChirho { receipt_ref_chirho } => write!(
                formatter_chirho,
                "GD7 adopted selector changed after durable obligation mint receipt {receipt_ref_chirho}; receipt is awaiting verified item-5b resume"
            ),
            Self::ObligationBindingMismatchChirho => formatter_chirho
                .write_str("GD7 losing-effect obligation binding differs from the sealed-plan value"),
            Self::MintedAwaitingConsumptionChirho { receipt_ref_chirho } => write!(
                formatter_chirho,
                "GD7 losing-effect obligation receipt {receipt_ref_chirho} is minted and awaiting verified item-5b consumption"
            ),
            Self::MalformedMintReceiptChirho => {
                formatter_chirho.write_str("GD7 obligation mint receipt is malformed")
            }
            Self::NonCanonicalMintReceiptChirho => {
                formatter_chirho.write_str("GD7 obligation mint receipt is not canonical")
            }
            Self::OversizedMintReceiptChirho => {
                formatter_chirho.write_str("GD7 obligation mint receipt exceeds its fixed bound")
            }
            Self::InvalidMintReceiptSignatureChirho => {
                formatter_chirho.write_str("GD7 obligation mint receipt signature is invalid")
            }
            Self::MintReceiptCollisionChirho => formatter_chirho
                .write_str("GD7 obligation mint identity collided with different durable bytes"),
            Self::PlanChirho(error_chirho) => {
                write!(formatter_chirho, "GD7 sealed plan refused obligation mint: {error_chirho}")
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 obligation mint serialization failed")
            }
            Self::SigningChirho => {
                formatter_chirho.write_str("GD7 obligation mint receipt signing failed")
            }
            Self::StorageChirho => {
                formatter_chirho.write_str("GD7 obligation mint storage operation failed")
            }
        }
    }
}

impl Error for Gd7LosingEffectObligationMintRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PlanChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7PlanRefusalChirho> for Gd7LosingEffectObligationMintRefusalChirho {
    fn from(error_chirho: Gd7PlanRefusalChirho) -> Self {
        Self::PlanChirho(error_chirho)
    }
}

/// Verified sealed-plan selection passed across the plan sibling boundary.
///
/// The value is cloneable verified evidence, not the affine runtime mint. The affine type is
/// `MintedGd7LosingEffectObligationChirho`, whose fields are private and whose compile-fail arms
/// reject cloning and caller construction.
///
/// Sibling modules may consume this value through accessors but cannot construct it:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::reconciliation_chirho::plan_chirho::VerifiedGd7SealedPlanObligationChirho;
/// let _forged_chirho = VerifiedGd7SealedPlanObligationChirho {
///     plan_page_ref_chirho: String::new(),
///     plan_page_index_chirho: 0,
///     obligation_index_chirho: 0,
///     obligation_chirho: panic!("not a real obligation"),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedGd7SealedPlanObligationChirho {
    plan_page_ref_chirho: String,
    plan_page_index_chirho: u64,
    obligation_index_chirho: u64,
    obligation_chirho: Gd7EffectPlanObligationChirho,
}

impl VerifiedGd7SealedPlanObligationChirho {
    pub(crate) fn plan_page_ref_chirho(&self) -> &str {
        &self.plan_page_ref_chirho
    }

    pub(crate) fn plan_page_index_chirho(&self) -> u64 {
        self.plan_page_index_chirho
    }

    pub(crate) fn obligation_index_chirho(&self) -> u64 {
        self.obligation_index_chirho
    }

    pub(crate) fn obligation_chirho(&self) -> &Gd7EffectPlanObligationChirho {
        &self.obligation_chirho
    }
}

pub(super) fn verified_gd7_sealed_plan_obligation_chirho(
    plan_page_ref_chirho: String,
    plan_page_index_chirho: u64,
    obligation_index_chirho: u64,
    obligation_chirho: Gd7EffectPlanObligationChirho,
) -> VerifiedGd7SealedPlanObligationChirho {
    VerifiedGd7SealedPlanObligationChirho {
        plan_page_ref_chirho,
        plan_page_index_chirho,
        obligation_index_chirho,
        obligation_chirho,
    }
}

#[cfg(test)]
pub(crate) fn verified_gd7_sealed_plan_obligation_for_test_chirho(
    plan_page_ref_chirho: String,
    plan_page_index_chirho: u64,
    obligation_index_chirho: u64,
    obligation_chirho: Gd7EffectPlanObligationChirho,
) -> VerifiedGd7SealedPlanObligationChirho {
    verified_gd7_sealed_plan_obligation_chirho(
        plan_page_ref_chirho,
        plan_page_index_chirho,
        obligation_index_chirho,
        obligation_chirho,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7LosingEffectObligationBindingChirho {
    schema_chirho: String,
    reconciliation_identity_digest_chirho: String,
    adopted_checkpoint_ref_chirho: String,
    plan_checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    plan_page_ref_chirho: String,
    plan_page_index_chirho: u64,
    obligation_index_chirho: u64,
    historical_winner_term_chirho: u64,
    kind_chirho: Gd7EffectPlanObligationKindChirho,
    lineage_chirho: Gd7EffectLineageChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_effect_key_chirho: Option<String>,
    terminal_state_chirho: Gd7LosingEffectObligationTerminalStateChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_marker_object_digest_chirho: Option<String>,
    source_seq_chirho: u64,
    source_record_digest_chirho: String,
    canonical_obligation_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct Gd7LosingEffectObligationMintIdentityChirho {
    schema_chirho: String,
    reconciliation_identity_digest_chirho: String,
    adopted_checkpoint_ref_chirho: String,
    plan_checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    canonical_obligation_digest_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Gd7LosingEffectObligationMintReceiptStateChirho {
    MintedAwaitingConsumptionChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7LosingEffectObligationMintReceiptChirho {
    schema_chirho: String,
    state_chirho: Gd7LosingEffectObligationMintReceiptStateChirho,
    reconciliation_identity_digest_chirho: String,
    adopted_checkpoint_ref_chirho: String,
    plan_checkpoint_ref_chirho: String,
    sealed_plan_ref_chirho: String,
    plan_page_ref_chirho: String,
    plan_page_index_chirho: u64,
    obligation_index_chirho: u64,
    mint_identity_digest_chirho: String,
    canonical_obligation_digest_chirho: String,
    key_id_chirho: String,
    sig_chirho: String,
}

pub fn gd7_losing_effect_obligation_mint_receipt_path_chirho(
    mint_identity_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7LosingEffectObligationMintRefusalChirho> {
    if !is_lower_hex_digest_chirho(mint_identity_digest_chirho) {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::InvalidSelectorChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/losing-effect-obligation-mints-chirho/{}/{}/{mint_identity_digest_chirho}.json",
        &mint_identity_digest_chirho[..2],
        &mint_identity_digest_chirho[2..4],
    )))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the mint binds the actor-verified adoption and exact plan coordinates without introducing a forgeable aggregate input"
)]
pub(crate) fn claim_verified_gd7_losing_effect_obligation_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    adopted_checkpoint_ref_chirho: &str,
    plan_checkpoint_ref_chirho: &str,
    sealed_plan_ref_chirho: &str,
    reconciliation_identity_digest_chirho: &str,
    historical_winner_term_chirho: u64,
    verified_obligation_chirho: VerifiedGd7SealedPlanObligationChirho,
) -> Result<MintedGd7LosingEffectObligationChirho, Gd7LosingEffectObligationMintRefusalChirho> {
    claim_verified_gd7_losing_effect_obligation_internal_chirho(
        storage_chirho,
        held_signer_chirho,
        adopted_checkpoint_ref_chirho,
        plan_checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        reconciliation_identity_digest_chirho,
        historical_winner_term_chirho,
        verified_obligation_chirho,
        |_binding_chirho| {},
    )
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "the hostile arm changes one derived binding only after the real verifier produced it"
)]
fn claim_verified_gd7_losing_effect_obligation_with_binding_transform_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    adopted_checkpoint_ref_chirho: &str,
    plan_checkpoint_ref_chirho: &str,
    sealed_plan_ref_chirho: &str,
    reconciliation_identity_digest_chirho: &str,
    historical_winner_term_chirho: u64,
    verified_obligation_chirho: VerifiedGd7SealedPlanObligationChirho,
    transform_chirho: impl FnOnce(&mut Gd7LosingEffectObligationBindingChirho),
) -> Result<MintedGd7LosingEffectObligationChirho, Gd7LosingEffectObligationMintRefusalChirho> {
    claim_verified_gd7_losing_effect_obligation_internal_chirho(
        storage_chirho,
        held_signer_chirho,
        adopted_checkpoint_ref_chirho,
        plan_checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        reconciliation_identity_digest_chirho,
        historical_winner_term_chirho,
        verified_obligation_chirho,
        transform_chirho,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the mint binds the actor-verified adoption and exact plan coordinates without introducing a forgeable aggregate input"
)]
fn claim_verified_gd7_losing_effect_obligation_internal_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    adopted_checkpoint_ref_chirho: &str,
    plan_checkpoint_ref_chirho: &str,
    sealed_plan_ref_chirho: &str,
    reconciliation_identity_digest_chirho: &str,
    historical_winner_term_chirho: u64,
    verified_obligation_chirho: VerifiedGd7SealedPlanObligationChirho,
    transform_chirho: impl FnOnce(&mut Gd7LosingEffectObligationBindingChirho),
) -> Result<MintedGd7LosingEffectObligationChirho, Gd7LosingEffectObligationMintRefusalChirho> {
    if !is_lower_hex_digest_chirho(adopted_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(plan_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(sealed_plan_ref_chirho)
        || !is_lower_hex_digest_chirho(reconciliation_identity_digest_chirho)
        || historical_winner_term_chirho == 0
    {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::InvalidAdoptionBindingChirho);
    }
    let expected_binding_chirho = derive_obligation_binding_chirho(
        adopted_checkpoint_ref_chirho,
        plan_checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        reconciliation_identity_digest_chirho,
        historical_winner_term_chirho,
        &verified_obligation_chirho,
    )?;
    let mut candidate_binding_chirho = expected_binding_chirho.clone();
    transform_chirho(&mut candidate_binding_chirho);
    require_exact_obligation_binding_chirho(&candidate_binding_chirho, &expected_binding_chirho)?;
    let mint_identity_digest_chirho =
        derive_obligation_mint_identity_digest_chirho(&candidate_binding_chirho)?;
    let path_chirho =
        gd7_losing_effect_obligation_mint_receipt_path_chirho(&mint_identity_digest_chirho)?;
    let expected_receipt_chirho = sign_mint_receipt_chirho(
        held_signer_chirho,
        &candidate_binding_chirho,
        &mint_identity_digest_chirho,
    )?;
    let receipt_bytes_chirho = canonical_json_chirho(&expected_receipt_chirho)?;
    if receipt_bytes_chirho.len() > MAX_GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_BYTES_CHIRHO {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::OversizedMintReceiptChirho);
    }

    if let Some(existing_bytes_chirho) =
        read_mint_receipt_optional_chirho(storage_chirho, &path_chirho)?
    {
        let existing_chirho =
            verify_mint_receipt_bytes_chirho(&existing_bytes_chirho, held_signer_chirho)?;
        require_same_receipt_identity_chirho(&existing_chirho, &expected_receipt_chirho)?;
        return Err(
            Gd7LosingEffectObligationMintRefusalChirho::MintedAwaitingConsumptionChirho {
                receipt_ref_chirho: digest_bytes_chirho(&existing_bytes_chirho),
            },
        );
    }

    match storage_chirho
        .create_durable_chirho(&path_chirho, &receipt_bytes_chirho)
        .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => {
            verify_mint_receipt_bytes_chirho(&receipt_bytes_chirho, held_signer_chirho)?;
            Ok(MintedGd7LosingEffectObligationChirho {
                receipt_ref_chirho: digest_bytes_chirho(&receipt_bytes_chirho),
                mint_identity_digest_chirho,
                binding_chirho: candidate_binding_chirho,
                obligation_chirho: verified_obligation_chirho.obligation_chirho().clone(),
            })
        }
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_bytes_chirho =
                read_mint_receipt_optional_chirho(storage_chirho, &path_chirho)?
                    .ok_or(Gd7LosingEffectObligationMintRefusalChirho::StorageChirho)?;
            let existing_chirho =
                verify_mint_receipt_bytes_chirho(&existing_bytes_chirho, held_signer_chirho)?;
            require_same_receipt_identity_chirho(&existing_chirho, &expected_receipt_chirho)?;
            Err(
                Gd7LosingEffectObligationMintRefusalChirho::MintedAwaitingConsumptionChirho {
                    receipt_ref_chirho: digest_bytes_chirho(&existing_bytes_chirho),
                },
            )
        }
    }
}

fn derive_obligation_binding_chirho(
    adopted_checkpoint_ref_chirho: &str,
    plan_checkpoint_ref_chirho: &str,
    sealed_plan_ref_chirho: &str,
    reconciliation_identity_digest_chirho: &str,
    historical_winner_term_chirho: u64,
    verified_obligation_chirho: &VerifiedGd7SealedPlanObligationChirho,
) -> Result<Gd7LosingEffectObligationBindingChirho, Gd7LosingEffectObligationMintRefusalChirho> {
    let obligation_chirho = verified_obligation_chirho.obligation_chirho();
    let terminal_state_chirho = match obligation_chirho.kind_chirho {
        Gd7EffectPlanObligationKindChirho::CommittedOnLosingForkChirho
            if obligation_chirho.outcome_ref_chirho.is_some()
                && obligation_chirho
                    .terminal_marker_object_digest_chirho
                    .is_some() =>
        {
            Gd7LosingEffectObligationTerminalStateChirho::CommittedFinalizeChirho
        }
        Gd7EffectPlanObligationKindChirho::InDoubtHoldOnLosingForkChirho
            if obligation_chirho.outcome_ref_chirho.is_none()
                && obligation_chirho
                    .terminal_marker_object_digest_chirho
                    .is_none() =>
        {
            Gd7LosingEffectObligationTerminalStateChirho::InDoubtNoTerminalChirho
        }
        _ => {
            return Err(Gd7LosingEffectObligationMintRefusalChirho::ObligationBindingMismatchChirho)
        }
    };
    let canonical_obligation_digest_chirho =
        digest_bytes_chirho(&canonical_json_chirho(obligation_chirho)?);
    let binding_chirho = Gd7LosingEffectObligationBindingChirho {
        schema_chirho: GD7_LOSING_EFFECT_OBLIGATION_BINDING_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: reconciliation_identity_digest_chirho.to_owned(),
        adopted_checkpoint_ref_chirho: adopted_checkpoint_ref_chirho.to_owned(),
        plan_checkpoint_ref_chirho: plan_checkpoint_ref_chirho.to_owned(),
        sealed_plan_ref_chirho: sealed_plan_ref_chirho.to_owned(),
        plan_page_ref_chirho: verified_obligation_chirho.plan_page_ref_chirho().to_owned(),
        plan_page_index_chirho: verified_obligation_chirho.plan_page_index_chirho(),
        obligation_index_chirho: verified_obligation_chirho.obligation_index_chirho(),
        historical_winner_term_chirho,
        kind_chirho: obligation_chirho.kind_chirho,
        lineage_chirho: obligation_chirho.lineage_chirho,
        original_effect_key_chirho: obligation_chirho.original_effect_key_chirho.clone(),
        terminal_state_chirho,
        terminal_marker_object_digest_chirho: obligation_chirho
            .terminal_marker_object_digest_chirho
            .clone(),
        source_seq_chirho: obligation_chirho.source_seq_chirho,
        source_record_digest_chirho: obligation_chirho.source_record_digest_chirho.clone(),
        canonical_obligation_digest_chirho,
    };
    validate_obligation_binding_shape_chirho(&binding_chirho)?;
    Ok(binding_chirho)
}

fn validate_obligation_binding_shape_chirho(
    binding_chirho: &Gd7LosingEffectObligationBindingChirho,
) -> Result<(), Gd7LosingEffectObligationMintRefusalChirho> {
    if binding_chirho.schema_chirho != GD7_LOSING_EFFECT_OBLIGATION_BINDING_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&binding_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&binding_chirho.adopted_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&binding_chirho.plan_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&binding_chirho.sealed_plan_ref_chirho)
        || !is_lower_hex_digest_chirho(&binding_chirho.plan_page_ref_chirho)
        || binding_chirho.historical_winner_term_chirho == 0
        || binding_chirho
            .original_effect_key_chirho
            .as_deref()
            .is_some_and(|key_chirho| {
                !is_bounded_label_chirho(key_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO)
            })
        || binding_chirho
            .terminal_marker_object_digest_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || !is_lower_hex_digest_chirho(&binding_chirho.source_record_digest_chirho)
        || !is_lower_hex_digest_chirho(&binding_chirho.canonical_obligation_digest_chirho)
    {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::ObligationBindingMismatchChirho);
    }
    Ok(())
}

/// Derive the mint identity digest and canonical obligation digest for one verified obligation.
///
/// The convergence classifier must read the durable R2/R3 row belonging to an obligation, and that
/// row is keyed by mint identity. This reuses the production binding derivation rather than
/// re-implementing the key: a second implementation could drift, and because a missing row
/// classifies as OPEN, drift would block convergence for a reason no arm could distinguish from a
/// genuinely unfinished obligation.
pub(super) fn gd7_mint_identity_for_verified_obligation_chirho(
    adopted_checkpoint_ref_chirho: &str,
    plan_checkpoint_ref_chirho: &str,
    sealed_plan_ref_chirho: &str,
    reconciliation_identity_digest_chirho: &str,
    historical_winner_term_chirho: u64,
    verified_obligation_chirho: &VerifiedGd7SealedPlanObligationChirho,
) -> Result<(String, String), Gd7LosingEffectObligationMintRefusalChirho> {
    let binding_chirho = derive_obligation_binding_chirho(
        adopted_checkpoint_ref_chirho,
        plan_checkpoint_ref_chirho,
        sealed_plan_ref_chirho,
        reconciliation_identity_digest_chirho,
        historical_winner_term_chirho,
        verified_obligation_chirho,
    )?;
    let mint_identity_digest_chirho =
        derive_obligation_mint_identity_digest_chirho(&binding_chirho)?;
    Ok((
        mint_identity_digest_chirho,
        binding_chirho.canonical_obligation_digest_chirho,
    ))
}

fn derive_obligation_mint_identity_digest_chirho(
    binding_chirho: &Gd7LosingEffectObligationBindingChirho,
) -> Result<String, Gd7LosingEffectObligationMintRefusalChirho> {
    let identity_chirho = Gd7LosingEffectObligationMintIdentityChirho {
        schema_chirho: GD7_LOSING_EFFECT_OBLIGATION_MINT_IDENTITY_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: binding_chirho
            .reconciliation_identity_digest_chirho
            .clone(),
        adopted_checkpoint_ref_chirho: binding_chirho.adopted_checkpoint_ref_chirho.clone(),
        plan_checkpoint_ref_chirho: binding_chirho.plan_checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho: binding_chirho.sealed_plan_ref_chirho.clone(),
        canonical_obligation_digest_chirho: binding_chirho
            .canonical_obligation_digest_chirho
            .clone(),
    };
    Ok(digest_bytes_chirho(&canonical_json_chirho(
        &identity_chirho,
    )?))
}

fn require_exact_obligation_binding_chirho(
    actual_chirho: &Gd7LosingEffectObligationBindingChirho,
    expected_chirho: &Gd7LosingEffectObligationBindingChirho,
) -> Result<(), Gd7LosingEffectObligationMintRefusalChirho> {
    validate_obligation_binding_shape_chirho(actual_chirho)?;
    if actual_chirho.schema_chirho != expected_chirho.schema_chirho
        || actual_chirho.reconciliation_identity_digest_chirho
            != expected_chirho.reconciliation_identity_digest_chirho
        || actual_chirho.adopted_checkpoint_ref_chirho
            != expected_chirho.adopted_checkpoint_ref_chirho
        || actual_chirho.plan_checkpoint_ref_chirho != expected_chirho.plan_checkpoint_ref_chirho
        || actual_chirho.sealed_plan_ref_chirho != expected_chirho.sealed_plan_ref_chirho
        || actual_chirho.plan_page_ref_chirho != expected_chirho.plan_page_ref_chirho
        || actual_chirho.plan_page_index_chirho != expected_chirho.plan_page_index_chirho
        || actual_chirho.obligation_index_chirho != expected_chirho.obligation_index_chirho
        || actual_chirho.historical_winner_term_chirho
            != expected_chirho.historical_winner_term_chirho
        || actual_chirho.kind_chirho != expected_chirho.kind_chirho
        || actual_chirho.lineage_chirho != expected_chirho.lineage_chirho
        || actual_chirho.original_effect_key_chirho != expected_chirho.original_effect_key_chirho
        || actual_chirho.terminal_state_chirho != expected_chirho.terminal_state_chirho
        || actual_chirho.terminal_marker_object_digest_chirho
            != expected_chirho.terminal_marker_object_digest_chirho
        || actual_chirho.source_seq_chirho != expected_chirho.source_seq_chirho
        || actual_chirho.source_record_digest_chirho != expected_chirho.source_record_digest_chirho
        || actual_chirho.canonical_obligation_digest_chirho
            != expected_chirho.canonical_obligation_digest_chirho
    {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::ObligationBindingMismatchChirho);
    }
    Ok(())
}

fn sign_mint_receipt_chirho(
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    binding_chirho: &Gd7LosingEffectObligationBindingChirho,
    mint_identity_digest_chirho: &str,
) -> Result<Gd7LosingEffectObligationMintReceiptChirho, Gd7LosingEffectObligationMintRefusalChirho>
{
    let mut receipt_chirho = Gd7LosingEffectObligationMintReceiptChirho {
        schema_chirho: GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_SCHEMA_V1_CHIRHO.to_owned(),
        state_chirho:
            Gd7LosingEffectObligationMintReceiptStateChirho::MintedAwaitingConsumptionChirho,
        reconciliation_identity_digest_chirho: binding_chirho
            .reconciliation_identity_digest_chirho
            .clone(),
        adopted_checkpoint_ref_chirho: binding_chirho.adopted_checkpoint_ref_chirho.clone(),
        plan_checkpoint_ref_chirho: binding_chirho.plan_checkpoint_ref_chirho.clone(),
        sealed_plan_ref_chirho: binding_chirho.sealed_plan_ref_chirho.clone(),
        plan_page_ref_chirho: binding_chirho.plan_page_ref_chirho.clone(),
        plan_page_index_chirho: binding_chirho.plan_page_index_chirho,
        obligation_index_chirho: binding_chirho.obligation_index_chirho,
        mint_identity_digest_chirho: mint_identity_digest_chirho.to_owned(),
        canonical_obligation_digest_chirho: binding_chirho
            .canonical_obligation_digest_chirho
            .clone(),
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_mint_receipt_shape_chirho(&receipt_chirho)?;
    let signing_bytes_chirho = canonical_json_chirho(&receipt_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::SerializationChirho)?;
    receipt_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(signing_line_chirho)
        .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::SigningChirho)?;
    validate_mint_receipt_shape_chirho(&receipt_chirho)?;
    Ok(receipt_chirho)
}

fn validate_mint_receipt_shape_chirho(
    receipt_chirho: &Gd7LosingEffectObligationMintReceiptChirho,
) -> Result<(), Gd7LosingEffectObligationMintRefusalChirho> {
    if receipt_chirho.schema_chirho != GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_SCHEMA_V1_CHIRHO
        || !is_lower_hex_digest_chirho(&receipt_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.adopted_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.plan_checkpoint_ref_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.sealed_plan_ref_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.plan_page_ref_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.mint_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&receipt_chirho.canonical_obligation_digest_chirho)
        || !is_bounded_label_chirho(
            &receipt_chirho.key_id_chirho,
            MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
        )
        || (!receipt_chirho.sig_chirho.is_empty()
            && !is_bounded_label_chirho(
                &receipt_chirho.sig_chirho,
                MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO,
            ))
    {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::MalformedMintReceiptChirho);
    }
    Ok(())
}

fn read_mint_receipt_optional_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
) -> Result<Option<Vec<u8>>, Gd7LosingEffectObligationMintRefusalChirho> {
    match read_bounded_optional_chirho(
        storage_chirho,
        path_chirho,
        MAX_GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_BYTES_CHIRHO,
    ) {
        Err(Gd7PlanRefusalChirho::OversizedPlanPageChirho) => {
            Err(Gd7LosingEffectObligationMintRefusalChirho::OversizedMintReceiptChirho)
        }
        Err(error_chirho) => Err(Gd7LosingEffectObligationMintRefusalChirho::PlanChirho(
            error_chirho,
        )),
        Ok(bytes_chirho) => Ok(bytes_chirho),
    }
}

fn verify_mint_receipt_bytes_chirho(
    bytes_chirho: &[u8],
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> Result<Gd7LosingEffectObligationMintReceiptChirho, Gd7LosingEffectObligationMintRefusalChirho>
{
    if bytes_chirho.len() > MAX_GD7_LOSING_EFFECT_OBLIGATION_MINT_RECEIPT_BYTES_CHIRHO {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::OversizedMintReceiptChirho);
    }
    let receipt_chirho: Gd7LosingEffectObligationMintReceiptChirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::MalformedMintReceiptChirho)?;
    if canonical_json_chirho(&receipt_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::NonCanonicalMintReceiptChirho);
    }
    validate_mint_receipt_shape_chirho(&receipt_chirho)?;
    if receipt_chirho.key_id_chirho != held_signer_chirho.key_id_chirho() {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::InvalidMintReceiptSignatureChirho);
    }
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    let signing_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let signing_line_chirho = std::str::from_utf8(&signing_bytes_chirho)
        .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::SerializationChirho)?;
    if !held_signer_chirho.verify_chirho(signing_line_chirho, &receipt_chirho.sig_chirho) {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::InvalidMintReceiptSignatureChirho);
    }
    Ok(receipt_chirho)
}

fn require_same_receipt_identity_chirho(
    actual_chirho: &Gd7LosingEffectObligationMintReceiptChirho,
    expected_chirho: &Gd7LosingEffectObligationMintReceiptChirho,
) -> Result<(), Gd7LosingEffectObligationMintRefusalChirho> {
    let mut actual_unsigned_chirho = actual_chirho.clone();
    actual_unsigned_chirho.sig_chirho.clear();
    let mut expected_unsigned_chirho = expected_chirho.clone();
    expected_unsigned_chirho.sig_chirho.clear();
    if actual_unsigned_chirho != expected_unsigned_chirho {
        return Err(Gd7LosingEffectObligationMintRefusalChirho::MintReceiptCollisionChirho);
    }
    Ok(())
}

fn canonical_json_chirho(
    value_chirho: &impl Serialize,
) -> Result<Vec<u8>, Gd7LosingEffectObligationMintRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| Gd7LosingEffectObligationMintRefusalChirho::SerializationChirho)
}

#[cfg(test)]
mod convergence_import_tests_chirho;
#[cfg(test)]
mod convergence_tests_chirho;
#[cfg(test)]
mod tests_chirho;
