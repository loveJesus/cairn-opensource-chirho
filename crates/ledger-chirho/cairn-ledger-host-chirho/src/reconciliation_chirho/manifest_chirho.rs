// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! One bounded, restart-stable losing-manifest page transition for GD7.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::contract_chirho::{
    is_lower_hex_digest_chirho, Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho,
};
use super::store_chirho::{
    gd7_reconciliation_identity_digest_chirho, ActiveGd7ReconciliationChirho,
    CommittedGd7ReconciliationCheckpointChirho, Gd7ReconciliationStoreChirho,
    Gd7ReconciliationStoreRefusalChirho,
};
use super::winner_witness_chirho::AuthenticatedGd7DeposedForkObservationChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho,
    LosingSuffixReadErrorChirho, LosingSuffixReaderChirho, VerifiedLosingSuffixPageChirho,
    MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, stored_line_digest_chirho,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO: &str = "gd7-losing-manifest-page-v1-chirho";
pub const MAX_GD7_LOSING_MANIFEST_PAGE_BYTES_CHIRHO: usize =
    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + 1024 * 1024;
const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gd7ManifestPageBudgetChirho {
    max_records_chirho: usize,
    max_bytes_chirho: usize,
}

impl Gd7ManifestPageBudgetChirho {
    pub fn new_chirho(max_records_chirho: usize, max_bytes_chirho: usize) -> Self {
        Self {
            max_records_chirho,
            max_bytes_chirho,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7LosingManifestRecordChirho {
    record_digest_chirho: String,
    record_chirho: LedgerRecordChirho,
}

impl Gd7LosingManifestRecordChirho {
    pub fn record_digest_chirho(&self) -> &str {
        &self.record_digest_chirho
    }

    pub fn record_chirho(&self) -> &LedgerRecordChirho {
        &self.record_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7LosingManifestPageChirho {
    schema_chirho: String,
    reconciliation_identity_digest_chirho: String,
    page_index_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newer_manifest_page_ref_chirho: Option<String>,
    frozen_losing_tail_chirho: Gd7JournalTailCoordinateChirho,
    exact_fork_anchor_chirho: Gd7ForkCoordinateChirho,
    records_newest_first_chirho: Vec<Gd7LosingManifestRecordChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_cursor_object_ref_chirho: Option<String>,
    reached_anchor_chirho: bool,
}

impl Gd7LosingManifestPageChirho {
    pub fn reconciliation_identity_digest_chirho(&self) -> &str {
        &self.reconciliation_identity_digest_chirho
    }

    pub fn page_index_chirho(&self) -> u64 {
        self.page_index_chirho
    }

    pub fn newer_manifest_page_ref_chirho(&self) -> Option<&str> {
        self.newer_manifest_page_ref_chirho.as_deref()
    }

    pub fn records_newest_first_chirho(&self) -> &[Gd7LosingManifestRecordChirho] {
        &self.records_newest_first_chirho
    }

    pub fn next_cursor_object_ref_chirho(&self) -> Option<&str> {
        self.next_cursor_object_ref_chirho.as_deref()
    }

    pub fn reached_anchor_chirho(&self) -> bool {
        self.reached_anchor_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7LosingManifestPageChirho {
    object_digest_chirho: String,
    page_chirho: Gd7LosingManifestPageChirho,
}

impl VerifiedGd7LosingManifestPageChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn page_chirho(&self) -> &Gd7LosingManifestPageChirho {
        &self.page_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7ManifestPageDriveOutcomeChirho {
    CommittedChirho {
        checkpoint_chirho: CommittedGd7ReconciliationCheckpointChirho,
        manifest_page_chirho: Box<VerifiedGd7LosingManifestPageChirho>,
    },
    AwaitingPlanReductionChirho(ActiveGd7ReconciliationChirho),
    AlreadyAdvancedChirho(ActiveGd7ReconciliationChirho),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7ManifestRefusalChirho {
    InvalidReferenceChirho,
    NoActiveReconciliationChirho,
    StaleCheckpointChirho,
    InvalidPhaseChirho,
    InvalidPageShapeChirho,
    MalformedPageChirho,
    NonCanonicalPageChirho,
    OversizedPageChirho,
    MissingObjectChirho,
    ObjectDigestMismatchChirho,
    ImmutableCollisionChirho,
    ArithmeticOverflowChirho,
    RecordEncodingChirho,
    LosingSuffixChirho(LosingSuffixReadErrorChirho),
    StoreChirho(Gd7ReconciliationStoreRefusalChirho),
    StorageChirho,
}

impl fmt::Display for Gd7ManifestRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidReferenceChirho => "GD7 manifest reference is invalid",
            Self::NoActiveReconciliationChirho => "GD7 reconciliation has no active checkpoint",
            Self::StaleCheckpointChirho => "GD7 manifest driver checkpoint is stale",
            Self::InvalidPhaseChirho => "GD7 reconciliation phase cannot drive a manifest page",
            Self::InvalidPageShapeChirho => "GD7 manifest page shape is invalid",
            Self::MalformedPageChirho => "GD7 manifest page is malformed",
            Self::NonCanonicalPageChirho => "GD7 manifest page is not canonical",
            Self::OversizedPageChirho => "GD7 manifest page exceeds its fixed bound",
            Self::MissingObjectChirho => "GD7 manifest object is missing",
            Self::ObjectDigestMismatchChirho => "GD7 manifest object digest mismatches its address",
            Self::ImmutableCollisionChirho => "GD7 manifest immutable object collided",
            Self::ArithmeticOverflowChirho => "GD7 manifest counter overflowed",
            Self::RecordEncodingChirho => "GD7 manifest record cannot be encoded canonically",
            Self::LosingSuffixChirho(_) => "GD7 losing suffix page verification failed",
            Self::StoreChirho(_) => "GD7 reconciliation checkpoint operation failed",
            Self::StorageChirho => "GD7 manifest storage operation failed",
        })
    }
}

impl Error for Gd7ManifestRefusalChirho {}

impl From<LosingSuffixReadErrorChirho> for Gd7ManifestRefusalChirho {
    fn from(error_chirho: LosingSuffixReadErrorChirho) -> Self {
        Self::LosingSuffixChirho(error_chirho)
    }
}

impl From<Gd7ReconciliationStoreRefusalChirho> for Gd7ManifestRefusalChirho {
    fn from(error_chirho: Gd7ReconciliationStoreRefusalChirho) -> Self {
        Self::StoreChirho(error_chirho)
    }
}

pub fn gd7_losing_manifest_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ManifestRefusalChirho> {
    content_addressed_path_chirho("manifest-pages-chirho", object_digest_chirho)
}

pub fn gd7_losing_manifest_cursor_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ManifestRefusalChirho> {
    content_addressed_path_chirho("manifest-cursors-chirho", object_digest_chirho)
}

/// Drive at most one verified suffix page from the caller's exact active checkpoint.
///
/// A lost response cannot accidentally consume the next page: replaying the old checkpoint ref
/// returns `StaleCheckpointChirho`; a coordinator must reload and deliberately name the new ref.
pub fn drive_authenticated_losing_manifest_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    losing_journal_chirho: &dyn LosingSuffixReaderChirho,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    expected_checkpoint_ref_chirho: &str,
    budget_chirho: Gd7ManifestPageBudgetChirho,
) -> Result<Gd7ManifestPageDriveOutcomeChirho, Gd7ManifestRefusalChirho> {
    if !is_lower_hex_digest_chirho(expected_checkpoint_ref_chirho) {
        return Err(Gd7ManifestRefusalChirho::InvalidReferenceChirho);
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
        .ok_or(Gd7ManifestRefusalChirho::NoActiveReconciliationChirho)?;
    if active_chirho.checkpoint_ref_chirho != expected_checkpoint_ref_chirho {
        return Err(Gd7ManifestRefusalChirho::StaleCheckpointChirho);
    }
    let newer_manifest_page_chirho = match active_chirho.checkpoint_chirho.state_chirho.phase_chirho
    {
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho => None,
        Gd7ReconciliationPhaseChirho::ManifestingChirho => {
            let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
            if state_chirho.plan_page_count_chirho < state_chirho.manifest_page_count_chirho {
                return Ok(
                    Gd7ManifestPageDriveOutcomeChirho::AwaitingPlanReductionChirho(active_chirho),
                );
            }
            if state_chirho.cursor_object_ref_chirho.is_none() {
                return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
            }
            let newer_manifest_page_ref_chirho = active_chirho
                .checkpoint_chirho
                .state_chirho
                .manifest_head_ref_chirho
                .as_deref()
                .ok_or(Gd7ManifestRefusalChirho::InvalidPageShapeChirho)?;
            let newer_manifest_page_chirho = load_verified_gd7_losing_manifest_page_chirho(
                storage_chirho,
                newer_manifest_page_ref_chirho,
                identity_chirho,
            )?;
            validate_active_manifest_head_chirho(&newer_manifest_page_chirho, &active_chirho)?;
            Some(newer_manifest_page_chirho)
        }
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => {
            return Ok(Gd7ManifestPageDriveOutcomeChirho::AlreadyAdvancedChirho(
                active_chirho,
            ));
        }
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            return Err(Gd7ManifestRefusalChirho::InvalidPhaseChirho);
        }
    };

    let mut request_chirho = LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(DigestChirho(
            identity_chirho.losing_journal_genesis_digest_chirho.clone(),
        )),
        LosingSuffixCoordinateChirho::new_chirho(
            identity_chirho.losing_journal_tail_chirho.seq_chirho,
            DigestChirho(
                identity_chirho
                    .losing_journal_tail_chirho
                    .record_digest_chirho
                    .clone(),
            ),
        ),
        LosingSuffixCoordinateChirho::new_chirho(
            identity_chirho.fork_chirho.seq_chirho,
            DigestChirho(identity_chirho.fork_chirho.record_digest_chirho.clone()),
        ),
        budget_chirho.max_records_chirho,
        budget_chirho.max_bytes_chirho,
    );
    if let Some(cursor_ref_chirho) = active_chirho
        .checkpoint_chirho
        .state_chirho
        .cursor_object_ref_chirho
        .as_deref()
    {
        let cursor_path_chirho = gd7_losing_manifest_cursor_path_chirho(cursor_ref_chirho)?;
        let cursor_bytes_chirho = read_bounded_object_chirho(
            storage_chirho,
            &cursor_path_chirho,
            MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO,
        )?;
        if digest_bytes_chirho(&cursor_bytes_chirho) != cursor_ref_chirho {
            return Err(Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho);
        }
        request_chirho = request_chirho.with_cursor_chirho(
            losing_journal_chirho
                .decode_verified_losing_suffix_cursor_chirho(&cursor_bytes_chirho)?,
        );
    }
    let verified_suffix_page_chirho =
        losing_journal_chirho.read_verified_losing_suffix_page_chirho(&request_chirho)?;
    let next_cursor_ref_chirho = persist_next_cursor_chirho(
        storage_chirho,
        verified_suffix_page_chirho.next_cursor_chirho(),
    )?;
    let manifest_page_chirho = build_manifest_page_chirho(
        identity_chirho,
        &active_chirho,
        &verified_suffix_page_chirho,
        next_cursor_ref_chirho.clone(),
    )?;
    validate_cross_page_transition_chirho(
        &manifest_page_chirho,
        newer_manifest_page_chirho.as_ref(),
    )?;
    let verified_manifest_page_chirho =
        persist_manifest_page_chirho(storage_chirho, manifest_page_chirho, identity_chirho)?;

    let committed_chirho = store_chirho.commit_manifest_checkpoint_chirho(
        expected_checkpoint_ref_chirho,
        &verified_manifest_page_chirho,
    )?;
    Ok(Gd7ManifestPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: committed_chirho,
        manifest_page_chirho: Box::new(verified_manifest_page_chirho),
    })
}

pub(crate) fn load_verified_gd7_losing_manifest_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7LosingManifestPageChirho, Gd7ManifestRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7ManifestRefusalChirho::InvalidReferenceChirho);
    }
    let path_chirho = gd7_losing_manifest_page_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_object_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_LOSING_MANIFEST_PAGE_BYTES_CHIRHO,
    )?;
    verify_manifest_page_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )
}

fn build_manifest_page_chirho(
    identity_chirho: &super::contract_chirho::Gd7ReconciliationIdentityChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
    verified_suffix_page_chirho: &VerifiedLosingSuffixPageChirho,
    next_cursor_object_ref_chirho: Option<String>,
) -> Result<Gd7LosingManifestPageChirho, Gd7ManifestRefusalChirho> {
    let records_newest_first_chirho = verified_suffix_page_chirho
        .records_newest_first_chirho()
        .iter()
        .map(|record_chirho| {
            let canonical_record_chirho = canonical_ledger_record_line_chirho(record_chirho)
                .map_err(|_| Gd7ManifestRefusalChirho::RecordEncodingChirho)?;
            Ok(Gd7LosingManifestRecordChirho {
                record_digest_chirho: stored_line_digest_chirho(&canonical_record_chirho).0,
                record_chirho: record_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>, Gd7ManifestRefusalChirho>>()?;
    let page_chirho = Gd7LosingManifestPageChirho {
        schema_chirho: GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
        reconciliation_identity_digest_chirho: gd7_reconciliation_identity_digest_chirho(
            identity_chirho,
        )?,
        page_index_chirho: active_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_page_count_chirho,
        newer_manifest_page_ref_chirho: active_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_head_ref_chirho
            .clone(),
        frozen_losing_tail_chirho: identity_chirho.losing_journal_tail_chirho.clone(),
        exact_fork_anchor_chirho: identity_chirho.fork_chirho.clone(),
        records_newest_first_chirho,
        next_cursor_object_ref_chirho,
        reached_anchor_chirho: verified_suffix_page_chirho.reached_anchor_chirho(),
    };
    validate_manifest_page_chirho(&page_chirho, identity_chirho)?;
    Ok(page_chirho)
}

fn persist_next_cursor_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    cursor_chirho: Option<&cairn_ledger_log_chirho::losing_suffix_chirho::LosingSuffixCursorChirho>,
) -> Result<Option<String>, Gd7ManifestRefusalChirho> {
    let Some(cursor_chirho) = cursor_chirho else {
        return Ok(None);
    };
    let bytes_chirho = cursor_chirho.encode_durable_chirho()?;
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_losing_manifest_cursor_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    Ok(Some(digest_chirho))
}

fn persist_manifest_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    page_chirho: Gd7LosingManifestPageChirho,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7LosingManifestPageChirho, Gd7ManifestRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(&page_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::MalformedPageChirho)?;
    if bytes_chirho.len() > MAX_GD7_LOSING_MANIFEST_PAGE_BYTES_CHIRHO {
        return Err(Gd7ManifestRefusalChirho::OversizedPageChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_losing_manifest_page_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    verify_manifest_page_bytes_chirho(&bytes_chirho, &digest_chirho, expected_identity_chirho)
}

fn verify_manifest_page_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<VerifiedGd7LosingManifestPageChirho, Gd7ManifestRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_LOSING_MANIFEST_PAGE_BYTES_CHIRHO {
        return Err(Gd7ManifestRefusalChirho::OversizedPageChirho);
    }
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho);
    }
    let page_chirho: Gd7LosingManifestPageChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::MalformedPageChirho)?;
    if serde_json::to_vec(&page_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::MalformedPageChirho)?
        != bytes_chirho
    {
        return Err(Gd7ManifestRefusalChirho::NonCanonicalPageChirho);
    }
    validate_manifest_page_chirho(&page_chirho, expected_identity_chirho)?;
    Ok(VerifiedGd7LosingManifestPageChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        page_chirho,
    })
}

fn validate_manifest_page_chirho(
    page_chirho: &Gd7LosingManifestPageChirho,
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<(), Gd7ManifestRefusalChirho> {
    let expected_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(expected_identity_chirho)?;
    if page_chirho.schema_chirho != GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO
        || page_chirho.reconciliation_identity_digest_chirho != expected_identity_digest_chirho
        || !is_lower_hex_digest_chirho(&page_chirho.reconciliation_identity_digest_chirho)
        || page_chirho.frozen_losing_tail_chirho
            != expected_identity_chirho.losing_journal_tail_chirho
        || page_chirho.exact_fork_anchor_chirho != expected_identity_chirho.fork_chirho
        || page_chirho.records_newest_first_chirho.is_empty()
        || page_chirho.records_newest_first_chirho.len() > MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO
        || (page_chirho.page_index_chirho == 0)
            != page_chirho.newer_manifest_page_ref_chirho.is_none()
        || page_chirho
            .newer_manifest_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || page_chirho.reached_anchor_chirho == page_chirho.next_cursor_object_ref_chirho.is_some()
        || page_chirho
            .next_cursor_object_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
    {
        return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
    }
    for (index_chirho, manifest_record_chirho) in
        page_chirho.records_newest_first_chirho.iter().enumerate()
    {
        if !is_lower_hex_digest_chirho(&manifest_record_chirho.record_digest_chirho) {
            return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
        }
        let canonical_record_chirho =
            canonical_ledger_record_line_chirho(&manifest_record_chirho.record_chirho)
                .map_err(|_| Gd7ManifestRefusalChirho::RecordEncodingChirho)?;
        if stored_line_digest_chirho(&canonical_record_chirho).0
            != manifest_record_chirho.record_digest_chirho
        {
            return Err(Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho);
        }
        if let Some(older_record_chirho) = page_chirho
            .records_newest_first_chirho
            .get(index_chirho + 1)
        {
            if manifest_record_chirho.record_chirho.seq_chirho
                != older_record_chirho
                    .record_chirho
                    .seq_chirho
                    .checked_add(1)
                    .ok_or(Gd7ManifestRefusalChirho::ArithmeticOverflowChirho)?
                || manifest_record_chirho.record_chirho.prev_chirho.0
                    != older_record_chirho.record_digest_chirho
            {
                return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
            }
        }
    }
    let newest_chirho = page_chirho
        .records_newest_first_chirho
        .first()
        .ok_or(Gd7ManifestRefusalChirho::InvalidPageShapeChirho)?;
    if page_chirho.page_index_chirho == 0
        && (newest_chirho.record_chirho.seq_chirho
            != page_chirho.frozen_losing_tail_chirho.seq_chirho
            || newest_chirho.record_digest_chirho
                != page_chirho.frozen_losing_tail_chirho.record_digest_chirho)
    {
        return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
    }
    if page_chirho.reached_anchor_chirho {
        let oldest_chirho = page_chirho
            .records_newest_first_chirho
            .last()
            .ok_or(Gd7ManifestRefusalChirho::InvalidPageShapeChirho)?;
        if oldest_chirho.record_chirho.seq_chirho
            != page_chirho
                .exact_fork_anchor_chirho
                .seq_chirho
                .checked_add(1)
                .ok_or(Gd7ManifestRefusalChirho::ArithmeticOverflowChirho)?
            || oldest_chirho.record_chirho.prev_chirho.0
                != page_chirho.exact_fork_anchor_chirho.record_digest_chirho
        {
            return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
        }
    }
    Ok(())
}

fn validate_active_manifest_head_chirho(
    manifest_page_chirho: &VerifiedGd7LosingManifestPageChirho,
    active_chirho: &ActiveGd7ReconciliationChirho,
) -> Result<(), Gd7ManifestRefusalChirho> {
    let state_chirho = &active_chirho.checkpoint_chirho.state_chirho;
    if manifest_page_chirho
        .page_chirho()
        .page_index_chirho
        .checked_add(1)
        != Some(state_chirho.manifest_page_count_chirho)
        || manifest_page_chirho
            .page_chirho()
            .next_cursor_object_ref_chirho
            != state_chirho.cursor_object_ref_chirho
        || manifest_page_chirho.page_chirho().reached_anchor_chirho
    {
        return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

fn validate_cross_page_transition_chirho(
    older_manifest_page_chirho: &Gd7LosingManifestPageChirho,
    newer_manifest_page_chirho: Option<&VerifiedGd7LosingManifestPageChirho>,
) -> Result<(), Gd7ManifestRefusalChirho> {
    let Some(newer_manifest_page_chirho) = newer_manifest_page_chirho else {
        return Ok(());
    };
    if older_manifest_page_chirho
        .newer_manifest_page_ref_chirho
        .as_deref()
        != Some(newer_manifest_page_chirho.object_digest_chirho())
    {
        return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
    }
    let newer_boundary_chirho = newer_manifest_page_chirho
        .page_chirho()
        .records_newest_first_chirho
        .last()
        .ok_or(Gd7ManifestRefusalChirho::InvalidPageShapeChirho)?;
    let older_boundary_chirho = older_manifest_page_chirho
        .records_newest_first_chirho
        .first()
        .ok_or(Gd7ManifestRefusalChirho::InvalidPageShapeChirho)?;
    if newer_boundary_chirho.record_chirho.seq_chirho
        != older_boundary_chirho
            .record_chirho
            .seq_chirho
            .checked_add(1)
            .ok_or(Gd7ManifestRefusalChirho::ArithmeticOverflowChirho)?
        || newer_boundary_chirho.record_chirho.prev_chirho.0
            != older_boundary_chirho.record_digest_chirho
    {
        return Err(Gd7ManifestRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

fn content_addressed_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ManifestRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7ManifestRefusalChirho::InvalidReferenceChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{object_digest_chirho}.json",
        &object_digest_chirho[..2],
        &object_digest_chirho[2..4],
    )))
}

fn persist_immutable_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
) -> Result<(), Gd7ManifestRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho =
                read_bounded_object_chirho(storage_chirho, path_chirho, bytes_chirho.len())?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7ManifestRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_object_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
) -> Result<Vec<u8>, Gd7ManifestRefusalChirho> {
    let length_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::StorageChirho)?
        .ok_or(Gd7ManifestRefusalChirho::MissingObjectChirho)?;
    if length_chirho > maximum_chirho as u64 {
        return Err(Gd7ManifestRefusalChirho::OversizedPageChirho);
    }
    let bytes_chirho = storage_chirho
        .read_exact_range_chirho(path_chirho, 0, length_chirho)
        .map_err(|_| Gd7ManifestRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != length_chirho as usize {
        return Err(Gd7ManifestRefusalChirho::StorageChirho);
    }
    Ok(bytes_chirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
