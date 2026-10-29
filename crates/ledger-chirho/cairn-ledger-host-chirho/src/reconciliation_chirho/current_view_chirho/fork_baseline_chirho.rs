// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Winner-signed account-head baseline at one accepted GD7 fork coordinate.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
//! The winner full-verifies its physical journal, replays it through the independently bound fork,
//! and signs fixed-size content-addressed pages. The held side may verify those pages as evidence.
//! This module cannot install a journal branch, adopt a view, authorize compensation, move a ref,
//! or enable writes.

use super::{
    is_lower_hex_digest_chirho, validate_identity_chirho, validate_key_and_signature_chirho,
};
use crate::reconciliation_chirho::{
    gd7_reconciliation_identity_digest_chirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::verified_prefix_state_chirho::{
    open_read_only_verified_prefix_state_chirho, LedgerPrefixCutChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::LegPostStateChirho;
use cairn_ledger_model_chirho::wire_chirho::validate_ledger_account_identifier_chirho;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
const GD7_FORK_BASELINE_PAGE_SCHEMA_V1_CHIRHO: &str =
    "gd7-fork-account-state-baseline-page-v1-chirho";
pub const GD7_FORK_BASELINE_ROOT_SCHEMA_V1_CHIRHO: &str =
    "gd7-fork-account-state-baseline-root-v1-chirho";
pub const GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO: usize = 256;
pub const MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO: usize = 256 * 1024;
pub const MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO: usize = 16 * 1024;

/// Exact reconciliation and accepted-handoff coordinate shared by every baseline object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ForkBaselineIdentityChirho {
    pub reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho,
    pub reconciliation_identity_digest_chirho: String,
    pub winner_handoff_attempt_digest_chirho: String,
}

impl Gd7ForkBaselineIdentityChirho {
    pub fn new_chirho(
        reconciliation_identity_chirho: Gd7ReconciliationIdentityChirho,
        winner_handoff_attempt_digest_chirho: String,
    ) -> Result<Self, Gd7ForkBaselineRefusalChirho> {
        if !validate_identity_chirho(&reconciliation_identity_chirho)
            || !is_lower_hex_digest_chirho(&winner_handoff_attempt_digest_chirho)
        {
            return Err(Gd7ForkBaselineRefusalChirho::InvalidIdentityChirho);
        }
        let reconciliation_identity_digest_chirho =
            gd7_reconciliation_identity_digest_chirho(&reconciliation_identity_chirho)
                .map_err(|_| Gd7ForkBaselineRefusalChirho::InvalidIdentityChirho)?;
        Ok(Self {
            reconciliation_identity_chirho,
            reconciliation_identity_digest_chirho,
            winner_handoff_attempt_digest_chirho,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7ForkBaselineRowChirho {
    account_chirho: AccountIdChirho,
    post_chirho: LegPostStateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7ForkBaselinePageChirho {
    schema_chirho: String,
    identity_chirho: Gd7ForkBaselineIdentityChirho,
    page_index_chirho: u64,
    rows_chirho: Vec<Gd7ForkBaselineRowChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_page_ref_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedGd7ForkBaselinePageChirho {
    object_digest_chirho: String,
    page_chirho: Gd7ForkBaselinePageChirho,
}

pub(super) struct Gd7ForkBaselineTransferPageChirho {
    pub canonical_bytes_chirho: Vec<u8>,
    pub page_index_chirho: u64,
    pub next_page_ref_chirho: Option<String>,
}

/// Winner-control-root-signed account states at the exact reconciliation fork.
///
/// This is an account-net input baseline only. It does not carry active holds as obligations,
/// consumed nullifiers, supply aggregates, idempotency state, or effect-receipt windows and must
/// never be treated as a general ledger checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ForkBaselineRootChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7ForkBaselineIdentityChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_page_ref_chirho: Option<String>,
    pub page_count_chirho: u64,
    pub account_count_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7ForkBaselineRootChirho {
    object_digest_chirho: String,
    root_chirho: Gd7ForkBaselineRootChirho,
}

impl VerifiedGd7ForkBaselineRootChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn root_chirho(&self) -> &Gd7ForkBaselineRootChirho {
        &self.root_chirho
    }
}

/// Opaque proof that the signed root and every bounded account-state page were reverified.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedGd7ForkBaselineChirho {
    root_chirho: VerifiedGd7ForkBaselineRootChirho,
    head_states_chirho: BTreeMap<AccountIdChirho, LegPostStateChirho>,
}

impl VerifiedGd7ForkBaselineChirho {
    pub fn root_chirho(&self) -> &VerifiedGd7ForkBaselineRootChirho {
        &self.root_chirho
    }

    pub fn head_states_chirho(&self) -> &BTreeMap<AccountIdChirho, LegPostStateChirho> {
        &self.head_states_chirho
    }

    pub(super) fn into_head_states_chirho(self) -> BTreeMap<AccountIdChirho, LegPostStateChirho> {
        self.head_states_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7ForkBaselineRefusalChirho {
    InvalidIdentityChirho,
    InvalidSourceBindingChirho,
    InvalidReferenceChirho,
    InvalidPageShapeChirho,
    InvalidRootShapeChirho,
    MalformedPageChirho,
    MalformedRootChirho,
    NonCanonicalPageChirho,
    NonCanonicalRootChirho,
    OversizedPageChirho,
    OversizedRootChirho,
    MissingObjectChirho,
    ObjectDigestMismatchChirho,
    ImmutableCollisionChirho,
    InvalidRootSignatureChirho,
    WrongControlSignerChirho,
    IncompleteChainChirho,
    DuplicateAccountChirho,
    ArithmeticOverflowChirho,
    SigningChirho,
    JournalChirho,
    StorageChirho,
}

impl fmt::Display for Gd7ForkBaselineRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidIdentityChirho => "GD7 fork-baseline identity is invalid",
            Self::InvalidSourceBindingChirho => {
                "GD7 fork-baseline source journal differs from the accepted reconciliation"
            }
            Self::InvalidReferenceChirho => "GD7 fork-baseline reference is invalid",
            Self::InvalidPageShapeChirho => "GD7 fork-baseline page shape is invalid",
            Self::InvalidRootShapeChirho => "GD7 fork-baseline root shape is invalid",
            Self::MalformedPageChirho => "GD7 fork-baseline page is malformed",
            Self::MalformedRootChirho => "GD7 fork-baseline root is malformed",
            Self::NonCanonicalPageChirho => "GD7 fork-baseline page is not canonical",
            Self::NonCanonicalRootChirho => "GD7 fork-baseline root is not canonical",
            Self::OversizedPageChirho => "GD7 fork-baseline page exceeds its fixed bound",
            Self::OversizedRootChirho => "GD7 fork-baseline root exceeds its fixed bound",
            Self::MissingObjectChirho => "GD7 fork-baseline object is missing",
            Self::ObjectDigestMismatchChirho => {
                "GD7 fork-baseline object digest mismatches its address"
            }
            Self::ImmutableCollisionChirho => "GD7 fork-baseline immutable object collided",
            Self::InvalidRootSignatureChirho => "GD7 fork-baseline root signature is invalid",
            Self::WrongControlSignerChirho => {
                "GD7 fork-baseline control signer is not the selected winner"
            }
            Self::IncompleteChainChirho => "GD7 fork-baseline page chain is incomplete",
            Self::DuplicateAccountChirho => {
                "GD7 fork-baseline account coordinate is duplicated or unordered"
            }
            Self::ArithmeticOverflowChirho => "GD7 fork-baseline counter overflowed",
            Self::SigningChirho => "GD7 fork-baseline root signing failed",
            Self::JournalChirho => "GD7 fork-baseline source journal verification failed",
            Self::StorageChirho => "GD7 fork-baseline storage operation failed",
        })
    }
}

impl Error for Gd7ForkBaselineRefusalChirho {}

pub fn gd7_fork_baseline_page_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ForkBaselineRefusalChirho> {
    content_addressed_path_chirho("fork-baseline-pages-chirho", object_digest_chirho)
}

pub fn gd7_fork_baseline_root_path_chirho(
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ForkBaselineRefusalChirho> {
    content_addressed_path_chirho("fork-baseline-roots-chirho", object_digest_chirho)
}

/// Full-replay the winner journal through the fork and persist one signed paged baseline.
///
/// The operation is O(full winner history + accounts) and belongs on reconciliation evidence
/// paths only. The underlying replay is read-only; this module writes only immutable evidence.
/// The journal port authenticates the ordinary records under its injected root; the independent
/// control signer authenticates the resulting baseline as selected-winner evidence.
pub(super) fn stage_gd7_fork_baseline_chirho(
    evidence_storage_chirho: &dyn LedgerStoragePortChirho,
    control_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    winner_journal_ports_chirho: JournalPortsChirho<'_>,
    winner_journal_path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
    identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7ForkBaselineRefusalChirho> {
    validate_baseline_identity_chirho(identity_chirho)?;
    let winner_node_chirho = &identity_chirho
        .reconciliation_identity_chirho
        .winner_node_chirho;
    if control_signer_chirho.key_id_chirho() != *winner_node_chirho {
        return Err(Gd7ForkBaselineRefusalChirho::WrongControlSignerChirho);
    }
    let reconciliation_chirho = &identity_chirho.reconciliation_identity_chirho;
    let requested_cut_chirho = LedgerPrefixCutChirho::new_chirho(
        reconciliation_chirho.fork_chirho.epoch_chirho,
        reconciliation_chirho.fork_chirho.seq_chirho,
        DigestChirho(
            reconciliation_chirho
                .fork_chirho
                .record_digest_chirho
                .clone(),
        ),
    );
    let prefix_state_chirho = open_read_only_verified_prefix_state_chirho(
        winner_journal_ports_chirho,
        winner_journal_path_chirho,
        expected_cluster_chirho,
        &requested_cut_chirho,
    )
    .map_err(|_| Gd7ForkBaselineRefusalChirho::JournalChirho)?;
    if prefix_state_chirho.genesis_digest_chirho().0
        != reconciliation_chirho.winner_journal_genesis_digest_chirho
        || prefix_state_chirho.prefix_cut_chirho().epoch_chirho()
            != reconciliation_chirho.fork_chirho.epoch_chirho
        || prefix_state_chirho.prefix_cut_chirho().seq_chirho()
            != reconciliation_chirho.fork_chirho.seq_chirho
        || prefix_state_chirho
            .prefix_cut_chirho()
            .record_digest_chirho()
            .0
            != reconciliation_chirho.fork_chirho.record_digest_chirho
        || prefix_state_chirho.source_tail_cut_chirho().epoch_chirho()
            != reconciliation_chirho
                .winner_journal_tail_chirho
                .epoch_chirho
        || prefix_state_chirho.source_tail_cut_chirho().seq_chirho()
            != reconciliation_chirho.winner_journal_tail_chirho.seq_chirho
        || prefix_state_chirho
            .source_tail_cut_chirho()
            .record_digest_chirho()
            .0
            != reconciliation_chirho
                .winner_journal_tail_chirho
                .record_digest_chirho
    {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidSourceBindingChirho);
    }

    let rows_chirho = prefix_state_chirho
        .head_states_chirho()
        .iter()
        .map(|(account_chirho, post_chirho)| Gd7ForkBaselineRowChirho {
            account_chirho: account_chirho.clone(),
            post_chirho: post_chirho.clone(),
        })
        .collect::<Vec<_>>();
    let page_count_chirho = if rows_chirho.is_empty() {
        0
    } else {
        rows_chirho
            .len()
            .div_ceil(GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO)
    };
    let mut next_page_ref_chirho = None;
    for (page_index_chirho, rows_page_chirho) in rows_chirho
        .chunks(GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO)
        .enumerate()
        .rev()
    {
        let page_chirho = Gd7ForkBaselinePageChirho {
            schema_chirho: GD7_FORK_BASELINE_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: identity_chirho.clone(),
            page_index_chirho: u64::try_from(page_index_chirho)
                .map_err(|_| Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?,
            rows_chirho: rows_page_chirho.to_vec(),
            next_page_ref_chirho,
        };
        next_page_ref_chirho = Some(
            persist_baseline_page_chirho(evidence_storage_chirho, page_chirho, identity_chirho)?
                .object_digest_chirho,
        );
    }
    let page_count_chirho = u64::try_from(page_count_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?;
    let account_count_chirho = u64::try_from(rows_chirho.len())
        .map_err(|_| Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?;
    persist_baseline_root_chirho(
        evidence_storage_chirho,
        control_signer_chirho,
        identity_chirho,
        next_page_ref_chirho,
        page_count_chirho,
        account_count_chirho,
    )
}

pub fn load_verified_gd7_fork_baseline_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7ForkBaselineRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidReferenceChirho);
    }
    let path_chirho = gd7_fork_baseline_root_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_object_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO,
        Gd7ForkBaselineRefusalChirho::OversizedRootChirho,
    )?;
    verify_root_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
        control_verifier_chirho,
    )
}

/// Reverify one signed baseline root and every canonical account-state page it reaches.
pub fn verify_complete_gd7_fork_baseline_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7ForkBaselineChirho, Gd7ForkBaselineRefusalChirho> {
    let root_chirho = load_verified_gd7_fork_baseline_root_chirho(
        storage_chirho,
        root_object_digest_chirho,
        expected_identity_chirho,
        control_verifier_chirho,
    )?;
    let mut current_ref_chirho = root_chirho.root_chirho.first_page_ref_chirho.clone();
    let mut observed_accounts_chirho = 0_u64;
    let mut previous_account_chirho: Option<AccountIdChirho> = None;
    let mut head_states_chirho = BTreeMap::new();

    for expected_index_chirho in 0..root_chirho.root_chirho.page_count_chirho {
        let page_ref_chirho = current_ref_chirho
            .take()
            .ok_or(Gd7ForkBaselineRefusalChirho::IncompleteChainChirho)?;
        let page_chirho = load_verified_baseline_page_chirho(
            storage_chirho,
            &page_ref_chirho,
            expected_identity_chirho,
        )?;
        if page_chirho.page_chirho.page_index_chirho != expected_index_chirho {
            return Err(Gd7ForkBaselineRefusalChirho::IncompleteChainChirho);
        }
        for row_chirho in &page_chirho.page_chirho.rows_chirho {
            if previous_account_chirho
                .as_ref()
                .is_some_and(|account_chirho| account_chirho >= &row_chirho.account_chirho)
                || head_states_chirho
                    .insert(
                        row_chirho.account_chirho.clone(),
                        row_chirho.post_chirho.clone(),
                    )
                    .is_some()
            {
                return Err(Gd7ForkBaselineRefusalChirho::DuplicateAccountChirho);
            }
            previous_account_chirho = Some(row_chirho.account_chirho.clone());
        }
        observed_accounts_chirho = observed_accounts_chirho
            .checked_add(
                u64::try_from(page_chirho.page_chirho.rows_chirho.len())
                    .map_err(|_| Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?,
            )
            .ok_or(Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?;
        current_ref_chirho = page_chirho.page_chirho.next_page_ref_chirho;
    }
    if current_ref_chirho.is_some()
        || observed_accounts_chirho != root_chirho.root_chirho.account_count_chirho
        || u64::try_from(head_states_chirho.len())
            .map_err(|_| Gd7ForkBaselineRefusalChirho::ArithmeticOverflowChirho)?
            != root_chirho.root_chirho.account_count_chirho
    {
        return Err(Gd7ForkBaselineRefusalChirho::IncompleteChainChirho);
    }
    Ok(VerifiedGd7ForkBaselineChirho {
        root_chirho,
        head_states_chirho,
    })
}

pub(super) fn load_gd7_fork_baseline_transfer_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<Gd7ForkBaselineTransferPageChirho, Gd7ForkBaselineRefusalChirho> {
    let page_chirho = load_verified_baseline_page_chirho(
        storage_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )?;
    transfer_page_from_verified_chirho(page_chirho)
}

pub(super) fn verify_gd7_fork_baseline_transfer_page_chirho(
    canonical_bytes_chirho: &[u8],
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<Gd7ForkBaselineTransferPageChirho, Gd7ForkBaselineRefusalChirho> {
    let page_chirho = verify_page_bytes_chirho(
        canonical_bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )?;
    transfer_page_from_verified_chirho(page_chirho)
}

fn transfer_page_from_verified_chirho(
    page_chirho: VerifiedGd7ForkBaselinePageChirho,
) -> Result<Gd7ForkBaselineTransferPageChirho, Gd7ForkBaselineRefusalChirho> {
    let canonical_bytes_chirho = canonical_json_chirho(&page_chirho.page_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedPageChirho)?;
    Ok(Gd7ForkBaselineTransferPageChirho {
        canonical_bytes_chirho,
        page_index_chirho: page_chirho.page_chirho.page_index_chirho,
        next_page_ref_chirho: page_chirho.page_chirho.next_page_ref_chirho,
    })
}

fn persist_baseline_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    page_chirho: Gd7ForkBaselinePageChirho,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<VerifiedGd7ForkBaselinePageChirho, Gd7ForkBaselineRefusalChirho> {
    validate_baseline_page_chirho(&page_chirho, expected_identity_chirho)?;
    let bytes_chirho = canonical_json_chirho(&page_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedPageChirho)?;
    if bytes_chirho.len() > MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO {
        return Err(Gd7ForkBaselineRefusalChirho::OversizedPageChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_fork_baseline_page_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    verify_page_bytes_chirho(&bytes_chirho, &digest_chirho, expected_identity_chirho)
}

fn load_verified_baseline_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<VerifiedGd7ForkBaselinePageChirho, Gd7ForkBaselineRefusalChirho> {
    let path_chirho = gd7_fork_baseline_page_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_object_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO,
        Gd7ForkBaselineRefusalChirho::OversizedPageChirho,
    )?;
    verify_page_bytes_chirho(
        &bytes_chirho,
        object_digest_chirho,
        expected_identity_chirho,
    )
}

fn verify_page_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<VerifiedGd7ForkBaselinePageChirho, Gd7ForkBaselineRefusalChirho> {
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7ForkBaselineRefusalChirho::ObjectDigestMismatchChirho);
    }
    let page_chirho: Gd7ForkBaselinePageChirho = parse_json_chirho(
        bytes_chirho,
        Gd7ForkBaselineRefusalChirho::MalformedPageChirho,
    )?;
    validate_baseline_page_chirho(&page_chirho, expected_identity_chirho)?;
    if canonical_json_chirho(&page_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedPageChirho)?
        != bytes_chirho
    {
        return Err(Gd7ForkBaselineRefusalChirho::NonCanonicalPageChirho);
    }
    Ok(VerifiedGd7ForkBaselinePageChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        page_chirho,
    })
}

fn persist_baseline_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    identity_chirho: &Gd7ForkBaselineIdentityChirho,
    first_page_ref_chirho: Option<String>,
    page_count_chirho: u64,
    account_count_chirho: u64,
) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7ForkBaselineRefusalChirho> {
    let mut root_chirho = Gd7ForkBaselineRootChirho {
        schema_chirho: GD7_FORK_BASELINE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        first_page_ref_chirho,
        page_count_chirho,
        account_count_chirho,
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_baseline_root_chirho(&root_chirho, identity_chirho, false)?;
    let unsigned_line_chirho = canonical_string_chirho(&root_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedRootChirho)?;
    root_chirho.sig_chirho = signer_chirho
        .sign_chirho(&unsigned_line_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::SigningChirho)?;
    validate_baseline_root_chirho(&root_chirho, identity_chirho, true)?;
    let bytes_chirho = canonical_json_chirho(&root_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedRootChirho)?;
    if bytes_chirho.len() > MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO {
        return Err(Gd7ForkBaselineRefusalChirho::OversizedRootChirho);
    }
    let digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_fork_baseline_root_path_chirho(&digest_chirho)?;
    persist_immutable_chirho(storage_chirho, &path_chirho, &bytes_chirho)?;
    verify_root_bytes_chirho(
        &bytes_chirho,
        &digest_chirho,
        identity_chirho,
        signer_chirho,
    )
}

fn verify_root_bytes_chirho(
    bytes_chirho: &[u8],
    expected_object_digest_chirho: &str,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7ForkBaselineRefusalChirho> {
    if digest_bytes_chirho(bytes_chirho) != expected_object_digest_chirho {
        return Err(Gd7ForkBaselineRefusalChirho::ObjectDigestMismatchChirho);
    }
    let root_chirho: Gd7ForkBaselineRootChirho = parse_json_chirho(
        bytes_chirho,
        Gd7ForkBaselineRefusalChirho::MalformedRootChirho,
    )?;
    validate_baseline_root_chirho(&root_chirho, expected_identity_chirho, true)?;
    if canonical_json_chirho(&root_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedRootChirho)?
        != bytes_chirho
    {
        return Err(Gd7ForkBaselineRefusalChirho::NonCanonicalRootChirho);
    }
    if root_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7ForkBaselineRefusalChirho::WrongControlSignerChirho);
    }
    let mut unsigned_chirho = root_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_line_chirho = canonical_string_chirho(&unsigned_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::MalformedRootChirho)?;
    if !verifier_chirho.verify_chirho(&unsigned_line_chirho, &signature_chirho) {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidRootSignatureChirho);
    }
    Ok(VerifiedGd7ForkBaselineRootChirho {
        object_digest_chirho: expected_object_digest_chirho.to_owned(),
        root_chirho,
    })
}

fn validate_baseline_identity_chirho(
    identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<(), Gd7ForkBaselineRefusalChirho> {
    if !validate_identity_chirho(&identity_chirho.reconciliation_identity_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.reconciliation_identity_digest_chirho)
        || !is_lower_hex_digest_chirho(&identity_chirho.winner_handoff_attempt_digest_chirho)
        || gd7_reconciliation_identity_digest_chirho(
            &identity_chirho.reconciliation_identity_chirho,
        )
        .map_err(|_| Gd7ForkBaselineRefusalChirho::InvalidIdentityChirho)?
            != identity_chirho.reconciliation_identity_digest_chirho
    {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidIdentityChirho);
    }
    Ok(())
}

fn validate_baseline_page_chirho(
    page_chirho: &Gd7ForkBaselinePageChirho,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
) -> Result<(), Gd7ForkBaselineRefusalChirho> {
    validate_baseline_identity_chirho(&page_chirho.identity_chirho)?;
    if page_chirho.schema_chirho != GD7_FORK_BASELINE_PAGE_SCHEMA_V1_CHIRHO
        || page_chirho.identity_chirho != *expected_identity_chirho
        || page_chirho.rows_chirho.is_empty()
        || page_chirho.rows_chirho.len() > GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO
        || page_chirho
            .next_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || !page_chirho
            .rows_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0].account_chirho < pair_chirho[1].account_chirho)
        || page_chirho.rows_chirho.iter().any(|row_chirho| {
            validate_ledger_account_identifier_chirho(&row_chirho.account_chirho).is_err()
        })
    {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidPageShapeChirho);
    }
    Ok(())
}

fn validate_baseline_root_chirho(
    root_chirho: &Gd7ForkBaselineRootChirho,
    expected_identity_chirho: &Gd7ForkBaselineIdentityChirho,
    require_signature_chirho: bool,
) -> Result<(), Gd7ForkBaselineRefusalChirho> {
    validate_baseline_identity_chirho(&root_chirho.identity_chirho)?;
    let empty_chirho = root_chirho.page_count_chirho == 0;
    if root_chirho.schema_chirho != GD7_FORK_BASELINE_ROOT_SCHEMA_V1_CHIRHO
        || root_chirho.identity_chirho != *expected_identity_chirho
        || empty_chirho != root_chirho.first_page_ref_chirho.is_none()
        || empty_chirho != (root_chirho.account_count_chirho == 0)
        || root_chirho
            .first_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
        || root_chirho.account_count_chirho < root_chirho.page_count_chirho
        || root_chirho.key_id_chirho
            != root_chirho
                .identity_chirho
                .reconciliation_identity_chirho
                .winner_node_chirho
        || if require_signature_chirho {
            !validate_key_and_signature_chirho(&root_chirho.key_id_chirho, &root_chirho.sig_chirho)
        } else {
            !root_chirho.sig_chirho.is_empty()
        }
    {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidRootShapeChirho);
    }
    Ok(())
}

fn content_addressed_path_chirho(
    family_chirho: &str,
    object_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7ForkBaselineRefusalChirho> {
    if !is_lower_hex_digest_chirho(object_digest_chirho) {
        return Err(Gd7ForkBaselineRefusalChirho::InvalidReferenceChirho);
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
) -> Result<(), Gd7ForkBaselineRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_object_chirho(
                storage_chirho,
                path_chirho,
                bytes_chirho.len(),
                Gd7ForkBaselineRefusalChirho::ImmutableCollisionChirho,
            )?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7ForkBaselineRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_object_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7ForkBaselineRefusalChirho,
) -> Result<Vec<u8>, Gd7ForkBaselineRefusalChirho> {
    let length_chirho = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7ForkBaselineRefusalChirho::StorageChirho)?
        .ok_or(Gd7ForkBaselineRefusalChirho::MissingObjectChirho)?;
    if length_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    let bytes_chirho = if length_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, length_chirho)
            .map_err(|_| Gd7ForkBaselineRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != length_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7ForkBaselineRefusalChirho::StorageChirho)?
            != Some(length_chirho)
    {
        return Err(Gd7ForkBaselineRefusalChirho::StorageChirho);
    }
    Ok(bytes_chirho)
}

fn parse_json_chirho<ValueChirho: DeserializeOwned>(
    bytes_chirho: &[u8],
    malformed_chirho: Gd7ForkBaselineRefusalChirho,
) -> Result<ValueChirho, Gd7ForkBaselineRefusalChirho> {
    serde_json::from_slice(bytes_chirho).map_err(|_| malformed_chirho)
}

fn canonical_json_chirho(value_chirho: &impl Serialize) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(value_chirho)
}

fn canonical_string_chirho(value_chirho: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_string(value_chirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
