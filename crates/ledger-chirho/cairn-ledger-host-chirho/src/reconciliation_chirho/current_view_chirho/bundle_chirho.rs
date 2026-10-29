// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Bounded, restartable account-net pages for one exact winner journal cut.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
//! This stages immutable evidence only. It cannot move a served ref, authorize compensation, adopt
//! a winner view, converge a held node, or re-enable writes.

use super::{
    canonical_json_chirho, consistency_group_digest_suffix_chirho, create_exact_chirho,
    digest_bytes_chirho, gd7_winner_view_bundle_page_path_chirho,
    gd7_winner_view_bundle_root_path_chirho, is_lower_hex_digest_chirho,
    load_verified_bundle_root_chirho, parse_json_chirho, read_bounded_chirho,
    validate_bundle_root_shape_chirho, Gd7JournalTailCoordinateChirho,
    Gd7WinnerCurrentViewRefusalChirho, Gd7WinnerJournalSnapshotChirho,
    Gd7WinnerViewBundleRootChirho, VerifiedGd7WinnerViewBundleRootChirho,
    GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO, MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
    MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::ids_chirho::AccountIdChirho;
use cairn_ledger_model_chirho::wire_chirho::validate_ledger_account_identifier_chirho;
use cairn_ledger_read_model_chirho::{
    account_net_projection_fold_ref_chirho, AccountNetProjectionPageSliceChirho,
    AccountNetProjectionRowChirho, ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::split_writer_epoch_chirho;
use serde::{Deserialize, Serialize};

const GD7_WINNER_VIEW_BUNDLE_PAGE_SCHEMA_V1_CHIRHO: &str = "gd7-winner-view-bundle-page-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gd7WinnerViewBundlePageChirho {
    pub(super) schema_chirho: String,
    pub(super) consistency_group_digest_chirho: String,
    pub(super) projection_fold_ref_chirho: String,
    pub(super) winner_journal_genesis_digest_chirho: String,
    pub(super) source_cut_chirho: Gd7JournalTailCoordinateChirho,
    pub(super) page_index_chirho: u64,
    pub(super) higher_page_ref_chirho: Option<String>,
    pub(super) rows_chirho: Vec<AccountNetProjectionRowChirho>,
    pub(super) next_upper_exclusive_account_chirho: Option<AccountIdChirho>,
    pub(super) cumulative_page_count_chirho: u64,
    pub(super) cumulative_row_count_chirho: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct VerifiedGd7WinnerViewBundlePageChirho {
    pub(super) object_digest_chirho: String,
    pub(super) page_chirho: Gd7WinnerViewBundlePageChirho,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerViewBundleStageOutcomeChirho {
    ContinueChirho {
        restart_chirho: Gd7WinnerViewBundleRestartChirho,
    },
    CompleteChirho {
        bundle_root_chirho: VerifiedGd7WinnerViewBundleRootChirho,
    },
}

/// Opaque in-process continuation for one exact content-addressed winner-view page.
///
/// Callers cannot construct or deserialize this token. Losing it is safe: restart staging from the
/// highest page and immutable create-exact writes converge on the same objects while the cut stays
/// unchanged. Durable reconciliation later reconstructs continuation only from its signed
/// checkpoint, never from caller strings.
#[derive(Debug, PartialEq, Eq)]
pub struct Gd7WinnerViewBundleRestartChirho {
    page_ref_chirho: String,
}

impl Gd7WinnerViewBundleRestartChirho {
    #[cfg(test)]
    pub(super) fn page_ref_chirho(&self) -> &str {
        &self.page_ref_chirho
    }
}

pub(super) fn stage_next_gd7_winner_view_bundle_page_guarded_chirho<
    SnapshotProviderChirho,
    PageProviderChirho,
>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_digest_chirho: &str,
    published_raft_term_chirho: u64,
    restart_chirho: Option<&Gd7WinnerViewBundleRestartChirho>,
    snapshot_provider_chirho: SnapshotProviderChirho,
    page_provider_chirho: PageProviderChirho,
) -> Result<Gd7WinnerViewBundleStageOutcomeChirho, Gd7WinnerCurrentViewRefusalChirho>
where
    SnapshotProviderChirho:
        FnOnce() -> Result<Gd7WinnerJournalSnapshotChirho, Gd7WinnerCurrentViewRefusalChirho>,
    PageProviderChirho:
        FnOnce(
            Option<&AccountIdChirho>,
        )
            -> Result<AccountNetProjectionPageSliceChirho, Gd7WinnerCurrentViewRefusalChirho>,
{
    let previous_page_chirho = restart_chirho
        .map(|restart_chirho| {
            load_verified_bundle_page_chirho(storage_chirho, &restart_chirho.page_ref_chirho)
        })
        .transpose()?;
    let snapshot_chirho = snapshot_provider_chirho()?;
    if u64::from(split_writer_epoch_chirho(snapshot_chirho.cut_chirho.epoch_chirho).geo_term_chirho)
        != published_raft_term_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho);
    }
    if let Some(previous_page_chirho) = &previous_page_chirho {
        validate_previous_page_chirho(previous_page_chirho, group_digest_chirho, &snapshot_chirho)?;
        if previous_page_chirho
            .page_chirho
            .next_upper_exclusive_account_chirho
            .is_none()
        {
            return persist_bundle_root_chirho(
                storage_chirho,
                group_digest_chirho,
                &snapshot_chirho,
                Some(previous_page_chirho.object_digest_chirho.clone()),
                previous_page_chirho
                    .page_chirho
                    .cumulative_page_count_chirho,
                previous_page_chirho.page_chirho.cumulative_row_count_chirho,
            )
            .map(|bundle_root_chirho| {
                Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho { bundle_root_chirho }
            });
        }
    }

    let cursor_chirho = previous_page_chirho.as_ref().and_then(|page_chirho| {
        page_chirho
            .page_chirho
            .next_upper_exclusive_account_chirho
            .as_ref()
    });
    let slice_chirho = page_provider_chirho(cursor_chirho)?;
    if slice_chirho.rows_chirho.is_empty() {
        if previous_page_chirho.is_some() {
            return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho);
        }
        return persist_bundle_root_chirho(
            storage_chirho,
            group_digest_chirho,
            &snapshot_chirho,
            None,
            0,
            0,
        )
        .map(
            |bundle_root_chirho| Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho {
                bundle_root_chirho,
            },
        );
    }

    let page_chirho = build_next_page_chirho(
        group_digest_chirho,
        &snapshot_chirho,
        previous_page_chirho.as_ref(),
        slice_chirho,
    )?;
    let verified_page_chirho = persist_bundle_page_chirho(storage_chirho, page_chirho)?;
    if verified_page_chirho
        .page_chirho
        .next_upper_exclusive_account_chirho
        .is_some()
    {
        return Ok(Gd7WinnerViewBundleStageOutcomeChirho::ContinueChirho {
            restart_chirho: Gd7WinnerViewBundleRestartChirho {
                page_ref_chirho: verified_page_chirho.object_digest_chirho,
            },
        });
    }
    persist_bundle_root_chirho(
        storage_chirho,
        group_digest_chirho,
        &snapshot_chirho,
        Some(verified_page_chirho.object_digest_chirho),
        verified_page_chirho
            .page_chirho
            .cumulative_page_count_chirho,
        verified_page_chirho.page_chirho.cumulative_row_count_chirho,
    )
    .map(
        |bundle_root_chirho| Gd7WinnerViewBundleStageOutcomeChirho::CompleteChirho {
            bundle_root_chirho,
        },
    )
}

fn build_next_page_chirho(
    group_digest_chirho: &str,
    snapshot_chirho: &Gd7WinnerJournalSnapshotChirho,
    previous_page_chirho: Option<&VerifiedGd7WinnerViewBundlePageChirho>,
    slice_chirho: AccountNetProjectionPageSliceChirho,
) -> Result<Gd7WinnerViewBundlePageChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let local_row_count_chirho = u64::try_from(slice_chirho.rows_chirho.len())
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
    let (page_index_chirho, higher_page_ref_chirho, cumulative_row_count_chirho) =
        if let Some(previous_page_chirho) = previous_page_chirho {
            if slice_chirho
                .rows_chirho
                .last()
                .zip(previous_page_chirho.page_chirho.rows_chirho.first())
                .is_none_or(|(lower_chirho, higher_chirho)| {
                    lower_chirho.account_chirho >= higher_chirho.account_chirho
                })
            {
                return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho);
            }
            (
                previous_page_chirho
                    .page_chirho
                    .page_index_chirho
                    .checked_add(1)
                    .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?,
                Some(previous_page_chirho.object_digest_chirho.clone()),
                previous_page_chirho
                    .page_chirho
                    .cumulative_row_count_chirho
                    .checked_add(local_row_count_chirho)
                    .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?,
            )
        } else {
            (0, None, local_row_count_chirho)
        };
    let cumulative_page_count_chirho = page_index_chirho
        .checked_add(1)
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
    let page_chirho = Gd7WinnerViewBundlePageChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_PAGE_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.to_owned(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: snapshot_chirho.genesis_digest_chirho.clone(),
        source_cut_chirho: snapshot_chirho.cut_chirho.clone(),
        page_index_chirho,
        higher_page_ref_chirho,
        rows_chirho: slice_chirho.rows_chirho,
        next_upper_exclusive_account_chirho: slice_chirho.next_upper_exclusive_account_chirho,
        cumulative_page_count_chirho,
        cumulative_row_count_chirho,
    };
    validate_bundle_page_shape_chirho(&page_chirho)?;
    Ok(page_chirho)
}

fn validate_previous_page_chirho(
    previous_page_chirho: &VerifiedGd7WinnerViewBundlePageChirho,
    group_digest_chirho: &str,
    snapshot_chirho: &Gd7WinnerJournalSnapshotChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if previous_page_chirho
        .page_chirho
        .consistency_group_digest_chirho
        != group_digest_chirho
        || previous_page_chirho
            .page_chirho
            .winner_journal_genesis_digest_chirho
            != snapshot_chirho.genesis_digest_chirho
        || previous_page_chirho.page_chirho.source_cut_chirho != snapshot_chirho.cut_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho);
    }
    Ok(())
}

fn persist_bundle_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    page_chirho: Gd7WinnerViewBundlePageChirho,
) -> Result<VerifiedGd7WinnerViewBundlePageChirho, Gd7WinnerCurrentViewRefusalChirho> {
    validate_bundle_page_shape_chirho(&page_chirho)?;
    let bytes_chirho = canonical_json_chirho(&page_chirho)?;
    if bytes_chirho.len() > MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedBundlePageChirho);
    }
    let object_digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_view_bundle_page_path_chirho(&object_digest_chirho)?;
    create_exact_chirho(
        storage_chirho,
        &path_chirho,
        &bytes_chirho,
        MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
    )?;
    load_verified_bundle_page_chirho(storage_chirho, &object_digest_chirho)
}

pub(super) fn parse_verified_inline_bundle_page_chirho(
    bytes_chirho: &[u8],
) -> Result<VerifiedGd7WinnerViewBundlePageChirho, Gd7WinnerCurrentViewRefusalChirho> {
    if bytes_chirho.len() > MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedBundlePageChirho);
    }
    let page_chirho: Gd7WinnerViewBundlePageChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::MalformedBundlePageChirho)?;
    validate_bundle_page_shape_chirho(&page_chirho)?;
    if canonical_json_chirho(&page_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::NonCanonicalBundlePageChirho);
    }
    Ok(VerifiedGd7WinnerViewBundlePageChirho {
        object_digest_chirho: digest_bytes_chirho(bytes_chirho),
        page_chirho,
    })
}

pub(super) fn load_verified_bundle_page_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    object_digest_chirho: &str,
) -> Result<VerifiedGd7WinnerViewBundlePageChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let path_chirho = gd7_winner_view_bundle_page_path_chirho(object_digest_chirho)?;
    let bytes_chirho = read_bounded_chirho(
        storage_chirho,
        &path_chirho,
        MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
        Gd7WinnerCurrentViewRefusalChirho::OversizedBundlePageChirho,
    )?
    .ok_or(Gd7WinnerCurrentViewRefusalChirho::MissingBundlePageChirho)?;
    if digest_bytes_chirho(&bytes_chirho) != object_digest_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho);
    }
    let page_chirho: Gd7WinnerViewBundlePageChirho = parse_json_chirho(
        &bytes_chirho,
        Gd7WinnerCurrentViewRefusalChirho::MalformedBundlePageChirho,
    )?;
    validate_bundle_page_shape_chirho(&page_chirho)?;
    if canonical_json_chirho(&page_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::NonCanonicalBundlePageChirho);
    }
    Ok(VerifiedGd7WinnerViewBundlePageChirho {
        object_digest_chirho: object_digest_chirho.to_owned(),
        page_chirho,
    })
}

fn validate_bundle_page_shape_chirho(
    page_chirho: &Gd7WinnerViewBundlePageChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    let row_count_chirho = u64::try_from(page_chirho.rows_chirho.len())
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
    let expected_page_count_chirho = page_chirho
        .page_index_chirho
        .checked_add(1)
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
    let maximum_cumulative_rows_chirho = expected_page_count_chirho
        .checked_mul(
            u64::try_from(ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO)
                .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?,
        )
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
    let cursor_valid_chirho = match &page_chirho.next_upper_exclusive_account_chirho {
        Some(cursor_chirho) => {
            page_chirho.rows_chirho.len() == ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
                && page_chirho
                    .rows_chirho
                    .first()
                    .is_some_and(|row_chirho| &row_chirho.account_chirho == cursor_chirho)
        }
        None => true,
    };
    if page_chirho.schema_chirho != GD7_WINNER_VIEW_BUNDLE_PAGE_SCHEMA_V1_CHIRHO
        || consistency_group_digest_suffix_chirho(&page_chirho.consistency_group_digest_chirho)
            .is_none()
        || page_chirho.projection_fold_ref_chirho != account_net_projection_fold_ref_chirho().0
        || !is_lower_hex_digest_chirho(&page_chirho.winner_journal_genesis_digest_chirho)
        || !is_lower_hex_digest_chirho(&page_chirho.source_cut_chirho.record_digest_chirho)
        || page_chirho.rows_chirho.is_empty()
        || page_chirho.rows_chirho.len() > ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO
        || !page_chirho
            .rows_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0].account_chirho < pair_chirho[1].account_chirho)
        || page_chirho.rows_chirho.iter().any(|row_chirho| {
            validate_ledger_account_identifier_chirho(&row_chirho.account_chirho).is_err()
        })
        || !cursor_valid_chirho
        || page_chirho.cumulative_page_count_chirho != expected_page_count_chirho
        || page_chirho.cumulative_row_count_chirho < row_count_chirho
        || page_chirho.cumulative_row_count_chirho > maximum_cumulative_rows_chirho
        || (page_chirho.page_index_chirho == 0) != page_chirho.higher_page_ref_chirho.is_none()
        || page_chirho
            .higher_page_ref_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho);
    }
    Ok(())
}

fn persist_bundle_root_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_digest_chirho: &str,
    snapshot_chirho: &Gd7WinnerJournalSnapshotChirho,
    lowest_page_ref_chirho: Option<String>,
    page_count_chirho: u64,
    row_count_chirho: u64,
) -> Result<VerifiedGd7WinnerViewBundleRootChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.to_owned(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: snapshot_chirho.genesis_digest_chirho.clone(),
        source_cut_chirho: snapshot_chirho.cut_chirho.clone(),
        lowest_page_ref_chirho,
        page_count_chirho,
        row_count_chirho,
    };
    validate_bundle_root_shape_chirho(&root_chirho)?;
    let bytes_chirho = canonical_json_chirho(&root_chirho)?;
    if bytes_chirho.len() > MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedBundleRootChirho);
    }
    let object_digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho = gd7_winner_view_bundle_root_path_chirho(&object_digest_chirho)?;
    create_exact_chirho(
        storage_chirho,
        &path_chirho,
        &bytes_chirho,
        MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO,
    )?;
    load_verified_bundle_root_chirho(storage_chirho, &object_digest_chirho)
}
