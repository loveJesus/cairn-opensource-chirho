// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Winner-signed, recipient-bound grants for one exact current-view page chain.
//!
//! A caller can fetch only the first page committed by the challenged root or the next page named
//! by a previously granted page. It never supplies a storage path, family, page size, or ungranted
//! object digest.

use super::bundle_chirho::load_verified_bundle_page_chirho;
use super::{
    canonical_json_chirho, consistency_group_digest_suffix_chirho, is_lower_hex_digest_chirho,
    load_verified_bundle_root_chirho, validate_key_and_signature_chirho,
    Gd7JournalTailCoordinateChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewRefusalChirho,
    VerifiedGd7WinnerViewBundleRootChirho, MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, split_writer_epoch_chirho, WRITER_EPOCH_COMPONENT_MAX_CHIRHO,
};
use serde::{Deserialize, Serialize};

pub const GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO: &str =
    "gd7-winner-view-page-grant-v1-chirho";
pub const MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO: usize = 8 * 1024;

/// Winner-signed authority to read one exact page for one exact held roster member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerViewPageGrantChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub held_node_chirho: String,
    pub winner_node_chirho: String,
    pub raft_term_chirho: u64,
    pub winner_process_generation_chirho: u64,
    pub winner_evidence_object_digest_chirho: String,
    pub bundle_root_object_digest_chirho: String,
    pub source_cut_chirho: Gd7JournalTailCoordinateChirho,
    pub page_index_chirho: u64,
    pub page_object_digest_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

impl Gd7WinnerViewPageGrantChirho {
    pub fn canonical_bytes_chirho(&self) -> Result<Vec<u8>, Gd7WinnerCurrentViewRefusalChirho> {
        let bytes_chirho = canonical_json_chirho(self)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO {
            return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
        }
        Ok(bytes_chirho)
    }
}

/// One canonical page plus the only grant that may continue its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gd7WinnerViewPageTransferChirho {
    pub grant_chirho: Gd7WinnerViewPageGrantChirho,
    pub canonical_page_bytes_chirho: Vec<u8>,
    pub next_grant_chirho: Option<Gd7WinnerViewPageGrantChirho>,
}

pub(crate) struct Gd7WinnerViewPageFetchContextChirho<'a> {
    pub storage_chirho: &'a dyn LedgerStoragePortChirho,
    pub signer_chirho: &'a dyn Gd7ReconciliationSignerPortChirho,
    pub local_authority_chirho: &'a LocalAppendAuthorityHandleChirho,
    pub requester_chirho: &'a NodeIdChirho,
    pub winner_evidence_object_digest_chirho: &'a str,
    pub bundle_root_chirho: &'a VerifiedGd7WinnerViewBundleRootChirho,
}

pub(crate) fn verify_gd7_winner_view_page_grant_chirho(
    grant_chirho: &Gd7WinnerViewPageGrantChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    validate_grant_shape_chirho(grant_chirho)?;
    if grant_chirho.key_id_chirho != verifier_chirho.key_id_chirho() {
        return Err(Gd7WinnerCurrentViewRefusalChirho::WrongSignerChirho);
    }
    let mut unsigned_chirho = grant_chirho.clone();
    let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, &signature_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidSignatureChirho);
    }
    if grant_chirho.canonical_bytes_chirho()?.len() > MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    Ok(())
}

pub(crate) fn issue_first_gd7_winner_view_page_grant_chirho<ResidentVerifierChirho>(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    held_node_chirho: &NodeIdChirho,
    winner_evidence_object_digest_chirho: &str,
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    verify_resident_chirho: ResidentVerifierChirho,
) -> Result<Option<Gd7WinnerViewPageGrantChirho>, Gd7WinnerCurrentViewRefusalChirho>
where
    ResidentVerifierChirho: FnOnce() -> Result<(), Gd7WinnerCurrentViewRefusalChirho>,
{
    validate_recipient_chirho(held_node_chirho, local_authority_chirho.node_id_chirho())?;
    let generation_guard_chirho = local_authority_chirho
        .try_acquire_chirho()
        .map_err(Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho)?;
    verify_resident_chirho()?;
    let reloaded_root_chirho = load_verified_bundle_root_chirho(
        storage_chirho,
        bundle_root_chirho.object_digest_chirho(),
    )?;
    let expected_group_digest_chirho =
        consistency_group_digest_chirho(local_authority_chirho.consistency_group_chirho())
            .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::InvalidCoordinateChirho)?;
    if &reloaded_root_chirho != bundle_root_chirho
        || reloaded_root_chirho
            .root_chirho()
            .consistency_group_digest_chirho
            != expected_group_digest_chirho
        || u64::from(
            split_writer_epoch_chirho(
                reloaded_root_chirho
                    .root_chirho()
                    .source_cut_chirho
                    .epoch_chirho,
            )
            .geo_term_chirho,
        ) != generation_guard_chirho.published_raft_term_chirho()
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho);
    }
    let Some(page_object_digest_chirho) = reloaded_root_chirho
        .root_chirho()
        .lowest_page_ref_chirho
        .as_ref()
    else {
        return Ok(None);
    };
    let page_index_chirho = reloaded_root_chirho
        .root_chirho()
        .page_count_chirho
        .checked_sub(1)
        .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundleRootChirho)?;
    build_grant_chirho(
        signer_chirho,
        held_node_chirho,
        local_authority_chirho.node_id_chirho(),
        generation_guard_chirho.published_raft_term_chirho(),
        generation_guard_chirho.process_generation_chirho(),
        winner_evidence_object_digest_chirho,
        &reloaded_root_chirho,
        page_index_chirho,
        page_object_digest_chirho,
    )
    .map(Some)
}

pub(crate) fn fetch_granted_gd7_winner_view_page_chirho<ResidentVerifierChirho>(
    context_chirho: Gd7WinnerViewPageFetchContextChirho<'_>,
    grant_chirho: Gd7WinnerViewPageGrantChirho,
    verify_resident_chirho: ResidentVerifierChirho,
) -> Result<Gd7WinnerViewPageTransferChirho, Gd7WinnerCurrentViewRefusalChirho>
where
    ResidentVerifierChirho: FnOnce() -> Result<(), Gd7WinnerCurrentViewRefusalChirho>,
{
    let Gd7WinnerViewPageFetchContextChirho {
        storage_chirho,
        signer_chirho,
        local_authority_chirho,
        requester_chirho,
        winner_evidence_object_digest_chirho,
        bundle_root_chirho,
    } = context_chirho;
    verify_gd7_winner_view_page_grant_chirho(&grant_chirho, signer_chirho)?;
    if grant_chirho.held_node_chirho != requester_chirho.0 {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    let generation_guard_chirho = local_authority_chirho
        .try_acquire_chirho()
        .map_err(Gd7WinnerCurrentViewRefusalChirho::LocalAuthorityChirho)?;
    verify_resident_chirho()?;
    let reloaded_root_chirho = load_verified_bundle_root_chirho(
        storage_chirho,
        bundle_root_chirho.object_digest_chirho(),
    )?;
    let root_chirho = reloaded_root_chirho.root_chirho();
    if &reloaded_root_chirho != bundle_root_chirho
        || grant_chirho.winner_node_chirho != local_authority_chirho.node_id_chirho().0
        || grant_chirho.raft_term_chirho != generation_guard_chirho.published_raft_term_chirho()
        || grant_chirho.winner_process_generation_chirho
            != generation_guard_chirho.process_generation_chirho()
        || grant_chirho.winner_evidence_object_digest_chirho != winner_evidence_object_digest_chirho
        || grant_chirho.bundle_root_object_digest_chirho
            != reloaded_root_chirho.object_digest_chirho()
        || grant_chirho.consistency_group_digest_chirho
            != root_chirho.consistency_group_digest_chirho
        || grant_chirho.source_cut_chirho != root_chirho.source_cut_chirho
        || grant_chirho.page_index_chirho >= root_chirho.page_count_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }

    let page_chirho =
        load_verified_bundle_page_chirho(storage_chirho, &grant_chirho.page_object_digest_chirho)?;
    let page_value_chirho = &page_chirho.page_chirho;
    if page_value_chirho.consistency_group_digest_chirho
        != root_chirho.consistency_group_digest_chirho
        || page_value_chirho.projection_fold_ref_chirho != root_chirho.projection_fold_ref_chirho
        || page_value_chirho.winner_journal_genesis_digest_chirho
            != root_chirho.winner_journal_genesis_digest_chirho
        || page_value_chirho.source_cut_chirho != root_chirho.source_cut_chirho
        || page_value_chirho.page_index_chirho != grant_chirho.page_index_chirho
        || (grant_chirho
            .page_index_chirho
            .checked_add(1)
            .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?
            == root_chirho.page_count_chirho
            && (page_value_chirho.cumulative_page_count_chirho != root_chirho.page_count_chirho
                || page_value_chirho.cumulative_row_count_chirho != root_chirho.row_count_chirho))
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho);
    }
    let canonical_page_bytes_chirho = canonical_json_chirho(page_value_chirho)?;
    if canonical_page_bytes_chirho.len() > MAX_GD7_WINNER_VIEW_BUNDLE_PAGE_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::OversizedBundlePageChirho);
    }
    let next_grant_chirho = match &page_value_chirho.higher_page_ref_chirho {
        Some(next_page_object_digest_chirho) => {
            let next_page_index_chirho = grant_chirho
                .page_index_chirho
                .checked_sub(1)
                .ok_or(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho)?;
            Some(build_grant_chirho(
                signer_chirho,
                requester_chirho,
                local_authority_chirho.node_id_chirho(),
                generation_guard_chirho.published_raft_term_chirho(),
                generation_guard_chirho.process_generation_chirho(),
                winner_evidence_object_digest_chirho,
                &reloaded_root_chirho,
                next_page_index_chirho,
                next_page_object_digest_chirho,
            )?)
        }
        None if grant_chirho.page_index_chirho == 0 => None,
        None => return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidBundlePageChirho),
    };
    Ok(Gd7WinnerViewPageTransferChirho {
        grant_chirho,
        canonical_page_bytes_chirho,
        next_grant_chirho,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the grant signs one exact bounded authority tuple without ambient inputs"
)]
fn build_grant_chirho(
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    held_node_chirho: &NodeIdChirho,
    winner_node_chirho: &NodeIdChirho,
    raft_term_chirho: u64,
    process_generation_chirho: u64,
    winner_evidence_object_digest_chirho: &str,
    bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    page_index_chirho: u64,
    page_object_digest_chirho: &str,
) -> Result<Gd7WinnerViewPageGrantChirho, Gd7WinnerCurrentViewRefusalChirho> {
    let root_chirho = bundle_root_chirho.root_chirho();
    let mut grant_chirho = Gd7WinnerViewPageGrantChirho {
        schema_chirho: GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: root_chirho.consistency_group_digest_chirho.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_node_chirho: winner_node_chirho.0.clone(),
        raft_term_chirho,
        winner_process_generation_chirho: process_generation_chirho,
        winner_evidence_object_digest_chirho: winner_evidence_object_digest_chirho.to_owned(),
        bundle_root_object_digest_chirho: bundle_root_chirho.object_digest_chirho().to_owned(),
        source_cut_chirho: root_chirho.source_cut_chirho.clone(),
        page_index_chirho,
        page_object_digest_chirho: page_object_digest_chirho.to_owned(),
        key_id_chirho: signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    validate_unsigned_grant_shape_chirho(&grant_chirho)?;
    let unsigned_bytes_chirho = canonical_json_chirho(&grant_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SerializationChirho)?;
    grant_chirho.sig_chirho = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
    validate_grant_shape_chirho(&grant_chirho)?;
    if grant_chirho.canonical_bytes_chirho()?.len() > MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    Ok(grant_chirho)
}

fn validate_recipient_chirho(
    held_node_chirho: &NodeIdChirho,
    winner_node_chirho: &NodeIdChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if !is_lower_hex_digest_chirho(&held_node_chirho.0) || held_node_chirho == winner_node_chirho {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    Ok(())
}

fn validate_unsigned_grant_shape_chirho(
    grant_chirho: &Gd7WinnerViewPageGrantChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    if grant_chirho.schema_chirho != GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO
        || consistency_group_digest_suffix_chirho(&grant_chirho.consistency_group_digest_chirho)
            .is_none()
        || !is_lower_hex_digest_chirho(&grant_chirho.held_node_chirho)
        || !is_lower_hex_digest_chirho(&grant_chirho.winner_node_chirho)
        || grant_chirho.held_node_chirho == grant_chirho.winner_node_chirho
        || grant_chirho.raft_term_chirho == 0
        || grant_chirho.raft_term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
        || grant_chirho.winner_process_generation_chirho == 0
        || !is_lower_hex_digest_chirho(&grant_chirho.winner_evidence_object_digest_chirho)
        || !is_lower_hex_digest_chirho(&grant_chirho.bundle_root_object_digest_chirho)
        || !is_lower_hex_digest_chirho(&grant_chirho.source_cut_chirho.record_digest_chirho)
        || u64::from(
            split_writer_epoch_chirho(grant_chirho.source_cut_chirho.epoch_chirho).geo_term_chirho,
        ) != grant_chirho.raft_term_chirho
        || !is_lower_hex_digest_chirho(&grant_chirho.page_object_digest_chirho)
        || grant_chirho.key_id_chirho != grant_chirho.winner_node_chirho
    {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    Ok(())
}

fn validate_grant_shape_chirho(
    grant_chirho: &Gd7WinnerViewPageGrantChirho,
) -> Result<(), Gd7WinnerCurrentViewRefusalChirho> {
    validate_unsigned_grant_shape_chirho(grant_chirho)?;
    if !validate_key_and_signature_chirho(&grant_chirho.key_id_chirho, &grant_chirho.sig_chirho) {
        return Err(Gd7WinnerCurrentViewRefusalChirho::InvalidPageGrantChirho);
    }
    Ok(())
}
