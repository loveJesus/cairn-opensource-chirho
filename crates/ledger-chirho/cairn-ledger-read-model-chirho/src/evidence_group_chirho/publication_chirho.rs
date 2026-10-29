// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF7 brick-1: DURABLE PUBLICATION of materialized projections — atomic OLD-OR-REFUSE with the
//! signed receipt as THE commit point (design ruled both-seat in
//! `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md` §3).
//!
//! Publication = (1) CAS-write the view bytes at their blake3 digest (content-addressed, hence
//! idempotent), then (2) `atomic_write` the signed follow receipt to the projection's published
//! HEAD path. The receipt already binds the view digest, descriptor digest, and full source cut,
//! and is self-authenticating under the feeder root — so the single atomic receipt write IS the
//! commit. A crash between (1) and (2) leaves the OLD receipt serving the OLD view; a receipt
//! whose view bytes are missing or divergent REFUSES (never partial, never unlabeled). This
//! module writes only DERIVED artifacts (views + receipts — rebuildable evidence, never money
//! records); the read-model's non-authority guard sanctions exactly this module for the
//! `atomic_write` surface.

use crate::feeder_chirho::{
    verify_follow_receipt_chirho, view_bytes_digest_hex_chirho, FollowReceiptChirho,
    MaterializedProjectionChirho,
};
use crate::merge_feeder_chirho::{
    verify_merge_follow_receipt_chirho, MaterializedMergeProjectionChirho, MergeFollowReceiptChirho,
};
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};

/// The CAS path for view bytes, by digest — content-addressed, so re-publication is idempotent
/// and two projections sharing identical bytes share one object.
pub fn view_cas_path_chirho(view_digest_hex_chirho: &str) -> StoragePathChirho {
    StoragePathChirho(format!("projections/views-chirho/{view_digest_hex_chirho}"))
}

/// Publish a STATE projection: CAS view bytes, then the atomic receipt commit.
pub fn publish_projection_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    materialized_chirho: &MaterializedProjectionChirho,
    head_path_chirho: &StoragePathChirho,
) -> Result<()> {
    let receipt_json_chirho = serde_json::to_vec(&materialized_chirho.receipt_chirho)
        .context("encode follow receipt for publication")?;
    publish_bytes_then_commit_chirho(
        storage_chirho,
        &materialized_chirho.view_bytes_chirho,
        &materialized_chirho.receipt_chirho.view_digest_hex_chirho,
        &receipt_json_chirho,
        head_path_chirho,
    )
}

/// Publish a MERGE projection: same commit law, vector receipt.
pub fn publish_merge_projection_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    materialized_chirho: &MaterializedMergeProjectionChirho,
    head_path_chirho: &StoragePathChirho,
) -> Result<()> {
    let receipt_json_chirho = serde_json::to_vec(&materialized_chirho.receipt_chirho)
        .context("encode merge follow receipt for publication")?;
    publish_bytes_then_commit_chirho(
        storage_chirho,
        &materialized_chirho.view_bytes_chirho,
        &materialized_chirho.receipt_chirho.view_digest_hex_chirho,
        &receipt_json_chirho,
        head_path_chirho,
    )
}

/// Load the published STATE projection at `head_path`: receipt (verified against the feeder root)
/// → view bytes by digest → binding re-hash. Missing or divergent bytes REFUSE.
pub fn load_published_projection_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    head_path_chirho: &StoragePathChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<MaterializedProjectionChirho> {
    let receipt_bytes_chirho =
        read_required_chirho(storage_chirho, head_path_chirho).context("published head receipt")?;
    let receipt_chirho: FollowReceiptChirho =
        serde_json::from_slice(&receipt_bytes_chirho).context("decode published follow receipt")?;
    verify_follow_receipt_chirho(&receipt_chirho, feeder_root_chirho)?;
    let view_bytes_chirho =
        load_bound_view_bytes_chirho(storage_chirho, &receipt_chirho.view_digest_hex_chirho)?;
    Ok(MaterializedProjectionChirho {
        view_bytes_chirho,
        receipt_chirho,
    })
}

/// Load the published MERGE projection at `head_path` — same law, vector receipt.
pub fn load_published_merge_projection_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    head_path_chirho: &StoragePathChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<MaterializedMergeProjectionChirho> {
    let receipt_bytes_chirho = read_required_chirho(storage_chirho, head_path_chirho)
        .context("published merge head receipt")?;
    let receipt_chirho: MergeFollowReceiptChirho = serde_json::from_slice(&receipt_bytes_chirho)
        .context("decode published merge follow receipt")?;
    verify_merge_follow_receipt_chirho(&receipt_chirho, feeder_root_chirho)?;
    let view_bytes_chirho =
        load_bound_view_bytes_chirho(storage_chirho, &receipt_chirho.view_digest_hex_chirho)?;
    Ok(MaterializedMergeProjectionChirho {
        view_bytes_chirho,
        receipt_chirho,
    })
}

fn publish_bytes_then_commit_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    view_bytes_chirho: &[u8],
    view_digest_hex_chirho: &str,
    receipt_json_chirho: &[u8],
    head_path_chirho: &StoragePathChirho,
) -> Result<()> {
    if view_bytes_digest_hex_chirho(view_bytes_chirho) != view_digest_hex_chirho {
        bail!("publication refused: view bytes do not re-hash to the receipt's bound digest");
    }
    storage_chirho
        .atomic_write_chirho(
            &view_cas_path_chirho(view_digest_hex_chirho),
            view_bytes_chirho,
        )
        .map_err(|error_chirho| anyhow::anyhow!("CAS view write failed: {error_chirho}"))?;
    storage_chirho
        .atomic_write_chirho(head_path_chirho, receipt_json_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("receipt commit failed: {error_chirho}"))?;
    Ok(())
}

fn read_required_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
) -> Result<Vec<u8>> {
    storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("read failed: {error_chirho}"))?
        .ok_or_else(|| anyhow::anyhow!("published object missing at {}", path_chirho.0))
}

fn load_bound_view_bytes_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    view_digest_hex_chirho: &str,
) -> Result<Vec<u8>> {
    let view_bytes_chirho = read_required_chirho(
        storage_chirho,
        &view_cas_path_chirho(view_digest_hex_chirho),
    )
    .context("published view bytes (a receipt without its bytes REFUSES, never partial)")?;
    if view_bytes_digest_hex_chirho(&view_bytes_chirho) != view_digest_hex_chirho {
        bail!("published view bytes do not re-hash to the receipt's bound digest");
    }
    Ok(view_bytes_chirho)
}

#[cfg(test)]
#[path = "publication_chirho/publication_tests_chirho.rs"]
mod publication_tests_chirho;
