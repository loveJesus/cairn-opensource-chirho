// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The projection FEEDER (CF4 brick-2): materialize a REGISTERED, CURRENT projection from a source
//! journal's VERIFIED state, and emit a signed FOLLOW RECEIPT — the staleness contract's evidence.
//!
//! Laws: (1) only a registry-CURRENT (name, digest) pair feeds — Superseded/Retired/Unknown refuse
//! typed (the downgrade law at feed time); (2) the fold is an INJECTED pure port over the journal's
//! verified state (the descriptor's fold_fn_ref names it; the port owns nothing, sees only verified
//! state); (3) the receipt is signed by the FEEDER's OWN injected root under a DISTINCT schema tag
//! (#4972b — per-authority keys, per-domain tags; a receipt is feeder evidence about a cut, never
//! journal authority); (4) the EQUIVALENCE CANARY re-opens and re-folds INDEPENDENTLY and requires
//! byte-equality — a divergent projection is a lying projection: rebuild + alarm, never trust.

use crate::registry_chirho::{ProjectionResolutionChirho, VerifiedProjectionRegistryChirho};
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{LedgerSignerPortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use serde::{Deserialize, Serialize};

pub const FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO: &str = "ledger-projection-follow-receipt-v1-chirho";

/// The verified journal state a fold may see — exactly what the journal's own verified open
/// establishes, nothing ambient. (Record-stream projections arrive with the merge increment; this
/// brick feeds the STATE-DERIVED class — balances and their kin.)
pub struct VerifiedSourceStateChirho<'journal_chirho> {
    pub journal_chirho: &'journal_chirho LedgerJournalChirho<'journal_chirho>,
}

/// The injected pure fold: verified source state → canonical view bytes. Implementations must be
/// DETERMINISTIC (the canary's byte-equality is the enforcement, not a convention).
pub trait ProjectionFoldPortChirho {
    fn fold_chirho(&self, source_chirho: &VerifiedSourceStateChirho<'_>) -> Result<Vec<u8>>;
}

/// The signed follow receipt: WHICH projection revision, from WHICH source cut, produced WHICH
/// view bytes — the evidence a degraded read carries per the bound staleness-serving law.
///
/// The cut is bound by FOUR coordinates, not two: seq + full HLC locate it, the GENESIS digest
/// names the journal INSTANCE (a rebuilt journal is a different instance, §11.6), and the TAIL
/// stored-line digest commits the exact verified prefix (dense prev-binding), so a forked history
/// replaying the same seq/HLC cannot wear this receipt. Named residual: an interior rewrite of a
/// SHARED-genesis chain below an old receipt's seq is detectable only with retained/anchored
/// per-seq digests — that is the cross-zone anchor hook's job, not this receipt's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FollowReceiptChirho {
    pub schema_chirho: String,
    pub projection_name_chirho: String,
    pub descriptor_digest_chirho: DigestChirho,
    pub source_cluster_chirho: String,
    pub source_genesis_digest_chirho: DigestChirho,
    pub source_tail_seq_chirho: u64,
    pub source_tail_hlc_chirho: HlcChirho,
    pub source_tail_line_digest_chirho: DigestChirho,
    pub view_digest_hex_chirho: String,
    pub feeder_sig_chirho: String,
}

/// One materialized feed: the view bytes plus the signed receipt binding them to the source cut.
#[derive(Debug)]
pub struct MaterializedProjectionChirho {
    pub view_bytes_chirho: Vec<u8>,
    pub receipt_chirho: FollowReceiptChirho,
}

/// The receipt-bound digest of the view BYTES — blake3 over the RAW bytes, never through a lossy
/// string conversion (distinct invalid-UTF8 views must never share a digest; the binding must be
/// injective over bytes, not over their replacement-character shadow).
pub fn view_bytes_digest_hex_chirho(view_bytes_chirho: &[u8]) -> String {
    blake3::hash(view_bytes_chirho).to_hex().to_string()
}

/// The receipt's signed content: the canonical line with the signature blanked.
pub fn follow_receipt_signed_content_chirho(
    receipt_chirho: &FollowReceiptChirho,
) -> Result<String> {
    if receipt_chirho.schema_chirho != FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO {
        bail!("unsupported follow receipt schema");
    }
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.feeder_sig_chirho = String::new();
    serde_json::to_string(&unsigned_chirho).context("encode follow receipt signed content")
}

/// Verify a carried receipt against the feeder's injected root (never an embedded key id).
pub fn verify_follow_receipt_chirho(
    receipt_chirho: &FollowReceiptChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<()> {
    let signed_content_chirho = follow_receipt_signed_content_chirho(receipt_chirho)?;
    if !feeder_root_chirho.verify_chirho(&signed_content_chirho, &receipt_chirho.feeder_sig_chirho)
    {
        bail!("follow receipt signature does not verify against the feeder root");
    }
    Ok(())
}

/// One source journal's coordinates: the ports + path + cluster a feed or canary opens through.
#[derive(Clone, Copy)]
pub struct ProjectionSourceChirho<'ports_chirho> {
    pub journal_ports_chirho: JournalPortsChirho<'ports_chirho>,
    pub journal_path_chirho: &'ports_chirho StoragePathChirho,
    pub cluster_chirho: &'ports_chirho ClusterIdChirho,
}

/// Feed ONE registered projection once: registry-CURRENT gate → the journal's VERIFIED read-only
/// open (never an unverified read and never a repair) → the injected fold → the signed receipt.
pub fn feed_projection_once_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    projection_name_chirho: &str,
    descriptor_digest_chirho: &DigestChirho,
    fold_chirho: &dyn ProjectionFoldPortChirho,
    source_chirho: ProjectionSourceChirho<'_>,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<MaterializedProjectionChirho> {
    match registry_chirho.resolve_chirho(projection_name_chirho, descriptor_digest_chirho) {
        ProjectionResolutionChirho::CurrentChirho { .. } => {}
        ProjectionResolutionChirho::SupersededChirho => {
            bail!("projection {projection_name_chirho} digest is SUPERSEDED — a new feed admits only the current revision")
        }
        ProjectionResolutionChirho::RetiredChirho => {
            bail!("projection {projection_name_chirho} is RETIRED — no revision feeds")
        }
        ProjectionResolutionChirho::UnknownChirho => {
            bail!("projection {projection_name_chirho} digest is UNKNOWN to the registry")
        }
    }
    let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("verified source open failed: {error_chirho:?}"))?;
    let state_chirho = VerifiedSourceStateChirho {
        journal_chirho: &journal_chirho,
    };
    let view_bytes_chirho = fold_chirho.fold_chirho(&state_chirho)?;
    let mut receipt_chirho = FollowReceiptChirho {
        schema_chirho: FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO.to_string(),
        projection_name_chirho: projection_name_chirho.to_string(),
        descriptor_digest_chirho: descriptor_digest_chirho.clone(),
        source_cluster_chirho: source_chirho.cluster_chirho.0.clone(),
        source_genesis_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
        source_tail_seq_chirho: journal_chirho.tail_seq_chirho(),
        source_tail_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
        source_tail_line_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        view_digest_hex_chirho: view_bytes_digest_hex_chirho(&view_bytes_chirho),
        feeder_sig_chirho: String::new(),
    };
    let signed_content_chirho = follow_receipt_signed_content_chirho(&receipt_chirho)?;
    receipt_chirho.feeder_sig_chirho = feeder_root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("sign follow receipt: {error_chirho}"))?;
    Ok(MaterializedProjectionChirho {
        view_bytes_chirho,
        receipt_chirho,
    })
}

/// THE EQUIVALENCE CANARY: independently re-open the source and re-fold, then require BYTE
/// equality with the materialized view. A mismatch means the projection LIES (a nondeterministic
/// fold, a stale materialization, or a divergent incremental path): the caller must rebuild and
/// alarm — never serve the divergent view. Returns the receipt-bound digest on success so the
/// caller can persist the canary pass as evidence.
pub fn equivalence_canary_chirho(
    materialized_chirho: &MaterializedProjectionChirho,
    fold_chirho: &dyn ProjectionFoldPortChirho,
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<String> {
    let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("canary source open failed: {error_chirho:?}"))?;
    if journal_chirho.tail_seq_chirho() != materialized_chirho.receipt_chirho.source_tail_seq_chirho
    {
        bail!(
            "canary source moved (tail {} vs receipt {}) — re-feed before comparing",
            journal_chirho.tail_seq_chirho(),
            materialized_chirho.receipt_chirho.source_tail_seq_chirho
        );
    }
    let state_chirho = VerifiedSourceStateChirho {
        journal_chirho: &journal_chirho,
    };
    let refolded_chirho = fold_chirho.fold_chirho(&state_chirho)?;
    if refolded_chirho != materialized_chirho.view_bytes_chirho {
        bail!(
            "EQUIVALENCE CANARY FIRED for projection {} — the materialized view diverges from the \
             independent re-fold; rebuild and alarm, never serve",
            materialized_chirho.receipt_chirho.projection_name_chirho
        );
    }
    Ok(materialized_chirho
        .receipt_chirho
        .view_digest_hex_chirho
        .clone())
}

#[cfg(test)]
#[path = "feeder_chirho/feeder_tests_chirho.rs"]
mod feeder_tests_chirho;
