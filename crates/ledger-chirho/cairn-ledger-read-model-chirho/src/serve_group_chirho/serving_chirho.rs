// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF4 brick-3: SERVE a follower read — the adapter that binds a signed follow receipt, the
//! registry-CURRENT gate, and a LIVE verified source open to the pure follower classifier, so
//! every served read is Fresh/Degraded/Refused by landed law over real evidence, never silently.
//!
//! Gate order (each refusal TYPED — the no-silent-downgrade law's serving half): (1) the receipt
//! must verify against the feeder root; (2) the (name, digest) pair must resolve registry-CURRENT
//! — a superseded/retired/unknown projection never serves however valid its bytes; (3) the view
//! bytes must re-hash to the receipt's bound digest; (4) the descriptor must verify against the
//! caller's source/privacy evidence and re-derive to the receipt's descriptor digest; (5) the live
//! verified open must be the SAME journal instance (genesis digest); then the pure classifier
//! decides Fresh/Degraded/Refused under the descriptor's own staleness contract, with the
//! receipt's tail-line digest giving the equal-seq fork net real teeth.

use crate::descriptor_chirho::{
    verify_projection_descriptor_chirho, VerifiedProjectionSourceChirho,
};
use crate::feeder_chirho::{
    verify_follow_receipt_chirho, MaterializedProjectionChirho, ProjectionSourceChirho,
};
use crate::follower_chirho::{
    classify_follower_read_chirho, FollowerReadRefusalChirho, ProjectionReadOutcomeChirho,
    ProjectionWatermarkChirho, PublishedProjectionViewChirho, VerifiedProjectionReadCutChirho,
    VerifiedProjectionSourceHeadChirho,
};
use crate::registry_chirho::{ProjectionResolutionChirho, VerifiedProjectionRegistryChirho};
use anyhow::Result;
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};

/// The canonical source-family id a cluster journal contributes under. Descriptors for
/// state-derived projections must bind exactly this id for their source cluster — the family
/// membership net in the classifier enforces it.
pub fn journal_source_family_id_chirho(cluster_chirho: &ClusterIdChirho) -> String {
    format!("ledger-journal-{}", cluster_chirho.0)
}

/// A serve-gate refusal: evidence failed BEFORE the read-law classifier could run. Every variant
/// is a distinct adversarial story — none may collapse into an unlabeled error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeGateRefusalChirho {
    /// The receipt does not verify against the feeder root (forged, tampered, or foreign-root).
    ReceiptSignatureChirho,
    /// The receipt's revision was valid once and is no longer current — re-feed, never serve.
    ProjectionSupersededChirho,
    /// The projection is retired: no revision serves.
    ProjectionRetiredChirho,
    /// The registry knows no such (name, digest) pair.
    ProjectionUnknownChirho,
    /// The view bytes do not re-hash to the receipt's bound digest (tampered materialization).
    ViewBytesDigestMismatchChirho,
    /// The descriptor failed source/privacy evidence verification or digest re-derivation.
    DescriptorEvidenceChirho { reason_chirho: String },
    /// The live journal is a DIFFERENT instance (genesis digest differs — rebuilt or foreign).
    SourceInstanceMismatchChirho,
    /// A merge receipt's safe frontier does not re-derive from its own bound source cuts.
    SafeFrontierMismatchChirho,
}

/// The outcome of one serve attempt: either the classifier ran (and its own Fresh/Degraded/
/// Refused stands), or a serve gate refused before evidence ever reached the read law.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FollowerServeOutcomeChirho {
    ReadChirho(ProjectionReadOutcomeChirho),
    GateRefusedChirho(ServeGateRefusalChirho),
}

#[derive(Clone, Copy)]
enum FollowerFreshnessPostureChirho {
    LagWindowChirho,
    EffectHostExactCutChirho,
}

/// Serve ONE follower read from a materialized projection over its live source journal.
///
/// `Err` is reserved for infrastructure failure (the live verified open itself failing); every
/// adversarial evidence failure returns a TYPED gate refusal or classifier refusal instead.
pub fn serve_follower_read_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedProjectionChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<FollowerServeOutcomeChirho> {
    serve_follower_read_with_posture_chirho(
        registry_chirho,
        materialized_chirho,
        feeder_root_chirho,
        verified_sources_chirho,
        source_chirho,
        FollowerFreshnessPostureChirho::LagWindowChirho,
    )
}

/// Serve a write-and-read effect host. A would-be Fresh view must bind the exact durable journal
/// cut; the ordinary lag allowance remains available only to projection-only followers.
pub fn serve_effect_host_follower_read_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedProjectionChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<FollowerServeOutcomeChirho> {
    serve_follower_read_with_posture_chirho(
        registry_chirho,
        materialized_chirho,
        feeder_root_chirho,
        verified_sources_chirho,
        source_chirho,
        FollowerFreshnessPostureChirho::EffectHostExactCutChirho,
    )
}

fn serve_follower_read_with_posture_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedProjectionChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    source_chirho: ProjectionSourceChirho<'_>,
    freshness_posture_chirho: FollowerFreshnessPostureChirho,
) -> Result<FollowerServeOutcomeChirho> {
    let receipt_chirho = &materialized_chirho.receipt_chirho;
    if verify_follow_receipt_chirho(receipt_chirho, feeder_root_chirho).is_err() {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ReceiptSignatureChirho,
        ));
    }
    let descriptor_chirho = match registry_chirho.resolve_chirho(
        &receipt_chirho.projection_name_chirho,
        &receipt_chirho.descriptor_digest_chirho,
    ) {
        ProjectionResolutionChirho::CurrentChirho { descriptor_chirho } => descriptor_chirho,
        ProjectionResolutionChirho::SupersededChirho => {
            return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
                ServeGateRefusalChirho::ProjectionSupersededChirho,
            ));
        }
        ProjectionResolutionChirho::RetiredChirho => {
            return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
                ServeGateRefusalChirho::ProjectionRetiredChirho,
            ));
        }
        ProjectionResolutionChirho::UnknownChirho => {
            return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
                ServeGateRefusalChirho::ProjectionUnknownChirho,
            ));
        }
    };
    let view_digest_chirho =
        crate::feeder_chirho::view_bytes_digest_hex_chirho(&materialized_chirho.view_bytes_chirho);
    if view_digest_chirho != receipt_chirho.view_digest_hex_chirho {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ViewBytesDigestMismatchChirho,
        ));
    }
    let verified_descriptor_chirho =
        match verify_projection_descriptor_chirho(descriptor_chirho, verified_sources_chirho) {
            Ok(verified_chirho) => verified_chirho,
            Err(error_chirho) => {
                return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
                    ServeGateRefusalChirho::DescriptorEvidenceChirho {
                        reason_chirho: error_chirho.to_string(),
                    },
                ));
            }
        };
    if verified_descriptor_chirho.digest_chirho() != &receipt_chirho.descriptor_digest_chirho {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::DescriptorEvidenceChirho {
                reason_chirho: "descriptor digest diverges from the receipt binding".to_string(),
            },
        ));
    }
    let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| {
        anyhow::anyhow!("live verified source open failed: {error_chirho:?}")
    })?;
    if journal_chirho.genesis_digest_chirho() != &receipt_chirho.source_genesis_digest_chirho {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::SourceInstanceMismatchChirho,
        ));
    }
    let family_id_chirho = journal_source_family_id_chirho(source_chirho.cluster_chirho);
    let watermark_chirho = ProjectionWatermarkChirho {
        source_family_id_chirho: family_id_chirho.clone(),
        source_seq_chirho: receipt_chirho.source_tail_seq_chirho,
        source_hlc_chirho: receipt_chirho.source_tail_hlc_chirho.clone(),
        signed_prefix_digest_chirho: receipt_chirho.source_tail_line_digest_chirho.clone(),
    };
    let view_chirho = PublishedProjectionViewChirho {
        descriptor_ref_chirho: verified_descriptor_chirho.digest_chirho().clone(),
        watermark_chirho: watermark_chirho.clone(),
        state_digest_chirho: DigestChirho(receipt_chirho.view_digest_hex_chirho.clone()),
    };
    let cut_chirho = VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: verified_descriptor_chirho.digest_chirho().clone(),
        view_prefix_chirho: watermark_chirho,
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: family_id_chirho,
            source_seq_chirho: journal_chirho.tail_seq_chirho(),
            source_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
            signed_prefix_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        },
    };
    let outcome_chirho =
        classify_follower_read_chirho(&view_chirho, &cut_chirho, &verified_descriptor_chirho);
    let outcome_chirho = if matches!(
        freshness_posture_chirho,
        FollowerFreshnessPostureChirho::EffectHostExactCutChirho
    ) && matches!(
        &outcome_chirho,
        ProjectionReadOutcomeChirho::FreshChirho { .. }
    ) && !effect_host_cut_is_exact_chirho(&cut_chirho)
    {
        ProjectionReadOutcomeChirho::RefusedChirho(FollowerReadRefusalChirho::EffectCutBehindChirho)
    } else {
        outcome_chirho
    };
    Ok(FollowerServeOutcomeChirho::ReadChirho(outcome_chirho))
}

fn effect_host_cut_is_exact_chirho(cut_chirho: &VerifiedProjectionReadCutChirho) -> bool {
    cut_chirho.view_prefix_chirho.source_seq_chirho
        == cut_chirho.current_head_chirho.source_seq_chirho
        && cut_chirho.view_prefix_chirho.signed_prefix_digest_chirho
            == cut_chirho.current_head_chirho.signed_prefix_digest_chirho
        && cut_chirho.view_prefix_chirho.source_hlc_chirho
            == cut_chirho.current_head_chirho.source_hlc_chirho
}

#[cfg(test)]
#[path = "serving_chirho/serving_tests_chirho.rs"]
mod serving_tests_chirho;
