// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF4 brick-5: SERVE a merge follower read — the vector-cut analog of the single-source serving
//! adapter. Gates mirror brick-3 (receipt sig → registry-CURRENT → view-bytes binding →
//! descriptor evidence → per-source instance identity), then the landed pure classifier runs PER
//! SOURCE against its live verified head, and the composite read is the WORST outcome: any
//! refusal refuses the read; otherwise the read is as stale as its stalest source, and the
//! descriptor's own staleness policy decides Fresh/Degraded exactly as in the single-source law.
//! One merge-only gate: the receipt's safe frontier must RE-DERIVE from its own bound cuts — a
//! receipt asserting a frontier its cuts contradict never reaches the classifier.

use crate::descriptor_chirho::{
    verify_projection_descriptor_chirho, VerifiedProjectionSourceChirho,
};
use crate::feeder_chirho::{view_bytes_digest_hex_chirho, ProjectionSourceChirho};
use crate::follower_chirho::{classify_follower_read_chirho, ProjectionReadOutcomeChirho};
use crate::merge_feeder_chirho::{
    verify_merge_follow_receipt_chirho, MaterializedMergeProjectionChirho,
};
use crate::registry_chirho::{ProjectionResolutionChirho, VerifiedProjectionRegistryChirho};
use crate::serving_chirho::{
    journal_source_family_id_chirho, FollowerServeOutcomeChirho, ServeGateRefusalChirho,
};
use crate::{
    ProjectionWatermarkChirho, PublishedProjectionViewChirho, VerifiedProjectionReadCutChirho,
    VerifiedProjectionSourceHeadChirho,
};
use anyhow::Result;
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

/// Serve ONE merge follower read from a materialized merge projection over its live sources.
///
/// `Err` is reserved for infrastructure failure; every adversarial evidence failure returns a
/// TYPED gate refusal or classifier refusal, and the composite outcome is the WORST per-source
/// outcome (refusal > degraded > fresh, lag = the maximum).
pub fn serve_merge_follower_read_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedMergeProjectionChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
) -> Result<FollowerServeOutcomeChirho> {
    let receipt_chirho = &materialized_chirho.receipt_chirho;
    if verify_merge_follow_receipt_chirho(receipt_chirho, feeder_root_chirho).is_err() {
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
    let view_digest_chirho = view_bytes_digest_hex_chirho(&materialized_chirho.view_bytes_chirho);
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
    // The merge-only gate: the asserted safe frontier must re-derive from the bound cuts —
    // per cut the EFFECTIVE head is max(head HLC, clock promise) (§5: a promise-advanced
    // frontier is exactly as trustworthy as the receipt carrying it; a frontier beyond what the
    // cuts + promises justify still refuses).
    let derived_frontier_chirho = receipt_chirho
        .source_cuts_chirho
        .iter()
        .map(|cut_chirho| {
            let head_chirho = cut_chirho.head_hlc_chirho.clone();
            match cut_chirho.clock_promise_ms_chirho {
                Some(promise_ms_chirho) => {
                    let promise_chirho = cairn_ledger_model_chirho::record_chirho::HlcChirho {
                        physical_ms_chirho: promise_ms_chirho,
                        logical_chirho: 0,
                    };
                    if promise_chirho > head_chirho {
                        promise_chirho
                    } else {
                        head_chirho
                    }
                }
                None => head_chirho,
            }
        })
        .min();
    if derived_frontier_chirho.as_ref() != Some(&receipt_chirho.safe_frontier_hlc_chirho) {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::SafeFrontierMismatchChirho,
        ));
    }
    let bindings_chirho = &verified_descriptor_chirho
        .descriptor_chirho()
        .source_families_chirho;
    if bindings_chirho.len() != sources_chirho.len()
        || receipt_chirho.source_cuts_chirho.len() != sources_chirho.len()
    {
        return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::DescriptorEvidenceChirho {
                reason_chirho: "merge serve sources must exactly cover the descriptor set"
                    .to_string(),
            },
        ));
    }

    // Per-source classification against the live verified heads; compose the WORST outcome.
    let mut worst_chirho: Option<ProjectionReadOutcomeChirho> = None;
    for (cut_chirho, source_chirho) in receipt_chirho.source_cuts_chirho.iter().zip(sources_chirho)
    {
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            source_chirho.journal_ports_chirho,
            source_chirho.journal_path_chirho.clone(),
            source_chirho.cluster_chirho,
        )
        .map_err(|error_chirho| {
            anyhow::anyhow!("live verified source open failed: {error_chirho:?}")
        })?;
        if journal_chirho.genesis_digest_chirho() != &cut_chirho.genesis_digest_chirho {
            return Ok(FollowerServeOutcomeChirho::GateRefusedChirho(
                ServeGateRefusalChirho::SourceInstanceMismatchChirho,
            ));
        }
        let family_id_chirho = journal_source_family_id_chirho(source_chirho.cluster_chirho);
        let watermark_chirho = ProjectionWatermarkChirho {
            source_family_id_chirho: family_id_chirho.clone(),
            source_seq_chirho: cut_chirho.head_seq_chirho,
            source_hlc_chirho: cut_chirho.head_hlc_chirho.clone(),
            signed_prefix_digest_chirho: cut_chirho.head_line_digest_chirho.clone(),
        };
        let view_chirho = PublishedProjectionViewChirho {
            descriptor_ref_chirho: verified_descriptor_chirho.digest_chirho().clone(),
            watermark_chirho: watermark_chirho.clone(),
            state_digest_chirho: DigestChirho(receipt_chirho.view_digest_hex_chirho.clone()),
        };
        let cut_dto_chirho = VerifiedProjectionReadCutChirho {
            descriptor_ref_chirho: verified_descriptor_chirho.digest_chirho().clone(),
            view_prefix_chirho: watermark_chirho,
            current_head_chirho: VerifiedProjectionSourceHeadChirho {
                source_family_id_chirho: family_id_chirho,
                source_seq_chirho: journal_chirho.tail_seq_chirho(),
                source_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
                signed_prefix_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
            },
        };
        let outcome_chirho = classify_follower_read_chirho(
            &view_chirho,
            &cut_dto_chirho,
            &verified_descriptor_chirho,
        );
        worst_chirho = Some(match worst_chirho.take() {
            None => outcome_chirho,
            Some(previous_chirho) => worse_outcome_chirho(previous_chirho, outcome_chirho),
        });
    }
    let composite_chirho =
        worst_chirho.ok_or_else(|| anyhow::anyhow!("merge serve requires at least one source"))?;
    Ok(FollowerServeOutcomeChirho::ReadChirho(composite_chirho))
}

/// The composite law: refusal dominates degraded dominates fresh; within a rank, keep the larger
/// lag (the read is as stale as its stalest source).
fn worse_outcome_chirho(
    left_chirho: ProjectionReadOutcomeChirho,
    right_chirho: ProjectionReadOutcomeChirho,
) -> ProjectionReadOutcomeChirho {
    use ProjectionReadOutcomeChirho as OutcomeChirho;
    match (left_chirho, right_chirho) {
        (refused_chirho @ OutcomeChirho::RefusedChirho(_), _) => refused_chirho,
        (_, refused_chirho @ OutcomeChirho::RefusedChirho(_)) => refused_chirho,
        (
            OutcomeChirho::DegradedChirho {
                view_chirho: left_view_chirho,
                lag_ms_chirho: left_lag_chirho,
                max_lag_ms_chirho,
            },
            OutcomeChirho::DegradedChirho {
                lag_ms_chirho: right_lag_chirho,
                ..
            },
        ) => OutcomeChirho::DegradedChirho {
            view_chirho: left_view_chirho,
            lag_ms_chirho: left_lag_chirho.max(right_lag_chirho),
            max_lag_ms_chirho,
        },
        (
            degraded_chirho @ OutcomeChirho::DegradedChirho { .. },
            OutcomeChirho::FreshChirho { .. },
        ) => degraded_chirho,
        (
            OutcomeChirho::FreshChirho { .. },
            degraded_chirho @ OutcomeChirho::DegradedChirho { .. },
        ) => degraded_chirho,
        (
            OutcomeChirho::FreshChirho {
                view_chirho: left_view_chirho,
                lag_ms_chirho: left_lag_chirho,
            },
            OutcomeChirho::FreshChirho {
                lag_ms_chirho: right_lag_chirho,
                ..
            },
        ) => OutcomeChirho::FreshChirho {
            view_chirho: left_view_chirho,
            lag_ms_chirho: left_lag_chirho.max(right_lag_chirho),
        },
    }
}

#[cfg(test)]
#[path = "merge_serving_chirho/merge_serving_tests_chirho.rs"]
mod merge_serving_tests_chirho;
