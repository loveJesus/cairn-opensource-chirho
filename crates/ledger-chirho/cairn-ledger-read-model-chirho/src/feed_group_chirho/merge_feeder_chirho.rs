// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF4 brick-4: the MERGE FEEDER — materialize a record-stream (multi-source) projection through
//! the landed canonical merge ORACLE, and emit a signed merge follow receipt binding EVERY source
//! cut plus the safe frontier.
//!
//! The extraction law: each source journal is first opened VERIFIED and read-only (the deep laws —
//! signatures, dense seq, prev-binding, epoch anchors, F4 fold — are proven by the open, exactly
//! once). The per-record event list is then built from a port RE-READ of the raw lines, and that is
//! BOUND to the proven chain by recomputing the stored-line digest walk: genesis digest must equal
//! the open's instance identity, every record's `prev` must bind the prior line digest, and the
//! final digest must equal the open's verified tail-line digest. A re-read that diverges from the
//! proven chain (a torn write or a TOCTOU mutation between open and read) fails closed — the deep
//! laws are never re-proven here, and never trusted from unbound bytes either.

use crate::descriptor_chirho::{
    verify_projection_descriptor_chirho, ProjectionDescriptorChirho,
    VerifiedProjectionDescriptorChirho, VerifiedProjectionSourceChirho,
};
use crate::feeder_chirho::{view_bytes_digest_hex_chirho, ProjectionSourceChirho};
use crate::merge_chirho::{
    canonical_projection_merge_chirho, CanonicalProjectionMergeChirho, ProjectionMergeEventChirho,
    ProjectionMergeSourcePrefixChirho,
};
use crate::registry_chirho::{ProjectionResolutionChirho, VerifiedProjectionRegistryChirho};
use crate::serving_chirho::journal_source_family_id_chirho;
use crate::{ProjectionWatermarkChirho, VerifiedProjectionSourceHeadChirho};
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_log_chirho::recompose_chirho::read_recomposed_journal_lines_chirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use serde::{Deserialize, Serialize};

pub const MERGE_FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO: &str =
    "ledger-projection-merge-follow-receipt-v1-chirho";

/// One source journal's cut as bound by a merge receipt: instance identity + verified head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeSourceCutChirho {
    pub family_id_chirho: String,
    pub cluster_chirho: String,
    pub genesis_digest_chirho: DigestChirho,
    pub head_seq_chirho: u64,
    pub head_hlc_chirho: HlcChirho,
    pub head_line_digest_chirho: DigestChirho,
    /// The clock promise this cut leaned on (§5): present ONLY when a valid heartbeat attesting
    /// EXACTLY this cut carried a declared-monotone promise. Serving re-derives the frontier as
    /// min over `max(head HLC, promise)` per cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_promise_ms_chirho: Option<u64>,
    /// The consumed heartbeat's content digest — the evidence coordinate for the promise above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_digest_hex_chirho: Option<String>,
}

/// The signed merge follow receipt: WHICH projection revision, from WHICH exact source VECTOR,
/// under WHICH safe frontier, produced WHICH view bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeFollowReceiptChirho {
    pub schema_chirho: String,
    pub projection_name_chirho: String,
    pub descriptor_digest_chirho: DigestChirho,
    pub safe_frontier_hlc_chirho: HlcChirho,
    pub source_cuts_chirho: Vec<MergeSourceCutChirho>,
    pub view_digest_hex_chirho: String,
    pub feeder_sig_chirho: String,
}

/// One materialized merge feed: view bytes + the receipt binding them to the source vector.
#[derive(Debug)]
pub struct MaterializedMergeProjectionChirho {
    pub view_bytes_chirho: Vec<u8>,
    pub receipt_chirho: MergeFollowReceiptChirho,
}

/// The injected pure merge fold: canonical merged prefix → canonical view bytes. Deterministic by
/// law — the merge canary's byte-equality is the enforcement.
pub trait MergeFoldPortChirho {
    fn fold_chirho(&self, merged_chirho: &CanonicalProjectionMergeChirho) -> Result<Vec<u8>>;
}

pub fn merge_receipt_signed_content_chirho(
    receipt_chirho: &MergeFollowReceiptChirho,
) -> Result<String> {
    if receipt_chirho.schema_chirho != MERGE_FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO {
        bail!("unsupported merge follow receipt schema");
    }
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.feeder_sig_chirho = String::new();
    serde_json::to_string(&unsigned_chirho).context("encode merge follow receipt signed content")
}

pub fn verify_merge_follow_receipt_chirho(
    receipt_chirho: &MergeFollowReceiptChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<()> {
    let signed_content_chirho = merge_receipt_signed_content_chirho(receipt_chirho)?;
    if !feeder_root_chirho.verify_chirho(&signed_content_chirho, &receipt_chirho.feeder_sig_chirho)
    {
        bail!("merge follow receipt signature does not verify against the feeder root");
    }
    Ok(())
}

/// One extracted, chain-bound source prefix plus the coordinates its receipt cut will bind.
struct ExtractedSourceChirho {
    prefix_chirho: ProjectionMergeSourcePrefixChirho,
    cut_chirho: MergeSourceCutChirho,
}

/// Extract one source journal's event prefix under the extraction law (see module doc).
fn extract_verified_source_prefix_chirho(
    source_chirho: ProjectionSourceChirho<'_>,
) -> Result<ExtractedSourceChirho> {
    let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("verified source open failed: {error_chirho:?}"))?;
    let family_id_chirho = journal_source_family_id_chirho(source_chirho.cluster_chirho);

    let lines_chirho = read_recomposed_journal_lines_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho,
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("source re-read failed: {error_chirho:?}"))?;

    let mut events_chirho: Vec<ProjectionMergeEventChirho> = Vec::new();
    let mut genesis_hlc_chirho: Option<HlcChirho> = None;
    let mut prev_digest_chirho: Option<DigestChirho> = None;
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        let parsed_chirho =
            parse_canonical_ledger_journal_line_chirho(line_chirho).map_err(|error_chirho| {
                anyhow::anyhow!("re-read parse at line {index_chirho}: {error_chirho:?}")
            })?;
        let line_digest_chirho = stored_line_digest_chirho(line_chirho);
        match parsed_chirho {
            LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => {
                if index_chirho != 0 {
                    bail!("genesis line at nonzero index {index_chirho}");
                }
                if &line_digest_chirho != journal_chirho.genesis_digest_chirho() {
                    bail!("re-read genesis does not bind the verified instance identity");
                }
                genesis_hlc_chirho = Some(genesis_chirho.hlc_chirho.clone());
            }
            LedgerJournalLineChirho::RecordChirho(record_chirho) => {
                let prev_bound_chirho = prev_digest_chirho
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("record before genesis in re-read"))?;
                if &record_chirho.prev_chirho != prev_bound_chirho {
                    bail!(
                        "re-read prev-binding breaks at seq {} — bytes diverge from the verified chain",
                        record_chirho.seq_chirho
                    );
                }
                events_chirho.push(ProjectionMergeEventChirho {
                    source_family_id_chirho: family_id_chirho.clone(),
                    source_seq_chirho: record_chirho.seq_chirho,
                    source_hlc_chirho: record_chirho.hlc_chirho.clone(),
                    signed_line_digest_chirho: line_digest_chirho.clone(),
                });
            }
        }
        prev_digest_chirho = Some(line_digest_chirho);
    }
    let tail_digest_chirho =
        prev_digest_chirho.ok_or_else(|| anyhow::anyhow!("source journal re-read is empty"))?;
    if &tail_digest_chirho != journal_chirho.tail_line_digest_chirho() {
        bail!("re-read tail digest does not bind the verified chain (TOCTOU or torn re-read)");
    }
    if events_chirho.len() as u64 != journal_chirho.tail_seq_chirho() {
        bail!(
            "re-read event count {} diverges from the verified tail seq {}",
            events_chirho.len(),
            journal_chirho.tail_seq_chirho()
        );
    }

    let genesis_hlc_chirho =
        genesis_hlc_chirho.ok_or_else(|| anyhow::anyhow!("source journal has no genesis line"))?;
    let prefix_chirho = ProjectionMergeSourcePrefixChirho {
        genesis_chirho: ProjectionWatermarkChirho {
            source_family_id_chirho: family_id_chirho.clone(),
            source_seq_chirho: 0,
            source_hlc_chirho: genesis_hlc_chirho,
            signed_prefix_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
        },
        verified_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: family_id_chirho.clone(),
            source_seq_chirho: journal_chirho.tail_seq_chirho(),
            source_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
            signed_prefix_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        },
        events_chirho,
    };
    let cut_chirho = MergeSourceCutChirho {
        family_id_chirho,
        cluster_chirho: source_chirho.cluster_chirho.0.clone(),
        genesis_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
        head_seq_chirho: journal_chirho.tail_seq_chirho(),
        head_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
        head_line_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        clock_promise_ms_chirho: None,
        heartbeat_digest_hex_chirho: None,
    };
    Ok(ExtractedSourceChirho {
        prefix_chirho,
        cut_chirho,
    })
}

/// Feed ONE registered record-stream projection once: registry-CURRENT gate → descriptor evidence
/// verification → per-source chain-bound extraction (descriptor order; each source's canonical
/// family id must match its binding) → the canonical merge ORACLE → the injected fold → the
/// signed vector receipt.
pub fn feed_merge_projection_once_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    projection_name_chirho: &str,
    descriptor_digest_chirho: &DigestChirho,
    fold_chirho: &dyn MergeFoldPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<MaterializedMergeProjectionChirho> {
    let none_heartbeats_chirho: Vec<Option<&crate::heartbeat_chirho::SourceHeartbeatChirho>> =
        vec![None; sources_chirho.len()];
    feed_merge_projection_with_heartbeats_chirho(
        registry_chirho,
        projection_name_chirho,
        descriptor_digest_chirho,
        fold_chirho,
        verified_sources_chirho,
        sources_chirho,
        &none_heartbeats_chirho,
        feeder_root_chirho,
    )
}

/// §5: feed with per-source OPTIONAL heartbeats (descriptor order). A valid heartbeat attesting a
/// source's EXACT current cut may raise that source's frontier contribution (tail-only by
/// default; past the tail only under a declared-monotone clock promise) — see
/// `heartbeat_chirho` for the ruling and laws.
#[allow(clippy::too_many_arguments)]
pub fn feed_merge_projection_with_heartbeats_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    projection_name_chirho: &str,
    descriptor_digest_chirho: &DigestChirho,
    fold_chirho: &dyn MergeFoldPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
    heartbeats_chirho: &[Option<&crate::heartbeat_chirho::SourceHeartbeatChirho>],
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<MaterializedMergeProjectionChirho> {
    let (verified_descriptor_chirho, merged_chirho, cuts_chirho) = merge_at_current_cut_chirho(
        registry_chirho,
        projection_name_chirho,
        descriptor_digest_chirho,
        verified_sources_chirho,
        sources_chirho,
        heartbeats_chirho,
        feeder_root_chirho,
    )?;
    let view_bytes_chirho = fold_chirho.fold_chirho(&merged_chirho)?;
    let mut receipt_chirho = MergeFollowReceiptChirho {
        schema_chirho: MERGE_FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO.to_string(),
        projection_name_chirho: projection_name_chirho.to_string(),
        descriptor_digest_chirho: verified_descriptor_chirho.digest_chirho().clone(),
        safe_frontier_hlc_chirho: merged_chirho.safe_frontier_hlc_chirho.clone(),
        source_cuts_chirho: cuts_chirho,
        view_digest_hex_chirho: view_bytes_digest_hex_chirho(&view_bytes_chirho),
        feeder_sig_chirho: String::new(),
    };
    let signed_content_chirho = merge_receipt_signed_content_chirho(&receipt_chirho)?;
    receipt_chirho.feeder_sig_chirho = feeder_root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("sign merge follow receipt: {error_chirho}"))?;
    Ok(MaterializedMergeProjectionChirho {
        view_bytes_chirho,
        receipt_chirho,
    })
}

/// THE MERGE EQUIVALENCE CANARY: independently re-extract every source, re-merge through the
/// oracle, re-fold, and require BYTE equality — after first requiring every source cut to still
/// be the receipt's cut (a moved source is an honest re-feed signal, never a lie verdict).
pub fn merge_equivalence_canary_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedMergeProjectionChirho,
    fold_chirho: &dyn MergeFoldPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<String> {
    let none_heartbeats_chirho: Vec<Option<&crate::heartbeat_chirho::SourceHeartbeatChirho>> =
        vec![None; sources_chirho.len()];
    merge_equivalence_canary_with_heartbeats_chirho(
        registry_chirho,
        materialized_chirho,
        fold_chirho,
        verified_sources_chirho,
        sources_chirho,
        &none_heartbeats_chirho,
        feeder_root_chirho,
    )
}

/// §5: the canary for heartbeat-fed materializations — the SAME heartbeats must re-derive the
/// SAME cuts and bytes (a moved vector stays the honest re-feed signal).
#[allow(clippy::too_many_arguments)]
pub fn merge_equivalence_canary_with_heartbeats_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedMergeProjectionChirho,
    fold_chirho: &dyn MergeFoldPortChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
    heartbeats_chirho: &[Option<&crate::heartbeat_chirho::SourceHeartbeatChirho>],
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<String> {
    let receipt_chirho = &materialized_chirho.receipt_chirho;
    let (_, merged_chirho, cuts_chirho) = merge_at_current_cut_chirho(
        registry_chirho,
        &receipt_chirho.projection_name_chirho,
        &receipt_chirho.descriptor_digest_chirho,
        verified_sources_chirho,
        sources_chirho,
        heartbeats_chirho,
        feeder_root_chirho,
    )?;
    if cuts_chirho != receipt_chirho.source_cuts_chirho {
        bail!("merge canary source vector moved — re-feed before comparing");
    }
    let refolded_chirho = fold_chirho.fold_chirho(&merged_chirho)?;
    if refolded_chirho != materialized_chirho.view_bytes_chirho {
        bail!(
            "MERGE EQUIVALENCE CANARY FIRED for projection {} — the materialized view diverges \
             from the independent re-merge; rebuild and alarm, never serve",
            receipt_chirho.projection_name_chirho
        );
    }
    Ok(receipt_chirho.view_digest_hex_chirho.clone())
}

/// Shared feed/canary spine: registry gate, descriptor evidence, ordered chain-bound extraction,
/// family binding check, oracle merge.
fn merge_at_current_cut_chirho(
    registry_chirho: &VerifiedProjectionRegistryChirho,
    projection_name_chirho: &str,
    descriptor_digest_chirho: &DigestChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
    sources_chirho: &[ProjectionSourceChirho<'_>],
    heartbeats_chirho: &[Option<&crate::heartbeat_chirho::SourceHeartbeatChirho>],
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<(
    VerifiedProjectionDescriptorChirho,
    CanonicalProjectionMergeChirho,
    Vec<MergeSourceCutChirho>,
)> {
    let descriptor_chirho: ProjectionDescriptorChirho = match registry_chirho
        .resolve_chirho(projection_name_chirho, descriptor_digest_chirho)
    {
        ProjectionResolutionChirho::CurrentChirho { descriptor_chirho } => descriptor_chirho,
        ProjectionResolutionChirho::SupersededChirho => {
            bail!("projection {projection_name_chirho} digest is SUPERSEDED — a new feed admits only the current revision")
        }
        ProjectionResolutionChirho::RetiredChirho => {
            bail!("projection {projection_name_chirho} is RETIRED — no revision feeds")
        }
        ProjectionResolutionChirho::UnknownChirho => {
            bail!("projection {projection_name_chirho} digest is UNKNOWN to the registry")
        }
    };
    let verified_descriptor_chirho =
        verify_projection_descriptor_chirho(descriptor_chirho, verified_sources_chirho)?;
    if verified_descriptor_chirho.digest_chirho() != descriptor_digest_chirho {
        bail!("descriptor digest diverges from the registry resolution");
    }
    let bindings_chirho = &verified_descriptor_chirho
        .descriptor_chirho()
        .source_families_chirho;
    if bindings_chirho.len() != sources_chirho.len()
        || heartbeats_chirho.len() != sources_chirho.len()
    {
        bail!(
            "merge feed sources/heartbeats must exactly cover the descriptor source set, in order"
        );
    }
    let mut prefixes_chirho = Vec::with_capacity(sources_chirho.len());
    let mut cuts_chirho = Vec::with_capacity(sources_chirho.len());
    let mut effective_heads_chirho = Vec::with_capacity(sources_chirho.len());
    for ((binding_chirho, source_chirho), heartbeat_chirho) in bindings_chirho
        .iter()
        .zip(sources_chirho)
        .zip(heartbeats_chirho)
    {
        let family_id_chirho = journal_source_family_id_chirho(source_chirho.cluster_chirho);
        if binding_chirho.family_id_chirho != family_id_chirho {
            bail!(
                "source cluster {} yields family {family_id_chirho} but the descriptor binds {}",
                source_chirho.cluster_chirho.0,
                binding_chirho.family_id_chirho
            );
        }
        let extracted_chirho = extract_verified_source_prefix_chirho(*source_chirho)?;
        let mut cut_chirho = extracted_chirho.cut_chirho;
        // §5: a heartbeat may raise this source's FRONTIER contribution iff it verifies under the
        // feeder root, names this exact source instance, and attests EXACTLY the extracted cut.
        // A stale or ahead heartbeat is ignored HONESTLY (the live head speaks); a forged or
        // foreign one refuses loudly rather than silently downgrading to tail-only.
        let mut effective_chirho = cut_chirho.head_hlc_chirho.clone();
        if let Some(heartbeat_chirho) = heartbeat_chirho {
            crate::heartbeat_chirho::verify_source_heartbeat_chirho(
                heartbeat_chirho,
                feeder_root_chirho,
            )?;
            if heartbeat_chirho.family_id_chirho != family_id_chirho
                || heartbeat_chirho.cluster_chirho != source_chirho.cluster_chirho.0
                || heartbeat_chirho.genesis_digest_chirho != cut_chirho.genesis_digest_chirho
            {
                bail!(
                    "heartbeat names a different source or instance than {} — refused",
                    family_id_chirho
                );
            }
            let attests_current_chirho = heartbeat_chirho.observed_seq_chirho
                == cut_chirho.head_seq_chirho
                && heartbeat_chirho.observed_tail_line_digest_chirho
                    == cut_chirho.head_line_digest_chirho;
            if attests_current_chirho {
                effective_chirho =
                    crate::heartbeat_chirho::effective_head_hlc_chirho(heartbeat_chirho);
                cut_chirho.clock_promise_ms_chirho = heartbeat_chirho.clock_promise_ms_chirho;
                cut_chirho.heartbeat_digest_hex_chirho = Some(
                    crate::heartbeat_chirho::heartbeat_digest_hex_chirho(heartbeat_chirho)?,
                );
            }
        }
        effective_heads_chirho.push(effective_chirho);
        prefixes_chirho.push(extracted_chirho.prefix_chirho);
        cuts_chirho.push(cut_chirho);
    }
    let mut merged_chirho =
        canonical_projection_merge_chirho(&verified_descriptor_chirho, &prefixes_chirho)?;
    // §5 frontier extension AT THE ADAPTER (the oracle stays frozen): the promised frontier is
    // min over per-source effective heads. Events between the oracle frontier and the promised
    // frontier already exist in the extracted prefixes (each source is complete through its own
    // head >= the promised frontier for active sources; the promise guarantees the idle source
    // has none) — selecting them with the oracle's OWN public merge key and appending preserves
    // the canonical total order because the key is HLC-major and every appended event is above
    // the oracle frontier.
    let promised_frontier_chirho = effective_heads_chirho
        .iter()
        .min()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("merge requires at least one source"))?;
    if promised_frontier_chirho > merged_chirho.safe_frontier_hlc_chirho {
        let mut pending_chirho: Vec<crate::merge_chirho::ProjectionMergeEventChirho> =
            prefixes_chirho
                .iter()
                .flat_map(|prefix_chirho| prefix_chirho.events_chirho.iter())
                .filter(|event_chirho| {
                    event_chirho.source_hlc_chirho > merged_chirho.safe_frontier_hlc_chirho
                        && event_chirho.source_hlc_chirho <= promised_frontier_chirho
                })
                .cloned()
                .collect();
        pending_chirho
            .sort_by_key(crate::merge_chirho::ProjectionMergeEventChirho::merge_key_chirho);
        merged_chirho.ordered_events_chirho.extend(pending_chirho);
        merged_chirho.safe_frontier_hlc_chirho = promised_frontier_chirho;
    }
    Ok((verified_descriptor_chirho, merged_chirho, cuts_chirho))
}

#[cfg(test)]
#[path = "merge_feeder_chirho/merge_feeder_tests_chirho.rs"]
mod merge_feeder_tests_chirho;
