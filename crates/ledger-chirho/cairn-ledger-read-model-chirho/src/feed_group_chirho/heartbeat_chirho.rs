// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! CF7 §5: SOURCE HEARTBEATS — idle-source frontier progress under the #5091 ruling.
//!
//! DEFAULT LAW (assumption-free): a heartbeat attests an OBSERVED verified head — family,
//! cluster, genesis instance, seq, HLC, tail-line digest — and frontier advance from it is
//! attested-TAIL-only. THE FULL CLOCK PROMISE (`clock_promise_ms`) exists ONLY under a DECLARED
//! compositional property: `ClockContractChirho::DeclaredMonotoneChirho`, which the composition
//! root may compose ONLY where the clock port implementation is documented never-regressing (the
//! written ports contract does NOT promise this — the engine tolerates regression by logical
//! bumps — so the promise is a COMPOSITION declaration, never an assumption; absence ⇒ tail-only,
//! the compositional-absence law's fourth application). Under a declared-monotone clock, the mint
//! reads the clock BEFORE the verified open, so every record OUTSIDE the observed prefix was
//! admitted after a later clock reading and carries `hlc.physical >= T` — the forward promise a
//! merge frontier may lean on. A record later observed BELOW a consumed promise is the h5
//! violation: a monitor-class alarm scoped to that source's projections (fail closed to rebuild),
//! never a silent reorder and never poison for sibling sources.

use crate::feeder_chirho::ProjectionSourceChirho;
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use serde::{Deserialize, Serialize};

pub const SOURCE_HEARTBEAT_SCHEMA_V1_CHIRHO: &str = "ledger-source-heartbeat-v1-chirho";

/// The composition-declared clock property. `DeclaredMonotoneChirho` may be composed ONLY where
/// the clock port implementation is documented never-regressing — the declaration is the
/// composition root's signed-off responsibility, and a breach is the h5 alarm's job to surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockContractChirho {
    UndeclaredChirho,
    DeclaredMonotoneChirho,
}

/// One signed heartbeat: the feeder root attests an observed verified head, plus the clock
/// promise iff minted under a declared-monotone clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceHeartbeatChirho {
    pub schema_chirho: String,
    pub family_id_chirho: String,
    pub cluster_chirho: String,
    pub genesis_digest_chirho: DigestChirho,
    pub observed_seq_chirho: u64,
    pub observed_hlc_chirho: HlcChirho,
    pub observed_tail_line_digest_chirho: DigestChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_promise_ms_chirho: Option<u64>,
    pub feeder_sig_chirho: String,
}

pub fn heartbeat_signed_content_chirho(heartbeat_chirho: &SourceHeartbeatChirho) -> Result<String> {
    if heartbeat_chirho.schema_chirho != SOURCE_HEARTBEAT_SCHEMA_V1_CHIRHO {
        bail!("unsupported source heartbeat schema");
    }
    let mut unsigned_chirho = heartbeat_chirho.clone();
    unsigned_chirho.feeder_sig_chirho = String::new();
    serde_json::to_string(&unsigned_chirho).context("encode heartbeat signed content")
}

pub fn verify_source_heartbeat_chirho(
    heartbeat_chirho: &SourceHeartbeatChirho,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
) -> Result<()> {
    let signed_content_chirho = heartbeat_signed_content_chirho(heartbeat_chirho)?;
    if !feeder_root_chirho
        .verify_chirho(&signed_content_chirho, &heartbeat_chirho.feeder_sig_chirho)
    {
        bail!("heartbeat signature does not verify against the feeder root");
    }
    Ok(())
}

/// The heartbeat's content digest (blake3 of the canonical signed line) — the coordinate a merge
/// receipt's source cut binds when it leans on this heartbeat.
pub fn heartbeat_digest_hex_chirho(heartbeat_chirho: &SourceHeartbeatChirho) -> Result<String> {
    let line_chirho =
        serde_json::to_string(heartbeat_chirho).context("encode canonical heartbeat line")?;
    Ok(blake3::hash(line_chirho.as_bytes()).to_hex().to_string())
}

/// Mint one heartbeat from a live verified read-only open. ORDER IS LOAD-BEARING under a
/// declared-monotone clock: the clock is read BEFORE the open, so every record outside the
/// observed prefix was admitted after a reading `>= T` and carries `hlc.physical >= T`.
pub fn mint_source_heartbeat_chirho(
    source_chirho: ProjectionSourceChirho<'_>,
    feeder_root_chirho: &dyn LedgerSignerPortChirho,
    clock_contract_chirho: ClockContractChirho,
) -> Result<SourceHeartbeatChirho> {
    let clock_promise_ms_chirho = match clock_contract_chirho {
        ClockContractChirho::DeclaredMonotoneChirho => Some(
            source_chirho
                .journal_ports_chirho
                .clock_chirho
                .physical_now_ms_chirho(),
        ),
        ClockContractChirho::UndeclaredChirho => None,
    };
    let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
        source_chirho.journal_ports_chirho,
        source_chirho.journal_path_chirho.clone(),
        source_chirho.cluster_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("verified source open failed: {error_chirho:?}"))?;
    let mut heartbeat_chirho = SourceHeartbeatChirho {
        schema_chirho: SOURCE_HEARTBEAT_SCHEMA_V1_CHIRHO.to_string(),
        family_id_chirho: crate::serving_chirho::journal_source_family_id_chirho(
            source_chirho.cluster_chirho,
        ),
        cluster_chirho: source_chirho.cluster_chirho.0.clone(),
        genesis_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
        observed_seq_chirho: journal_chirho.tail_seq_chirho(),
        observed_hlc_chirho: journal_chirho.tail_hlc_chirho().clone(),
        observed_tail_line_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        clock_promise_ms_chirho,
        feeder_sig_chirho: String::new(),
    };
    let signed_content_chirho = heartbeat_signed_content_chirho(&heartbeat_chirho)?;
    heartbeat_chirho.feeder_sig_chirho = feeder_root_chirho
        .sign_chirho(&signed_content_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("sign heartbeat: {error_chirho}"))?;
    Ok(heartbeat_chirho)
}

/// The h4 monotonicity law between consecutive heartbeats of one source: identity fields equal,
/// observed coordinates non-decreasing, and a promise never regresses or withdraws.
pub fn heartbeat_advances_chirho(
    prev_chirho: &SourceHeartbeatChirho,
    next_chirho: &SourceHeartbeatChirho,
) -> Result<()> {
    if prev_chirho.family_id_chirho != next_chirho.family_id_chirho
        || prev_chirho.cluster_chirho != next_chirho.cluster_chirho
        || prev_chirho.genesis_digest_chirho != next_chirho.genesis_digest_chirho
    {
        bail!("heartbeats name different sources or instances");
    }
    if next_chirho.observed_seq_chirho < prev_chirho.observed_seq_chirho {
        bail!("heartbeat observed seq regressed");
    }
    if next_chirho.observed_hlc_chirho < prev_chirho.observed_hlc_chirho {
        bail!("heartbeat observed HLC regressed");
    }
    match (
        prev_chirho.clock_promise_ms_chirho,
        next_chirho.clock_promise_ms_chirho,
    ) {
        (Some(prev_promise_chirho), Some(next_promise_chirho))
            if next_promise_chirho < prev_promise_chirho =>
        {
            bail!("heartbeat clock promise regressed");
        }
        (Some(_), None) => {
            bail!("heartbeat clock promise withdrawn (declared-monotone contract abandoned)");
        }
        _ => {}
    }
    Ok(())
}

/// The effective frontier coordinate a source contributes when a VALID heartbeat attests its
/// CURRENT cut: `max(observed HLC, promise-as-HLC)` — never past the observation's promise, and
/// exactly the observed tail when no promise was declared (tail-only default).
pub fn effective_head_hlc_chirho(heartbeat_chirho: &SourceHeartbeatChirho) -> HlcChirho {
    match heartbeat_chirho.clock_promise_ms_chirho {
        Some(promise_ms_chirho) => {
            let promise_hlc_chirho = HlcChirho {
                physical_ms_chirho: promise_ms_chirho,
                logical_chirho: 0,
            };
            if promise_hlc_chirho > heartbeat_chirho.observed_hlc_chirho {
                promise_hlc_chirho
            } else {
                heartbeat_chirho.observed_hlc_chirho.clone()
            }
        }
        None => heartbeat_chirho.observed_hlc_chirho.clone(),
    }
}

/// One h5 violation: a record OUTSIDE a prior receipt's observed prefix whose HLC is at-or-below
/// that receipt's (promise-advanced) frontier — the declared-monotone contract was breached for
/// this source (clock regression or a forged promise).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromiseViolationChirho {
    pub family_id_chirho: String,
    pub record_seq_chirho: u64,
    pub record_hlc_chirho: HlcChirho,
    pub promised_frontier_chirho: HlcChirho,
}

/// THE h5 NET (monitor-class, observational): re-extract each source and report every record that
/// arrived BEYOND a prior receipt's cut yet AT-OR-BELOW its promised frontier. Violations are
/// scoped evidence — the caller fails THAT source's projections closed to rebuild and pages;
/// sibling sources are never poisoned, and money gates are never touched.
pub fn heartbeat_promise_violation_check_chirho(
    prior_receipt_chirho: &crate::merge_feeder_chirho::MergeFollowReceiptChirho,
    sources_chirho: &[ProjectionSourceChirho<'_>],
) -> Result<Vec<PromiseViolationChirho>> {
    if prior_receipt_chirho.source_cuts_chirho.len() != sources_chirho.len() {
        bail!("violation check sources must cover the receipt's cut vector, in order");
    }
    let mut violations_chirho = Vec::new();
    for (cut_chirho, source_chirho) in prior_receipt_chirho
        .source_cuts_chirho
        .iter()
        .zip(sources_chirho)
    {
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            source_chirho.journal_ports_chirho,
            source_chirho.journal_path_chirho.clone(),
            source_chirho.cluster_chirho,
        )
        .map_err(|error_chirho| anyhow::anyhow!("verified source open failed: {error_chirho:?}"))?;
        if journal_chirho.genesis_digest_chirho() != &cut_chirho.genesis_digest_chirho {
            bail!(
                "live source {} is a different instance than the receipt's cut",
                cut_chirho.family_id_chirho
            );
        }
        let lines_chirho =
            cairn_ledger_log_chirho::recompose_chirho::read_recomposed_journal_lines_chirho(
                source_chirho.journal_ports_chirho,
                source_chirho.journal_path_chirho,
                source_chirho.cluster_chirho,
            )
            .map_err(|error_chirho| {
                anyhow::anyhow!("recomposed re-read failed: {error_chirho:?}")
            })?;
        for line_chirho in lines_chirho.iter().skip(1) {
            let parsed_chirho =
                cairn_ledger_model_chirho::wire_chirho::parse_canonical_ledger_journal_line_chirho(
                    line_chirho,
                )
                .map_err(|error_chirho| anyhow::anyhow!("re-read parse: {error_chirho:?}"))?;
            if let cairn_ledger_model_chirho::wire_chirho::LedgerJournalLineChirho::RecordChirho(
                record_chirho,
            ) = parsed_chirho
            {
                if record_chirho.seq_chirho > cut_chirho.head_seq_chirho
                    && record_chirho.hlc_chirho <= prior_receipt_chirho.safe_frontier_hlc_chirho
                {
                    violations_chirho.push(PromiseViolationChirho {
                        family_id_chirho: cut_chirho.family_id_chirho.clone(),
                        record_seq_chirho: record_chirho.seq_chirho,
                        record_hlc_chirho: record_chirho.hlc_chirho.clone(),
                        promised_frontier_chirho: prior_receipt_chirho
                            .safe_frontier_hlc_chirho
                            .clone(),
                    });
                }
            }
        }
    }
    Ok(violations_chirho)
}

#[cfg(test)]
#[path = "heartbeat_chirho/heartbeat_tests_chirho.rs"]
mod heartbeat_tests_chirho;
