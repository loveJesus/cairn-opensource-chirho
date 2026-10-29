// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The realtime evidence doors that bind their answer against the verified legacy ledger.
//!
//! # Why this is its own module rather than lines in the evidence module
//!
//! `realtime_legacy_evidence_chirho`'s own header ends "**No writer, no session lifecycle, no ledger
//! dependency lives here**" — one sentence naming its job, which is the convention. Putting the
//! ledger-bound view beside the evidence bodies would falsify that sentence on the day it moved, so
//! the binding gets its own home and the evidence module keeps being exactly what it says it is.
//! Same reasoning, same shape, as `legacy_single_road_probe_chirho` (#7672): a gate is not a reader,
//! and a ledger binding is not evidence.
//!
//! Direction matters as much as tidiness. These symbols cannot live in `legacy_evidence_chirho`
//! beside the ledger read they call, because they also need the realtime record types — that would
//! make `legacy_evidence` → `privacy_compliance` against an existing
//! `privacy_compliance` → `legacy_evidence`, which is a NEW CYCLE in a program whose whole subject is
//! removing them. Here, both reaches run one way.
//!
//! # What moved here at CF6 wave-1, and the thing that had quietly stopped being true
//!
//! These are the wrappers that lived in the deleted `execution_runtime_chirho/realtime_chirho.rs`.
//! Their bodies always lived in the kept evidence module; what died with the spine was only the
//! injection of this view.
//!
//! Slice 2 (`ab1f5b81`) recorded that after wave-1 the realtime evidence family would verify with
//! `None` — full signature, sequence-density, arithmetic, conservation and privacy-subject checks,
//! but no ledger binding — because the entries it bound against came from the two-road dispatcher
//! that dies with the spine. **The (a2-1) probe rebase (`0ef98b63`) then repointed this view onto
//! `legacy_ledger_evidence_chirho::verified_entries_single_road_chirho`, which survives wave-1, and
//! did not update that sentence.** So the documented degradation had already stopped being
//! reachable. Preserving the injection here is therefore not new hardening; it keeps a binding the
//! system had already stopped losing.
//!
//! One measurement note, because it decided the question: the retained read's gate reaches
//! `GATE1_AUTHORITY_MODE_BRANCH_CHIRHO` from the `cairn_model_gate1_chirho` **crate**, not from the
//! `gate1_authority_mode_chirho` **module** that shares its name-stem and dies with the spine.
//! Resolved to the stem, this read looks like it dies; resolved to the crate, it lives.

use crate::economic_model_chirho::{AssetChirho, LedgerEntryChirho, PostingChirho};
use crate::realtime_legacy_evidence_chirho::{
    self, RealtimeEpilogueDisplayRecordChirho, RealtimeEpilogueRecordChirho,
    RealtimeEventDisplayRecordChirho, RealtimeEventRecordChirho, RealtimeLegacyLedgerViewChirho,
    RealtimeLegacyPostingChirho, RealtimeSessionDisplayRecordChirho, RealtimeSessionRecordChirho,
    RealtimeTranscriptRevealChirho,
};
use crate::{display_chirho, legacy_ledger_evidence_chirho};
use anyhow::{anyhow, bail, Result};
use std::path::Path;

/// Verified ledger entries, presented as the cross-check the realtime evidence bodies ask for.
struct LegacyLedgerEntriesViewChirho {
    entries_chirho: Vec<LedgerEntryChirho>,
}

impl RealtimeLegacyLedgerViewChirho for LegacyLedgerEntriesViewChirho {
    fn assert_entry_chirho(
        &self,
        seq_chirho: u64,
        memo_prefix_chirho: &str,
        postings_chirho: &[RealtimeLegacyPostingChirho],
    ) -> Result<()> {
        assert_ledger_entry_chirho(
            &self.entries_chirho,
            seq_chirho,
            memo_prefix_chirho,
            postings_chirho
                .iter()
                .map(|posting_chirho| PostingChirho {
                    account_chirho: posting_chirho.account_chirho.clone(),
                    asset_chirho: AssetChirho::TokenChirho,
                    amount_chirho: posting_chirho.amount_token_chirho,
                })
                .collect(),
        )
    }
}

fn assert_ledger_entry_chirho(
    entries_chirho: &[LedgerEntryChirho],
    seq_chirho: u64,
    memo_prefix_chirho: &str,
    postings_chirho: Vec<PostingChirho>,
) -> Result<()> {
    let entry_chirho = entries_chirho
        .get(seq_chirho as usize)
        .ok_or_else(|| anyhow!("missing ledger entry #{seq_chirho}"))?;
    if !entry_chirho.memo_chirho.starts_with(memo_prefix_chirho) {
        bail!(
            "ledger entry #{seq_chirho} memo '{}' does not start with '{}'",
            entry_chirho.memo_chirho,
            memo_prefix_chirho
        );
    }
    if entry_chirho.postings_chirho != postings_chirho {
        bail!("ledger entry #{seq_chirho} postings do not match realtime record");
    }
    Ok(())
}

/// The verified legacy ledger view the realtime evidence paths bind against.
///
/// **Probed, and its three consumers are why.** All three are READS that assert wholeness --
/// `verify_realtime_chirho` (which feeds `data_rights_chirho`'s SUBJECT EXPORT and the compliance
/// evidence registry), `verify_realtime_epilogues_chirho`, and `reveal_realtime_transcript_chirho`,
/// a PII disclosure. None is a writer, so none needs to run on whichever road is active, and all
/// three produce artifacts that TRAVEL. That is exactly the case the probe's own doc argues for
/// refusing over warning: a gate that can only fire after the artifact has left can strand a bad
/// state but never prevent one.
fn legacy_ledger_view_chirho(root_chirho: &Path) -> Result<LegacyLedgerEntriesViewChirho> {
    Ok(LegacyLedgerEntriesViewChirho {
        entries_chirho: legacy_ledger_evidence_chirho::verified_entries_single_road_chirho(
            root_chirho,
        )?,
    })
}

pub fn verify_realtime_chirho(root_chirho: &Path) -> Result<(usize, usize)> {
    let view_chirho = legacy_ledger_view_chirho(root_chirho)?;
    realtime_legacy_evidence_chirho::verify_realtime_evidence_chirho(
        root_chirho,
        Some(&view_chirho),
    )
}

pub fn verify_realtime_epilogues_chirho(root_chirho: &Path) -> Result<usize> {
    let view_chirho = legacy_ledger_view_chirho(root_chirho)?;
    realtime_legacy_evidence_chirho::verify_realtime_epilogues_evidence_chirho(
        root_chirho,
        Some(&view_chirho),
    )
}

pub fn reveal_realtime_transcript_chirho(
    root_chirho: &Path,
    session_id_chirho: &str,
    accessed_by_chirho: &str,
    purpose_chirho: &str,
) -> Result<RealtimeTranscriptRevealChirho> {
    let view_chirho = legacy_ledger_view_chirho(root_chirho)?;
    realtime_legacy_evidence_chirho::reveal_realtime_transcript_evidence_chirho(
        root_chirho,
        Some(&view_chirho),
        session_id_chirho,
        accessed_by_chirho,
        purpose_chirho,
    )
}

/// The display loaders, which live here for the same reason the verifiers do: each one RUNS the
/// verification and reports its failure as a per-row label instead of refusing.
///
/// That is the display-honesty contract -- an operator listing rows must see INVALID rows rather
/// than an empty list, because hiding a damaged row and having no rows look identical. The
/// authoritative verify commands still fail closed; these do not, and that difference is the whole
/// reason they exist separately.
pub fn load_realtime_sessions_for_display_chirho(
    root_chirho: &Path,
) -> Result<Vec<RealtimeSessionDisplayRecordChirho>> {
    let validation_error_chirho = verify_realtime_chirho(root_chirho)
        .err()
        .map(|error_chirho| error_chirho.to_string());
    display_chirho::load_jsonl_for_display_chirho(
        &realtime_legacy_evidence_chirho::sessions_path_chirho(root_chirho),
        "RealtimeSessionRecordChirho",
        validation_error_chirho.as_deref(),
        |record_chirho: &RealtimeSessionRecordChirho| record_chirho.seq_chirho,
    )
}

pub fn load_realtime_events_for_display_chirho(
    root_chirho: &Path,
) -> Result<Vec<RealtimeEventDisplayRecordChirho>> {
    let validation_error_chirho = verify_realtime_chirho(root_chirho)
        .err()
        .map(|error_chirho| error_chirho.to_string());
    display_chirho::load_jsonl_for_display_chirho(
        &realtime_legacy_evidence_chirho::events_path_chirho(root_chirho),
        "RealtimeEventRecordChirho",
        validation_error_chirho.as_deref(),
        |record_chirho: &RealtimeEventRecordChirho| record_chirho.seq_chirho,
    )
}

pub fn load_realtime_epilogues_for_display_chirho(
    root_chirho: &Path,
) -> Result<Vec<RealtimeEpilogueDisplayRecordChirho>> {
    let validation_error_chirho = verify_realtime_epilogues_chirho(root_chirho)
        .err()
        .map(|error_chirho| error_chirho.to_string());
    display_chirho::load_jsonl_for_display_chirho(
        &realtime_legacy_evidence_chirho::epilogues_path_chirho(root_chirho),
        "RealtimeEpilogueRecordChirho",
        validation_error_chirho.as_deref(),
        |record_chirho: &RealtimeEpilogueRecordChirho| record_chirho.seq_chirho,
    )
}

#[cfg(test)]
#[path = "realtime_ledger_bound_evidence_chirho/tests_chirho.rs"]
mod tests_chirho;
