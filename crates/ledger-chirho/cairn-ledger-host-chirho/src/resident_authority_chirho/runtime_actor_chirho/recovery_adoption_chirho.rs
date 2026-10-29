// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! F1 mirror recovery adoption before resident composition.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/item7-f1-mirror-recovery-adoption-chirho.md`.
//! Imported objects are inert by logical location until the node-signed canary-generation selector
//! commits. Every authority and durable-owner check is repeated after transfer and immediately
//! before that selector write. Activation commits the exact candidate in the selector BEFORE its
//! atomic rename to the already-bound canonical journal key. A crash can therefore leave authorized
//! intent plus inert bytes for retry; the reverse order would expose canonical bytes with no committed
//! continuity head.
//!
//! The durable mutation population and order are explicit:
//! 1. before candidate authority exists, cleanup may delete only unselected inert candidate objects;
//! 2. after a fresh authority check, cleanup may delete stale inert staging objects and each dense
//!    imported record may be created under its own fresh local-generation guard;
//! 3. under another guard, candidate assembly may remove/recreate only the inert candidate object;
//! 4. under the final guard, recovery installs the prospective elected writer fence, writes the immutable
//!    canary descriptor, writes its selector, then durably renames the selected candidate to the canonical
//!    key; and
//! 5. after activation, cleanup may delete only inert staging and unselected candidate objects.
//!
//! A fence without a canary head grants no recovery selection: production startup must reselect and
//! finish the adoption before it can publish a resident handle. A committed head with candidate bytes
//! still inert resumes only the rename; a committed head already aligned with canonical bytes performs
//! no second install. The W1 drill exhaustively inventories the dedicated recovery namespace and
//! separately point-checks the fence, canary head, and canonical journal. It does not census unrelated
//! storage-root paths; inert writes there are outside that exact-population claim.

use super::append_barrier_chirho::{
    require_recovery_adoption_slot_chirho, ResidentAppendBarrierRefusalChirho,
};
use crate::reconciliation_chirho::Gd7WinnerHandoffStoreChirho;
use crate::storage_chirho::FsLedgerStorageChirho;
use anyhow::{anyhow, bail, Context, Result};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::losing_suffix_chirho::MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorPrefixSourceChirho, LedgerMirrorRecoveryCandidateChirho,
    LedgerMirrorRecoveryPortChirho, LedgerMirrorRuntimePortsChirho,
    RawCanonicalGroupIdDigestChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_record_chirho, stored_line_digest_chirho,
};
use cairn_ledger_tenant_migration_durable_chirho::TenantMigrationStoreChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryAdoptionGenerationChirho, ShadowCanaryAdoptionGenerationInputChirho,
    ShadowCanaryGenerationStoreChirho, ShadowCanaryLedgerCutChirho,
    VerifiedShadowCanaryCurrentGenerationChirho,
};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendHandoffControlHandleChirho,
    LocalLeadershipGenerationGuardChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    prepare_reused_or_issued_elected_writer_fence_chirho, split_writer_epoch_chirho,
    writer_fence_storage_key_chirho, ConsistencyGroupIdChirho, MAX_WRITER_FENCE_FILE_BYTES_CHIRHO,
    WRITER_FENCE_LOCK_CHIRHO,
};
use std::path::Path;

#[path = "recovery_adoption_chirho/recovery_contention_chirho.rs"]
mod recovery_contention_chirho;
use recovery_contention_chirho::{
    retry_recovery_revalidation_chirho, RecoveryContentionTallyChirho,
    RecoveryRevalidationRefusalChirho,
};

const RECOVERY_ROOT_CHIRHO: &str = "f1-recovery-adoption-chirho";
const RECOVERY_CANDIDATES_DIR_CHIRHO: &str = "candidates-chirho";
const RECOVERY_STAGING_DIR_CHIRHO: &str = "staging-chirho";
const RECOVERY_RECORDS_DIR_CHIRHO: &str = "records-chirho";
const RECOVERY_CANDIDATE_JOURNAL_FILE_CHIRHO: &str = "candidate-journal-chirho.jsonl";

pub(super) struct ResidentRecoveryAdoptionInputChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub authority_storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    pub journal_ports_chirho: JournalPortsChirho<'ports_chirho>,
    pub config_chirho: &'ports_chirho LedgerHostConfigChirho,
    pub monitor_namespace_chirho: &'ports_chirho Path,
    pub sign_root_chirho: &'ports_chirho Path,
    pub cluster_chirho: &'ports_chirho ClusterIdChirho,
    pub group_chirho: &'ports_chirho ConsistencyGroupIdChirho,
    pub node_chirho: &'ports_chirho NodeIdChirho,
    pub mirror_runtime_chirho: Option<&'ports_chirho LedgerMirrorRuntimePortsChirho>,
    pub gd7_store_chirho: &'ports_chirho Gd7WinnerHandoffStoreChirho<'ports_chirho>,
    pub migration_store_chirho: Option<&'ports_chirho TenantMigrationStoreChirho<'ports_chirho>>,
    pub handoff_control_chirho: &'ports_chirho LocalAppendHandoffControlHandleChirho,
    pub local_authority_chirho: &'ports_chirho LocalAppendAuthorityHandleChirho,
    /// The pause between revalidation attempts while the local authority reports contention. It is
    /// injected so a test can count or drive the waits; production passes the actor's short thread
    /// sleep from the composition root.
    pub contention_pause_chirho: &'ports_chirho (dyn Fn() + Sync),
}

struct ResidentRecoveryEffectContextChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    gd7_store_chirho: &'ports_chirho Gd7WinnerHandoffStoreChirho<'ports_chirho>,
    migration_store_chirho: Option<&'ports_chirho TenantMigrationStoreChirho<'ports_chirho>>,
    handoff_control_chirho: &'ports_chirho LocalAppendHandoffControlHandleChirho,
    local_authority_chirho: &'ports_chirho LocalAppendAuthorityHandleChirho,
    contention_pause_chirho: &'ports_chirho (dyn Fn() + Sync),
}

impl<'ports_chirho> ResidentRecoveryEffectContextChirho<'ports_chirho> {
    fn from_input_chirho(
        input_chirho: &ResidentRecoveryAdoptionInputChirho<'ports_chirho>,
    ) -> Self {
        Self {
            storage_chirho: input_chirho.storage_chirho,
            gd7_store_chirho: input_chirho.gd7_store_chirho,
            migration_store_chirho: input_chirho.migration_store_chirho,
            handoff_control_chirho: input_chirho.handoff_control_chirho,
            local_authority_chirho: input_chirho.local_authority_chirho,
            contention_pause_chirho: input_chirho.contention_pause_chirho,
        }
    }
}

/// Whether this startup managed to seed the remote write population.
///
/// `NotAttemptedChirho` is NOT a synonym for success: it means this path never reached the
/// bootstrap, either because no mirror runtime is configured or because a recovery candidate was
/// selected instead. Only `BootstrappedChirho` says the holders were seeded, so a caller that
/// treats anything-but-refused as ready would be reading it wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentCurrentHolderWriteReadinessChirho {
    NotAttemptedChirho,
    BootstrappedChirho,
    RefusedChirho,
}

pub(super) struct ResidentRecoveryAdoptionOutcomeChirho {
    pub journal_path_chirho: StoragePathChirho,
    pub canary_store_chirho: ShadowCanaryGenerationStoreChirho,
    pub current_canary_chirho: VerifiedShadowCanaryCurrentGenerationChirho,
    /// Reads stay available when this is `RefusedChirho`; WRITES do not. Nothing here changes that
    /// fail-closed behaviour -- it makes the state sayable instead of silent.
    pub current_holder_write_readiness_chirho: ResidentCurrentHolderWriteReadinessChirho,
}

pub(super) fn prepare_resident_recovery_adoption_chirho(
    input_chirho: ResidentRecoveryAdoptionInputChirho<'_>,
) -> Result<ResidentRecoveryAdoptionOutcomeChirho> {
    let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &input_chirho
            .monitor_namespace_chirho
            .join(super::RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO),
        input_chirho.sign_root_chirho,
        input_chirho.group_chirho.clone(),
        input_chirho.node_chirho.clone(),
    )?;
    let mut current_canary_chirho = canary_store_chirho.verify_current_read_only_chirho()?;
    super::verify_canary_generation_posture_chirho(
        &current_canary_chirho,
        input_chirho.group_chirho,
    )?;
    let journal_path_chirho =
        selected_journal_path_chirho(input_chirho.config_chirho, &current_canary_chirho)?;
    retire_inert_candidates_chirho(
        input_chirho.storage_chirho,
        current_canary_chirho
            .adoption_chirho()
            .map(|adoption_chirho| adoption_chirho.candidate_journal_binding_digest_chirho()),
    )?;
    let mut journal_chirho = full_open_chirho(
        input_chirho.journal_ports_chirho,
        journal_path_chirho.clone(),
        input_chirho.cluster_chirho,
    )?;
    let alignment_result_chirho = super::verify_preflight_canary_alignment_chirho(
        &journal_chirho,
        current_canary_chirho.latest_ledger_cut_chirho(),
        input_chirho.group_chirho,
    );
    if let Err(alignment_error_chirho) = alignment_result_chirho {
        if current_canary_chirho.adoption_chirho().is_none() {
            return Err(alignment_error_chirho);
        }
        let mirror_runtime_chirho = input_chirho
            .mirror_runtime_chirho
            .ok_or_else(|| anyhow!("ShadowCanaryCommittedAdoptionRecoveryPortUnavailableChirho"))?;
        journal_chirho = finish_committed_adoption_activation_chirho(
            &input_chirho,
            mirror_runtime_chirho.recovery_source_chirho().as_ref(),
            &journal_path_chirho,
            journal_chirho,
            &current_canary_chirho,
        )?;
    }
    verify_selected_adoption_chirho(
        input_chirho.storage_chirho,
        &journal_path_chirho,
        &journal_chirho,
        &current_canary_chirho,
    )?;

    let Some(mirror_runtime_chirho) = input_chirho.mirror_runtime_chirho else {
        // SAYABLE, NOT SILENT. The readiness has always carried this distinction in the type and
        // nothing ever emitted it, so the two not-attempted branches were indistinguishable from
        // outside the process -- and from a seeded success. A hosted drill measured the consequence:
        // the returning holder never gains a continuity anchor across an entire loss sequence, and no
        // evidence available to the operator could say which branch skipped the seeding.
        // Fixed identity, no value, greppable -- the same shape as the refusal below.
        eprintln!("ResidentCurrentHolderWriteNoMirrorRuntimeChirho");
        return Ok(ResidentRecoveryAdoptionOutcomeChirho {
            journal_path_chirho,
            canary_store_chirho,
            current_canary_chirho,
            current_holder_write_readiness_chirho:
                ResidentCurrentHolderWriteReadinessChirho::NotAttemptedChirho,
        });
    };
    let recovery_chirho = mirror_runtime_chirho.recovery_source_chirho();
    let local_tail_chirho = journal_chirho.verified_append_mirror_tail_chirho();
    let Some(candidate_chirho) = recovery_chirho
        .select_recovery_candidate_chirho(&local_tail_chirho, &journal_chirho)
        .map_err(|error_chirho| {
            anyhow!(
                "select F1 recovery candidate: {}",
                error_chirho.detail_chirho()
            )
        })?
    else {
        // Current-holder bootstrap prepares the remote write population; it is not authority for
        // serving this already full-verified, canary-aligned local journal. A newly adopted leader
        // can therefore remain readable while one current holder is unavailable. The append mirror
        // still PREPAREs every current holder before local commit, so writes continue to fail closed
        // until a later startup successfully bootstraps the complete population.
        //
        // THE FAIL-CLOSED PART IS DELIBERATE; THE SILENCE WAS NOT. This outcome was previously bound
        // to `_`, so a leader could boot, fail to seed a holder for any reason -- holder unreachable,
        // transport error, view change mid-walk -- and proceed as if nothing happened. The node then
        // serves reads while writes are already dead, and the first symptom is a refused mutation
        // surfacing at the HOLDER's store, three components away from the cause. That silence cost
        // six hosted windows to diagnose. It now announces itself with a fixed identity, and the
        // readiness travels in the outcome so a caller can ask instead of inferring.
        let current_holder_write_readiness_chirho = recovery_chirho
            .ensure_verified_prefix_bootstrapped_chirho(&local_tail_chirho, &journal_chirho);
        let current_holder_write_readiness_chirho = match current_holder_write_readiness_chirho {
            Ok(()) => {
                // The only outcome that means the holders were actually seeded. Emitted for the same
                // reason as its siblings: absence of a refusal is not evidence of success.
                eprintln!("ResidentCurrentHolderWriteBootstrappedChirho");
                ResidentCurrentHolderWriteReadinessChirho::BootstrappedChirho
            }
            Err(error_chirho) => {
                // Fixed identity first so the line is greppable without parsing; the detail follows
                // for a human and is never the thing anything keys on.
                eprintln!(
                    "ResidentCurrentHolderWriteBootstrapRefusedChirho:{}",
                    error_chirho
                );
                ResidentCurrentHolderWriteReadinessChirho::RefusedChirho
            }
        };
        return Ok(ResidentRecoveryAdoptionOutcomeChirho {
            journal_path_chirho,
            canary_store_chirho,
            current_canary_chirho,
            current_holder_write_readiness_chirho,
        });
    };

    verify_candidate_static_binding_chirho(
        &candidate_chirho,
        &local_tail_chirho,
        input_chirho.group_chirho,
    )?;
    let effect_context_chirho =
        ResidentRecoveryEffectContextChirho::from_input_chirho(&input_chirho);
    let initial_authority_guard_chirho = revalidate_before_recovery_effect_chirho(
        recovery_chirho.as_ref(),
        &candidate_chirho,
        &effect_context_chirho,
    )?;
    drop(initial_authority_guard_chirho);
    let binding_digest_chirho = candidate_chirho.binding_digest_chirho();
    retire_inert_staging_chirho(input_chirho.storage_chirho, Some(&binding_digest_chirho))?;
    stage_candidate_records_chirho(
        &effect_context_chirho,
        recovery_chirho.as_ref(),
        &candidate_chirho,
        &binding_digest_chirho,
    )?;

    let canonical_genesis_line_chirho = journal_chirho.canonical_genesis_line_chirho()?;
    drop(journal_chirho);
    let assembly_authority_guard_chirho = revalidate_before_recovery_effect_chirho(
        recovery_chirho.as_ref(),
        &candidate_chirho,
        &effect_context_chirho,
    )?;
    let (candidate_path_chirho, candidate_journal_digest_chirho) =
        assemble_candidate_journal_chirho(
            input_chirho.storage_chirho,
            &candidate_chirho,
            &binding_digest_chirho,
            &canonical_genesis_line_chirho,
        )?;
    drop(assembly_authority_guard_chirho);
    let candidate_journal_chirho = full_open_chirho(
        input_chirho.journal_ports_chirho,
        candidate_path_chirho.clone(),
        input_chirho.cluster_chirho,
    )?;
    verify_replayed_candidate_tail_chirho(&candidate_journal_chirho, &candidate_chirho)?;

    // Recovery authority is the historical A+B holder pair. Do not make the failed historical
    // leader reachable here merely because it becomes a holder under the adopter's new leadership.
    // A later no-candidate open reconciles that current holder population before admitting writes.
    let selector_authority_guard_chirho = revalidate_before_recovery_effect_chirho(
        recovery_chirho.as_ref(),
        &candidate_chirho,
        &effect_context_chirho,
    )?;
    install_recovery_adoption_writer_fence_chirho(
        &input_chirho,
        &selector_authority_guard_chirho,
        &candidate_chirho,
    )?;

    canary_store_chirho.commit_adoption_generation_chirho(
        ShadowCanaryAdoptionGenerationInputChirho {
            adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                candidate_chirho.tail_seq_chirho(),
                candidate_chirho.tail_record_digest_chirho().to_string(),
                candidate_chirho.tail_hlc_chirho().physical_ms_chirho,
                candidate_chirho.tail_hlc_chirho().logical_chirho,
                candidate_chirho.tail_epoch_chirho(),
                input_chirho.group_chirho,
            )?,
            cluster_id_chirho: candidate_chirho.cluster_id_chirho().to_string(),
            journal_genesis_digest_chirho: candidate_chirho
                .journal_genesis_digest_chirho()
                .to_string(),
            assignment_digest_chirho: candidate_chirho.assignment_digest_chirho().to_string(),
            historical_leader_node_id_chirho: candidate_chirho
                .historical_leader_node_id_chirho()
                .to_string(),
            holder_node_ids_chirho: candidate_chirho.holder_node_ids_chirho().clone(),
            historical_term_chirho: candidate_chirho.historical_term_chirho(),
            historical_membership_view_digest_chirho: candidate_chirho
                .historical_membership_view_digest_chirho()
                .to_string(),
            elected_term_chirho: candidate_chirho.current_term_chirho(),
            membership_view_digest_chirho: candidate_chirho
                .current_membership_view_digest_chirho()
                .to_string(),
            holder_receipt_digests_chirho: candidate_chirho.holder_receipt_digests_chirho().clone(),
            holder_receipt_wires_chirho: candidate_chirho.holder_receipt_wires_chirho().clone(),
            candidate_journal_binding_digest_chirho: binding_digest_chirho.clone(),
            candidate_journal_digest_chirho: candidate_journal_digest_chirho.clone(),
        },
    )?;
    drop(candidate_journal_chirho);
    input_chirho
        .storage_chirho
        .rename_chirho(&candidate_path_chirho, &journal_path_chirho)?;
    drop(selector_authority_guard_chirho);
    current_canary_chirho = canary_store_chirho.verify_current_read_only_chirho()?;
    super::verify_canary_generation_posture_chirho(
        &current_canary_chirho,
        input_chirho.group_chirho,
    )?;
    let activated_journal_chirho = full_open_chirho(
        input_chirho.journal_ports_chirho,
        journal_path_chirho.clone(),
        input_chirho.cluster_chirho,
    )?;
    verify_replayed_candidate_tail_chirho(&activated_journal_chirho, &candidate_chirho)?;
    super::verify_preflight_canary_alignment_chirho(
        &activated_journal_chirho,
        current_canary_chirho.latest_ledger_cut_chirho(),
        input_chirho.group_chirho,
    )?;
    verify_selected_adoption_chirho(
        input_chirho.storage_chirho,
        &journal_path_chirho,
        &activated_journal_chirho,
        &current_canary_chirho,
    )?;
    if hash_storage_object_chirho(input_chirho.storage_chirho, &journal_path_chirho)?
        != candidate_journal_digest_chirho
    {
        bail!("ShadowCanaryActivatedJournalDigestRefusedChirho");
    }
    drop(activated_journal_chirho);
    retire_inert_staging_chirho(input_chirho.storage_chirho, None)?;
    retire_inert_candidates_chirho(input_chirho.storage_chirho, Some(&binding_digest_chirho))?;

    // The SECOND not-attempted branch: a recovery candidate was selected, so this startup recovered
    // from a peer and never reached the bootstrap that seeds the holders. Distinct identity from the
    // no-mirror-runtime branch precisely because the two are what an operator needs to tell apart.
    eprintln!("ResidentCurrentHolderWriteRecoveryCandidateSelectedChirho");
    Ok(ResidentRecoveryAdoptionOutcomeChirho {
        journal_path_chirho,
        canary_store_chirho,
        current_canary_chirho,
        current_holder_write_readiness_chirho:
            ResidentCurrentHolderWriteReadinessChirho::NotAttemptedChirho,
    })
}

/// Install prospective append authority before the adoption selector can make imported bytes live.
///
/// Imported records retain their historical epochs. This transition only installs the adopter's
/// current elected fence, under the same local-generation -> writer-lock order as an ordinary append,
/// so the first later append can advance the journal epoch before adding an adopter-authored record.
/// The canary commit follows this durable write; a committed adoption therefore never names a journal
/// whose imported epoch is ahead of its local fence state. Ordinary append remains unable to repair a
/// missing or rolled-back fence.
fn install_recovery_adoption_writer_fence_chirho(
    input_chirho: &ResidentRecoveryAdoptionInputChirho<'_>,
    authority_guard_chirho: &LocalLeadershipGenerationGuardChirho<'_>,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
) -> Result<()> {
    let writer_lock_path_chirho =
        StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
    let mut writer_lock_chirho = input_chirho
        .authority_storage_chirho
        .open_existing_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
        .context("open recovery-adoption writer-fence lock")?;
    let writer_lock_guard_chirho = writer_lock_chirho
        .try_acquire_chirho()
        .context("acquire recovery-adoption writer-fence lock")?;
    let writer_fence_path_chirho = StoragePathChirho::new_chirho(
        writer_fence_storage_key_chirho(input_chirho.group_chirho)
            .context("derive recovery-adoption writer-fence path")?,
    );
    let max_fence_bytes_chirho = u64::try_from(MAX_WRITER_FENCE_FILE_BYTES_CHIRHO)
        .expect("fixed writer-fence byte bound fits u64");
    let durable_state_bytes_chirho = writer_lock_guard_chirho
        .storage_chirho()
        .read_bounded_object_chirho(&writer_fence_path_chirho, max_fence_bytes_chirho)
        .context("read recovery-adoption writer-fence state")?;
    let published_raft_term_chirho = authority_guard_chirho.published_raft_term_chirho();
    let prepared_fence_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
        input_chirho.group_chirho,
        published_raft_term_chirho,
        None,
        durable_state_bytes_chirho.as_deref(),
        input_chirho
            .journal_ports_chirho
            .clock_chirho
            .physical_now_ms_chirho(),
    )
    .context("prepare recovery-adoption writer fence")?;
    let fence_chirho = prepared_fence_chirho.token_chirho();
    if u64::from(split_writer_epoch_chirho(fence_chirho.epoch_chirho).geo_term_chirho)
        != published_raft_term_chirho
    {
        bail!("ShadowCanaryAdoptionWriterFenceTermRefusedChirho");
    }
    if fence_chirho.epoch_chirho < candidate_chirho.tail_epoch_chirho() {
        bail!("ShadowCanaryAdoptionWriterFenceEpochRefusedChirho");
    }
    if let Some(replacement_state_bytes_chirho) =
        prepared_fence_chirho.replacement_state_bytes_chirho()
    {
        writer_lock_guard_chirho
            .storage_chirho()
            .atomic_write_chirho(&writer_fence_path_chirho, replacement_state_bytes_chirho)
            .context("install recovery-adoption writer-fence state")?;
    }
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .context("verify recovery-adoption writer-fence custody")
}

fn finish_committed_adoption_activation_chirho<'ports_chirho>(
    input_chirho: &ResidentRecoveryAdoptionInputChirho<'ports_chirho>,
    recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    journal_path_chirho: &StoragePathChirho,
    prior_journal_chirho: LedgerJournalChirho<'ports_chirho>,
    current_canary_chirho: &VerifiedShadowCanaryCurrentGenerationChirho,
) -> Result<LedgerJournalChirho<'ports_chirho>> {
    let adoption_chirho = current_canary_chirho
        .adoption_chirho()
        .ok_or_else(|| anyhow!("ShadowCanaryCommittedAdoptionHeadMissingChirho"))?;
    let local_tail_chirho = prior_journal_chirho.verified_append_mirror_tail_chirho();
    let adopted_cut_chirho = adoption_chirho.adopted_ledger_cut_chirho();
    let local_matches_adopted_cut_chirho = super::verify_preflight_canary_alignment_chirho(
        &prior_journal_chirho,
        adopted_cut_chirho,
        input_chirho.group_chirho,
    )
    .is_ok();

    // The caller compared canonical bytes with the current generation's latest cut, which may be a
    // post-adoption window cut. Compare with the adopted cut directly so an exact adopted journal
    // behind that window is not mislabeled as divergence.
    if local_tail_chirho.tail_seq_chirho() > adopted_cut_chirho.append_seq_chirho() {
        bail!("ShadowCanaryCommittedAdoptionCanonicalTailRollbackRefusedChirho");
    }
    if local_tail_chirho.tail_seq_chirho() == adopted_cut_chirho.append_seq_chirho()
        && !local_matches_adopted_cut_chirho
    {
        bail!("ShadowCanaryCommittedAdoptionCanonicalTailDivergenceRefusedChirho");
    }
    if current_canary_chirho.window_chirho().is_some() {
        bail!("ShadowCanaryCommittedAdoptionCanonicalTailBehindCanaryWindowRefusedChirho");
    }
    super::verify_preflight_canary_alignment_chirho(
        &prior_journal_chirho,
        adoption_chirho.prior_latest_ledger_cut_chirho(),
        input_chirho.group_chirho,
    )
    .map_err(|_| anyhow!("ShadowCanaryCommittedAdoptionCanonicalBaseRefusedChirho"))?;

    // Re-read the holder population under FRESH current authority. A term-free candidate path may
    // resume the same historical evidence, but a holder pair that advanced or a changed assignment
    // must not let an older committed selector install a stale cut automatically.
    let candidate_chirho = recovery_chirho
        .select_recovery_candidate_chirho(&local_tail_chirho, &prior_journal_chirho)
        .map_err(|error_chirho| {
            anyhow!(
                "resume committed F1 recovery candidate: {}",
                error_chirho.detail_chirho()
            )
        })?
        .ok_or_else(|| anyhow!("ShadowCanaryCommittedAdoptionCandidateUnavailableChirho"))?;
    verify_candidate_static_binding_chirho(
        &candidate_chirho,
        &local_tail_chirho,
        input_chirho.group_chirho,
    )?;
    verify_committed_adoption_candidate_chirho(adoption_chirho, &candidate_chirho)?;

    let candidate_path_chirho =
        candidate_journal_path_chirho(adoption_chirho.candidate_journal_binding_digest_chirho());
    if !input_chirho
        .storage_chirho
        .exists_chirho(&candidate_path_chirho)?
    {
        bail!("ShadowCanaryCommittedAdoptionCandidateBytesMissingChirho");
    }
    if hash_storage_object_chirho(input_chirho.storage_chirho, &candidate_path_chirho)?
        != adoption_chirho.candidate_journal_digest_chirho()
    {
        bail!("ShadowCanaryCommittedAdoptionCandidateDigestRefusedChirho");
    }
    let candidate_journal_chirho = full_open_chirho(
        input_chirho.journal_ports_chirho,
        candidate_path_chirho.clone(),
        input_chirho.cluster_chirho,
    )?;
    verify_replayed_candidate_tail_chirho(&candidate_journal_chirho, &candidate_chirho)?;

    let effect_context_chirho =
        ResidentRecoveryEffectContextChirho::from_input_chirho(input_chirho);
    let activation_guard_chirho = revalidate_before_recovery_effect_chirho(
        recovery_chirho,
        &candidate_chirho,
        &effect_context_chirho,
    )?;
    drop(candidate_journal_chirho);
    drop(prior_journal_chirho);
    input_chirho
        .storage_chirho
        .rename_chirho(&candidate_path_chirho, journal_path_chirho)?;
    drop(activation_guard_chirho);

    let activated_journal_chirho = full_open_chirho(
        input_chirho.journal_ports_chirho,
        journal_path_chirho.clone(),
        input_chirho.cluster_chirho,
    )?;
    verify_replayed_candidate_tail_chirho(&activated_journal_chirho, &candidate_chirho)?;
    super::verify_preflight_canary_alignment_chirho(
        &activated_journal_chirho,
        current_canary_chirho.latest_ledger_cut_chirho(),
        input_chirho.group_chirho,
    )?;
    verify_selected_adoption_chirho(
        input_chirho.storage_chirho,
        journal_path_chirho,
        &activated_journal_chirho,
        current_canary_chirho,
    )?;
    Ok(activated_journal_chirho)
}

fn verify_committed_adoption_candidate_chirho(
    adoption_chirho: &ShadowCanaryAdoptionGenerationChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
) -> Result<()> {
    let cut_chirho = adoption_chirho.adopted_ledger_cut_chirho();
    if candidate_chirho.binding_digest_chirho()
        != adoption_chirho.candidate_journal_binding_digest_chirho()
        || candidate_chirho.assignment_digest_chirho() != adoption_chirho.assignment_digest_chirho()
        || candidate_chirho.historical_leader_node_id_chirho()
            != adoption_chirho.historical_leader_node_id_chirho()
        || candidate_chirho.holder_node_ids_chirho() != adoption_chirho.holder_node_ids_chirho()
        || adoption_chirho
            .historical_term_chirho()
            .is_some_and(|term_chirho| candidate_chirho.historical_term_chirho() != term_chirho)
        || adoption_chirho
            .historical_membership_view_digest_chirho()
            .is_some_and(|digest_chirho| {
                candidate_chirho.historical_membership_view_digest_chirho() != digest_chirho
            })
        || candidate_chirho.cluster_id_chirho() != adoption_chirho.cluster_id_chirho()
        || candidate_chirho.journal_genesis_digest_chirho()
            != adoption_chirho.journal_genesis_digest_chirho()
        || candidate_chirho.tail_seq_chirho() != cut_chirho.append_seq_chirho()
        || candidate_chirho.tail_record_digest_chirho() != cut_chirho.append_record_digest_chirho()
        || candidate_chirho.tail_epoch_chirho() != cut_chirho.record_epoch_chirho()
        || candidate_chirho.tail_hlc_chirho().physical_ms_chirho
            != cut_chirho.append_hlc_physical_ms_chirho()
        || candidate_chirho.tail_hlc_chirho().logical_chirho
            != cut_chirho.append_hlc_logical_chirho()
        || candidate_chirho.holder_receipt_digests_chirho()
            != adoption_chirho.holder_receipt_digests_chirho()
        || candidate_chirho.holder_receipt_wires_chirho()
            != adoption_chirho.holder_receipt_wires_chirho()
    {
        bail!("ShadowCanaryCommittedAdoptionEvidenceChangedChirho");
    }
    Ok(())
}

fn full_open_chirho<'ports_chirho>(
    ports_chirho: JournalPortsChirho<'ports_chirho>,
    path_chirho: StoragePathChirho,
    cluster_chirho: &ClusterIdChirho,
) -> Result<LedgerJournalChirho<'ports_chirho>> {
    LedgerJournalChirho::open_read_only_full_chirho(ports_chirho, path_chirho, cluster_chirho)
        .map_err(|error_chirho| {
            anyhow!("resident full journal verification refused: {error_chirho:?}")
        })
}

fn selected_journal_path_chirho(
    config_chirho: &LedgerHostConfigChirho,
    current_chirho: &VerifiedShadowCanaryCurrentGenerationChirho,
) -> Result<StoragePathChirho> {
    if current_chirho
        .adoption_chirho()
        .is_some_and(|adoption_chirho| {
            adoption_chirho.cluster_id_chirho() != config_chirho.cluster_id_chirho
        })
    {
        bail!("ShadowCanaryAdoptionClusterBindingRefusedChirho");
    }
    // The immutable resident Bound identity names this key. Recovery candidates are staging objects,
    // never alternate resident identities; activation atomically installs the selected bytes here.
    Ok(StoragePathChirho::new_chirho(
        &config_chirho.journal_path_chirho,
    ))
}

fn verify_selected_adoption_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    journal_chirho: &LedgerJournalChirho<'_>,
    current_chirho: &VerifiedShadowCanaryCurrentGenerationChirho,
) -> Result<()> {
    let Some(adoption_chirho) = current_chirho.adoption_chirho() else {
        return Ok(());
    };
    if journal_chirho
        .verified_append_mirror_tail_chirho()
        .journal_genesis_digest_chirho()
        .0
        != adoption_chirho.journal_genesis_digest_chirho()
    {
        bail!("ShadowCanaryAdoptionJournalBindingRefusedChirho");
    }
    if current_chirho.window_chirho().is_none()
        && hash_storage_object_chirho(storage_chirho, path_chirho)?
            != adoption_chirho.candidate_journal_digest_chirho()
    {
        bail!("ShadowCanaryAdoptionCandidateDigestRefusedChirho");
    }
    Ok(())
}

fn verify_candidate_static_binding_chirho(
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    local_tail_chirho: &cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorTailChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> Result<()> {
    if candidate_chirho.consistency_group_digest_chirho()
        != &RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(
            &group_chirho.canonical_id_chirho(),
        )
    {
        bail!("LedgerMirrorRecoveryCandidateGroupBindingRefusedChirho");
    }
    if candidate_chirho.cluster_id_chirho() != local_tail_chirho.cluster_id_chirho().0
        || candidate_chirho.journal_genesis_digest_chirho()
            != local_tail_chirho.journal_genesis_digest_chirho().0
        || candidate_chirho.tail_seq_chirho() <= local_tail_chirho.tail_seq_chirho()
    {
        bail!("LedgerMirrorRecoveryCandidateLocalBindingRefusedChirho");
    }
    Ok(())
}

/// Re-check everything a recovery effect depends on, then take a fresh local leadership guard bound
/// to the term the candidate was validated at.
///
/// A local Raft transition in flight makes the local authority refuse at once, because admission
/// never blocks. So the WHOLE check is retried through the actor's shared contention retry
/// (`recovery_contention_chirho`), which waits only on a pending transition or a busy guard and
/// stops at its attempt budget. Every other refusal returns immediately. A revalidation that needed
/// to wait says so on one fixed-identity line, so a restart budget is not quietly traded for unseen
/// latency. The line is per revalidation: an open revalidates before each effect, so it can print
/// several. Each attempt reruns the slot check's idempotent `release_if_observed_owner_chirho`, so
/// a retry is not a second release.
///
/// CALLER INVARIANT: the caller holds no local leadership guard on this thread. A transition queued
/// behind a held guard cannot finish while it is held, so this would spend the whole attempt budget
/// and then refuse (gpt #29650). Every caller here drops its previous guard first (claude2 #29644).
///
/// Same-term membership drift (gpt #29658, A6-c): the guard alone binds the Raft term, not the
/// membership view. So each attempt revalidates the candidate's authority once more AFTER acquiring
/// the guard. The guard seals every local Raft transition and every authenticated-roster update, so
/// the view that second check saw holds until the guard drops.
fn revalidate_before_recovery_effect_chirho<'authority_chirho>(
    recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    context_chirho: &ResidentRecoveryEffectContextChirho<'authority_chirho>,
) -> Result<LocalLeadershipGenerationGuardChirho<'authority_chirho>> {
    let (guard_chirho, tally_chirho) = retry_recovery_revalidation_chirho(
        || {
            revalidate_once_before_recovery_effect_chirho(
                recovery_chirho,
                candidate_chirho,
                context_chirho,
            )
        },
        context_chirho.contention_pause_chirho,
    );
    report_recovery_contention_chirho(tally_chirho);
    let guard_chirho = guard_chirho.map_err(anyhow::Error::new)?;
    // Bound to the validated term: a transition between the candidate's validation and this
    // acquisition must not carry the old candidate into a recovery effect under a newer term.
    if guard_chirho.published_raft_term_chirho() != candidate_chirho.current_term_chirho() {
        bail!("LedgerMirrorRecoveryAuthorityTermChangedChirho");
    }
    Ok(guard_chirho)
}

/// One attempt: the candidate's authority, the durable owners and local slot, the local guard, and
/// then the candidate's authority once more under that guard.
///
/// Only the port check reruns under the guard. The slot check and the acquisition never run while
/// this thread holds a guard. A refusal from the second check is an authority refusal, so the guard
/// drops with it and the retry does not repeat it.
fn revalidate_once_before_recovery_effect_chirho<'authority_chirho>(
    recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    context_chirho: &ResidentRecoveryEffectContextChirho<'authority_chirho>,
) -> std::result::Result<
    LocalLeadershipGenerationGuardChirho<'authority_chirho>,
    RecoveryRevalidationRefusalChirho,
> {
    revalidate_candidate_authority_chirho(recovery_chirho, candidate_chirho)?;
    require_recovery_adoption_slot_chirho(
        context_chirho.gd7_store_chirho,
        context_chirho.migration_store_chirho,
        context_chirho.handoff_control_chirho,
    )
    .map_err(RecoveryRevalidationRefusalChirho::SlotChirho)?;
    let guard_chirho = context_chirho
        .local_authority_chirho
        .try_acquire_chirho()
        .map_err(RecoveryRevalidationRefusalChirho::LocalAuthorityChirho)?;
    revalidate_candidate_authority_chirho(recovery_chirho, candidate_chirho)?;
    Ok(guard_chirho)
}

fn revalidate_candidate_authority_chirho(
    recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
) -> std::result::Result<(), RecoveryRevalidationRefusalChirho> {
    recovery_chirho
        .revalidate_recovery_authority_chirho(candidate_chirho)
        .map_err(|error_chirho| {
            RecoveryRevalidationRefusalChirho::AuthorityChirho(
                error_chirho.detail_chirho().to_string(),
            )
        })
}

/// One greppable line when a revalidation met contention. The count is attempts that met it, not
/// pauses: an attempt at the budget is counted and is followed by no pause.
fn report_recovery_contention_chirho(tally_chirho: RecoveryContentionTallyChirho) {
    if tally_chirho.contended_attempts_chirho > 0 {
        eprintln!(
            "ResidentRecoveryTransitionContentionChirho:contended_attempts_chirho={}:pauses_chirho={}",
            tally_chirho.contended_attempts_chirho, tally_chirho.pauses_chirho
        );
    }
}

fn stage_candidate_records_chirho(
    context_chirho: &ResidentRecoveryEffectContextChirho<'_>,
    recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    binding_digest_chirho: &str,
) -> Result<()> {
    let mut expected_digest_chirho = candidate_chirho.tail_record_digest_chirho().to_string();
    for seq_chirho in (1..=candidate_chirho.tail_seq_chirho()).rev() {
        let path_chirho =
            staged_record_path_chirho(binding_digest_chirho, seq_chirho, &expected_digest_chirho);
        let bytes_chirho = match context_chirho
            .storage_chirho
            .read_all_chirho(&path_chirho)?
        {
            Some(bytes_chirho) => bytes_chirho,
            None => {
                let bytes_chirho = recovery_chirho
                    .read_recovery_record_chirho(
                        candidate_chirho,
                        seq_chirho,
                        &expected_digest_chirho,
                    )
                    .map_err(|error_chirho| {
                        anyhow!(
                            "read F1 recovery record {seq_chirho}: {}",
                            error_chirho.detail_chirho()
                        )
                    })?;
                let durable_write_guard_chirho = revalidate_before_recovery_effect_chirho(
                    recovery_chirho,
                    candidate_chirho,
                    context_chirho,
                )?;
                match context_chirho
                    .storage_chirho
                    .create_durable_chirho(&path_chirho, &bytes_chirho)?
                {
                    CreateDurableOutcomeChirho::CreatedChirho => {}
                    CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                        let existing_chirho = context_chirho
                            .storage_chirho
                            .read_all_chirho(&path_chirho)?
                            .ok_or_else(|| anyhow!("F1 staged record disappeared after create"))?;
                        if existing_chirho != bytes_chirho {
                            bail!("LedgerMirrorRecoveryStagedRecordConflictChirho");
                        }
                    }
                }
                drop(durable_write_guard_chirho);
                bytes_chirho
            }
        };
        let record_chirho =
            verify_staged_record_chirho(&bytes_chirho, seq_chirho, &expected_digest_chirho)?;
        if seq_chirho == candidate_chirho.tail_seq_chirho()
            && (record_chirho.epoch_chirho != candidate_chirho.tail_epoch_chirho()
                || record_chirho.hlc_chirho != *candidate_chirho.tail_hlc_chirho())
        {
            bail!("LedgerMirrorRecoveryTailCoordinateRefusedChirho");
        }
        expected_digest_chirho = record_chirho.prev_chirho.0;
    }
    if expected_digest_chirho != candidate_chirho.journal_genesis_digest_chirho() {
        bail!("LedgerMirrorRecoveryGenesisPredecessorRefusedChirho");
    }
    Ok(())
}

fn verify_staged_record_chirho(
    bytes_chirho: &[u8],
    expected_seq_chirho: u64,
    expected_digest_chirho: &str,
) -> Result<cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho> {
    if bytes_chirho.is_empty() || bytes_chirho.len() > MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO {
        bail!("LedgerMirrorRecoveryRecordBoundRefusedChirho");
    }
    let line_chirho = std::str::from_utf8(bytes_chirho)
        .context("decode F1 recovery record as canonical UTF-8")?;
    let record_chirho = parse_canonical_ledger_record_chirho(line_chirho)
        .map_err(|_| anyhow!("LedgerMirrorRecoveryRecordCanonicalRefusedChirho"))?;
    if record_chirho.seq_chirho != expected_seq_chirho
        || stored_line_digest_chirho(line_chirho).0 != expected_digest_chirho
    {
        bail!("LedgerMirrorRecoveryRecordCoordinateRefusedChirho");
    }
    Ok(record_chirho)
}

fn assemble_candidate_journal_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    binding_digest_chirho: &str,
    canonical_genesis_line_chirho: &str,
) -> Result<(StoragePathChirho, String)> {
    if stored_line_digest_chirho(canonical_genesis_line_chirho).0
        != candidate_chirho.journal_genesis_digest_chirho()
    {
        bail!("LedgerMirrorRecoveryLocalGenesisRefusedChirho");
    }
    let path_chirho = candidate_journal_path_chirho(binding_digest_chirho);
    storage_chirho.remove_chirho(&path_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    let mut genesis_bytes_chirho = canonical_genesis_line_chirho.as_bytes().to_vec();
    genesis_bytes_chirho.push(b'\n');
    if storage_chirho.create_durable_chirho(&path_chirho, &genesis_bytes_chirho)?
        != CreateDurableOutcomeChirho::CreatedChirho
    {
        bail!("LedgerMirrorRecoveryCandidateCreateRefusedChirho");
    }
    hasher_chirho.update(&genesis_bytes_chirho);
    let mut expected_digest_chirho = candidate_chirho.journal_genesis_digest_chirho().to_string();
    for seq_chirho in 1..=candidate_chirho.tail_seq_chirho() {
        let staged_paths_chirho = storage_chirho.list_chirho(&StoragePathChirho::new_chirho(
            format!(
                "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{binding_digest_chirho}/{RECOVERY_RECORDS_DIR_CHIRHO}/{seq_chirho:020}-"
            ),
        ))?;
        let [staged_path_chirho] = staged_paths_chirho.as_slice() else {
            bail!("LedgerMirrorRecoveryStagedRecordPopulationRefusedChirho");
        };
        let bytes_chirho = storage_chirho
            .read_all_chirho(staged_path_chirho)?
            .ok_or_else(|| anyhow!("F1 staged record disappeared during assembly"))?;
        let staged_digest_chirho =
            staged_record_digest_from_path_chirho(staged_path_chirho, seq_chirho)?;
        let record_chirho =
            verify_staged_record_chirho(&bytes_chirho, seq_chirho, &staged_digest_chirho)?;
        if record_chirho.prev_chirho.0 != expected_digest_chirho {
            bail!("LedgerMirrorRecoveryAssemblyChainRefusedChirho");
        }
        expected_digest_chirho = stored_line_digest_chirho(std::str::from_utf8(&bytes_chirho)?).0;
        let mut physical_line_chirho = bytes_chirho;
        physical_line_chirho.push(b'\n');
        storage_chirho.append_durable_chirho(&path_chirho, &physical_line_chirho)?;
        hasher_chirho.update(&physical_line_chirho);
    }
    if expected_digest_chirho != candidate_chirho.tail_record_digest_chirho() {
        bail!("LedgerMirrorRecoveryAssemblyTailRefusedChirho");
    }
    Ok((path_chirho, hasher_chirho.finalize().to_hex().to_string()))
}

fn verify_replayed_candidate_tail_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
    candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
) -> Result<()> {
    if journal_chirho.tail_seq_chirho() != candidate_chirho.tail_seq_chirho()
        || journal_chirho.tail_line_digest_chirho().0
            != candidate_chirho.tail_record_digest_chirho()
        || journal_chirho.current_epoch_chirho() != candidate_chirho.tail_epoch_chirho()
        || journal_chirho.tail_hlc_chirho() != candidate_chirho.tail_hlc_chirho()
        || journal_chirho
            .verified_append_mirror_tail_chirho()
            .journal_genesis_digest_chirho()
            .0
            != candidate_chirho.journal_genesis_digest_chirho()
    {
        bail!("LedgerMirrorRecoveryFullReplayTailRefusedChirho");
    }
    Ok(())
}

fn hash_storage_object_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
) -> Result<String> {
    let len_chirho = storage_chirho
        .object_len_chirho(path_chirho)?
        .ok_or_else(|| anyhow!("F1 selected recovery journal is absent"))?;
    let mut hasher_chirho = blake3::Hasher::new();
    let mut offset_chirho = 0_u64;
    while offset_chirho < len_chirho {
        let chunk_len_chirho = (len_chirho - offset_chirho).min(1024 * 1024);
        hasher_chirho.update(&storage_chirho.read_exact_range_chirho(
            path_chirho,
            offset_chirho,
            chunk_len_chirho,
        )?);
        offset_chirho += chunk_len_chirho;
    }
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

fn retire_inert_candidates_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    retained_binding_chirho: Option<&str>,
) -> Result<()> {
    let retained_prefix_chirho = retained_binding_chirho.map(|binding_chirho| {
        format!("{RECOVERY_ROOT_CHIRHO}/{RECOVERY_CANDIDATES_DIR_CHIRHO}/{binding_chirho}/")
    });
    retire_unselected_objects_chirho(
        storage_chirho,
        &StoragePathChirho::new_chirho(format!(
            "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_CANDIDATES_DIR_CHIRHO}/"
        )),
        retained_prefix_chirho.as_deref(),
    )
}

fn retire_inert_staging_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    retained_binding_chirho: Option<&str>,
) -> Result<()> {
    let retained_prefix_chirho = retained_binding_chirho.map(|binding_chirho| {
        format!("{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{binding_chirho}/")
    });
    retire_unselected_objects_chirho(
        storage_chirho,
        &StoragePathChirho::new_chirho(format!(
            "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/"
        )),
        retained_prefix_chirho.as_deref(),
    )
}

fn retire_unselected_objects_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    root_chirho: &StoragePathChirho,
    retained_prefix_chirho: Option<&str>,
) -> Result<()> {
    for path_chirho in storage_chirho.list_chirho(root_chirho)? {
        if retained_prefix_chirho
            .is_some_and(|prefix_chirho| path_chirho.key_chirho().starts_with(prefix_chirho))
        {
            continue;
        }
        storage_chirho.remove_chirho(&path_chirho)?;
    }
    Ok(())
}

fn candidate_journal_path_chirho(binding_digest_chirho: &str) -> StoragePathChirho {
    StoragePathChirho::new_chirho(format!(
        "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_CANDIDATES_DIR_CHIRHO}/{binding_digest_chirho}/{RECOVERY_CANDIDATE_JOURNAL_FILE_CHIRHO}"
    ))
}

fn staged_record_path_chirho(
    binding_digest_chirho: &str,
    seq_chirho: u64,
    digest_chirho: &str,
) -> StoragePathChirho {
    StoragePathChirho::new_chirho(format!(
        "{RECOVERY_ROOT_CHIRHO}/{RECOVERY_STAGING_DIR_CHIRHO}/{binding_digest_chirho}/{RECOVERY_RECORDS_DIR_CHIRHO}/{seq_chirho:020}-{digest_chirho}.json"
    ))
}

fn staged_record_digest_from_path_chirho(
    path_chirho: &StoragePathChirho,
    seq_chirho: u64,
) -> Result<String> {
    let file_name_chirho = path_chirho
        .key_chirho()
        .rsplit('/')
        .next()
        .ok_or_else(|| anyhow!("LedgerMirrorRecoveryStagedRecordPathRefusedChirho"))?;
    let prefix_chirho = format!("{seq_chirho:020}-");
    let digest_chirho = file_name_chirho
        .strip_prefix(&prefix_chirho)
        .and_then(|value_chirho| value_chirho.strip_suffix(".json"))
        .ok_or_else(|| anyhow!("LedgerMirrorRecoveryStagedRecordPathRefusedChirho"))?;
    if digest_chirho.len() != 64
        || !digest_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("LedgerMirrorRecoveryStagedRecordPathRefusedChirho");
    }
    Ok(digest_chirho.to_owned())
}

#[cfg(test)]
#[path = "recovery_adoption_chirho/tests_chirho.rs"]
mod tests_chirho;
