// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exact resident identity and physical losing-journal custody retained by the held coordinator.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use crate::resident_ledger_identity_chirho::{
    inspect_bound_identity_opening_epoch_chirho, verify_bound_identity_public_chirho,
    ResidentLedgerCoordinateSourceChirho, RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
};
use crate::storage_chirho::{
    FsLedgerStorageChirho, StableLedgerExclusiveLockGuardChirho,
    StableLedgerNamespaceSnapshotChirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::{ExpectedLedgerGenesisChirho, JournalPortsChirho};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    ExpectedLosingTailFloorChirho, FrozenLosingJournalReaderChirho, LosingSuffixReaderChirho,
    VerifiedLosingJournalTailChirho,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryGenerationStoreChirho, ShadowCanaryLedgerCutChirho,
    VerifiedShadowCanaryCurrentGenerationChirho,
};
use cairn_writer_head_chirho::resident_writer_chirho::{
    try_inspect_resident_writer_identity_in_custody_chirho, ResidentWriterLeaseChirho,
    ResidentWriterRootCustodyChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::{Path, PathBuf};

pub(super) struct HeldLosingJournalIdentityChirho<'ports_chirho> {
    canonical_root_chirho: PathBuf,
    identity_storage_namespace_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    local_node_chirho: NodeIdChirho,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
    opening_epoch_chirho: u64,
    storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    authority_root_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
    storage_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
    resident_identity_digest_chirho: String,
    expected_genesis_chirho: ExpectedLedgerGenesisChirho,
    resident_lease_chirho: ResidentWriterLeaseChirho,
    canary_store_chirho: ShadowCanaryGenerationStoreChirho,
    canary_current_chirho: VerifiedShadowCanaryCurrentGenerationChirho,
    floor_chirho: ExpectedLosingTailFloorChirho,
}

pub(super) struct HeldLosingJournalCustodyChirho<'ports_chirho> {
    reader_chirho: FrozenLosingJournalReaderChirho<'ports_chirho>,
    identity_chirho: HeldLosingJournalIdentityChirho<'ports_chirho>,
}

impl<'ports_chirho> HeldLosingJournalIdentityChirho<'ports_chirho> {
    #[allow(
        clippy::too_many_arguments,
        reason = "one held identity lease binds one explicit resident coordinate without ambient state"
    )]
    pub(super) fn open_chirho(
        canonical_root_chirho: &Path,
        group_chirho: &ConsistencyGroupIdChirho,
        local_node_chirho: &NodeIdChirho,
        storage_chirho: &'ports_chirho FsLedgerStorageChirho,
        authority_storage_chirho: &FsLedgerStorageChirho,
        canary_root_chirho: &Path,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
    ) -> Result<Self> {
        let identity_storage_namespace_chirho =
            storage_chirho.namespace_root_chirho().to_path_buf();
        if identity_storage_namespace_chirho == canonical_root_chirho
            || !identity_storage_namespace_chirho.starts_with(canonical_root_chirho)
        {
            bail!("held GD7 journal storage lies outside the selected root");
        }
        let resident_root_custody_chirho =
            ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
                canonical_root_chirho,
                authority_storage_chirho
                    .clone_namespace_root_descriptor_chirho()
                    .context("clone held authority-root descriptor")?,
            )
            .context("retain held resident-writer root custody")?;
        let authority_root_snapshot_chirho = authority_storage_chirho
            .stable_namespace_snapshot_chirho()
            .context("snapshot held authority root")?;
        let storage_snapshot_chirho = storage_chirho
            .stable_namespace_snapshot_chirho()
            .context("snapshot held journal storage")?;
        let inspection_chirho =
            try_inspect_resident_writer_identity_in_custody_chirho(&resident_root_custody_chirho)
                .context("inspect held resident identity")?
                .ok_or_else(|| anyhow!("held resident identity is missing or unreadable"))?;
        if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO {
            bail!("held resident identity kind differs from the ledger identity");
        }
        let opening_epoch_chirho = inspect_bound_identity_opening_epoch_chirho(
            inspection_chirho.canonical_identity_chirho(),
        )
        .context("inspect held resident opening epoch")?;
        let source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: canonical_root_chirho,
            authority_root_snapshot_chirho: &authority_root_snapshot_chirho,
            group_chirho,
            storage_chirho,
            storage_snapshot_chirho: &storage_snapshot_chirho,
            identity_storage_namespace_chirho: &identity_storage_namespace_chirho,
            journal_path_chirho: &journal_path_chirho,
            cluster_id_chirho: &cluster_id_chirho,
            opening_epoch_chirho,
            local_node_chirho,
        };
        let verified_identity_chirho = verify_bound_identity_public_chirho(
            inspection_chirho.canonical_identity_chirho(),
            source_chirho,
        )
        .context("publicly verify exact held resident identity")?;
        let expected_genesis_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
            verified_identity_chirho.verified_genesis_line_chirho(),
            verified_identity_chirho
                .verified_genesis_digest_chirho()
                .clone(),
        )
        .map_err(|error_chirho| anyhow!("held resident genesis refused: {error_chirho:?}"))?;
        let resident_identity_digest_chirho = inspection_chirho.identity_digest_chirho().to_owned();
        let resident_lease_chirho = inspection_chirho
            .open_exact_chirho()
            .context("retain exact held resident identity lease")?;
        if resident_lease_chirho.identity_digest_chirho() != resident_identity_digest_chirho {
            bail!("held resident identity changed while its lease opened");
        }
        let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
            canary_root_chirho,
            canonical_root_chirho,
            group_chirho.clone(),
            local_node_chirho.clone(),
        )
        .context("open existing held shadow-canary evidence")?;
        let canary_current_chirho = canary_store_chirho
            .verify_current_read_only_chirho()
            .context("verify current held shadow-canary generation")?;
        let floor_chirho = floor_from_canary_cut_chirho(
            group_chirho,
            canary_current_chirho.latest_ledger_cut_chirho(),
        )?;
        authority_root_snapshot_chirho
            .verify_current_path_chirho(canonical_root_chirho)
            .context("reverify held authority root after identity lease")?;
        storage_snapshot_chirho
            .verify_current_path_chirho(&identity_storage_namespace_chirho)
            .context("reverify held storage after identity lease")?;
        Ok(Self {
            canonical_root_chirho: canonical_root_chirho.to_path_buf(),
            identity_storage_namespace_chirho,
            group_chirho: group_chirho.clone(),
            local_node_chirho: local_node_chirho.clone(),
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            storage_chirho,
            authority_root_snapshot_chirho,
            storage_snapshot_chirho,
            resident_identity_digest_chirho,
            expected_genesis_chirho,
            resident_lease_chirho,
            canary_store_chirho,
            canary_current_chirho,
            floor_chirho,
        })
    }

    pub(super) fn freeze_chirho(
        self,
        ports_chirho: JournalPortsChirho<'ports_chirho>,
        writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    ) -> Result<HeldLosingJournalCustodyChirho<'ports_chirho>> {
        writer_lock_guard_chirho
            .verify_custody_chirho()
            .context("verify held writer lock before freezing losing cut")?;
        self.verify_identity_and_canary_chirho()?;
        let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
            ports_chirho,
            self.journal_path_chirho.clone(),
            &self.expected_genesis_chirho,
            &self.floor_chirho,
        )
        .map_err(|error_chirho| anyhow!("derive held losing journal cut: {error_chirho:?}"))?;
        if reader_chirho
            .verified_losing_tail_chirho()
            .identity_chirho()
            .genesis_digest_chirho()
            != self.expected_genesis_chirho.digest_chirho()
        {
            bail!("held losing journal genesis differs from its resident identity");
        }
        self.verify_identity_and_canary_chirho()?;
        writer_lock_guard_chirho
            .verify_custody_chirho()
            .context("reverify held writer lock after freezing losing cut")?;
        Ok(HeldLosingJournalCustodyChirho {
            reader_chirho,
            identity_chirho: self,
        })
    }

    fn verify_identity_and_canary_chirho(&self) -> Result<()> {
        self.authority_root_snapshot_chirho
            .verify_current_path_chirho(&self.canonical_root_chirho)
            .context("verify held authority-root identity")?;
        self.storage_snapshot_chirho
            .verify_current_path_chirho(&self.identity_storage_namespace_chirho)
            .context("verify held storage identity")?;
        let inspection_chirho = self
            .resident_lease_chirho
            .inspect_identity_chirho()
            .context("reinspect held resident identity")?;
        if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO
            || inspection_chirho.identity_digest_chirho() != self.resident_identity_digest_chirho
            || self.resident_lease_chirho.identity_digest_chirho()
                != self.resident_identity_digest_chirho
        {
            bail!("held resident identity changed after its lease was retained");
        }
        let source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &self.canonical_root_chirho,
            authority_root_snapshot_chirho: &self.authority_root_snapshot_chirho,
            group_chirho: &self.group_chirho,
            storage_chirho: self.storage_chirho,
            storage_snapshot_chirho: &self.storage_snapshot_chirho,
            identity_storage_namespace_chirho: &self.identity_storage_namespace_chirho,
            journal_path_chirho: &self.journal_path_chirho,
            cluster_id_chirho: &self.cluster_id_chirho,
            opening_epoch_chirho: self.opening_epoch_chirho,
            local_node_chirho: &self.local_node_chirho,
        };
        let verified_identity_chirho = verify_bound_identity_public_chirho(
            inspection_chirho.canonical_identity_chirho(),
            source_chirho,
        )
        .context("publicly reverify exact held resident identity")?;
        if verified_identity_chirho.verified_genesis_digest_chirho()
            != self.expected_genesis_chirho.digest_chirho()
        {
            bail!("held resident genesis changed after the identity lease was retained");
        }
        let observed_canary_chirho = self
            .canary_store_chirho
            .verify_current_read_only_chirho()
            .context("reverify held shadow-canary generation")?;
        if observed_canary_chirho != self.canary_current_chirho
            || floor_from_canary_cut_chirho(
                &self.group_chirho,
                observed_canary_chirho.latest_ledger_cut_chirho(),
            )? != self.floor_chirho
        {
            bail!("held shadow-canary floor changed after the losing cut was frozen");
        }
        Ok(())
    }
}

impl HeldLosingJournalCustodyChirho<'_> {
    pub(super) fn reader_chirho(&self) -> &dyn LosingSuffixReaderChirho {
        &self.reader_chirho
    }

    pub(super) fn expected_genesis_chirho(&self) -> &ExpectedLedgerGenesisChirho {
        &self.identity_chirho.expected_genesis_chirho
    }

    pub(super) fn losing_tail_chirho(&self) -> VerifiedLosingJournalTailChirho {
        self.reader_chirho.verified_losing_tail_chirho()
    }

    pub(super) fn verify_custody_chirho(
        &self,
        writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    ) -> Result<VerifiedLosingJournalTailChirho> {
        writer_lock_guard_chirho
            .verify_custody_chirho()
            .context("verify held writer-lock custody")?;
        self.identity_chirho.verify_identity_and_canary_chirho()?;
        self.reader_chirho
            .revalidate_current_losing_tail_chirho()
            .map_err(|error_chirho| anyhow!("revalidate held losing journal: {error_chirho:?}"))
    }
}

fn floor_from_canary_cut_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    cut_chirho: &ShadowCanaryLedgerCutChirho,
) -> Result<ExpectedLosingTailFloorChirho> {
    let expected_group_digest_chirho = consistency_group_digest_chirho(group_chirho)?;
    if cut_chirho.consistency_group_digest_chirho().as_str_chirho() != expected_group_digest_chirho
    {
        bail!("held shadow-canary generation does not prove an authenticated append floor");
    }
    Ok(ExpectedLosingTailFloorChirho::new_chirho(
        cut_chirho.append_seq_chirho(),
        cairn_ledger_model_chirho::ids_chirho::DigestChirho(
            cut_chirho.append_record_digest_chirho().to_string(),
        ),
        HlcChirho {
            physical_ms_chirho: cut_chirho.append_hlc_physical_ms_chirho(),
            logical_chirho: cut_chirho.append_hlc_logical_chirho(),
        },
        cut_chirho.record_epoch_chirho(),
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_writer_elector_chirho::shadow_canary_chirho::ShadowCanaryAppendCutChirho;

    #[test]
    fn held_floor_accepts_a_signed_latest_refusal_cut_chirho() {
        let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "held-refusal-floor-chirho".to_owned(),
        };
        let group_digest_chirho = consistency_group_digest_chirho(&group_chirho).unwrap();
        let cut_chirho = ShadowCanaryAppendCutChirho {
            append_seq_chirho: 7,
            append_record_digest_chirho: "a".repeat(64),
            append_hlc_physical_ms_chirho: 11,
            append_hlc_logical_chirho: 2,
            process_generation_chirho: 3,
            durable_term_chirho: 4,
            fence_epoch_chirho: 5,
            fence_group_digest_chirho: group_digest_chirho,
        };
        let ledger_cut_chirho =
            ShadowCanaryLedgerCutChirho::from_append_cut_chirho(&cut_chirho, &group_chirho)
                .expect("derive generation-aware held floor");

        assert_eq!(
            floor_from_canary_cut_chirho(&group_chirho, &ledger_cut_chirho).unwrap(),
            ExpectedLosingTailFloorChirho::new_chirho(
                cut_chirho.append_seq_chirho,
                cairn_ledger_model_chirho::ids_chirho::DigestChirho(
                    cut_chirho.append_record_digest_chirho,
                ),
                HlcChirho {
                    physical_ms_chirho: cut_chirho.append_hlc_physical_ms_chirho,
                    logical_chirho: cut_chirho.append_hlc_logical_chirho,
                },
                cut_chirho.fence_epoch_chirho,
            )
        );
    }
}
