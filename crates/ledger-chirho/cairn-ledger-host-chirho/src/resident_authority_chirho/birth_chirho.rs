// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Sealed preactivation Pending-to-Bound birth for one resident ledger coordinate. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md` §4.

use super::sink_term_lifecycle_chirho::{
    create_or_recover_resident_sink_term_cell_at_birth_chirho, local_generation_refusal_chirho,
    require_no_sink_term_cell_before_fresh_pending_chirho, resident_identity_refusal_chirho,
    resident_lease_refusal_chirho, stable_namespace_refusal_chirho, writer_fence_refusal_chirho,
};
use super::{
    journal_ports_chirho, validate_epoch_posture_chirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerLocalPortsChirho,
};
use crate::resident_ledger_identity_chirho::{
    canonical_bound_identity_chirho, canonical_pending_identity_chirho,
    verify_bound_identity_chirho, verify_pending_identity_chirho,
    ResidentLedgerCoordinateSourceChirho, RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
};
use crate::storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    JournalErrorChirho, LedgerJournalChirho, PreparedLedgerGenesisChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho;
use cairn_writer_head_chirho::resident_writer_chirho::{
    reserve_resident_writer_in_custody_chirho,
    try_inspect_resident_writer_identity_in_custody_chirho, ResidentWriterBindingChirho,
    ResidentWriterReservationOutcomeChirho, ResidentWriterRootCustodyChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, WRITER_FENCE_LOCK_CHIRHO,
};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

/// Consumed, coordinate-bound birth capability with one reviewed activation constructor.
pub struct ResidentLedgerBirthPermitChirho {
    canonical_root_chirho: PathBuf,
    identity_storage_namespace_chirho: Option<PathBuf>,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
    opening_epoch_chirho: u64,
    /// ADOPT an existing journal instead of being born over a pristine one.
    ///
    /// A migrated root is the one legitimate case: it carries the tenant's history and has no
    /// resident writer identity, because an identity binds a root's device and inode and therefore
    /// cannot travel. Birth is otherwise the ONLY path that issues one, and it requires
    /// `tail_seq == 0` — so without this a migrated root can never be opened by anyone.
    ///
    /// It is `false` for every ordinary birth and is set only by a caller holding a VERIFIED
    /// activation authorization bound to this exact root, so the relaxation rides on the same
    /// signature that authorizes a genesis rather than on a caller's word.
    adopt_existing_journal_chirho: bool,
}

impl ResidentLedgerBirthPermitChirho {
    #[cfg(test)]
    pub(crate) fn for_test_chirho(
        root_chirho: &Path,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
    ) -> Self {
        Self {
            canonical_root_chirho: root_chirho
                .canonicalize()
                .expect("resident birth test root must exist"),
            identity_storage_namespace_chirho: None,
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_with_identity_storage_chirho(
        root_chirho: &Path,
        identity_storage_namespace_chirho: PathBuf,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
    ) -> Self {
        Self {
            canonical_root_chirho: root_chirho
                .canonicalize()
                .expect("resident birth test root must exist"),
            identity_storage_namespace_chirho: Some(identity_storage_namespace_chirho),
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho: false,
        }
    }

    pub(super) fn for_reviewed_activation_chirho(
        canonical_root_chirho: PathBuf,
        identity_storage_namespace_chirho: PathBuf,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
    ) -> Self {
        Self {
            canonical_root_chirho,
            identity_storage_namespace_chirho: Some(identity_storage_namespace_chirho),
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho: false,
        }
    }

    /// The same reviewed activation, ADOPTING the journal already in the root.
    ///
    /// Separate constructor rather than a boolean parameter on the other one: a caller cannot reach
    /// adoption by passing the wrong argument, and every existing call site keeps its meaning
    /// unchanged and visibly.
    /// The adoption permit, for arms that must prove the mode rather than describe it.
    #[cfg(test)]
    pub(crate) fn for_test_adoption_chirho(
        root_chirho: &Path,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
    ) -> Self {
        Self {
            canonical_root_chirho: root_chirho
                .canonicalize()
                .expect("resident adoption test root must exist"),
            identity_storage_namespace_chirho: None,
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho: true,
        }
    }

    pub(super) fn for_reviewed_adoption_chirho(
        canonical_root_chirho: PathBuf,
        identity_storage_namespace_chirho: PathBuf,
        journal_path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
    ) -> Self {
        Self {
            canonical_root_chirho,
            identity_storage_namespace_chirho: Some(identity_storage_namespace_chirho),
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho: true,
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static RESIDENT_BIRTH_POST_GENESIS_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static RESIDENT_BIRTH_POST_SINK_TERM_CELL_TEST_HOOK_CHIRHO:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn install_resident_birth_post_genesis_test_hook_chirho(
    hook_chirho: impl FnOnce() + 'static,
) {
    RESIDENT_BIRTH_POST_GENESIS_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        assert!(
            slot_chirho.borrow().is_none(),
            "resident birth test hook must be installed at most once"
        );
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
pub(crate) fn install_resident_birth_post_sink_term_cell_test_hook_chirho(
    hook_chirho: impl FnOnce() + 'static,
) {
    RESIDENT_BIRTH_POST_SINK_TERM_CELL_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        assert!(
            slot_chirho.borrow().is_none(),
            "resident birth sink-term-cell test hook must be installed at most once"
        );
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
fn run_resident_birth_post_genesis_test_hook_chirho() {
    let hook_chirho = RESIDENT_BIRTH_POST_GENESIS_TEST_HOOK_CHIRHO
        .with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

#[cfg(test)]
fn run_resident_birth_post_sink_term_cell_test_hook_chirho() {
    let hook_chirho = RESIDENT_BIRTH_POST_SINK_TERM_CELL_TEST_HOOK_CHIRHO
        .with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

impl<'ports_chirho> ResidentLedgerAuthorityChirho<'ports_chirho> {
    /// Create or recover one exact Pending identity and bind it without dropping its lifetime lease.
    ///
    /// The reviewed H3 activation capsule is the only production caller. It binds the final logical
    /// storage namespace before staging is renamed, while retained descriptor custody binds the
    /// actual storage inode.
    pub fn create_bound_preactivation_chirho(
        permit_chirho: ResidentLedgerBirthPermitChirho,
        ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
        local_authority_chirho: LocalAppendAuthorityHandleChirho,
    ) -> Result<Self, ResidentLedgerAuthorityRefusalChirho> {
        let ResidentLedgerBirthPermitChirho {
            canonical_root_chirho,
            identity_storage_namespace_chirho,
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            adopt_existing_journal_chirho,
        } = permit_chirho;
        let observed_root_chirho = canonical_root_chirho
            .canonicalize()
            .map_err(|error_chirho| stable_namespace_refusal_chirho(error_chirho.into()))?;
        if observed_root_chirho != canonical_root_chirho {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        let group_chirho = local_authority_chirho.consistency_group_chirho().clone();
        let local_node_chirho = local_authority_chirho.node_id_chirho().clone();
        let actual_group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        if actual_group_chirho != group_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::RootGroupMismatchChirho {
                    expected_group_chirho: group_chirho,
                    actual_group_chirho,
                },
            );
        }
        let storage_root_chirho = ports_chirho.storage_chirho.namespace_root_chirho();
        if storage_root_chirho == canonical_root_chirho
            || !storage_root_chirho.starts_with(&canonical_root_chirho)
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::StorageOutsideSelectedRootChirho);
        }
        let identity_storage_namespace_chirho = identity_storage_namespace_chirho
            .as_deref()
            .unwrap_or(storage_root_chirho);

        let generation_authority_chirho = local_authority_chirho.clone();
        let generation_guard_chirho = generation_authority_chirho
            .try_acquire_chirho()
            .map_err(local_generation_refusal_chirho)?;
        require_opening_membership_chirho(
            ports_chirho.membership_chirho.current_epoch_chirho(),
            opening_epoch_chirho,
        )?;
        let authority_storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho)
                .map_err(stable_namespace_refusal_chirho)?;
        let resident_root_custody_chirho =
            ResidentWriterRootCustodyChirho::from_retained_directory_chirho(
                &canonical_root_chirho,
                authority_storage_chirho
                    .clone_namespace_root_descriptor_chirho()
                    .map_err(stable_namespace_refusal_chirho)?,
            )
            .map_err(resident_identity_refusal_chirho)?;
        let authority_root_snapshot_chirho = authority_storage_chirho
            .stable_namespace_snapshot_chirho()
            .map_err(stable_namespace_refusal_chirho)?;
        let storage_snapshot_chirho = ports_chirho
            .storage_chirho
            .stable_namespace_snapshot_chirho()
            .map_err(stable_namespace_refusal_chirho)?;
        let writer_lock_path_chirho =
            StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
        let mut writer_lock_chirho = authority_storage_chirho
            .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
            .map_err(writer_fence_refusal_chirho)?;
        let writer_lock_guard_chirho = writer_lock_chirho
            .try_acquire_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        let source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &canonical_root_chirho,
            authority_root_snapshot_chirho: &authority_root_snapshot_chirho,
            group_chirho: &group_chirho,
            storage_chirho: ports_chirho.storage_chirho,
            storage_snapshot_chirho: &storage_snapshot_chirho,
            identity_storage_namespace_chirho,
            journal_path_chirho: &journal_path_chirho,
            cluster_id_chirho: &cluster_id_chirho,
            opening_epoch_chirho,
            local_node_chirho: &local_node_chirho,
        };
        let prior_identity_chirho =
            try_inspect_resident_writer_identity_in_custody_chirho(&resident_root_custody_chirho)
                .map_err(resident_identity_refusal_chirho)?;
        // A FRESH birth must find no sink-term cell — a residue means something already held this
        // group's writer authority. An ADOPTED root is the one case where a residue is expected and
        // correct: the cell is a tenant-scoped monotonic winner-term mark that travels with the
        // root, so refusing it here would refuse the very state the migration is preserving. What
        // replaces this check for adoption is stricter than skipping it, and lives below: the cell
        // goes through the RECOVER path, which refuses one that is ahead of the acting authority,
        // keeps an equal one, and advances a behind one monotonically.
        if prior_identity_chirho.is_none() && !adopt_existing_journal_chirho {
            require_no_sink_term_cell_before_fresh_pending_chirho(
                &group_chirho,
                &writer_lock_guard_chirho,
            )
            .map_err(ResidentLedgerAuthorityRefusalChirho::from)?;
        }
        let (pending_identity_chirho, prepared_genesis_chirho) = if let Some(inspection_chirho) =
            prior_identity_chirho
        {
            if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO {
                return Err(
                    ResidentLedgerAuthorityRefusalChirho::ResidentIdentityKindMismatchChirho,
                );
            }
            let verified_pending_chirho = verify_pending_identity_chirho(
                inspection_chirho.canonical_identity_chirho(),
                source_chirho,
            )
            .map_err(resident_identity_refusal_chirho)?;
            let prepared_genesis_chirho = LedgerJournalChirho::verify_prepared_genesis_chirho(
                journal_ports_chirho(ports_chirho),
                verified_pending_chirho.prepared_genesis_line_chirho(),
                &cluster_id_chirho,
                opening_epoch_chirho,
                verified_pending_chirho.prepared_genesis_digest_chirho(),
            )
            .map_err(journal_composition_refusal_chirho)?;
            (
                inspection_chirho.canonical_identity_chirho().to_vec(),
                prepared_genesis_chirho,
            )
        } else if adopt_existing_journal_chirho
            && ports_chirho
                .storage_chirho
                .exists_chirho(&journal_path_chirho)
                .map_err(journal_storage_refusal_chirho)?
        {
            // ADOPTION. The genesis is the journal's OWN, never a freshly prepared one — preparing
            // would mint a second genesis for a history that already has one, and the mismatch check
            // below would then reject the very journal being adopted. It is read from storage and
            // re-verified against the cluster, the opening epoch and the digest the opened journal
            // reports, so an adopted genesis passes exactly the checks a prepared one does.
            let genesis_line_chirho =
                adopted_genesis_line_chirho(ports_chirho, &journal_path_chirho)?;
            let adopted_digest_chirho = {
                let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
                    journal_ports_chirho(ports_chirho),
                    journal_path_chirho.clone(),
                    &cluster_id_chirho,
                )
                .map_err(journal_composition_refusal_chirho)?;
                journal_chirho.genesis_digest_chirho().clone()
            };
            let prepared_genesis_chirho = LedgerJournalChirho::verify_prepared_genesis_chirho(
                journal_ports_chirho(ports_chirho),
                &genesis_line_chirho,
                &cluster_id_chirho,
                opening_epoch_chirho,
                &adopted_digest_chirho,
            )
            .map_err(journal_composition_refusal_chirho)?;
            let pending_identity_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_genesis_chirho)
                    .map_err(resident_identity_refusal_chirho)?;
            (pending_identity_chirho, prepared_genesis_chirho)
        } else {
            if ports_chirho
                .storage_chirho
                .exists_chirho(&journal_path_chirho)
                .map_err(journal_storage_refusal_chirho)?
            {
                return Err(ResidentLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho);
            }
            let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                journal_ports_chirho(ports_chirho),
                cluster_id_chirho.clone(),
                opening_epoch_chirho,
            )
            .map_err(journal_composition_refusal_chirho)?;
            let pending_identity_chirho =
                canonical_pending_identity_chirho(source_chirho, &prepared_genesis_chirho)
                    .map_err(resident_identity_refusal_chirho)?;
            (pending_identity_chirho, prepared_genesis_chirho)
        };
        let pending_binding_chirho = ResidentWriterBindingChirho {
            root_chirho: &canonical_root_chirho,
            identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
            canonical_identity_chirho: &pending_identity_chirho,
        };
        let (provisioning_chirho, reservation_outcome_chirho) =
            reserve_resident_writer_in_custody_chirho(
                &resident_root_custody_chirho,
                &pending_binding_chirho,
            )
            .map_err(resident_lease_refusal_chirho)?;
        let journal_exists_chirho = ports_chirho
            .storage_chirho
            .exists_chirho(&journal_path_chirho)
            .map_err(journal_storage_refusal_chirho)?;
        let recovered_pending_chirho = matches!(
            reservation_outcome_chirho,
            ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
        );
        if journal_exists_chirho && !recovered_pending_chirho && !adopt_existing_journal_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho,
            );
        }
        if !journal_exists_chirho {
            let created_chirho = LedgerJournalChirho::create_prepared_chirho(
                journal_ports_chirho(ports_chirho),
                journal_path_chirho.clone(),
                prepared_genesis_chirho.clone(),
            )
            .map_err(journal_composition_refusal_chirho)?;
            drop(created_chirho);
        }
        let expected_genesis_bytes_chirho = prepared_genesis_bytes_chirho(&prepared_genesis_chirho);
        let genesis_bytes_match_chirho = |storage_chirho: &FsLedgerStorageChirho| {
            if adopt_existing_journal_chirho {
                resident_genesis_prefix_matches_chirho(
                    storage_chirho,
                    &journal_path_chirho,
                    &expected_genesis_bytes_chirho,
                )
            } else {
                exact_resident_genesis_bytes_chirho(
                    storage_chirho,
                    &journal_path_chirho,
                    &expected_genesis_bytes_chirho,
                )
            }
        };
        if !genesis_bytes_match_chirho(ports_chirho.storage_chirho)
            .map_err(journal_storage_refusal_chirho)?
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho);
        }
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            journal_ports_chirho(ports_chirho),
            journal_path_chirho.clone(),
            &cluster_id_chirho,
        )
        .map_err(journal_composition_refusal_chirho)?;
        #[cfg(test)]
        run_resident_birth_post_genesis_test_hook_chirho();
        if !genesis_bytes_match_chirho(ports_chirho.storage_chirho)
            .map_err(journal_storage_refusal_chirho)?
            || journal_chirho.genesis_digest_chirho() != prepared_genesis_chirho.digest_chirho()
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho);
        }
        // The pristine check is what a BIRTH means: a root being born must have written nothing.
        // An adopted journal carries the tenant's history by definition, so the check is skipped for
        // it and ONLY for it — the genesis identity above is still proven exactly as it is for a
        // birth, which is what keeps this from becoming "trust whatever journal is in the directory".
        if !adopt_existing_journal_chirho
            && (journal_chirho.tail_seq_chirho() != 0
                || journal_chirho.current_epoch_chirho() != opening_epoch_chirho)
        {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::PendingJournalNotPristineChirho {
                    tail_seq_chirho: journal_chirho.tail_seq_chirho(),
                    current_epoch_chirho: journal_chirho.current_epoch_chirho(),
                    opening_epoch_chirho,
                },
            );
        }
        require_opening_membership_chirho(
            ports_chirho.membership_chirho.current_epoch_chirho(),
            opening_epoch_chirho,
        )?;
        authority_root_snapshot_chirho
            .verify_current_path_chirho(&canonical_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        storage_snapshot_chirho
            .verify_current_path_chirho(storage_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        let sink_term_cell_birth_chirho =
            create_or_recover_resident_sink_term_cell_at_birth_chirho(
                &group_chirho,
                &generation_guard_chirho,
                &writer_lock_guard_chirho,
                // ADOPTION RECOVERS the cell rather than creating one. The reservation itself is
                // fresh — a migrated root has no identity to recover — but the CELL is the tenant's
                // travelling mark, and treating it as unowned residue would refuse the migration
                // while treating it as freshly created would silently reset a monotonic fence. The
                // recover path is the only one with the right guards for it.
                if adopt_existing_journal_chirho {
                    ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
                } else {
                    reservation_outcome_chirho
                },
            )
            .map_err(ResidentLedgerAuthorityRefusalChirho::from)?;
        #[cfg(test)]
        run_resident_birth_post_sink_term_cell_test_hook_chirho();
        let bound_identity_chirho = canonical_bound_identity_chirho(
            source_chirho,
            prepared_genesis_chirho.canonical_line_chirho(),
            journal_chirho.genesis_digest_chirho(),
            sink_term_cell_birth_chirho,
        )
        .map_err(resident_identity_refusal_chirho)?;
        let bound_binding_chirho = ResidentWriterBindingChirho {
            root_chirho: &canonical_root_chirho,
            identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
            canonical_identity_chirho: &bound_identity_chirho,
        };
        let resident_lease_chirho = provisioning_chirho
            .bind_resident_writer_chirho(&bound_binding_chirho)
            .map_err(resident_lease_refusal_chirho)?;
        let resident_identity_digest_chirho =
            resident_lease_chirho.identity_digest_chirho().to_owned();
        let inspection_chirho = resident_lease_chirho
            .inspect_identity_chirho()
            .map_err(resident_identity_refusal_chirho)?;
        if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO
            || inspection_chirho.canonical_identity_chirho() != bound_identity_chirho
            || inspection_chirho.identity_digest_chirho() != resident_identity_digest_chirho
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        verify_bound_identity_chirho(inspection_chirho.canonical_identity_chirho(), source_chirho)
            .map_err(resident_identity_refusal_chirho)?;
        authority_root_snapshot_chirho
            .verify_current_path_chirho(&canonical_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        storage_snapshot_chirho
            .verify_current_path_chirho(storage_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        writer_lock_guard_chirho
            .verify_custody_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        validate_epoch_posture_chirho(
            journal_chirho.current_epoch_chirho(),
            ports_chirho.membership_chirho.current_epoch_chirho(),
            generation_guard_chirho.published_raft_term_chirho(),
        )?;
        drop(writer_lock_guard_chirho);
        let resident_chirho = Self {
            canonical_root_chirho,
            identity_storage_namespace_chirho: identity_storage_namespace_chirho.to_path_buf(),
            group_chirho,
            local_node_chirho,
            journal_path_chirho,
            cluster_id_chirho,
            opening_epoch_chirho,
            ports_chirho,
            local_authority_chirho,
            resident_identity_digest_chirho,
            authority_storage_chirho,
            authority_root_snapshot_chirho,
            storage_snapshot_chirho,
            writer_lock_chirho,
            active_fence_chirho: None,
            journal_chirho: Some(journal_chirho),
            ordinary_term_acceptance_source_chirho: None,
            ordinary_term_acceptance_placement_binding_chirho: None,
            resident_lease_chirho: Some(resident_lease_chirho),
        };
        drop(generation_guard_chirho);
        Ok(resident_chirho)
    }
}

fn require_opening_membership_chirho(
    membership_epoch_chirho: u64,
    opening_epoch_chirho: u64,
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    if membership_epoch_chirho != opening_epoch_chirho {
        return Err(
            ResidentLedgerAuthorityRefusalChirho::OpeningMembershipEpochMismatchChirho {
                opening_epoch_chirho,
                membership_epoch_chirho,
            },
        );
    }
    Ok(())
}

fn prepared_genesis_bytes_chirho(prepared_genesis_chirho: &PreparedLedgerGenesisChirho) -> Vec<u8> {
    let mut expected_bytes_chirho = prepared_genesis_chirho
        .canonical_line_chirho()
        .as_bytes()
        .to_vec();
    expected_bytes_chirho.push(b'\n');
    expected_bytes_chirho
}

/// The journal's genesis bytes, checked as a PREFIX rather than as the whole file.
///
/// [`exact_resident_genesis_bytes_chirho`] requires the object's total length to equal the genesis
/// line — a journal that is nothing but its genesis. That is exactly right for a BIRTH and is a
/// third pristine-journal assumption, after the `tail_seq` check and the existing-journal refusal.
/// An adopted journal has history by definition, so the whole-file form rejects every real one.
///
/// This is no weaker about the genesis itself: the same bytes must appear, at the same offset, in
/// the same order. What it drops is the claim that nothing follows them, which for an adopted
/// journal is not a property anyone wants.
fn resident_genesis_prefix_matches_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    path_chirho: &StoragePathChirho,
    expected_bytes_chirho: &[u8],
) -> anyhow::Result<bool> {
    let expected_len_chirho = u64::try_from(expected_bytes_chirho.len())
        .map_err(|_error_chirho| anyhow::anyhow!("resident genesis length exceeds u64"))?;
    let Some(actual_bytes_chirho) =
        storage_chirho.read_object_prefix_chirho(path_chirho, expected_len_chirho)?
    else {
        anyhow::bail!("adopted resident genesis disappeared before bounded verification");
    };
    Ok(actual_bytes_chirho == expected_bytes_chirho)
}

fn exact_resident_genesis_bytes_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    path_chirho: &StoragePathChirho,
    expected_bytes_chirho: &[u8],
) -> anyhow::Result<bool> {
    let expected_len_chirho = u64::try_from(expected_bytes_chirho.len())
        .map_err(|_error_chirho| anyhow::anyhow!("resident genesis length exceeds u64"))?;
    let Some(length_before_chirho) = storage_chirho.object_len_chirho(path_chirho)? else {
        anyhow::bail!("prepared resident genesis disappeared before bounded verification");
    };
    if length_before_chirho != expected_len_chirho {
        return Ok(false);
    }
    let actual_bytes_chirho =
        storage_chirho.read_exact_range_chirho(path_chirho, 0, expected_len_chirho)?;
    let Some(length_after_chirho) = storage_chirho.object_len_chirho(path_chirho)? else {
        anyhow::bail!("prepared resident genesis disappeared during bounded verification");
    };
    Ok(length_after_chirho == expected_len_chirho && actual_bytes_chirho == expected_bytes_chirho)
}

fn journal_composition_refusal_chirho(
    error_chirho: JournalErrorChirho,
) -> ResidentLedgerAuthorityRefusalChirho {
    ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
        detail_chirho: format!("{error_chirho:?}"),
    }
}

fn journal_storage_refusal_chirho(
    error_chirho: anyhow::Error,
) -> ResidentLedgerAuthorityRefusalChirho {
    ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

/// The first line of an adopted journal: its genesis, read under a bound.
///
/// Bounded on purpose — this runs before anything about the journal has been verified, so it must
/// not be able to pull an arbitrary amount of a file that has not yet earned any trust. The caller
/// re-verifies the returned line against the cluster, the opening epoch and the digest, so a wrong
/// or truncated read fails there rather than being adopted.
fn adopted_genesis_line_chirho(
    ports_chirho: ResidentLedgerLocalPortsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
) -> Result<String, ResidentLedgerAuthorityRefusalChirho> {
    const MAX_ADOPTED_GENESIS_LINE_BYTES_CHIRHO: u64 = 64 * 1024;
    let bytes_chirho = ports_chirho
        .storage_chirho
        .read_object_prefix_chirho(journal_path_chirho, MAX_ADOPTED_GENESIS_LINE_BYTES_CHIRHO)
        .map_err(journal_storage_refusal_chirho)?
        .ok_or(
            ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                detail_chirho: "AdoptedJournalObjectAbsentChirho".to_owned(),
            },
        )?;
    let newline_chirho = bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho == b'\n')
        .ok_or(
            ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                detail_chirho: "AdoptedJournalHasNoFirstLineChirho".to_owned(),
            },
        )?;
    // DISTINCT identities per failure: "the object is not there", "the prefix has no line" and
    // "the bytes are not UTF-8" call for three different investigations, and one message for all
    // three turns a hosted diagnosis into a guess.
    String::from_utf8(bytes_chirho[..newline_chirho].to_vec()).map_err(|_error_chirho| {
        ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
            detail_chirho: "AdoptedGenesisLineIsNotUtf8Chirho".to_owned(),
        }
    })
}
