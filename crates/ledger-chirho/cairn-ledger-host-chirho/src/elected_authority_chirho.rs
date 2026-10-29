// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Executable `cfg(test)` A6 join proof between elected leadership and the real ledger final sink.
//!
//! The bridge is deliberately outside the election crate: election reports authority but cannot
//! mint a fence or commit a journal. No production build compiles this module yet.

use crate::authority_chirho::ElectedClusterMembershipChirho;
use crate::resident_authority_chirho::sink_term_lifecycle_chirho::create_or_recover_resident_sink_term_cell_at_term_for_test_chirho;
use crate::resident_ledger_identity_chirho::{
    canonical_bound_identity_chirho, canonical_pending_identity_chirho,
    verify_bound_identity_chirho, verify_pending_identity_chirho,
    ResidentLedgerCoordinateSourceChirho, RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
};
use crate::storage_chirho::{FsLedgerStorageChirho, StableLedgerNamespaceSnapshotChirho};
use anyhow::Result;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendReceiptChirho, AppendRequestChirho, JournalErrorChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::{
    LeadershipChirho, NodeIdChirho, WriterElectorChirho,
};
use cairn_writer_head_chirho::resident_writer_chirho::{
    inspect_resident_writer_identity_chirho, open_resident_writer_chirho,
    reserve_resident_writer_chirho, resident_writer_identity_path_chirho,
    ResidentWriterBindingChirho, ResidentWriterLeaseChirho, ResidentWriterReservationOutcomeChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, split_writer_epoch_chirho,
    with_reused_or_issued_elected_writer_fence_chirho, ConsistencyGroupIdChirho,
    WriterFenceTokenChirho, WRITER_EPOCH_COMPONENT_MAX_CHIRHO, WRITER_FENCE_LOCK_CHIRHO,
};
use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

// This entire module is cfg(test). Production birth obtains this coordinate from the live
// generation guard; the synthetic A6 bridge has no runtime elector at construction time.
const TEST_ONLY_INITIAL_CURRENT_WINNER_TERM_CHIRHO: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ElectedLedgerAuthorityRefusalChirho {
    RootGroupMismatchChirho {
        expected_group_chirho: ConsistencyGroupIdChirho,
        actual_group_chirho: ConsistencyGroupIdChirho,
    },
    StorageOutsideSelectedRootChirho,
    ResidentIdentityRefusedChirho {
        detail_chirho: String,
    },
    ExistingJournalWithoutVerifiedPendingIdentityChirho,
    PendingJournalNotPristineChirho {
        tail_seq_chirho: u64,
        current_epoch_chirho: u64,
        opening_epoch_chirho: u64,
    },
    ResidentGenesisMismatchChirho,
    ResidentNodeIdentityMismatchChirho {
        bound_node_chirho: NodeIdChirho,
        elector_node_chirho: NodeIdChirho,
    },
    OpeningMembershipEpochMismatchChirho {
        journal_epoch_chirho: u64,
        membership_epoch_chirho: u64,
    },
    NotLocalLeaderChirho,
    LeaderIdentityMismatchChirho {
        expected_node_chirho: NodeIdChirho,
        actual_node_chirho: Option<NodeIdChirho>,
    },
    LeaseInvalidChirho,
    InvalidTermChirho {
        term_chirho: u64,
    },
    LeadershipChangedChirho {
        approved_chirho: LeadershipChirho,
        revalidated_chirho: LeadershipChirho,
    },
    FenceTermMismatchChirho {
        leadership_term_chirho: u64,
        fence_term_chirho: u64,
    },
    JournalAheadOfFenceChirho {
        journal_epoch_chirho: u64,
        fence_epoch_chirho: u64,
    },
    MembershipAheadOfFenceChirho {
        membership_epoch_chirho: u64,
        fence_epoch_chirho: u64,
    },
    JournalCompositionRefusedChirho {
        detail_chirho: String,
    },
    JournalMutationRefusedChirho {
        detail_chirho: String,
    },
}

impl fmt::Display for ElectedLedgerAuthorityRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootGroupMismatchChirho { .. } => {
                formatter_chirho.write_str("elected bridge root and consistency group differ")
            }
            Self::StorageOutsideSelectedRootChirho => formatter_chirho
                .write_str("ledger storage namespace is outside the selected authority root"),
            Self::ResidentIdentityRefusedChirho { detail_chirho } => {
                // Same fix as its resident-layer twin, and for the same reason: a wrapper that
                // discards the wrapped cause turns every distinct identity failure into one
                // sentence, one layer before an operator ever sees it.
                write!(
                    formatter_chirho,
                    "resident ledger identity was refused: {detail_chirho}"
                )
            }
            Self::ExistingJournalWithoutVerifiedPendingIdentityChirho => formatter_chirho
                .write_str("existing journal lacks an exact prior verified Pending identity"),
            Self::PendingJournalNotPristineChirho { .. } => {
                formatter_chirho.write_str("Pending resident identity names a non-pristine journal")
            }
            Self::ResidentGenesisMismatchChirho => formatter_chirho
                .write_str("resident Bound identity and verified journal genesis differ"),
            Self::ResidentNodeIdentityMismatchChirho { .. } => {
                formatter_chirho.write_str("resident identity node and elected local node differ")
            }
            Self::OpeningMembershipEpochMismatchChirho { .. } => formatter_chirho
                .write_str("journal and elected membership epochs differ at host binding"),
            Self::NotLocalLeaderChirho => {
                formatter_chirho.write_str("local node is not the elected writer")
            }
            Self::LeaderIdentityMismatchChirho { .. } => formatter_chirho
                .write_str("elected leader identity does not match the local elector identity"),
            Self::LeaseInvalidChirho => {
                formatter_chirho.write_str("elected writer quorum lease is not valid")
            }
            Self::InvalidTermChirho { term_chirho } => {
                write!(
                    formatter_chirho,
                    "elected writer term {term_chirho} is invalid"
                )
            }
            Self::LeadershipChangedChirho { .. } => formatter_chirho
                .write_str("elected leadership changed before the final sink mutation"),
            Self::FenceTermMismatchChirho { .. } => {
                formatter_chirho.write_str("durable fence term differs from elected leadership")
            }
            Self::JournalAheadOfFenceChirho { .. } => {
                formatter_chirho.write_str("journal epoch is ahead of the durable elected fence")
            }
            Self::MembershipAheadOfFenceChirho { .. } => {
                formatter_chirho.write_str("membership epoch is ahead of the durable elected fence")
            }
            Self::JournalCompositionRefusedChirho { .. } => {
                formatter_chirho.write_str("elected host journal composition was refused")
            }
            Self::JournalMutationRefusedChirho { .. } => {
                formatter_chirho.write_str("elected journal mutation was refused")
            }
        }
    }
}

impl Error for ElectedLedgerAuthorityRefusalChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectedAppendReceiptChirho {
    pub append_chirho: AppendReceiptChirho,
    pub fence_chirho: WriterFenceTokenChirho,
    pub leadership_chirho: LeadershipChirho,
}

/// The one host-owned elected journal composition. Construction wires concrete local adapters and
/// permanently binds their journal to one canonical authority root, one group, and one membership
/// object. Callers never pass a journal or trait-object port into the append lock.
pub(crate) struct ElectedLedgerHostJournalChirho<'ports_chirho> {
    canonical_root_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    local_node_chirho: NodeIdChirho,
    membership_chirho: &'ports_chirho ElectedClusterMembershipChirho,
    journal_chirho: Option<LedgerJournalChirho<'ports_chirho>>,
    resident_lease_chirho: Option<ResidentWriterLeaseChirho>,
    _authority_root_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
    _storage_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
}

/// Exact concrete local journal ports for the elected final sink. Keeping this bundle private to the
/// host crate prevents a network/provider adapter from replacing a journal port. The test bridge's
/// generic elector is a separate activation blocker and must become a sealed local snapshot.
#[derive(Clone, Copy)]
pub(crate) struct ElectedLedgerLocalPortsChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho crate::storage_chirho::FsLedgerStorageChirho,
    pub signer_chirho: &'ports_chirho crate::signer_chirho::RoleBoundLedgerSignerChirho,
    pub clock_chirho: &'ports_chirho crate::clock_chirho::SystemLedgerClockChirho,
    pub membership_chirho: &'ports_chirho crate::authority_chirho::ElectedClusterMembershipChirho,
    pub kind_registry_chirho:
        &'ports_chirho cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho,
    pub authority_chirho:
        &'ports_chirho crate::authority_chirho::PlatformPolicyMintAuthorityChirho<'ports_chirho>,
}

#[cfg(test)]
std::thread_local! {
    static RESIDENT_POST_VERIFICATION_TEST_HOOK_CHIRHO:
        RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn install_resident_post_verification_test_hook_chirho(
    hook_chirho: impl FnOnce() + 'static,
) {
    RESIDENT_POST_VERIFICATION_TEST_HOOK_CHIRHO.with(|slot_chirho| {
        assert!(
            slot_chirho.borrow().is_none(),
            "resident post-verification test hook must be installed at most once"
        );
        *slot_chirho.borrow_mut() = Some(Box::new(hook_chirho));
    });
}

#[cfg(test)]
fn run_resident_post_verification_test_hook_chirho() {
    let hook_chirho = RESIDENT_POST_VERIFICATION_TEST_HOOK_CHIRHO
        .with(|slot_chirho| slot_chirho.borrow_mut().take());
    if let Some(hook_chirho) = hook_chirho {
        hook_chirho();
    }
}

impl<'ports_chirho> ElectedLedgerHostJournalChirho<'ports_chirho> {
    pub(crate) fn create_chirho(
        root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        ports_chirho: ElectedLedgerLocalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        cluster_id_chirho: ClusterIdChirho,
        opening_epoch_chirho: u64,
        local_node_chirho: NodeIdChirho,
    ) -> Result<Self> {
        let canonical_root_chirho =
            bind_storage_root_chirho(root_chirho, &group_chirho, ports_chirho.storage_chirho)?;
        let authority_root_snapshot_chirho =
            StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&canonical_root_chirho)?;
        let storage_snapshot_chirho = ports_chirho
            .storage_chirho
            .stable_namespace_snapshot_chirho()?;
        if ports_chirho.membership_chirho.current_epoch_chirho() != opening_epoch_chirho {
            return Err(
                ElectedLedgerAuthorityRefusalChirho::OpeningMembershipEpochMismatchChirho {
                    journal_epoch_chirho: opening_epoch_chirho,
                    membership_epoch_chirho: ports_chirho.membership_chirho.current_epoch_chirho(),
                }
                .into(),
            );
        }
        let membership_chirho = ports_chirho.membership_chirho;
        let identity_source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &canonical_root_chirho,
            authority_root_snapshot_chirho: &authority_root_snapshot_chirho,
            group_chirho: &group_chirho,
            storage_chirho: ports_chirho.storage_chirho,
            storage_snapshot_chirho: &storage_snapshot_chirho,
            identity_storage_namespace_chirho: ports_chirho.storage_chirho.namespace_root_chirho(),
            journal_path_chirho: &path_chirho,
            cluster_id_chirho: &cluster_id_chirho,
            opening_epoch_chirho,
            local_node_chirho: &local_node_chirho,
        };
        let journal_ports_chirho = journal_ports_chirho(ports_chirho);
        let identity_path_chirho = resident_writer_identity_path_chirho(&canonical_root_chirho)
            .map_err(resident_identity_refusal_chirho)?;
        let (pending_identity_chirho, prepared_genesis_chirho) = match std::fs::symlink_metadata(
            &identity_path_chirho,
        ) {
            Ok(_metadata_chirho) => {
                let inspection_chirho =
                    inspect_resident_writer_identity_chirho(&canonical_root_chirho)
                        .map_err(resident_identity_refusal_chirho)?;
                if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO
                {
                    return Err(resident_identity_refusal_chirho(anyhow::anyhow!(
                        "ResidentLedgerIdentityKindMismatchChirho"
                    ))
                    .into());
                }
                let verified_pending_chirho = verify_pending_identity_chirho(
                    inspection_chirho.canonical_identity_chirho(),
                    identity_source_chirho,
                )
                .map_err(resident_identity_refusal_chirho)?;
                let prepared_genesis_chirho = LedgerJournalChirho::verify_prepared_genesis_chirho(
                    journal_ports_chirho,
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
            }
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
                if ports_chirho
                    .storage_chirho
                    .exists_chirho(&path_chirho)
                    .map_err(|error_chirho| {
                        ElectedLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                            detail_chirho: error_chirho.to_string(),
                        }
                    })?
                {
                    return Err(ElectedLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho.into());
                }
                let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
                    journal_ports_chirho,
                    cluster_id_chirho.clone(),
                    opening_epoch_chirho,
                )
                .map_err(journal_composition_refusal_chirho)?;
                let pending_identity_chirho = canonical_pending_identity_chirho(
                    identity_source_chirho,
                    &prepared_genesis_chirho,
                )
                .map_err(resident_identity_refusal_chirho)?;
                (pending_identity_chirho, prepared_genesis_chirho)
            }
            Err(error_chirho) => {
                return Err(resident_identity_refusal_chirho(error_chirho.into()).into());
            }
        };
        let pending_binding_chirho = ResidentWriterBindingChirho {
            root_chirho: &canonical_root_chirho,
            identity_kind_chirho: RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
            canonical_identity_chirho: &pending_identity_chirho,
        };
        let (provisioning_chirho, reservation_outcome_chirho) =
            reserve_resident_writer_chirho(&pending_binding_chirho)
                .map_err(resident_identity_refusal_chirho)?;
        let journal_exists_chirho = ports_chirho
            .storage_chirho
            .exists_chirho(&path_chirho)
            .map_err(|error_chirho| {
                ElectedLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        let recovered_pending_chirho = matches!(
            reservation_outcome_chirho,
            ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho
        );
        if journal_exists_chirho && !recovered_pending_chirho {
            return Err(ElectedLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho.into());
        }
        if !journal_exists_chirho {
            let created_chirho = LedgerJournalChirho::create_prepared_chirho(
                journal_ports_chirho,
                path_chirho.clone(),
                prepared_genesis_chirho.clone(),
            )
            .map_err(journal_composition_refusal_chirho)?;
            drop(created_chirho);
        }
        let mut expected_genesis_bytes_chirho = prepared_genesis_chirho
            .canonical_line_chirho()
            .as_bytes()
            .to_vec();
        expected_genesis_bytes_chirho.push(b'\n');
        if !exact_resident_genesis_bytes_chirho(
            ports_chirho.storage_chirho,
            &path_chirho,
            &expected_genesis_bytes_chirho,
        )
        .map_err(|error_chirho| {
            ElectedLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })? {
            return Err(ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho.into());
        }
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            journal_ports_chirho,
            path_chirho.clone(),
            &cluster_id_chirho,
        )
        .map_err(journal_composition_refusal_chirho)?;
        #[cfg(test)]
        run_resident_post_verification_test_hook_chirho();
        if !exact_resident_genesis_bytes_chirho(
            ports_chirho.storage_chirho,
            &path_chirho,
            &expected_genesis_bytes_chirho,
        )
        .map_err(|error_chirho| {
            ElectedLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })? {
            return Err(ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho.into());
        }
        if journal_chirho.genesis_digest_chirho() != prepared_genesis_chirho.digest_chirho() {
            return Err(ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho.into());
        }
        if journal_chirho.tail_seq_chirho() != 0
            || journal_chirho.current_epoch_chirho() != opening_epoch_chirho
        {
            return Err(
                ElectedLedgerAuthorityRefusalChirho::PendingJournalNotPristineChirho {
                    tail_seq_chirho: journal_chirho.tail_seq_chirho(),
                    current_epoch_chirho: journal_chirho.current_epoch_chirho(),
                    opening_epoch_chirho,
                }
                .into(),
            );
        }
        let authority_storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho)?;
        let writer_lock_path_chirho =
            StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
        let mut writer_lock_chirho = authority_storage_chirho
            .provision_exclusive_lock_handle_chirho(&writer_lock_path_chirho)?;
        let writer_lock_guard_chirho = writer_lock_chirho.try_acquire_chirho()?;
        let sink_term_cell_birth_chirho =
            create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
                &group_chirho,
                TEST_ONLY_INITIAL_CURRENT_WINNER_TERM_CHIRHO,
                &writer_lock_guard_chirho,
                reservation_outcome_chirho,
            )?;
        let bound_identity_chirho = canonical_bound_identity_chirho(
            identity_source_chirho,
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
            .map_err(resident_identity_refusal_chirho)?;
        Ok(Self {
            canonical_root_chirho,
            group_chirho,
            local_node_chirho,
            membership_chirho,
            journal_chirho: Some(journal_chirho),
            resident_lease_chirho: Some(resident_lease_chirho),
            _authority_root_snapshot_chirho: authority_root_snapshot_chirho,
            _storage_snapshot_chirho: storage_snapshot_chirho,
        })
    }

    pub(crate) fn open_chirho(
        root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        ports_chirho: ElectedLedgerLocalPortsChirho<'ports_chirho>,
        path_chirho: StoragePathChirho,
        expected_cluster_chirho: &ClusterIdChirho,
        expected_opening_epoch_chirho: u64,
        local_node_chirho: NodeIdChirho,
    ) -> Result<Self> {
        let canonical_root_chirho =
            bind_storage_root_chirho(root_chirho, &group_chirho, ports_chirho.storage_chirho)?;
        let authority_root_snapshot_chirho =
            StableLedgerNamespaceSnapshotChirho::acquire_existing_chirho(&canonical_root_chirho)?;
        let storage_snapshot_chirho = ports_chirho
            .storage_chirho
            .stable_namespace_snapshot_chirho()?;
        let identity_source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &canonical_root_chirho,
            authority_root_snapshot_chirho: &authority_root_snapshot_chirho,
            group_chirho: &group_chirho,
            storage_chirho: ports_chirho.storage_chirho,
            storage_snapshot_chirho: &storage_snapshot_chirho,
            identity_storage_namespace_chirho: ports_chirho.storage_chirho.namespace_root_chirho(),
            journal_path_chirho: &path_chirho,
            cluster_id_chirho: expected_cluster_chirho,
            opening_epoch_chirho: expected_opening_epoch_chirho,
            local_node_chirho: &local_node_chirho,
        };
        let inspection_chirho = inspect_resident_writer_identity_chirho(&canonical_root_chirho)
            .map_err(resident_identity_refusal_chirho)?;
        if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO {
            return Err(resident_identity_refusal_chirho(anyhow::anyhow!(
                "ResidentLedgerIdentityKindMismatchChirho"
            ))
            .into());
        }
        let verified_identity_chirho = verify_bound_identity_chirho(
            inspection_chirho.canonical_identity_chirho(),
            identity_source_chirho,
        )
        .map_err(resident_identity_refusal_chirho)?;
        let resident_lease_chirho =
            open_resident_writer_chirho(&inspection_chirho.as_binding_chirho())
                .map_err(resident_identity_refusal_chirho)?;
        let membership_chirho = ports_chirho.membership_chirho;
        let journal_chirho = LedgerJournalChirho::open_read_only_chirho(
            journal_ports_chirho(ports_chirho),
            path_chirho,
            expected_cluster_chirho,
        )
        .map_err(journal_composition_refusal_chirho)?;
        if journal_chirho.genesis_digest_chirho()
            != verified_identity_chirho.verified_genesis_digest_chirho()
        {
            return Err(ElectedLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho.into());
        }
        let journal_epoch_chirho = journal_chirho.current_epoch_chirho();
        let membership_epoch_chirho = membership_chirho.current_epoch_chirho();
        if membership_epoch_chirho > journal_epoch_chirho {
            return Err(
                ElectedLedgerAuthorityRefusalChirho::OpeningMembershipEpochMismatchChirho {
                    journal_epoch_chirho,
                    membership_epoch_chirho,
                }
                .into(),
            );
        }
        membership_chirho.rebind_epoch_chirho(journal_epoch_chirho)?;
        Ok(Self {
            canonical_root_chirho,
            group_chirho,
            local_node_chirho,
            membership_chirho,
            journal_chirho: Some(journal_chirho),
            resident_lease_chirho: Some(resident_lease_chirho),
            _authority_root_snapshot_chirho: authority_root_snapshot_chirho,
            _storage_snapshot_chirho: storage_snapshot_chirho,
        })
    }

    pub(crate) fn journal_ref_chirho(&self) -> &LedgerJournalChirho<'ports_chirho> {
        self.journal_chirho
            .as_ref()
            .expect("resident host must retain its journal until drop")
    }

    fn journal_mut_ref_chirho(&mut self) -> &mut LedgerJournalChirho<'ports_chirho> {
        self.journal_chirho
            .as_mut()
            .expect("resident host must retain its journal until drop")
    }

    #[cfg(test)]
    pub(crate) fn journal_mut_chirho(&mut self) -> &mut LedgerJournalChirho<'ports_chirho> {
        self.journal_mut_ref_chirho()
    }
}

impl Drop for ElectedLedgerHostJournalChirho<'_> {
    fn drop(&mut self) {
        drop(self.journal_chirho.take());
        drop(self.resident_lease_chirho.take());
    }
}

fn journal_ports_chirho<'ports_chirho>(
    ports_chirho: ElectedLedgerLocalPortsChirho<'ports_chirho>,
) -> JournalPortsChirho<'ports_chirho> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

fn exact_resident_genesis_bytes_chirho(
    storage_chirho: &FsLedgerStorageChirho,
    path_chirho: &StoragePathChirho,
    expected_bytes_chirho: &[u8],
) -> Result<bool> {
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
) -> ElectedLedgerAuthorityRefusalChirho {
    ElectedLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
        detail_chirho: format!("{error_chirho:?}"),
    }
}

fn resident_identity_refusal_chirho(
    error_chirho: anyhow::Error,
) -> ElectedLedgerAuthorityRefusalChirho {
    ElectedLedgerAuthorityRefusalChirho::ResidentIdentityRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

fn bind_storage_root_chirho(
    root_chirho: &Path,
    group_chirho: &ConsistencyGroupIdChirho,
    storage_chirho: &FsLedgerStorageChirho,
) -> Result<PathBuf> {
    let canonical_root_chirho = root_chirho.canonicalize()?;
    let actual_group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
    if actual_group_chirho != *group_chirho {
        return Err(
            ElectedLedgerAuthorityRefusalChirho::RootGroupMismatchChirho {
                expected_group_chirho: group_chirho.clone(),
                actual_group_chirho,
            }
            .into(),
        );
    }
    let storage_root_chirho = storage_chirho.namespace_root_chirho();
    if storage_root_chirho == canonical_root_chirho
        || !storage_root_chirho.starts_with(&canonical_root_chirho)
    {
        return Err(ElectedLedgerAuthorityRefusalChirho::StorageOutsideSelectedRootChirho.into());
    }
    Ok(canonical_root_chirho)
}

/// A resident, one-group bridge. Its cached token makes the steady-state fence check one bounded
/// per-group read rather than another durable fence write; the journal append remains the one
/// durable write.
pub(crate) struct ElectedLedgerAuthorityBridgeChirho<
    'bridge_chirho,
    'ports_chirho,
    ElectorChirho: WriterElectorChirho + ?Sized,
> {
    sink_chirho: &'bridge_chirho mut ElectedLedgerHostJournalChirho<'ports_chirho>,
    elector_chirho: &'bridge_chirho ElectorChirho,
    active_fence_chirho: Option<WriterFenceTokenChirho>,
}

impl<'bridge_chirho, 'ports_chirho, ElectorChirho: WriterElectorChirho + ?Sized>
    ElectedLedgerAuthorityBridgeChirho<'bridge_chirho, 'ports_chirho, ElectorChirho>
{
    pub(crate) fn new_chirho(
        sink_chirho: &'bridge_chirho mut ElectedLedgerHostJournalChirho<'ports_chirho>,
        elector_chirho: &'bridge_chirho ElectorChirho,
    ) -> Self {
        Self {
            sink_chirho,
            elector_chirho,
            active_fence_chirho: None,
        }
    }

    /// Append through the exact elected fence and final journal admission sink.
    ///
    /// See `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md`
    /// section 4. The second leadership read occurs while the local group-fence lock is held. The
    /// closure accepts no caller callback or caller-supplied journal ports. A production composition
    /// must additionally seal the elector to the reviewed local-read implementation before activation.
    pub(crate) fn append_chirho(
        &mut self,
        request_chirho: AppendRequestChirho,
    ) -> Result<ElectedAppendReceiptChirho> {
        let root_chirho = self.sink_chirho.canonical_root_chirho.clone();
        let group_chirho = self.sink_chirho.group_chirho.clone();
        if self.elector_chirho.node_id_chirho() != &self.sink_chirho.local_node_chirho {
            return Err(
                ElectedLedgerAuthorityRefusalChirho::ResidentNodeIdentityMismatchChirho {
                    bound_node_chirho: self.sink_chirho.local_node_chirho.clone(),
                    elector_node_chirho: self.elector_chirho.node_id_chirho().clone(),
                }
                .into(),
            );
        }
        let approved_chirho = self.elector_chirho.leadership_chirho(&group_chirho);
        validate_local_leadership_chirho(self.elector_chirho, &approved_chirho)?;

        let observed_fence_chirho = RefCell::new(None);
        let elector_chirho = self.elector_chirho;
        let sink_chirho = &mut *self.sink_chirho;
        let result_chirho = with_reused_or_issued_elected_writer_fence_chirho(
            &root_chirho,
            &group_chirho,
            approved_chirho.term_chirho,
            self.active_fence_chirho.as_ref(),
            |fence_chirho| {
                observed_fence_chirho.replace(Some(fence_chirho.clone()));
                let revalidated_chirho = elector_chirho.leadership_chirho(&group_chirho);
                if revalidated_chirho != approved_chirho {
                    return Err(
                        ElectedLedgerAuthorityRefusalChirho::LeadershipChangedChirho {
                            approved_chirho: approved_chirho.clone(),
                            revalidated_chirho,
                        }
                        .into(),
                    );
                }

                let fence_term_chirho =
                    u64::from(split_writer_epoch_chirho(fence_chirho.epoch_chirho).geo_term_chirho);
                if fence_term_chirho != approved_chirho.term_chirho {
                    return Err(
                        ElectedLedgerAuthorityRefusalChirho::FenceTermMismatchChirho {
                            leadership_term_chirho: approved_chirho.term_chirho,
                            fence_term_chirho,
                        }
                        .into(),
                    );
                }

                let journal_epoch_chirho = sink_chirho.journal_ref_chirho().current_epoch_chirho();
                if journal_epoch_chirho > fence_chirho.epoch_chirho {
                    return Err(
                        ElectedLedgerAuthorityRefusalChirho::JournalAheadOfFenceChirho {
                            journal_epoch_chirho,
                            fence_epoch_chirho: fence_chirho.epoch_chirho,
                        }
                        .into(),
                    );
                }
                let membership_epoch_chirho = sink_chirho.membership_chirho.current_epoch_chirho();
                if membership_epoch_chirho > fence_chirho.epoch_chirho {
                    return Err(
                        ElectedLedgerAuthorityRefusalChirho::MembershipAheadOfFenceChirho {
                            membership_epoch_chirho,
                            fence_epoch_chirho: fence_chirho.epoch_chirho,
                        }
                        .into(),
                    );
                }
                if journal_epoch_chirho < fence_chirho.epoch_chirho {
                    sink_chirho
                        .journal_mut_ref_chirho()
                        .advance_epoch_chirho(fence_chirho.epoch_chirho)
                        .map_err(|error_chirho| {
                            ElectedLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho {
                                detail_chirho: format!("{error_chirho:?}"),
                            }
                        })?;
                }
                sink_chirho
                    .membership_chirho
                    .rebind_epoch_chirho(fence_chirho.epoch_chirho)?;
                sink_chirho
                    .journal_mut_ref_chirho()
                    .append_chirho(request_chirho)
                    .map_err(|error_chirho| {
                        ElectedLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho {
                            detail_chirho: format!("{error_chirho:?}"),
                        }
                        .into()
                    })
            },
        );

        if let Some(fence_chirho) = observed_fence_chirho.into_inner() {
            self.active_fence_chirho = Some(fence_chirho);
        }
        let (fence_chirho, append_chirho) = result_chirho?;
        Ok(ElectedAppendReceiptChirho {
            append_chirho,
            fence_chirho,
            leadership_chirho: approved_chirho,
        })
    }

    #[cfg(test)]
    pub(crate) fn active_fence_chirho(&self) -> Option<&WriterFenceTokenChirho> {
        self.active_fence_chirho.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn journal_chirho(&self) -> &LedgerJournalChirho<'ports_chirho> {
        self.sink_chirho.journal_ref_chirho()
    }
}

fn validate_local_leadership_chirho<ElectorChirho: WriterElectorChirho + ?Sized>(
    elector_chirho: &ElectorChirho,
    leadership_chirho: &LeadershipChirho,
) -> Result<()> {
    if !leadership_chirho.is_leader_chirho {
        return Err(ElectedLedgerAuthorityRefusalChirho::NotLocalLeaderChirho.into());
    }
    if leadership_chirho.leader_id_chirho.as_ref() != Some(elector_chirho.node_id_chirho()) {
        return Err(
            ElectedLedgerAuthorityRefusalChirho::LeaderIdentityMismatchChirho {
                expected_node_chirho: elector_chirho.node_id_chirho().clone(),
                actual_node_chirho: leadership_chirho.leader_id_chirho.clone(),
            }
            .into(),
        );
    }
    if !leadership_chirho.lease_valid_chirho {
        return Err(ElectedLedgerAuthorityRefusalChirho::LeaseInvalidChirho.into());
    }
    if leadership_chirho.term_chirho == 0
        || leadership_chirho.term_chirho > WRITER_EPOCH_COMPONENT_MAX_CHIRHO
    {
        return Err(ElectedLedgerAuthorityRefusalChirho::InvalidTermChirho {
            term_chirho: leadership_chirho.term_chirho,
        }
        .into());
    }
    Ok(())
}
