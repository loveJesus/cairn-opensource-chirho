// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho;

impl<'ports_chirho> ResidentLedgerAuthorityChirho<'ports_chirho> {
    pub(crate) fn open_bound_serving_chirho(
        root_chirho: &Path,
        ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
        journal_path_chirho: StoragePathChirho,
        expected_cluster_chirho: ClusterIdChirho,
        expected_opening_epoch_chirho: u64,
        local_authority_chirho: LocalAppendAuthorityHandleChirho,
    ) -> Result<Self, ResidentLedgerAuthorityRefusalChirho> {
        Self::open_bound_preactivation_chirho(
            root_chirho,
            ports_chirho,
            journal_path_chirho,
            expected_cluster_chirho,
            expected_opening_epoch_chirho,
            local_authority_chirho,
        )
    }

    /// Open an existing exact Bound resident without creating, repairing, fencing, or appending.
    pub fn open_bound_preactivation_chirho(
        root_chirho: &Path,
        ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
        journal_path_chirho: StoragePathChirho,
        expected_cluster_chirho: ClusterIdChirho,
        expected_opening_epoch_chirho: u64,
        local_authority_chirho: LocalAppendAuthorityHandleChirho,
    ) -> Result<Self, ResidentLedgerAuthorityRefusalChirho> {
        let canonical_root_chirho = root_chirho
            .canonicalize()
            .map_err(|error_chirho| stable_namespace_refusal_chirho(error_chirho.into()))?;
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

        let initial_guard_chirho =
            acquire_resident_startup_generation_chirho(&local_authority_chirho)
                .map_err(local_generation_refusal_chirho)?;
        let initial_generation_chirho = initial_guard_chirho.process_generation_chirho();
        let initial_term_chirho = initial_guard_chirho.published_raft_term_chirho();
        drop(initial_guard_chirho);

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
        let writer_lock_path_chirho =
            StoragePathChirho::new_chirho(named_lock_storage_key_chirho(WRITER_FENCE_LOCK_CHIRHO));
        let mut writer_lock_chirho = authority_storage_chirho
            .open_existing_exclusive_lock_handle_chirho(&writer_lock_path_chirho)
            .map_err(writer_fence_refusal_chirho)?;
        let storage_snapshot_chirho = ports_chirho
            .storage_chirho
            .stable_namespace_snapshot_chirho()
            .map_err(stable_namespace_refusal_chirho)?;
        let source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &canonical_root_chirho,
            authority_root_snapshot_chirho: &authority_root_snapshot_chirho,
            group_chirho: &group_chirho,
            storage_chirho: ports_chirho.storage_chirho,
            storage_snapshot_chirho: &storage_snapshot_chirho,
            identity_storage_namespace_chirho: storage_root_chirho,
            journal_path_chirho: &journal_path_chirho,
            cluster_id_chirho: &expected_cluster_chirho,
            opening_epoch_chirho: expected_opening_epoch_chirho,
            local_node_chirho: &local_node_chirho,
        };
        let inspection_chirho =
            try_inspect_resident_writer_identity_in_custody_chirho(&resident_root_custody_chirho)
                .map_err(resident_identity_refusal_chirho)?
                .ok_or_else(|| {
                    resident_identity_refusal_chirho(anyhow::anyhow!(
                        "ResidentWriterIdentityMissingOrUnreadableChirho"
                    ))
                })?;
        let (verified_identity_chirho, legacy_v3_chirho) =
            match inspection_chirho.identity_kind_chirho() {
                RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO => (
                    verify_bound_identity_chirho(
                        inspection_chirho.canonical_identity_chirho(),
                        source_chirho,
                    )
                    .map_err(current_bound_identity_refusal_chirho)?,
                    false,
                ),
                RESIDENT_LEDGER_LEGACY_V3_IDENTITY_KIND_CHIRHO => (
                    verify_legacy_v3_bound_identity_chirho(
                        inspection_chirho.canonical_identity_chirho(),
                        source_chirho,
                    )
                    .map_err(resident_identity_refusal_chirho)?,
                    true,
                ),
                _ => {
                    return Err(
                        ResidentLedgerAuthorityRefusalChirho::ResidentIdentityKindMismatchChirho,
                    );
                }
            };
        let resident_identity_digest_chirho = inspection_chirho.identity_digest_chirho().to_owned();
        let resident_lease_chirho = inspection_chirho
            .open_exact_chirho()
            .map_err(resident_lease_refusal_chirho)?;
        if resident_lease_chirho.identity_digest_chirho() != resident_identity_digest_chirho {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        let final_guard_chirho =
            acquire_resident_startup_generation_chirho(&local_authority_chirho)
                .map_err(local_generation_refusal_chirho)?;
        let observed_generation_chirho = final_guard_chirho.process_generation_chirho();
        let observed_term_chirho = final_guard_chirho.published_raft_term_chirho();
        if observed_generation_chirho != initial_generation_chirho
            || observed_term_chirho != initial_term_chirho
        {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::LocalGenerationChangedChirho {
                    initial_generation_chirho,
                    observed_generation_chirho,
                    initial_term_chirho,
                    observed_term_chirho,
                },
            );
        }
        if legacy_v3_chirho {
            let writer_lock_guard_chirho = writer_lock_chirho
                .try_acquire_chirho()
                .map_err(writer_fence_refusal_chirho)?;
            return Err(ResidentLedgerAuthorityRefusalChirho::from(
                legacy_bound_resident_sink_term_cell_refusal_chirho(
                    &group_chirho,
                    &writer_lock_guard_chirho,
                ),
            ));
        }
        let expected_genesis_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
            verified_identity_chirho.verified_genesis_line_chirho(),
            verified_identity_chirho
                .verified_genesis_digest_chirho()
                .clone(),
        )
        .map_err(|error_chirho| expected_genesis_refusal_chirho(format!("{error_chirho:?}")))?;
        let journal_chirho = LedgerJournalChirho::open_read_only_with_expected_genesis_chirho(
            journal_ports_chirho(ports_chirho),
            journal_path_chirho.clone(),
            &expected_genesis_chirho,
        )
        .map_err(expected_genesis_open_refusal_chirho)?;
        if journal_chirho.genesis_digest_chirho()
            != verified_identity_chirho.verified_genesis_digest_chirho()
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho);
        }

        let writer_lock_guard_chirho = writer_lock_chirho
            .try_acquire_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        let signed_birth_term_chirho = verified_identity_chirho
            .sink_term_fence_birth_term_chirho()
            .map_err(|_reason_chirho| {
                ResidentLedgerAuthorityRefusalChirho::from(
                    ResidentSinkTermCellRefusalChirho::CurrentBoundIdentityMissingSignedBirthTermChirho,
                )
            })?;
        verify_resident_sink_term_cell_for_bound_open_chirho(
            &group_chirho,
            signed_birth_term_chirho,
            &final_guard_chirho,
            &writer_lock_guard_chirho,
        )
        .map_err(ResidentLedgerAuthorityRefusalChirho::from)?;
        authority_root_snapshot_chirho
            .verify_current_path_chirho(&canonical_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        storage_snapshot_chirho
            .verify_current_path_chirho(storage_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        validate_epoch_posture_chirho(
            journal_chirho.current_epoch_chirho(),
            ports_chirho.membership_chirho.current_epoch_chirho(),
            observed_term_chirho,
        )?;
        drop(writer_lock_guard_chirho);
        drop(final_guard_chirho);

        Ok(Self {
            canonical_root_chirho,
            identity_storage_namespace_chirho: storage_root_chirho.to_path_buf(),
            group_chirho,
            local_node_chirho,
            journal_path_chirho,
            cluster_id_chirho: expected_cluster_chirho,
            opening_epoch_chirho: expected_opening_epoch_chirho,
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
        })
    }

    pub(super) fn install_mirror_runtime_chirho(
        &mut self,
        append_mirror_chirho: Arc<dyn LedgerAppendMirrorPortChirho>,
        ordinary_term_acceptance_source_chirho: Arc<
            dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
        >,
        ordinary_term_acceptance_placement_binding_chirho: LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
    ) {
        let journal_chirho = self
            .journal_chirho
            .take()
            .expect("resident authority retains its journal before mirror composition");
        self.journal_chirho = Some(journal_chirho.with_append_mirror_chirho(append_mirror_chirho));
        self.ordinary_term_acceptance_source_chirho = Some(ordinary_term_acceptance_source_chirho);
        self.ordinary_term_acceptance_placement_binding_chirho =
            Some(ordinary_term_acceptance_placement_binding_chirho);
    }

    /// Revalidate fixed local authority and bounded resident identity evidence without history scan.
    pub(crate) fn gd7_obligation_processing_storage_chirho(&self) -> &FsLedgerStorageChirho {
        &self.authority_storage_chirho
    }

    pub fn probe_chirho(
        &self,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        let local_authority_chirho = self.local_authority_chirho.clone();
        let generation_guard_chirho = local_authority_chirho
            .try_acquire_chirho()
            .map_err(local_generation_refusal_chirho)?;
        self.probe_under_generation_chirho(
            &self.group_chirho,
            &self.local_node_chirho,
            generation_guard_chirho.process_generation_chirho(),
            generation_guard_chirho.published_raft_term_chirho(),
        )
    }

    pub(crate) fn probe_during_handoff_preparation_chirho(
        &self,
        preparation_chirho: &LocalAppendHandoffPreparationChirho<'_>,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_under_generation_chirho(
            preparation_chirho.consistency_group_chirho(),
            preparation_chirho.node_id_chirho(),
            preparation_chirho.process_generation_chirho(),
            preparation_chirho.published_raft_term_chirho(),
        )
    }

    pub(crate) fn probe_during_handoff_chirho(
        &self,
        handoff_guard_chirho: &LocalAppendHandoffGenerationGuardChirho<'_>,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_under_generation_chirho(
            handoff_guard_chirho.consistency_group_chirho(),
            handoff_guard_chirho.node_id_chirho(),
            handoff_guard_chirho.process_generation_chirho(),
            handoff_guard_chirho.published_raft_term_chirho(),
        )
    }

    pub(crate) fn probe_during_handoff_read_chirho(
        &self,
        handoff_read_chirho: &LocalAppendHandoffReadGenerationChirho,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.probe_under_generation_chirho(
            handoff_read_chirho.consistency_group_chirho(),
            handoff_read_chirho.node_id_chirho(),
            handoff_read_chirho.process_generation_chirho(),
            handoff_read_chirho.published_raft_term_chirho(),
        )
    }

    fn probe_under_generation_chirho(
        &self,
        consistency_group_chirho: &ConsistencyGroupIdChirho,
        local_node_chirho: &NodeIdChirho,
        process_generation_chirho: u64,
        published_raft_term_chirho: u64,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        if consistency_group_chirho != &self.group_chirho
            || local_node_chirho != &self.local_node_chirho
            || process_generation_chirho == 0
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        self.verify_fixed_resident_evidence_chirho()?;
        let journal_chirho = self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal");
        let journal_epoch_chirho = journal_chirho.current_epoch_chirho();
        let membership_epoch_chirho = self.ports_chirho.membership_chirho.current_epoch_chirho();
        validate_epoch_posture_chirho(
            journal_epoch_chirho,
            membership_epoch_chirho,
            published_raft_term_chirho,
        )?;
        Ok(ResidentLedgerAuthorityReadinessChirho {
            consistency_group_chirho: self.group_chirho.clone(),
            local_node_chirho: self.local_node_chirho.clone(),
            process_generation_chirho,
            published_raft_term_chirho,
            journal_epoch_chirho,
            membership_epoch_chirho,
            journal_tail_seq_chirho: journal_chirho.tail_seq_chirho(),
            journal_tail_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
            genesis_digest_chirho: journal_chirho.genesis_digest_chirho().clone(),
            resident_identity_digest_chirho: self.resident_identity_digest_chirho.clone(),
        })
    }

    /// Seal one challenged, content-addressed current-view statement under this exact resident
    /// generation. This creates evidence only; it cannot move a served ref or authorize adoption.
    pub fn seal_gd7_winner_current_view_chirho(
        &self,
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
        bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    ) -> Result<Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho> {
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            &self.canonical_root_chirho,
            &self.local_node_chirho,
        )
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
        seal_gd7_winner_current_view_chirho(
            &self.authority_storage_chirho,
            &signer_chirho,
            &self.local_authority_chirho,
            challenge_chirho,
            bundle_root_chirho,
            || {
                self.verify_fixed_resident_evidence_chirho().map_err(|_| {
                    Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho
                })?;
                Ok(Gd7WinnerJournalSnapshotChirho::from_verified_tail_chirho(
                    self.journal_chirho
                        .as_ref()
                        .expect("resident authority retains its journal")
                        .verified_losing_tail_chirho(),
                ))
            },
        )
        .map(|verified_chirho| verified_chirho.into_inspection_chirho())
    }

    /// Re-seal one exact view while a handoff preparation guard still owns append admission.
    pub(crate) fn seal_gd7_winner_current_view_during_handoff_chirho(
        &self,
        preparation_chirho: &LocalAppendHandoffPreparationChirho<'_>,
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
        bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    ) -> Result<Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho> {
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            &self.canonical_root_chirho,
            &self.local_node_chirho,
        )
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
        seal_gd7_winner_current_view_during_handoff_chirho(
            &self.authority_storage_chirho,
            &signer_chirho,
            preparation_chirho,
            challenge_chirho,
            bundle_root_chirho,
            || {
                self.verify_fixed_resident_evidence_chirho().map_err(|_| {
                    Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho
                })?;
                Ok(Gd7WinnerJournalSnapshotChirho::from_verified_tail_chirho(
                    self.journal_chirho
                        .as_ref()
                        .expect("resident authority retains its journal")
                        .verified_losing_tail_chirho(),
                ))
            },
        )
        .map(|verified_chirho| verified_chirho.into_inspection_chirho())
    }

    /// Stage at most one fixed account-net page for this exact resident generation.
    ///
    /// The only continuation is the opaque token returned by the preceding call. This creates
    /// immutable evidence only; it cannot move a served ref, authorize adoption or compensation,
    /// converge a held node, or re-enable writes.
    pub fn stage_next_gd7_winner_view_bundle_page_chirho(
        &self,
        restart_chirho: Option<&Gd7WinnerViewBundleRestartChirho>,
    ) -> Result<Gd7WinnerViewBundleStageOutcomeChirho, Gd7WinnerCurrentViewRefusalChirho> {
        let journal_chirho = self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal");
        stage_next_gd7_winner_view_bundle_page_chirho(
            &self.authority_storage_chirho,
            &self.local_authority_chirho,
            restart_chirho,
            || {
                self.verify_fixed_resident_evidence_chirho().map_err(|_| {
                    Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho
                })?;
                Ok(Gd7WinnerJournalSnapshotChirho::from_verified_tail_chirho(
                    journal_chirho.verified_losing_tail_chirho(),
                ))
            },
            |cursor_chirho| {
                account_net_projection_page_chirho(
                    &VerifiedSourceStateChirho { journal_chirho },
                    cursor_chirho,
                )
                .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ProjectionChirho)
            },
        )
    }

    pub(crate) fn stage_next_accepted_gd7_winner_history_page_chirho(
        &self,
        handoff_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
        plan_checkpoint_ref_chirho: &str,
        plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
        restart_chirho: Option<&Gd7WinnerHistoryRestartChirho>,
    ) -> Result<Gd7WinnerHistoryStageOutcomeChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        handoff_store_chirho.stage_next_accepted_winner_history_page_chirho(
            plan_checkpoint_ref_chirho,
            plan_checkpoint_chirho,
            held_verifier_chirho,
            self.journal_chirho
                .as_ref()
                .expect("resident authority retains its journal"),
            restart_chirho,
        )
    }

    pub(crate) fn stage_accepted_gd7_fork_baseline_chirho(
        &self,
        handoff_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
        plan_checkpoint_ref_chirho: &str,
        plan_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
        held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ) -> Result<VerifiedGd7ForkBaselineRootChirho, Gd7WinnerHandoffStoreRefusalChirho> {
        handoff_store_chirho.stage_accepted_fork_baseline_chirho(
            plan_checkpoint_ref_chirho,
            plan_checkpoint_chirho,
            held_verifier_chirho,
            journal_ports_chirho(self.ports_chirho),
            &self.journal_path_chirho,
            &self.cluster_id_chirho,
        )
    }

    /// Mint the first recipient-bound page grant from one exact completed bundle root.
    pub(crate) fn issue_first_gd7_winner_view_page_grant_chirho(
        &self,
        held_node_chirho: &NodeIdChirho,
        winner_evidence_object_digest_chirho: &str,
        bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
    ) -> Result<Option<Gd7WinnerViewPageGrantChirho>, Gd7WinnerCurrentViewRefusalChirho> {
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            &self.canonical_root_chirho,
            &self.local_node_chirho,
        )
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
        issue_first_gd7_winner_view_page_grant_chirho(
            &self.authority_storage_chirho,
            &signer_chirho,
            &self.local_authority_chirho,
            held_node_chirho,
            winner_evidence_object_digest_chirho,
            bundle_root_chirho,
            || {
                self.verify_fixed_resident_evidence_chirho()
                    .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho)
            },
        )
    }

    /// Read one exact granted page and mint only its verified higher-page continuation.
    pub(crate) fn fetch_granted_gd7_winner_view_page_chirho(
        &self,
        requester_chirho: &NodeIdChirho,
        winner_evidence_object_digest_chirho: &str,
        bundle_root_chirho: &VerifiedGd7WinnerViewBundleRootChirho,
        grant_chirho: Gd7WinnerViewPageGrantChirho,
    ) -> Result<Gd7WinnerViewPageTransferChirho, Gd7WinnerCurrentViewRefusalChirho> {
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            &self.canonical_root_chirho,
            &self.local_node_chirho,
        )
        .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::SigningChirho)?;
        fetch_granted_gd7_winner_view_page_chirho(
            Gd7WinnerViewPageFetchContextChirho {
                storage_chirho: &self.authority_storage_chirho,
                signer_chirho: &signer_chirho,
                local_authority_chirho: &self.local_authority_chirho,
                requester_chirho,
                winner_evidence_object_digest_chirho,
                bundle_root_chirho,
            },
            grant_chirho,
            || {
                self.verify_fixed_resident_evidence_chirho()
                    .map_err(|_| Gd7WinnerCurrentViewRefusalChirho::ResidentEvidenceChangedChirho)
            },
        )
    }

    pub(crate) fn tail_epoch_first_record_evidence_chirho(
        &self,
    ) -> Result<Option<EpochFirstRecordEvidenceChirho>, ResidentLedgerAuthorityRefusalChirho> {
        self.journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .tail_epoch_first_record_evidence_chirho()
            .map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })
    }

    pub(super) fn probe_for_read_chirho(
        &self,
        handoff_read_chirho: Option<&LocalAppendHandoffReadGenerationChirho>,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        match handoff_read_chirho {
            Some(handoff_read_chirho) => self.probe_during_handoff_read_chirho(handoff_read_chirho),
            None => self.probe_chirho(),
        }
    }

    pub(super) fn verify_fixed_resident_evidence_chirho(
        &self,
    ) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
        if self.local_authority_chirho.consistency_group_chirho() != &self.group_chirho
            || self.local_authority_chirho.node_id_chirho() != &self.local_node_chirho
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        self.authority_root_snapshot_chirho
            .verify_current_path_chirho(&self.canonical_root_chirho)
            .map_err(stable_namespace_refusal_chirho)?;
        self.storage_snapshot_chirho
            .verify_current_path_chirho(self.ports_chirho.storage_chirho.namespace_root_chirho())
            .map_err(stable_namespace_refusal_chirho)?;
        let source_chirho = ResidentLedgerCoordinateSourceChirho {
            root_chirho: &self.canonical_root_chirho,
            authority_root_snapshot_chirho: &self.authority_root_snapshot_chirho,
            group_chirho: &self.group_chirho,
            storage_chirho: self.ports_chirho.storage_chirho,
            storage_snapshot_chirho: &self.storage_snapshot_chirho,
            identity_storage_namespace_chirho: &self.identity_storage_namespace_chirho,
            journal_path_chirho: &self.journal_path_chirho,
            cluster_id_chirho: &self.cluster_id_chirho,
            opening_epoch_chirho: self.opening_epoch_chirho,
            local_node_chirho: &self.local_node_chirho,
        };
        let inspection_chirho = self
            .resident_lease_chirho
            .as_ref()
            .expect("resident authority retains its lifetime lease")
            .inspect_identity_chirho()
            .map_err(resident_identity_refusal_chirho)?;
        if inspection_chirho.identity_kind_chirho() != RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO
            || inspection_chirho.identity_digest_chirho() != self.resident_identity_digest_chirho
            || self
                .resident_lease_chirho
                .as_ref()
                .expect("resident authority retains its lifetime lease")
                .identity_digest_chirho()
                != self.resident_identity_digest_chirho
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho);
        }
        let verified_identity_chirho = verify_bound_identity_chirho(
            inspection_chirho.canonical_identity_chirho(),
            source_chirho,
        )
        .map_err(resident_identity_refusal_chirho)?;
        let journal_chirho = self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal");
        if journal_chirho.genesis_digest_chirho()
            != verified_identity_chirho.verified_genesis_digest_chirho()
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho);
        }
        Ok(())
    }
}
