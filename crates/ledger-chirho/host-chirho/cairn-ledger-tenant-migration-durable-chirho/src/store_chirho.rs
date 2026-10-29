// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::model_chirho::{
    ActiveTenantMigrationChirho, CommittedTenantMigrationChirho, TenantMigrationCheckpointChirho,
    TenantMigrationCommitOutcomeChirho, TenantMigrationControlSignerPortChirho,
    TenantMigrationCutClaimChirho, TenantMigrationHeadChirho,
    TenantMigrationOperationAuthorityBindingChirho, TenantMigrationPhaseChirho,
    TenantMigrationStoreRefusalChirho, MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO,
    MAX_TENANT_MIGRATION_HEAD_BYTES_CHIRHO, TENANT_MIGRATION_CHECKPOINT_SCHEMA_V2_CHIRHO,
    TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO, TENANT_MIGRATION_HEAD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};

const TENANT_MIGRATION_NAMESPACE_CHIRHO: &str = "tenant-migration-control-chirho";
const MAX_TENANT_MIGRATION_LABEL_BYTES_CHIRHO: usize = 512;
const MAX_TENANT_MIGRATION_SIGNATURE_BYTES_CHIRHO: usize = 1024;

/// Node-control-signed immutable migration checkpoints plus one fixed current head.
///
/// Signatures reject corruption, truncation, wrong identity, and operation-retry divergence. They
/// do not stop a durable-store writer from replacing the fixed head with an older validly signed
/// head. Such rollback can deny availability, but startup grants no migration operation authority
/// and operational recovery full-verifies persisted cut requests before use. A non-rewindable head
/// anchor remains an owed substrate brick rather than a property of this store.
pub struct TenantMigrationStoreChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    signer_chirho: &'ports_chirho dyn TenantMigrationControlSignerPortChirho,
    consistency_group_digest_chirho: String,
    source_node_chirho: String,
    head_path_chirho: StoragePathChirho,
}

impl<'ports_chirho> TenantMigrationStoreChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        signer_chirho: &'ports_chirho dyn TenantMigrationControlSignerPortChirho,
        consistency_group_digest_chirho: String,
        source_node_chirho: String,
    ) -> Result<Self, TenantMigrationStoreRefusalChirho> {
        if !valid_label_chirho(&consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&source_node_chirho)
            || signer_chirho.key_id_chirho() != source_node_chirho
        {
            return Err(if signer_chirho.key_id_chirho() != source_node_chirho {
                TenantMigrationStoreRefusalChirho::WrongNodeSignerChirho
            } else {
                TenantMigrationStoreRefusalChirho::InvalidIdentityChirho
            });
        }
        let group_path_digest_chirho =
            digest_bytes_chirho(consistency_group_digest_chirho.as_bytes());
        let head_path_chirho = StoragePathChirho::new_chirho(format!(
            "{TENANT_MIGRATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{group_path_digest_chirho}/nodes-chirho/{}/{source_node_chirho}/active-head-chirho.json",
            &group_path_digest_chirho[..2],
            &source_node_chirho[..2],
        ));
        Ok(Self {
            storage_chirho,
            signer_chirho,
            consistency_group_digest_chirho,
            source_node_chirho,
            head_path_chirho,
        })
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn source_node_chirho(&self) -> &str {
        &self.source_node_chirho
    }

    pub fn load_current_chirho(
        &self,
    ) -> Result<Option<ActiveTenantMigrationChirho>, TenantMigrationStoreRefusalChirho> {
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &self.head_path_chirho,
            MAX_TENANT_MIGRATION_HEAD_BYTES_CHIRHO,
            TenantMigrationStoreRefusalChirho::OversizedHeadChirho,
        )?
        else {
            return Ok(None);
        };
        let head_chirho = self.parse_and_verify_head_chirho(&head_bytes_chirho)?;
        let checkpoint_path_chirho =
            checkpoint_path_chirho(&head_chirho.active_checkpoint_ref_chirho)?;
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO,
            TenantMigrationStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(TenantMigrationStoreRefusalChirho::MissingCheckpointChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho
        {
            return Err(TenantMigrationStoreRefusalChirho::DigestMismatchChirho);
        }
        let checkpoint_chirho =
            self.parse_and_verify_checkpoint_chirho(&checkpoint_bytes_chirho)?;
        if checkpoint_chirho.attempt_digest_chirho != head_chirho.attempt_digest_chirho
            || checkpoint_chirho.transition_seq_chirho != head_chirho.transition_seq_chirho
            || checkpoint_chirho.phase_chirho != head_chirho.phase_chirho
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
        }
        Ok(Some(ActiveTenantMigrationChirho {
            checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
            checkpoint_chirho,
        }))
    }

    /// Test-only signed Preparing seed used by downstream startup-arbitration arms.
    #[cfg(feature = "test-hooks-chirho")]
    pub fn commit_preparing_test_hook_chirho(
        &self,
        tenant_id_chirho: String,
        cluster_id_chirho: String,
        journal_path_chirho: String,
        attempt_digest_chirho: String,
        preliminary_source_cut_chirho: TenantMigrationCutClaimChirho,
    ) -> Result<ActiveTenantMigrationChirho, TenantMigrationStoreRefusalChirho> {
        let operation_authority_chirho =
            TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(
                r#"{"test_hook_chirho":"tenant-migration-preparing-chirho"}"#.to_owned(),
            )
            .map_err(|_refusal_chirho| TenantMigrationStoreRefusalChirho::InvalidIdentityChirho)?;
        let (committed_chirho, durable_chirho) = self
            .commit_preparing_chirho(
                tenant_id_chirho,
                cluster_id_chirho,
                journal_path_chirho,
                attempt_digest_chirho,
                preliminary_source_cut_chirho,
                operation_authority_chirho,
            )?
            .into_parts_chirho();
        if !durable_chirho {
            return Err(TenantMigrationStoreRefusalChirho::StorageChirho);
        }
        Ok(committed_chirho.active_chirho)
    }

    /// Test-only: re-sign the CURRENT checkpoint carrying a different operation-authority binding.
    ///
    /// Exists so a legacy-envelope arm can put one specific, legitimately signed operation authority
    /// into the persisted head. Rewriting the signed head from the host test instead would make such
    /// an arm refuse on the SIGNATURE rather than on the property under test — it would pass, and it
    /// would read as though it covered the property while covering nothing.
    ///
    /// Changes exactly one field and re-signs, so the operation-authority envelope is the only
    /// variable an arm built on this can be measuring. It deliberately does not run
    /// `validate_transition_chirho`: replacing an authority leaves the phase unchanged, which is not
    /// a lawful transition, and the point here is to reproduce a head that a PRIOR release could have
    /// written rather than to perform a new one.
    #[cfg(feature = "test-hooks-chirho")]
    pub fn replace_active_operation_authority_test_hook_chirho(
        &self,
        operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
    ) -> Result<ActiveTenantMigrationChirho, TenantMigrationStoreRefusalChirho> {
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(TenantMigrationStoreRefusalChirho::InvalidIdentityChirho)?;
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        checkpoint_chirho.operation_authority_chirho = operation_authority_chirho;
        checkpoint_chirho.key_id_chirho = self.signer_chirho.key_id_chirho();
        checkpoint_chirho.sig_chirho.clear();
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, false)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)?;
        checkpoint_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SigningChirho)?;
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, true)?;
        let checkpoint_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        if checkpoint_bytes_chirho.len() > MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO {
            return Err(TenantMigrationStoreRefusalChirho::OversizedCheckpointChirho);
        }
        let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho(&checkpoint_ref_chirho)?,
            &checkpoint_bytes_chirho,
        )?;
        let active_chirho = ActiveTenantMigrationChirho {
            checkpoint_ref_chirho,
            checkpoint_chirho,
        };
        let head_bytes_chirho = self.canonical_signed_head_chirho(&active_chirho)?;
        self.storage_chirho
            .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::StorageChirho)?;
        Ok(active_chirho)
    }

    /// Test-only signed Aborted transition used by downstream shared-slot recovery arms.
    #[cfg(feature = "test-hooks-chirho")]
    pub fn commit_aborted_test_hook_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<ActiveTenantMigrationChirho, TenantMigrationStoreRefusalChirho> {
        let (committed_chirho, durable_chirho) = self
            .commit_aborted_chirho(
                active_chirho.attempt_digest_chirho(),
                active_chirho.checkpoint_ref_chirho(),
            )?
            .into_parts_chirho();
        if !durable_chirho {
            return Err(TenantMigrationStoreRefusalChirho::StorageChirho);
        }
        Ok(committed_chirho.active_chirho)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one fixed migration identity record"
    )]
    pub(crate) fn commit_preparing_chirho(
        &self,
        tenant_id_chirho: String,
        cluster_id_chirho: String,
        journal_path_chirho: String,
        attempt_digest_chirho: String,
        preliminary_source_cut_chirho: TenantMigrationCutClaimChirho,
        operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let active_chirho = self.load_current_chirho()?;
        if let Some(active_chirho) = &active_chirho {
            if active_chirho.attempt_digest_chirho() == attempt_digest_chirho {
                if active_chirho.operation_authority_chirho() != &operation_authority_chirho {
                    return Err(TenantMigrationStoreRefusalChirho::ActiveAttemptMismatchChirho);
                }
                return match active_chirho.phase_chirho() {
                    TenantMigrationPhaseChirho::PreparingChirho
                    | TenantMigrationPhaseChirho::SourceFencedChirho => {
                        self.confirm_active_chirho(active_chirho)
                    }
                    TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
                    | TenantMigrationPhaseChirho::AbortedChirho => {
                        Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho)
                    }
                };
            }
            if active_chirho.phase_chirho() != TenantMigrationPhaseChirho::AbortedChirho {
                return Err(TenantMigrationStoreRefusalChirho::ActiveAttemptMismatchChirho);
            }
        }
        let previous_checkpoint_ref_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.clone());
        let transition_seq_chirho = active_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_chirho.transition_seq_chirho)
            .unwrap_or(0)
            .checked_add(u64::from(active_chirho.is_some()))
            .ok_or(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho)?;
        let expected_prior_ref_chirho = previous_checkpoint_ref_chirho.clone();
        self.commit_checkpoint_chirho(
            expected_prior_ref_chirho.as_deref(),
            TenantMigrationCheckpointChirho {
                domain_chirho: TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO.to_owned(),
                schema_chirho: TENANT_MIGRATION_CHECKPOINT_SCHEMA_V2_CHIRHO.to_owned(),
                tenant_id_chirho,
                consistency_group_digest_chirho: self.consistency_group_digest_chirho.clone(),
                source_node_chirho: self.source_node_chirho.clone(),
                cluster_id_chirho,
                journal_path_chirho,
                attempt_digest_chirho,
                operation_authority_chirho,
                preliminary_source_cut_chirho,
                post_fence_source_cut_chirho: None,
                fence_identity_digest_chirho: None,
                transition_seq_chirho,
                previous_checkpoint_ref_chirho,
                phase_chirho: TenantMigrationPhaseChirho::PreparingChirho,
                key_id_chirho: String::new(),
                sig_chirho: String::new(),
            },
        )
    }

    pub(crate) fn commit_source_fenced_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
        post_fence_source_cut_chirho: TenantMigrationCutClaimChirho,
        fence_identity_digest_chirho: String,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let active_chirho =
            self.load_exact_prior_chirho(attempt_digest_chirho, expected_prior_ref_chirho)?;
        if active_chirho.phase_chirho() == TenantMigrationPhaseChirho::SourceFencedChirho {
            return self.confirm_active_chirho(&active_chirho);
        }
        if active_chirho.phase_chirho() != TenantMigrationPhaseChirho::PreparingChirho {
            return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_chirho(&mut checkpoint_chirho, expected_prior_ref_chirho)?;
        checkpoint_chirho.phase_chirho = TenantMigrationPhaseChirho::SourceFencedChirho;
        checkpoint_chirho.post_fence_source_cut_chirho = Some(post_fence_source_cut_chirho);
        checkpoint_chirho.fence_identity_digest_chirho = Some(fence_identity_digest_chirho);
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    pub(crate) fn commit_aborted_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let active_chirho =
            self.load_exact_prior_chirho(attempt_digest_chirho, expected_prior_ref_chirho)?;
        if active_chirho.phase_chirho() == TenantMigrationPhaseChirho::AbortedChirho {
            return self.confirm_active_chirho(&active_chirho);
        }
        if !matches!(
            active_chirho.phase_chirho(),
            TenantMigrationPhaseChirho::PreparingChirho
                | TenantMigrationPhaseChirho::SourceFencedChirho
        ) {
            return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
        }
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_chirho(&mut checkpoint_chirho, expected_prior_ref_chirho)?;
        checkpoint_chirho.phase_chirho = TenantMigrationPhaseChirho::AbortedChirho;
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    /// Commit the ONE transition into `TargetActivatedSourceRetainedChirho`.
    ///
    /// This replaced a `#[cfg(test)]` hook that checked only the phase. Two things the hook could
    /// not do, and a production mover must:
    ///
    /// 1. It binds the fence identity the caller INDEPENDENTLY verified to the one this attempt
    ///    recorded when it fenced, so a caller that verified some other fence cannot activate
    ///    against this attempt.
    /// 2. It selects the exact signed head itself via `load_exact_prior_chirho`, so no caller
    ///    chooses which state it is transitioning from.
    ///
    /// Idempotent by the same rule as every sibling: an attempt already activated re-confirms
    /// rather than advancing a second time, so a crash between commit and reply cannot double-move.
    pub(crate) fn commit_target_activated_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
        verified_fence_identity_digest_chirho: &str,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let active_chirho =
            self.load_exact_prior_chirho(attempt_digest_chirho, expected_prior_ref_chirho)?;
        if active_chirho.phase_chirho()
            == TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
        {
            return self.confirm_active_chirho(&active_chirho);
        }
        // Only an ESTABLISHED source fence may activate. `PreparingChirho` must not: the source is
        // not yet provably frozen, so activating there could leave two writers.
        if active_chirho.phase_chirho() != TenantMigrationPhaseChirho::SourceFencedChirho {
            return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
        }
        // ABSENT and MISMATCHED are different failures. A fenced checkpoint with no recorded fence
        // identity is malformed; activating on one would bind the target to nothing at all.
        let recorded_chirho = active_chirho
            .checkpoint_chirho
            .fence_identity_digest_chirho
            .as_deref()
            .ok_or(TenantMigrationStoreRefusalChirho::MalformedCheckpointChirho)?;
        if recorded_chirho != verified_fence_identity_digest_chirho {
            return Err(TenantMigrationStoreRefusalChirho::FenceIdentityMismatchChirho);
        }
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        advance_checkpoint_chirho(&mut checkpoint_chirho, expected_prior_ref_chirho)?;
        checkpoint_chirho.phase_chirho =
            TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho;
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    pub(crate) fn confirm_active_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let checkpoint_bytes_chirho = canonical_json_chirho(&active_chirho.checkpoint_chirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != active_chirho.checkpoint_ref_chirho {
            return Err(TenantMigrationStoreRefusalChirho::DigestMismatchChirho);
        }
        if self.parse_and_verify_checkpoint_chirho(&checkpoint_bytes_chirho)?
            != active_chirho.checkpoint_chirho
        {
            return Err(TenantMigrationStoreRefusalChirho::NonCanonicalCheckpointChirho);
        }
        let current_chirho = self.load_current_chirho()?;
        if current_chirho.as_ref() != Some(active_chirho) {
            return Err(TenantMigrationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        let head_bytes_chirho = self.canonical_signed_head_chirho(active_chirho)?;
        let committed_chirho = CommittedTenantMigrationChirho {
            active_chirho: active_chirho.clone(),
        };
        Ok(
            if self
                .storage_chirho
                .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
                .is_ok()
            {
                TenantMigrationCommitOutcomeChirho::DurableChirho(committed_chirho)
            } else {
                TenantMigrationCommitOutcomeChirho::DurabilityUnconfirmedChirho(committed_chirho)
            },
        )
    }

    fn load_exact_prior_chirho(
        &self,
        attempt_digest_chirho: &str,
        expected_prior_ref_chirho: &str,
    ) -> Result<ActiveTenantMigrationChirho, TenantMigrationStoreRefusalChirho> {
        if !is_lower_hex_digest_chirho(attempt_digest_chirho)
            || !is_lower_hex_digest_chirho(expected_prior_ref_chirho)
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidIdentityChirho);
        }
        let active_chirho = self
            .load_current_chirho()?
            .ok_or(TenantMigrationStoreRefusalChirho::WrongExpectedPriorChirho)?;
        if active_chirho.attempt_digest_chirho() != attempt_digest_chirho {
            return Err(TenantMigrationStoreRefusalChirho::ActiveAttemptMismatchChirho);
        }
        if active_chirho.checkpoint_ref_chirho() != expected_prior_ref_chirho {
            return Err(TenantMigrationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        Ok(active_chirho)
    }

    fn commit_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        mut checkpoint_chirho: TenantMigrationCheckpointChirho,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        if checkpoint_chirho.previous_checkpoint_ref_chirho.as_deref() != expected_prior_ref_chirho
        {
            return Err(TenantMigrationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        checkpoint_chirho.key_id_chirho = self.signer_chirho.key_id_chirho();
        checkpoint_chirho.sig_chirho.clear();
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, false)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)?;
        checkpoint_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SigningChirho)?;
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, true)?;
        let checkpoint_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)?;
        if checkpoint_bytes_chirho.len() > MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO {
            return Err(TenantMigrationStoreRefusalChirho::OversizedCheckpointChirho);
        }
        let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho(&checkpoint_ref_chirho)?,
            &checkpoint_bytes_chirho,
        )?;
        let active_chirho = self.load_current_chirho()?;
        if active_chirho
            .as_ref()
            .map(ActiveTenantMigrationChirho::checkpoint_ref_chirho)
            == Some(checkpoint_ref_chirho.as_str())
        {
            return self.confirm_active_chirho(
                active_chirho
                    .as_ref()
                    .expect("the exact migration checkpoint was just observed"),
            );
        }
        let actual_prior_chirho = active_chirho
            .as_ref()
            .map(ActiveTenantMigrationChirho::checkpoint_ref_chirho);
        if actual_prior_chirho != expected_prior_ref_chirho {
            return Err(TenantMigrationStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        validate_transition_chirho(active_chirho.as_ref(), &checkpoint_chirho)?;
        let active_chirho = ActiveTenantMigrationChirho {
            checkpoint_ref_chirho,
            checkpoint_chirho,
        };
        let head_bytes_chirho = self.canonical_signed_head_chirho(&active_chirho)?;
        let committed_chirho = CommittedTenantMigrationChirho { active_chirho };
        Ok(
            if self
                .storage_chirho
                .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
                .is_ok()
            {
                TenantMigrationCommitOutcomeChirho::DurableChirho(committed_chirho)
            } else {
                TenantMigrationCommitOutcomeChirho::DurabilityUnconfirmedChirho(committed_chirho)
            },
        )
    }

    fn canonical_signed_head_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<Vec<u8>, TenantMigrationStoreRefusalChirho> {
        let mut head_chirho = TenantMigrationHeadChirho {
            domain_chirho: TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO.to_owned(),
            schema_chirho: TENANT_MIGRATION_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: self.consistency_group_digest_chirho.clone(),
            source_node_chirho: self.source_node_chirho.clone(),
            attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
            active_checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho.clone(),
            transition_seq_chirho: active_chirho.checkpoint_chirho.transition_seq_chirho,
            phase_chirho: active_chirho.phase_chirho(),
            key_id_chirho: self.signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        self.validate_head_shape_chirho(&head_chirho, false)?;
        let unsigned_bytes_chirho = canonical_json_chirho(&head_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)?;
        head_chirho.sig_chirho = self
            .signer_chirho
            .sign_chirho(unsigned_line_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SigningChirho)?;
        self.validate_head_shape_chirho(&head_chirho, true)?;
        let bytes_chirho = canonical_json_chirho(&head_chirho)?;
        if bytes_chirho.len() > MAX_TENANT_MIGRATION_HEAD_BYTES_CHIRHO {
            return Err(TenantMigrationStoreRefusalChirho::OversizedHeadChirho);
        }
        Ok(bytes_chirho)
    }

    fn parse_and_verify_head_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<TenantMigrationHeadChirho, TenantMigrationStoreRefusalChirho> {
        let head_chirho: TenantMigrationHeadChirho = serde_json::from_slice(bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::MalformedHeadChirho)?;
        self.validate_head_shape_chirho(&head_chirho, true)?;
        if canonical_json_chirho(&head_chirho)?.as_slice() != bytes_chirho {
            return Err(TenantMigrationStoreRefusalChirho::NonCanonicalHeadChirho);
        }
        let mut unsigned_chirho = head_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)?;
        if !self
            .signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidHeadSignatureChirho);
        }
        Ok(head_chirho)
    }

    fn parse_and_verify_checkpoint_chirho(
        &self,
        bytes_chirho: &[u8],
    ) -> Result<TenantMigrationCheckpointChirho, TenantMigrationStoreRefusalChirho> {
        let checkpoint_chirho: TenantMigrationCheckpointChirho =
            serde_json::from_slice(bytes_chirho)
                .map_err(|_| TenantMigrationStoreRefusalChirho::MalformedCheckpointChirho)?;
        self.validate_checkpoint_shape_chirho(&checkpoint_chirho, true)?;
        if canonical_json_chirho(&checkpoint_chirho)?.as_slice() != bytes_chirho {
            return Err(TenantMigrationStoreRefusalChirho::NonCanonicalCheckpointChirho);
        }
        let mut unsigned_chirho = checkpoint_chirho.clone();
        let signature_chirho = std::mem::take(&mut unsigned_chirho.sig_chirho);
        let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
        let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
            .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)?;
        if !self
            .signer_chirho
            .verify_chirho(unsigned_line_chirho, &signature_chirho)
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidCheckpointSignatureChirho);
        }
        Ok(checkpoint_chirho)
    }

    fn validate_head_shape_chirho(
        &self,
        head_chirho: &TenantMigrationHeadChirho,
        signed_chirho: bool,
    ) -> Result<(), TenantMigrationStoreRefusalChirho> {
        if head_chirho.domain_chirho != TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO
            || head_chirho.schema_chirho != TENANT_MIGRATION_HEAD_SCHEMA_V1_CHIRHO
            || head_chirho.consistency_group_digest_chirho != self.consistency_group_digest_chirho
            || head_chirho.source_node_chirho != self.source_node_chirho
            || !is_lower_hex_digest_chirho(&head_chirho.attempt_digest_chirho)
            || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
            || head_chirho.key_id_chirho != self.source_node_chirho
            || !valid_signature_posture_chirho(&head_chirho.sig_chirho, signed_chirho)
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidIdentityChirho);
        }
        Ok(())
    }

    fn validate_checkpoint_shape_chirho(
        &self,
        checkpoint_chirho: &TenantMigrationCheckpointChirho,
        signed_chirho: bool,
    ) -> Result<(), TenantMigrationStoreRefusalChirho> {
        let post_and_fence_align_chirho = checkpoint_chirho.post_fence_source_cut_chirho.is_some()
            == checkpoint_chirho.fence_identity_digest_chirho.is_some();
        let phase_payload_valid_chirho = match checkpoint_chirho.phase_chirho {
            TenantMigrationPhaseChirho::PreparingChirho => {
                checkpoint_chirho.post_fence_source_cut_chirho.is_none()
            }
            TenantMigrationPhaseChirho::SourceFencedChirho
            | TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho => {
                checkpoint_chirho.post_fence_source_cut_chirho.is_some()
            }
            TenantMigrationPhaseChirho::AbortedChirho => true,
        };
        if checkpoint_chirho.domain_chirho != TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO
            || checkpoint_chirho.schema_chirho != TENANT_MIGRATION_CHECKPOINT_SCHEMA_V2_CHIRHO
            || checkpoint_chirho.consistency_group_digest_chirho
                != self.consistency_group_digest_chirho
            || checkpoint_chirho.source_node_chirho != self.source_node_chirho
            || checkpoint_chirho.key_id_chirho != self.source_node_chirho
            || !valid_label_chirho(&checkpoint_chirho.tenant_id_chirho)
            || !valid_label_chirho(&checkpoint_chirho.cluster_id_chirho)
            || !valid_label_chirho(&checkpoint_chirho.journal_path_chirho)
            || !is_lower_hex_digest_chirho(&checkpoint_chirho.attempt_digest_chirho)
            || checkpoint_chirho
                .operation_authority_chirho
                .validate_chirho()
                .is_err()
            || !valid_cut_chirho(&checkpoint_chirho.preliminary_source_cut_chirho)
            || checkpoint_chirho
                .post_fence_source_cut_chirho
                .as_ref()
                .is_some_and(|cut_chirho| !valid_cut_chirho(cut_chirho))
            || checkpoint_chirho
                .fence_identity_digest_chirho
                .as_ref()
                .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || !post_and_fence_align_chirho
            || !phase_payload_valid_chirho
            || checkpoint_chirho
                .previous_checkpoint_ref_chirho
                .as_ref()
                .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || !valid_signature_posture_chirho(&checkpoint_chirho.sig_chirho, signed_chirho)
        {
            return Err(TenantMigrationStoreRefusalChirho::InvalidIdentityChirho);
        }
        Ok(())
    }
}

fn validate_transition_chirho(
    prior_chirho: Option<&ActiveTenantMigrationChirho>,
    next_chirho: &TenantMigrationCheckpointChirho,
) -> Result<(), TenantMigrationStoreRefusalChirho> {
    match prior_chirho {
        None => {
            if next_chirho.transition_seq_chirho != 0
                || next_chirho.previous_checkpoint_ref_chirho.is_some()
                || next_chirho.phase_chirho != TenantMigrationPhaseChirho::PreparingChirho
            {
                return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
            }
        }
        Some(prior_chirho) => {
            if next_chirho.transition_seq_chirho
                != prior_chirho
                    .checkpoint_chirho
                    .transition_seq_chirho
                    .checked_add(1)
                    .ok_or(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho)?
                || next_chirho.previous_checkpoint_ref_chirho.as_deref()
                    != Some(prior_chirho.checkpoint_ref_chirho())
            {
                return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
            }
            let same_attempt_chirho =
                prior_chirho.attempt_digest_chirho() == next_chirho.attempt_digest_chirho;
            let valid_chirho = matches!(
                (
                    prior_chirho.phase_chirho(),
                    next_chirho.phase_chirho,
                    same_attempt_chirho,
                ),
                (
                    TenantMigrationPhaseChirho::PreparingChirho,
                    TenantMigrationPhaseChirho::SourceFencedChirho
                        | TenantMigrationPhaseChirho::AbortedChirho,
                    true,
                ) | (
                    TenantMigrationPhaseChirho::SourceFencedChirho,
                    TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
                        | TenantMigrationPhaseChirho::AbortedChirho,
                    true,
                ) | (
                    TenantMigrationPhaseChirho::AbortedChirho,
                    TenantMigrationPhaseChirho::PreparingChirho,
                    false,
                )
            );
            if !valid_chirho {
                return Err(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho);
            }
        }
    }
    Ok(())
}

fn advance_checkpoint_chirho(
    checkpoint_chirho: &mut TenantMigrationCheckpointChirho,
    prior_ref_chirho: &str,
) -> Result<(), TenantMigrationStoreRefusalChirho> {
    checkpoint_chirho.transition_seq_chirho = checkpoint_chirho
        .transition_seq_chirho
        .checked_add(1)
        .ok_or(TenantMigrationStoreRefusalChirho::InvalidTransitionChirho)?;
    checkpoint_chirho.previous_checkpoint_ref_chirho = Some(prior_ref_chirho.to_owned());
    checkpoint_chirho.sig_chirho.clear();
    Ok(())
}

fn checkpoint_path_chirho(
    checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, TenantMigrationStoreRefusalChirho> {
    if !is_lower_hex_digest_chirho(checkpoint_ref_chirho) {
        return Err(TenantMigrationStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{TENANT_MIGRATION_NAMESPACE_CHIRHO}/checkpoints-chirho/{}/{}/{checkpoint_ref_chirho}.json",
        &checkpoint_ref_chirho[..2],
        &checkpoint_ref_chirho[2..4],
    )))
}

fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
) -> Result<(), TenantMigrationStoreRefusalChirho> {
    if bytes_chirho.len() > MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO {
        return Err(TenantMigrationStoreRefusalChirho::OversizedCheckpointChirho);
    }
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| TenantMigrationStoreRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO,
                TenantMigrationStoreRefusalChirho::OversizedCheckpointChirho,
            )?
            .ok_or(TenantMigrationStoreRefusalChirho::StorageChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(TenantMigrationStoreRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: TenantMigrationStoreRefusalChirho,
) -> Result<Option<Vec<u8>>, TenantMigrationStoreRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| TenantMigrationStoreRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if length_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    if length_chirho == 0 {
        return Ok(Some(Vec::new()));
    }
    storage_chirho
        .read_exact_range_chirho(path_chirho, 0, length_chirho)
        .map(Some)
        .map_err(|_| TenantMigrationStoreRefusalChirho::StorageChirho)
}

fn canonical_json_chirho<T: serde::Serialize>(
    value_chirho: &T,
) -> Result<Vec<u8>, TenantMigrationStoreRefusalChirho> {
    serde_json::to_vec(value_chirho)
        .map_err(|_| TenantMigrationStoreRefusalChirho::SerializationChirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn valid_label_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= MAX_TENANT_MIGRATION_LABEL_BYTES_CHIRHO
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_graphic())
}

fn valid_cut_chirho(cut_chirho: &TenantMigrationCutClaimChirho) -> bool {
    is_lower_hex_digest_chirho(&cut_chirho.record_digest_chirho)
}

fn valid_signature_posture_chirho(signature_chirho: &str, signed_chirho: bool) -> bool {
    if signed_chirho {
        !signature_chirho.is_empty()
            && signature_chirho.len() <= MAX_TENANT_MIGRATION_SIGNATURE_BYTES_CHIRHO
            && signature_chirho.bytes().all(|byte_chirho| {
                byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)
            })
    } else {
        signature_chirho.is_empty()
    }
}
