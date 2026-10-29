// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Authority contract for moving one tenant ledger root without stale verification or two writers.
//!
//! The generic tenant precheck answers whether a target is presently complete enough to justify a
//! bounded source-append fence. It is deliberately not authority. This crate binds authority to retained source
//! and target root descriptors plus independently full-verified ledger cuts, and exposes activation
//! only after consuming a source-append-fence witness and verifying the target at that exact cut.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use cairn_durable_chirho::DescriptorRootCustodyChirho;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerifierViewChirho, KindRegistryViewChirho, MembershipViewChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::verified_prefix_state_chirho::{
    open_read_only_verified_prefix_state_chirho, open_read_only_verified_tail_cut_chirho,
    LedgerPrefixCutChirho, VerifiedLedgerReadCutChirho,
};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_tenant_chirho::migration_completeness_chirho::PreliminaryMigrationCheckChirho;
use cairn_tenant_chirho::migration_completeness_chirho::RootSurfaceEnumeratorChirho;
use cairn_tenant_chirho::root_surfaces_chirho::{
    RootSurfaceSnapshotChirho, TenantScopedArtifactResolverChirho,
};
use cairn_tenant_chirho::tenant_chirho::{tenant_id_for_root_chirho, TenantIdChirho};
use std::fmt;
use std::sync::Arc;

/// A tenant root held by descriptor identity rather than by a caller-supplied path string.
#[derive(Clone, Debug)]
pub struct VerifiedTenantMigrationRootChirho {
    custody_chirho: Arc<DescriptorRootCustodyChirho>,
    tenant_id_chirho: String,
}

impl VerifiedTenantMigrationRootChirho {
    /// Open one existing tenant root without creating or changing it.
    pub fn open_existing_chirho(
        root_chirho: &std::path::Path,
    ) -> Result<Self, TenantMigrationRefusalChirho> {
        let custody_chirho = DescriptorRootCustodyChirho::open_path_chirho(root_chirho)
            .map_err(|_error_chirho| TenantMigrationRefusalChirho::RootUnavailableChirho)?;
        require_current_custody_chirho(&custody_chirho)?;
        let tenant_id_chirho =
            match tenant_id_for_root_chirho(custody_chirho.canonical_root_chirho())
                .map_err(|_error_chirho| TenantMigrationRefusalChirho::TenantMarkerInvalidChirho)?
            {
                TenantIdChirho::TenantChirho(tenant_id_chirho) => tenant_id_chirho,
                TenantIdChirho::PlatformRootChirho => {
                    return Err(TenantMigrationRefusalChirho::PlatformRootRefusedChirho)
                }
            };
        require_current_custody_chirho(&custody_chirho)?;
        Ok(Self {
            custody_chirho,
            tenant_id_chirho,
        })
    }

    pub fn tenant_id_chirho(&self) -> &str {
        &self.tenant_id_chirho
    }

    /// A tenant-scoped object resolver over this root's custody-verified canonical path.
    ///
    /// Hands out the narrow CAPABILITY rather than the path: this type holds a root by descriptor
    /// identity on purpose, and returning a `&Path` would re-admit the caller-supplied path string
    /// it exists to refuse. The one caller that needs this is the migration precheck, which must ask
    /// "does the source still have the object my target is missing" — a question about objects, not
    /// about directories.
    /// This root's observed top-level surfaces, read through custody rather than a path.
    ///
    /// Returns an empty list if the root cannot be enumerated, and the caller must treat empty as
    /// NO EVIDENCE rather than as "nothing travels" — the required-surface half's anti-vacuity guard
    /// is what enforces that, because a silent empty source would make every target look complete.
    pub fn observed_surfaces_chirho(&self) -> Vec<String> {
        RootSurfaceSnapshotChirho::open_chirho(self.custody_chirho.canonical_root_chirho())
            .map(|snapshot_chirho| snapshot_chirho.observed_surfaces_chirho())
            .unwrap_or_default()
    }

    pub fn object_resolver_chirho(&self) -> TenantScopedArtifactResolverChirho {
        TenantScopedArtifactResolverChirho::for_root_chirho(
            self.custody_chirho.canonical_root_chirho(),
        )
    }

    /// Re-check and expose this root's descriptor-backed binding digest as lower hex.
    ///
    /// This is identity evidence, not a path and not append authority. Tenant placement readiness
    /// prefixes it with its own domain before signing so it cannot be confused with another digest.
    pub fn binding_identity_digest_hex_chirho(
        &self,
    ) -> Result<String, TenantMigrationRefusalChirho> {
        Ok(self
            .binding_identity_digest_chirho()?
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect())
    }

    fn verify_current_chirho(&self) -> Result<(), TenantMigrationRefusalChirho> {
        require_current_custody_chirho(&self.custody_chirho)
    }

    fn binding_identity_digest_chirho(&self) -> Result<[u8; 32], TenantMigrationRefusalChirho> {
        self.verify_current_chirho()?;
        self.custody_chirho
            .binding_identity_digest_chirho()
            .map_err(|_error_chirho| TenantMigrationRefusalChirho::RootIdentityChangedChirho)
    }

    fn same_root_chirho(&self, other_chirho: &Self) -> Result<bool, TenantMigrationRefusalChirho> {
        self.verify_current_chirho()?;
        other_chirho.verify_current_chirho()?;
        self.custody_chirho
            .binding_root_matches_chirho(other_chirho.custody_chirho.canonical_root_chirho())
            .map_err(|_error_chirho| TenantMigrationRefusalChirho::RootIdentityChangedChirho)
    }

    /// Refuse a pair where either canonical root contains the other.
    ///
    /// `same_root_chirho` compares roots for IDENTITY, so it cannot see nesting. Both directions
    /// matter: a target inside the source means retiring the source erases the key of a tree the
    /// target lives in, and a source inside the target means the move's own destination already
    /// contains what it is moving.
    fn require_not_nested_with_chirho(
        &self,
        other_chirho: &Self,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        self.verify_current_chirho()?;
        other_chirho.verify_current_chirho()?;
        let own_chirho = self.custody_chirho.canonical_root_chirho();
        let other_root_chirho = other_chirho.custody_chirho.canonical_root_chirho();
        if own_chirho.starts_with(other_root_chirho) || other_root_chirho.starts_with(own_chirho) {
            return Err(TenantMigrationRefusalChirho::NestedRootRefusedChirho);
        }
        Ok(())
    }

    fn contains_namespace_chirho(
        &self,
        namespace_chirho: &std::path::Path,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        self.verify_current_chirho()?;
        if !namespace_chirho.starts_with(self.custody_chirho.canonical_root_chirho()) {
            return Err(TenantMigrationRefusalChirho::LedgerNamespaceOutsideRootChirho);
        }
        Ok(())
    }
}

fn require_current_custody_chirho(
    custody_chirho: &DescriptorRootCustodyChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if custody_chirho
        .canonical_path_still_names_custody_chirho()
        .map_err(|_error_chirho| TenantMigrationRefusalChirho::RootIdentityChangedChirho)?
    {
        Ok(())
    } else {
        Err(TenantMigrationRefusalChirho::RootIdentityChangedChirho)
    }
}

/// Read-only views needed to full-verify a journal. Storage is intentionally absent: the helper
/// injects the exact descriptor-backed namespace it first binds to the tenant root.
#[derive(Clone, Copy)]
pub struct TenantLedgerVerificationViewsChirho<'views_chirho> {
    pub signer_chirho: &'views_chirho dyn LedgerSignerPortChirho,
    pub clock_chirho: &'views_chirho dyn LedgerClockPortChirho,
    pub membership_chirho: &'views_chirho dyn MembershipViewChirho,
    pub kind_registry_chirho: &'views_chirho dyn KindRegistryViewChirho,
    pub authority_chirho: &'views_chirho dyn AuthorityVerifierViewChirho,
}

/// A full-verified ledger cut bound to one retained tenant root and one storage namespace.
///
/// Fields are private and there is no constructor. Possessing this value means the namespace was
/// identity-checked under the root and the journal's full read-only verifier accepted its tail.
#[derive(Clone, Debug)]
pub struct VerifiedTenantLedgerCutChirho {
    root_chirho: VerifiedTenantMigrationRootChirho,
    cluster_id_chirho: ClusterIdChirho,
    journal_path_chirho: StoragePathChirho,
    cut_chirho: VerifiedLedgerReadCutChirho,
}

impl VerifiedTenantLedgerCutChirho {
    pub fn cut_chirho(&self) -> &VerifiedLedgerReadCutChirho {
        &self.cut_chirho
    }

    /// Ordinary request coordinate suitable for a durable record.
    ///
    /// This value is not evidence. Recovery must pass it back through
    /// [`open_verified_tenant_ledger_prefix_chirho`] before rebuilding migration authority.
    pub fn prefix_request_chirho(&self) -> LedgerPrefixCutChirho {
        LedgerPrefixCutChirho::new_chirho(
            self.cut_chirho.epoch_chirho(),
            self.cut_chirho.seq_chirho(),
            self.cut_chirho.record_digest_chirho().clone(),
        )
    }

    pub fn cluster_id_chirho(&self) -> &ClusterIdChirho {
        &self.cluster_id_chirho
    }

    pub fn journal_path_chirho(&self) -> &StoragePathChirho {
        &self.journal_path_chirho
    }
}

/// Stable name for one migration attempt before the source append fence is active.
///
/// The embedded preliminary source cut is a naming input only. It proves that the attempt was
/// derived from a real journal coordinate, but it carries NO evidence about the eventual fenced
/// tail because the source may still append after this identity is derived. There is no public
/// constructor and no deserializer: callers obtain it only from [`RootMoveChirho`].
#[derive(Clone)]
pub struct TenantMigrationAttemptIdentityChirho {
    digest_chirho: String,
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    target_root_chirho: VerifiedTenantMigrationRootChirho,
    preliminary_source_binding_chirho: TenantLedgerCutBindingChirho,
}

impl TenantMigrationAttemptIdentityChirho {
    pub fn digest_chirho(&self) -> &str {
        &self.digest_chirho
    }

    /// The verified tenant whose one-writer consistency group this attempt must fence.
    pub fn tenant_id_chirho(&self) -> &str {
        self.source_root_chirho.tenant_id_chirho()
    }
}

impl fmt::Debug for TenantMigrationAttemptIdentityChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("TenantMigrationAttemptIdentityChirho")
            .field("digest_chirho", &self.digest_chirho)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TenantMigrationAttemptIdentityChirho {
    fn eq(&self, other_chirho: &Self) -> bool {
        self.digest_chirho == other_chirho.digest_chirho
    }
}

impl Eq for TenantMigrationAttemptIdentityChirho {}

/// Post-fence identity binding one prepared attempt to the source tail verified under its marker.
///
/// The identity is derived from opaque verified values rather than caller-supplied identity parts.
/// Persisted recovery must re-open and reverify those values before deriving this type again.
#[derive(Clone)]
pub struct TenantMigrationFenceIdentityChirho {
    digest_chirho: String,
    attempt_chirho: TenantMigrationAttemptIdentityChirho,
    verified_source_cut_chirho: VerifiedTenantLedgerCutChirho,
}

impl TenantMigrationFenceIdentityChirho {
    /// Bind a full-verified source cut to one prepared attempt after its exact marker is active.
    ///
    /// The later durable adapter owns that ordering. This constructor validates the typed bindings;
    /// it cannot by itself prove when the caller ran the journal verification.
    pub fn bind_post_fence_source_cut_chirho(
        attempt_chirho: TenantMigrationAttemptIdentityChirho,
        verified_source_cut_chirho: VerifiedTenantLedgerCutChirho,
    ) -> Result<Self, TenantMigrationRefusalChirho> {
        require_distinct_same_tenant_chirho(
            &attempt_chirho.source_root_chirho,
            &attempt_chirho.target_root_chirho,
        )?;
        require_cut_root_chirho(
            &verified_source_cut_chirho,
            &attempt_chirho.source_root_chirho,
            true,
        )?;
        let verified_binding_chirho = binding_from_cut_chirho(verified_source_cut_chirho.clone());
        require_same_journal_lane_chirho(
            &attempt_chirho.preliminary_source_binding_chirho,
            &verified_binding_chirho,
        )?;
        let digest_chirho =
            derive_fence_identity_digest_chirho(&attempt_chirho, &verified_binding_chirho);
        Ok(Self {
            digest_chirho,
            attempt_chirho,
            verified_source_cut_chirho,
        })
    }

    pub fn digest_chirho(&self) -> &str {
        &self.digest_chirho
    }

    pub fn attempt_chirho(&self) -> &TenantMigrationAttemptIdentityChirho {
        &self.attempt_chirho
    }

    fn verified_source_cut_chirho(&self) -> &VerifiedTenantLedgerCutChirho {
        &self.verified_source_cut_chirho
    }
}

impl fmt::Debug for TenantMigrationFenceIdentityChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("TenantMigrationFenceIdentityChirho")
            .field("digest_chirho", &self.digest_chirho)
            .field("attempt_chirho", &self.attempt_chirho)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TenantMigrationFenceIdentityChirho {
    fn eq(&self, other_chirho: &Self) -> bool {
        self.digest_chirho == other_chirho.digest_chirho
    }
}

impl Eq for TenantMigrationFenceIdentityChirho {}

/// Port proving that the source's append path remains fenced while migration authority advances.
///
/// This crate deliberately provides no production implementation. The durable adapter must wrap its
/// real writer/elector fence and retain whatever capability makes `remains_active_chirho` truthful.
/// Taking the witness by value makes every transition site name that dependency; a phase cannot be
/// reached from a verified cut alone.
pub trait SourceAppendFenceWitnessChirho: fmt::Debug + Send {
    fn fence_identity_chirho(&self) -> &TenantMigrationFenceIdentityChirho;
    fn remains_active_chirho(&self) -> bool;
}

/// Full-verify one tail through a descriptor-backed storage namespace contained by `root_chirho`.
/// Corrupt or truncated journal bytes return `JournalVerificationRefusedChirho`; they are never
/// packaged as a cut.
pub fn open_verified_tenant_ledger_tail_chirho(
    root_chirho: VerifiedTenantMigrationRootChirho,
    storage_chirho: &FsLedgerStorageChirho,
    views_chirho: TenantLedgerVerificationViewsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
) -> Result<VerifiedTenantLedgerCutChirho, TenantMigrationRefusalChirho> {
    let namespace_chirho = storage_chirho.namespace_root_chirho();
    root_chirho.contains_namespace_chirho(namespace_chirho)?;
    let namespace_snapshot_chirho =
        storage_chirho
            .stable_namespace_snapshot_chirho()
            .map_err(|_error_chirho| {
                TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
            })?;
    namespace_snapshot_chirho
        .verify_current_path_chirho(namespace_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
        })?;
    let cut_chirho = open_read_only_verified_tail_cut_chirho(
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: views_chirho.signer_chirho,
            clock_chirho: views_chirho.clock_chirho,
            membership_chirho: views_chirho.membership_chirho,
            kind_registry_chirho: views_chirho.kind_registry_chirho,
            authority_chirho: views_chirho.authority_chirho,
        },
        journal_path_chirho,
        expected_cluster_chirho,
    )
    .map_err(|_error_chirho| TenantMigrationRefusalChirho::JournalVerificationRefusedChirho)?;
    namespace_snapshot_chirho
        .verify_current_path_chirho(namespace_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
        })?;
    root_chirho.verify_current_chirho()?;
    Ok(VerifiedTenantLedgerCutChirho {
        root_chirho,
        cluster_id_chirho: expected_cluster_chirho.clone(),
        journal_path_chirho: journal_path_chirho.clone(),
        cut_chirho,
    })
}

/// Full-verify one journal and re-derive an opaque historical cut from an ordinary persisted
/// request coordinate.
///
/// The full current journal and the recomposed prefix walk must both verify. A durable checkpoint
/// therefore cannot turn its caller-constructible [`LedgerPrefixCutChirho`] into authority merely
/// by deserializing it; corrupt, truncated, absent, or wrong-lane history refuses before this helper
/// can construct [`VerifiedTenantLedgerCutChirho`].
pub fn open_verified_tenant_ledger_prefix_chirho(
    root_chirho: VerifiedTenantMigrationRootChirho,
    storage_chirho: &FsLedgerStorageChirho,
    views_chirho: TenantLedgerVerificationViewsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
    requested_cut_chirho: &LedgerPrefixCutChirho,
) -> Result<VerifiedTenantLedgerCutChirho, TenantMigrationRefusalChirho> {
    let namespace_chirho = storage_chirho.namespace_root_chirho();
    root_chirho.contains_namespace_chirho(namespace_chirho)?;
    let namespace_snapshot_chirho =
        storage_chirho
            .stable_namespace_snapshot_chirho()
            .map_err(|_error_chirho| {
                TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
            })?;
    namespace_snapshot_chirho
        .verify_current_path_chirho(namespace_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
        })?;
    let verified_prefix_chirho = open_read_only_verified_prefix_state_chirho(
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: views_chirho.signer_chirho,
            clock_chirho: views_chirho.clock_chirho,
            membership_chirho: views_chirho.membership_chirho,
            kind_registry_chirho: views_chirho.kind_registry_chirho,
            authority_chirho: views_chirho.authority_chirho,
        },
        journal_path_chirho,
        expected_cluster_chirho,
        requested_cut_chirho,
    )
    .map_err(|_error_chirho| TenantMigrationRefusalChirho::JournalVerificationRefusedChirho)?;
    namespace_snapshot_chirho
        .verify_current_path_chirho(namespace_chirho)
        .map_err(|_error_chirho| {
            TenantMigrationRefusalChirho::LedgerNamespaceIdentityChangedChirho
        })?;
    root_chirho.verify_current_chirho()?;
    Ok(VerifiedTenantLedgerCutChirho {
        root_chirho,
        cluster_id_chirho: expected_cluster_chirho.clone(),
        journal_path_chirho: journal_path_chirho.clone(),
        cut_chirho: verified_prefix_chirho.prefix_cut_chirho().clone(),
    })
}

/// Where a move is, and therefore who may write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RootMovePhaseChirho {
    NotStartedChirho,
    PreparingChirho,
    /// Operational confidence only. The source still writes and activation is impossible.
    PreliminaryTargetCheckedChirho,
    /// A pre-fence attempt identity exists. Its naming cut is not fenced-tail evidence.
    SourceFenceAttemptPreparedChirho,
    /// A source-fence witness is held and the target still needs a fresh exact-cut verification.
    SourceFenceWitnessedAwaitingFinalVerificationChirho,
    /// A post-fence, root-bound, exact-cut warrant exists. Nobody writes until activation.
    SourceFenceWitnessedTargetVerifiedChirho,
    ActivatedChirho,
    SourceRetiredChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterChirho {
    SourceChirho,
    NobodyChirho,
    TargetChirho,
}

/// What must arrive before the source may be retired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CarriedObligationsChirho {
    pub signed_history_complete_chirho: bool,
    pub projections_rebuilt_chirho: bool,
    pub privacy_key_custody_transferred_chirho: bool,
    pub audit_coordinates_preserved_chirho: bool,
}

impl CarriedObligationsChirho {
    fn missing_chirho(&self) -> Vec<&'static str> {
        let mut missing_chirho = Vec::new();
        if !self.signed_history_complete_chirho {
            missing_chirho.push("signed_history_complete_chirho");
        }
        if !self.projections_rebuilt_chirho {
            missing_chirho.push("projections_rebuilt_chirho");
        }
        if !self.privacy_key_custody_transferred_chirho {
            missing_chirho.push("privacy_key_custody_transferred_chirho");
        }
        if !self.audit_coordinates_preserved_chirho {
            missing_chirho.push("audit_coordinates_preserved_chirho");
        }
        missing_chirho
    }
}

#[derive(Clone, Debug)]
struct TenantLedgerCutBindingChirho {
    cluster_id_chirho: ClusterIdChirho,
    journal_path_chirho: StoragePathChirho,
    cut_chirho: VerifiedLedgerReadCutChirho,
}

/// Activation authority issued only while a source-fence witness remains active and only for its
/// exact verified cut.
///
/// There is no public constructor. The sole mint moves a verified target cut into this value after
/// checking source/target root identity, tenant, cluster, journal path, and complete tail equality.
#[derive(Debug)]
pub struct BoundMigrationWarrantChirho {
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    target_root_chirho: VerifiedTenantMigrationRootChirho,
    fence_identity_chirho: TenantMigrationFenceIdentityChirho,
    binding_chirho: TenantLedgerCutBindingChirho,
}

impl BoundMigrationWarrantChirho {
    /// The digest of the fence identity this warrant is bound to.
    ///
    /// Deliberately the ONLY accessor: the durable layer needs this one value to bind its committed
    /// transition to the fence the attempt actually recorded. Handing out the verified roots or the
    /// binding itself would let a consumer reconstruct authority it was never granted, which is the
    /// same trap as persisting a `Verified…` type and reading it back as proof.
    pub fn fence_identity_digest_chirho(&self) -> &str {
        self.fence_identity_chirho.digest_chirho()
    }
}

/// In-memory authority contract. A later brick persists and re-verifies these transitions; it must
/// consume this ordering rather than serializing private verified types as caller-authored claims.
#[derive(Debug)]
pub struct RootMoveChirho {
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    target_root_chirho: VerifiedTenantMigrationRootChirho,
    /// Opaque digest of the independently verified operator authorities admitted for this move.
    /// The migration contract does not interpret policy records; it only keeps one attempt from
    /// being recovered under different authority bytes.
    operation_authority_binding_digest_chirho: Option<String>,
    phase_chirho: RootMovePhaseChirho,
    preliminary_check_chirho: Option<PreliminaryMigrationCheckChirho>,
    source_fence_attempt_chirho: Option<TenantMigrationAttemptIdentityChirho>,
    source_fence_witness_chirho: Option<Box<dyn SourceAppendFenceWitnessChirho>>,
    source_fence_identity_chirho: Option<TenantMigrationFenceIdentityChirho>,
    source_fence_binding_chirho: Option<TenantLedgerCutBindingChirho>,
    verified_target_binding_chirho: Option<TenantLedgerCutBindingChirho>,
}

impl RootMoveChirho {
    pub fn new_chirho(
        source_root_chirho: VerifiedTenantMigrationRootChirho,
        target_root_chirho: VerifiedTenantMigrationRootChirho,
    ) -> Result<Self, TenantMigrationRefusalChirho> {
        require_distinct_same_tenant_chirho(&source_root_chirho, &target_root_chirho)?;
        Ok(Self {
            source_root_chirho,
            target_root_chirho,
            operation_authority_binding_digest_chirho: None,
            phase_chirho: RootMovePhaseChirho::NotStartedChirho,
            preliminary_check_chirho: None,
            source_fence_attempt_chirho: None,
            source_fence_witness_chirho: None,
            source_fence_identity_chirho: None,
            source_fence_binding_chirho: None,
            verified_target_binding_chirho: None,
        })
    }

    /// Create a move whose attempt identity is inseparable from one verified authority binding.
    ///
    /// Existing in-memory contract callers keep [`Self::new_chirho`]. Durable operator migration
    /// uses this constructor so restart cannot substitute a different destination or writer-
    /// adoption authorization while preserving the same roots and preliminary cut.
    pub fn new_with_operation_authority_binding_chirho(
        source_root_chirho: VerifiedTenantMigrationRootChirho,
        target_root_chirho: VerifiedTenantMigrationRootChirho,
        operation_authority_binding_digest_chirho: String,
    ) -> Result<Self, TenantMigrationRefusalChirho> {
        if !is_lower_hex_digest_chirho(&operation_authority_binding_digest_chirho) {
            return Err(TenantMigrationRefusalChirho::OperationAuthorityBindingInvalidChirho);
        }
        let mut move_chirho = Self::new_chirho(source_root_chirho, target_root_chirho)?;
        move_chirho.operation_authority_binding_digest_chirho =
            Some(operation_authority_binding_digest_chirho);
        Ok(move_chirho)
    }

    pub fn phase_chirho(&self) -> RootMovePhaseChirho {
        self.phase_chirho
    }

    pub fn writer_chirho(&self) -> WriterChirho {
        match self.phase_chirho {
            RootMovePhaseChirho::NotStartedChirho
            | RootMovePhaseChirho::PreparingChirho
            | RootMovePhaseChirho::PreliminaryTargetCheckedChirho
            | RootMovePhaseChirho::SourceFenceAttemptPreparedChirho => WriterChirho::SourceChirho,
            RootMovePhaseChirho::SourceFenceWitnessedAwaitingFinalVerificationChirho
            | RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho => {
                WriterChirho::NobodyChirho
            }
            RootMovePhaseChirho::ActivatedChirho | RootMovePhaseChirho::SourceRetiredChirho => {
                WriterChirho::TargetChirho
            }
        }
    }

    pub fn begin_preparing_chirho(&mut self) -> Result<(), TenantMigrationRefusalChirho> {
        match self.phase_chirho {
            RootMovePhaseChirho::NotStartedChirho => {
                self.phase_chirho = RootMovePhaseChirho::PreparingChirho;
                Ok(())
            }
            RootMovePhaseChirho::PreparingChirho => Ok(()),
            from_chirho => Err(out_of_order_chirho(from_chirho, "begin_preparing_chirho")),
        }
    }

    /// Record operational confidence before outage. This phase cannot mint a bound warrant or
    /// activate the target.
    pub fn record_preliminary_target_check_chirho(
        &mut self,
        check_chirho: PreliminaryMigrationCheckChirho,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        require_evidence_chirho(&check_chirho)?;
        match self.phase_chirho {
            RootMovePhaseChirho::PreparingChirho => {
                self.preliminary_check_chirho = Some(check_chirho);
                self.phase_chirho = RootMovePhaseChirho::PreliminaryTargetCheckedChirho;
                Ok(())
            }
            RootMovePhaseChirho::PreliminaryTargetCheckedChirho => Ok(()),
            from_chirho => Err(out_of_order_chirho(
                from_chirho,
                "record_preliminary_target_check_chirho",
            )),
        }
    }

    /// Derive and retain the marker identity before acquiring the source append fence.
    ///
    /// The source may still append in this phase. `preliminary_source_cut_chirho` therefore names
    /// this attempt but does not become the fenced source binding used for activation.
    pub fn prepare_source_append_fence_attempt_chirho(
        &mut self,
        preliminary_source_cut_chirho: VerifiedTenantLedgerCutChirho,
    ) -> Result<TenantMigrationAttemptIdentityChirho, TenantMigrationRefusalChirho> {
        require_cut_root_chirho(
            &preliminary_source_cut_chirho,
            &self.source_root_chirho,
            true,
        )?;
        let preliminary_source_binding_chirho =
            binding_from_cut_chirho(preliminary_source_cut_chirho);
        let attempt_chirho = derive_attempt_identity_chirho(
            &self.source_root_chirho,
            &self.target_root_chirho,
            preliminary_source_binding_chirho,
            self.operation_authority_binding_digest_chirho.as_deref(),
        )?;
        match self.phase_chirho {
            RootMovePhaseChirho::PreliminaryTargetCheckedChirho => {
                self.source_fence_attempt_chirho = Some(attempt_chirho.clone());
                self.phase_chirho = RootMovePhaseChirho::SourceFenceAttemptPreparedChirho;
                Ok(attempt_chirho)
            }
            RootMovePhaseChirho::SourceFenceAttemptPreparedChirho => {
                require_same_attempt_identity_chirho(
                    self.source_fence_attempt_chirho
                        .as_ref()
                        .ok_or(TenantMigrationRefusalChirho::SourceFenceAttemptMissingChirho)?,
                    &attempt_chirho,
                )?;
                Ok(attempt_chirho)
            }
            RootMovePhaseChirho::NotStartedChirho | RootMovePhaseChirho::PreparingChirho => {
                Err(TenantMigrationRefusalChirho::PreliminaryCheckRequiredChirho)
            }
            from_chirho => Err(out_of_order_chirho(
                from_chirho,
                "prepare_source_append_fence_attempt_chirho",
            )),
        }
    }

    /// Record an externally enforced append fence at one full-verified, root-bound tail.
    ///
    /// This method does not freeze a writer. It consumes a witness port whose production
    /// implementation belongs to the later durable adapter. A retry must reproduce the same cut.
    pub fn record_source_append_fence_chirho<FenceChirho>(
        &mut self,
        fence_chirho: FenceChirho,
    ) -> Result<(), TenantMigrationRefusalChirho>
    where
        FenceChirho: SourceAppendFenceWitnessChirho + 'static,
    {
        let fence_identity_chirho = fence_chirho.fence_identity_chirho().clone();
        require_same_attempt_identity_chirho(
            self.source_fence_attempt_chirho
                .as_ref()
                .ok_or(TenantMigrationRefusalChirho::SourceFenceAttemptMissingChirho)?,
            fence_identity_chirho.attempt_chirho(),
        )?;
        if !fence_chirho.remains_active_chirho() {
            return Err(TenantMigrationRefusalChirho::SourceAppendFenceNotActiveChirho);
        }
        require_cut_root_chirho(
            fence_identity_chirho.verified_source_cut_chirho(),
            &self.source_root_chirho,
            true,
        )?;
        let binding_chirho =
            binding_from_cut_chirho(fence_identity_chirho.verified_source_cut_chirho().clone());
        match self.phase_chirho {
            RootMovePhaseChirho::SourceFenceAttemptPreparedChirho => {
                self.source_fence_binding_chirho = Some(binding_chirho);
                self.source_fence_identity_chirho = Some(fence_identity_chirho);
                self.source_fence_witness_chirho = Some(Box::new(fence_chirho));
                self.phase_chirho =
                    RootMovePhaseChirho::SourceFenceWitnessedAwaitingFinalVerificationChirho;
                Ok(())
            }
            RootMovePhaseChirho::SourceFenceWitnessedAwaitingFinalVerificationChirho
            | RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho => {
                self.require_source_append_fence_active_chirho()?;
                require_same_binding_chirho(
                    self.source_fence_binding_chirho
                        .as_ref()
                        .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?,
                    &binding_chirho,
                    TenantMigrationRefusalChirho::SourceFenceCutChangedChirho,
                )?;
                require_same_fence_identity_chirho(
                    self.source_fence_identity_chirho
                        .as_ref()
                        .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?,
                    &fence_identity_chirho,
                )?;
                self.source_fence_witness_chirho = Some(Box::new(fence_chirho));
                Ok(())
            }
            RootMovePhaseChirho::NotStartedChirho
            | RootMovePhaseChirho::PreparingChirho
            | RootMovePhaseChirho::PreliminaryTargetCheckedChirho => {
                Err(TenantMigrationRefusalChirho::PreliminaryCheckRequiredChirho)
            }
            from_chirho => Err(out_of_order_chirho(
                from_chirho,
                "record_source_append_fence_chirho",
            )),
        }
    }

    /// Reverify the target after the source fence and mint the only activation-capable warrant.
    pub fn record_post_fence_target_verified_chirho(
        &mut self,
        target_cut_chirho: VerifiedTenantLedgerCutChirho,
    ) -> Result<BoundMigrationWarrantChirho, TenantMigrationRefusalChirho> {
        self.require_source_append_fence_active_chirho()?;
        require_cut_root_chirho(&target_cut_chirho, &self.target_root_chirho, false)?;
        if !matches!(
            self.phase_chirho,
            RootMovePhaseChirho::SourceFenceWitnessedAwaitingFinalVerificationChirho
                | RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho
        ) {
            return Err(out_of_order_chirho(
                self.phase_chirho,
                "record_post_fence_target_verified_chirho",
            ));
        }
        require_distinct_same_tenant_chirho(&self.source_root_chirho, &self.target_root_chirho)?;
        let source_fence_binding_chirho = self
            .source_fence_binding_chirho
            .as_ref()
            .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?;
        let target_binding_chirho = binding_from_cut_chirho(target_cut_chirho);
        require_same_binding_chirho(
            source_fence_binding_chirho,
            &target_binding_chirho,
            TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho,
        )?;
        if let Some(verified_chirho) = &self.verified_target_binding_chirho {
            require_same_binding_chirho(
                verified_chirho,
                &target_binding_chirho,
                TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho,
            )?;
        }
        self.verified_target_binding_chirho = Some(target_binding_chirho.clone());
        self.phase_chirho = RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho;
        Ok(BoundMigrationWarrantChirho {
            source_root_chirho: self.source_root_chirho.clone(),
            target_root_chirho: self.target_root_chirho.clone(),
            fence_identity_chirho: self
                .source_fence_identity_chirho
                .as_ref()
                .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?
                .clone(),
            binding_chirho: target_binding_chirho,
        })
    }

    pub fn activate_target_chirho(
        &mut self,
        warrant_chirho: &BoundMigrationWarrantChirho,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        if !matches!(
            self.phase_chirho,
            RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho
                | RootMovePhaseChirho::ActivatedChirho
        ) {
            return Err(out_of_order_chirho(
                self.phase_chirho,
                "activate_target_chirho",
            ));
        }
        self.require_source_append_fence_active_chirho()?;
        require_root_match_chirho(
            &warrant_chirho.source_root_chirho,
            &self.source_root_chirho,
            TenantMigrationRefusalChirho::SourceRootMismatchChirho,
        )?;
        require_root_match_chirho(
            &warrant_chirho.target_root_chirho,
            &self.target_root_chirho,
            TenantMigrationRefusalChirho::TargetRootMismatchChirho,
        )?;
        require_distinct_same_tenant_chirho(&self.source_root_chirho, &self.target_root_chirho)?;
        require_same_fence_identity_chirho(
            self.source_fence_identity_chirho
                .as_ref()
                .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?,
            &warrant_chirho.fence_identity_chirho,
        )?;
        require_same_binding_chirho(
            self.source_fence_binding_chirho
                .as_ref()
                .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?,
            &warrant_chirho.binding_chirho,
            TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho,
        )?;
        require_same_binding_chirho(
            self.verified_target_binding_chirho
                .as_ref()
                .ok_or(TenantMigrationRefusalChirho::SourceFenceBindingMissingChirho)?,
            &warrant_chirho.binding_chirho,
            TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho,
        )?;
        self.phase_chirho = RootMovePhaseChirho::ActivatedChirho;
        Ok(())
    }

    pub fn retire_source_chirho(
        &mut self,
        carried_chirho: &CarriedObligationsChirho,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        if self.phase_chirho == RootMovePhaseChirho::SourceRetiredChirho {
            return Ok(());
        }
        if self.phase_chirho != RootMovePhaseChirho::ActivatedChirho {
            return Err(out_of_order_chirho(
                self.phase_chirho,
                "retire_source_chirho",
            ));
        }
        self.require_source_append_fence_active_chirho()?;
        let missing_chirho = carried_chirho.missing_chirho();
        if !missing_chirho.is_empty() {
            return Err(TenantMigrationRefusalChirho::ObligationsNotCarriedChirho {
                missing_chirho,
            });
        }
        self.phase_chirho = RootMovePhaseChirho::SourceRetiredChirho;
        Ok(())
    }

    fn require_source_append_fence_active_chirho(
        &self,
    ) -> Result<(), TenantMigrationRefusalChirho> {
        let fence_chirho = self
            .source_fence_witness_chirho
            .as_ref()
            .ok_or(TenantMigrationRefusalChirho::SourceAppendFenceWitnessMissingChirho)?;
        if fence_chirho.remains_active_chirho() {
            Ok(())
        } else {
            Err(TenantMigrationRefusalChirho::SourceAppendFenceNotActiveChirho)
        }
    }
}

fn require_evidence_chirho(
    check_chirho: &PreliminaryMigrationCheckChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if check_chirho.references_checked_chirho() == 0 || check_chirho.surfaces_observed_chirho() == 0
    {
        Err(TenantMigrationRefusalChirho::TargetEvidenceEmptyChirho)
    } else {
        Ok(())
    }
}

fn require_distinct_same_tenant_chirho(
    source_chirho: &VerifiedTenantMigrationRootChirho,
    target_chirho: &VerifiedTenantMigrationRootChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if source_chirho.tenant_id_chirho != target_chirho.tenant_id_chirho {
        return Err(TenantMigrationRefusalChirho::TenantMismatchChirho);
    }
    if source_chirho.same_root_chirho(target_chirho)? {
        return Err(TenantMigrationRefusalChirho::SameRootRefusedChirho);
    }
    source_chirho.require_not_nested_with_chirho(target_chirho)?;
    Ok(())
}

fn require_cut_root_chirho(
    cut_chirho: &VerifiedTenantLedgerCutChirho,
    expected_root_chirho: &VerifiedTenantMigrationRootChirho,
    source_chirho: bool,
) -> Result<(), TenantMigrationRefusalChirho> {
    require_root_match_chirho(
        &cut_chirho.root_chirho,
        expected_root_chirho,
        if source_chirho {
            TenantMigrationRefusalChirho::SourceRootMismatchChirho
        } else {
            TenantMigrationRefusalChirho::TargetRootMismatchChirho
        },
    )
}

fn require_root_match_chirho(
    observed_chirho: &VerifiedTenantMigrationRootChirho,
    expected_chirho: &VerifiedTenantMigrationRootChirho,
    refusal_chirho: TenantMigrationRefusalChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if observed_chirho.tenant_id_chirho != expected_chirho.tenant_id_chirho
        || !observed_chirho.same_root_chirho(expected_chirho)?
    {
        return Err(refusal_chirho);
    }
    Ok(())
}

fn binding_from_cut_chirho(
    cut_chirho: VerifiedTenantLedgerCutChirho,
) -> TenantLedgerCutBindingChirho {
    TenantLedgerCutBindingChirho {
        cluster_id_chirho: cut_chirho.cluster_id_chirho,
        journal_path_chirho: cut_chirho.journal_path_chirho,
        cut_chirho: cut_chirho.cut_chirho,
    }
}

fn derive_attempt_identity_chirho(
    source_root_chirho: &VerifiedTenantMigrationRootChirho,
    target_root_chirho: &VerifiedTenantMigrationRootChirho,
    preliminary_source_binding_chirho: TenantLedgerCutBindingChirho,
    operation_authority_binding_digest_chirho: Option<&str>,
) -> Result<TenantMigrationAttemptIdentityChirho, TenantMigrationRefusalChirho> {
    require_distinct_same_tenant_chirho(source_root_chirho, target_root_chirho)?;
    let source_root_identity_chirho = source_root_chirho.binding_identity_digest_chirho()?;
    let target_root_identity_chirho = target_root_chirho.binding_identity_digest_chirho()?;
    let mut hasher_chirho = blake3::Hasher::new();
    frame_identity_field_chirho(
        &mut hasher_chirho,
        b"cairn-tenant-migration-attempt-v1-chirho",
    );
    frame_identity_field_chirho(
        &mut hasher_chirho,
        source_root_chirho.tenant_id_chirho.as_bytes(),
    );
    frame_identity_field_chirho(&mut hasher_chirho, &source_root_identity_chirho);
    frame_identity_field_chirho(&mut hasher_chirho, &target_root_identity_chirho);
    if let Some(operation_authority_binding_digest_chirho) =
        operation_authority_binding_digest_chirho
    {
        frame_identity_field_chirho(
            &mut hasher_chirho,
            b"tenant-migration-operation-authority-binding-v1-chirho",
        );
        frame_identity_field_chirho(
            &mut hasher_chirho,
            operation_authority_binding_digest_chirho.as_bytes(),
        );
    }
    frame_cut_binding_chirho(&mut hasher_chirho, &preliminary_source_binding_chirho);
    Ok(TenantMigrationAttemptIdentityChirho {
        digest_chirho: hasher_chirho.finalize().to_hex().to_string(),
        source_root_chirho: source_root_chirho.clone(),
        target_root_chirho: target_root_chirho.clone(),
        preliminary_source_binding_chirho,
    })
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn derive_fence_identity_digest_chirho(
    attempt_chirho: &TenantMigrationAttemptIdentityChirho,
    verified_source_binding_chirho: &TenantLedgerCutBindingChirho,
) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    frame_identity_field_chirho(
        &mut hasher_chirho,
        b"cairn-tenant-migration-fence-v1-chirho",
    );
    frame_identity_field_chirho(&mut hasher_chirho, attempt_chirho.digest_chirho.as_bytes());
    frame_cut_binding_chirho(&mut hasher_chirho, verified_source_binding_chirho);
    hasher_chirho.finalize().to_hex().to_string()
}

fn frame_cut_binding_chirho(
    hasher_chirho: &mut blake3::Hasher,
    binding_chirho: &TenantLedgerCutBindingChirho,
) {
    frame_identity_field_chirho(hasher_chirho, binding_chirho.cluster_id_chirho.0.as_bytes());
    frame_identity_field_chirho(
        hasher_chirho,
        binding_chirho.journal_path_chirho.key_chirho().as_bytes(),
    );
    frame_identity_field_chirho(
        hasher_chirho,
        &binding_chirho.cut_chirho.epoch_chirho().to_le_bytes(),
    );
    frame_identity_field_chirho(
        hasher_chirho,
        &binding_chirho.cut_chirho.seq_chirho().to_le_bytes(),
    );
    frame_identity_field_chirho(
        hasher_chirho,
        binding_chirho
            .cut_chirho
            .record_digest_chirho()
            .0
            .as_bytes(),
    );
    frame_identity_field_chirho(
        hasher_chirho,
        &binding_chirho
            .cut_chirho
            .hlc_chirho()
            .physical_ms_chirho
            .to_le_bytes(),
    );
    frame_identity_field_chirho(
        hasher_chirho,
        &binding_chirho
            .cut_chirho
            .hlc_chirho()
            .logical_chirho
            .to_le_bytes(),
    );
}

fn frame_identity_field_chirho(hasher_chirho: &mut blake3::Hasher, field_chirho: &[u8]) {
    let len_chirho =
        u64::try_from(field_chirho.len()).expect("tenant migration identity field length fits u64");
    hasher_chirho.update(&len_chirho.to_le_bytes());
    hasher_chirho.update(field_chirho);
}

fn require_same_journal_lane_chirho(
    preliminary_chirho: &TenantLedgerCutBindingChirho,
    verified_chirho: &TenantLedgerCutBindingChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if preliminary_chirho.cluster_id_chirho != verified_chirho.cluster_id_chirho
        || preliminary_chirho.journal_path_chirho != verified_chirho.journal_path_chirho
    {
        Err(TenantMigrationRefusalChirho::SourceFenceJournalLaneChangedChirho)
    } else {
        Ok(())
    }
}

fn require_same_attempt_identity_chirho(
    expected_chirho: &TenantMigrationAttemptIdentityChirho,
    observed_chirho: &TenantMigrationAttemptIdentityChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if expected_chirho == observed_chirho {
        Ok(())
    } else {
        Err(TenantMigrationRefusalChirho::SourceFenceAttemptMismatchChirho)
    }
}

fn require_same_fence_identity_chirho(
    expected_chirho: &TenantMigrationFenceIdentityChirho,
    observed_chirho: &TenantMigrationFenceIdentityChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if expected_chirho == observed_chirho {
        Ok(())
    } else {
        Err(TenantMigrationRefusalChirho::SourceFenceIdentityMismatchChirho)
    }
}

fn require_same_binding_chirho(
    left_chirho: &TenantLedgerCutBindingChirho,
    right_chirho: &TenantLedgerCutBindingChirho,
    refusal_chirho: TenantMigrationRefusalChirho,
) -> Result<(), TenantMigrationRefusalChirho> {
    if left_chirho.cluster_id_chirho != right_chirho.cluster_id_chirho
        || left_chirho.journal_path_chirho != right_chirho.journal_path_chirho
        || left_chirho.cut_chirho != right_chirho.cut_chirho
    {
        Err(refusal_chirho)
    } else {
        Ok(())
    }
}

fn out_of_order_chirho(
    from_chirho: RootMovePhaseChirho,
    attempted_chirho: &'static str,
) -> TenantMigrationRefusalChirho {
    TenantMigrationRefusalChirho::OutOfOrderChirho {
        from_chirho,
        attempted_chirho,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMigrationRefusalChirho {
    RootUnavailableChirho,
    RootIdentityChangedChirho,
    TenantMarkerInvalidChirho,
    PlatformRootRefusedChirho,
    TenantMismatchChirho,
    SameRootRefusedChirho,
    /// One root is nested inside the other. Distinct from `SameRootRefusedChirho`: the binding match
    /// there compares roots for IDENTITY, so a target sitting inside the source is two different
    /// roots and passes it. Measured 2026-08-19: a nested tenant root prepares and verifies, so this
    /// is reachable rather than theoretical, and a move onto a root inside the source would retire
    /// the source's key while the target lives in the retired tree.
    NestedRootRefusedChirho,
    LedgerNamespaceOutsideRootChirho,
    LedgerNamespaceIdentityChangedChirho,
    JournalVerificationRefusedChirho,
    SourceRootMismatchChirho,
    TargetRootMismatchChirho,
    TargetEvidenceEmptyChirho,
    PreliminaryCheckRequiredChirho,
    SourceFenceAttemptMissingChirho,
    SourceFenceAttemptMismatchChirho,
    SourceAppendFenceWitnessMissingChirho,
    SourceAppendFenceNotActiveChirho,
    SourceFenceIdentityMismatchChirho,
    SourceFenceJournalLaneChangedChirho,
    SourceFenceBindingMissingChirho,
    SourceFenceCutChangedChirho,
    SourceFenceTargetCutMismatchChirho,
    OperationAuthorityBindingInvalidChirho,
    OutOfOrderChirho {
        from_chirho: RootMovePhaseChirho,
        attempted_chirho: &'static str,
    },
    ObligationsNotCarriedChirho {
        missing_chirho: Vec<&'static str>,
    },
}

impl fmt::Display for TenantMigrationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl std::error::Error for TenantMigrationRefusalChirho {}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
