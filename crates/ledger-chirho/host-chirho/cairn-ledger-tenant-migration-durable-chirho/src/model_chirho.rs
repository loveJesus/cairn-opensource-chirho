// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use anyhow::Result;
use cairn_ledger_log_chirho::verified_prefix_state_chirho::{
    LedgerPrefixCutChirho, VerifiedLedgerReadCutChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const TENANT_MIGRATION_CONTROL_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-node-control-v1-chirho";
pub const TENANT_MIGRATION_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-checkpoint-v1-chirho";
pub const TENANT_MIGRATION_CHECKPOINT_SCHEMA_V2_CHIRHO: &str =
    "tenant-migration-checkpoint-v2-chirho";
pub const TENANT_MIGRATION_HEAD_SCHEMA_V1_CHIRHO: &str = "tenant-migration-head-v1-chirho";
pub const MAX_TENANT_MIGRATION_CHECKPOINT_BYTES_CHIRHO: usize = 32 * 1024;
pub const MAX_TENANT_MIGRATION_HEAD_BYTES_CHIRHO: usize = 8 * 1024;
pub const TENANT_MIGRATION_OPERATION_AUTHORITY_SCHEMA_V1_CHIRHO: &str =
    "tenant-migration-operation-authority-v1-chirho";
pub const TENANT_MIGRATION_OPERATION_AUTHORITY_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-operation-authority-digest-v1-chirho";
pub const MAX_TENANT_MIGRATION_OPERATION_AUTHORITY_BYTES_CHIRHO: usize = 16 * 1024;

/// Node-control signer for migration coordination records.
///
/// This is deliberately not a ledger signer. Ledger coordinates in these records are requests that
/// recovery full-verifies again; the signature authenticates which attempt this node was running.
pub trait TenantMigrationControlSignerPortChirho {
    fn key_id_chirho(&self) -> String;
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String>;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// Canonical operator-authority bytes bound into one durable migration attempt.
///
/// This crate deliberately does not interpret destination or writer-adoption policy. The resident
/// host verifies those typed records first, then hands this layer their exact canonical envelope.
/// Persisting and digesting that envelope means recovery can never replace either authority while
/// preserving the same roots and preliminary ledger cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationOperationAuthorityBindingChirho {
    schema_chirho: String,
    digest_domain_chirho: String,
    binding_digest_chirho: String,
    canonical_payload_chirho: String,
}

impl TenantMigrationOperationAuthorityBindingChirho {
    pub fn from_canonical_payload_chirho(
        canonical_payload_chirho: String,
    ) -> Result<Self, TenantMigrationOperationAuthorityRefusalChirho> {
        if canonical_payload_chirho.is_empty()
            || canonical_payload_chirho.len()
                > MAX_TENANT_MIGRATION_OPERATION_AUTHORITY_BYTES_CHIRHO
        {
            return Err(TenantMigrationOperationAuthorityRefusalChirho::SizeChirho);
        }
        let parsed_chirho: serde_json::Value = serde_json::from_str(&canonical_payload_chirho)
            .map_err(|_error_chirho| {
                TenantMigrationOperationAuthorityRefusalChirho::CanonicalPayloadChirho
            })?;
        if !parsed_chirho.is_object()
            || serde_json::to_string(&parsed_chirho).map_err(|_error_chirho| {
                TenantMigrationOperationAuthorityRefusalChirho::CanonicalPayloadChirho
            })? != canonical_payload_chirho
        {
            return Err(TenantMigrationOperationAuthorityRefusalChirho::CanonicalPayloadChirho);
        }
        let binding_digest_chirho =
            operation_authority_digest_chirho(canonical_payload_chirho.as_bytes());
        Ok(Self {
            schema_chirho: TENANT_MIGRATION_OPERATION_AUTHORITY_SCHEMA_V1_CHIRHO.to_owned(),
            digest_domain_chirho: TENANT_MIGRATION_OPERATION_AUTHORITY_DOMAIN_V1_CHIRHO.to_owned(),
            binding_digest_chirho,
            canonical_payload_chirho,
        })
    }

    pub fn binding_digest_chirho(&self) -> &str {
        &self.binding_digest_chirho
    }

    pub fn canonical_payload_chirho(&self) -> &str {
        &self.canonical_payload_chirho
    }

    pub(crate) fn validate_chirho(
        &self,
    ) -> Result<(), TenantMigrationOperationAuthorityRefusalChirho> {
        if self.schema_chirho != TENANT_MIGRATION_OPERATION_AUTHORITY_SCHEMA_V1_CHIRHO
            || self.digest_domain_chirho != TENANT_MIGRATION_OPERATION_AUTHORITY_DOMAIN_V1_CHIRHO
        {
            return Err(TenantMigrationOperationAuthorityRefusalChirho::SchemaChirho);
        }
        let rebuilt_chirho =
            Self::from_canonical_payload_chirho(self.canonical_payload_chirho.clone())?;
        if rebuilt_chirho != *self {
            return Err(TenantMigrationOperationAuthorityRefusalChirho::DigestChirho);
        }
        Ok(())
    }
}

fn operation_authority_digest_chirho(payload_chirho: &[u8]) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(TENANT_MIGRATION_OPERATION_AUTHORITY_DOMAIN_V1_CHIRHO.as_bytes());
    hasher_chirho.update(&(payload_chirho.len() as u64).to_be_bytes());
    hasher_chirho.update(payload_chirho);
    hasher_chirho.finalize().to_hex().to_string()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantMigrationOperationAuthorityRefusalChirho {
    SchemaChirho,
    SizeChirho,
    CanonicalPayloadChirho,
    DigestChirho,
}

/// Caller-constructible coordinate persisted for later full re-verification, never authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationCutClaimChirho {
    pub epoch_chirho: u64,
    pub seq_chirho: u64,
    pub record_digest_chirho: String,
}

impl TenantMigrationCutClaimChirho {
    pub(crate) fn from_verified_chirho(cut_chirho: &VerifiedLedgerReadCutChirho) -> Self {
        Self {
            epoch_chirho: cut_chirho.epoch_chirho(),
            seq_chirho: cut_chirho.seq_chirho(),
            record_digest_chirho: cut_chirho.record_digest_chirho().0.clone(),
        }
    }

    pub fn request_chirho(&self) -> LedgerPrefixCutChirho {
        LedgerPrefixCutChirho::new_chirho(
            self.epoch_chirho,
            self.seq_chirho,
            DigestChirho(self.record_digest_chirho.clone()),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationPhaseChirho {
    PreparingChirho,
    SourceFencedChirho,
    /// Reserved in v1 so target activation does not require a signed-schema migration later.
    /// This brick parses but refuses the phase as unimplemented at startup.
    TargetActivatedSourceRetainedChirho,
    AbortedChirho,
}

impl TenantMigrationPhaseChirho {
    pub fn is_active_source_fence_chirho(self) -> bool {
        matches!(self, Self::PreparingChirho | Self::SourceFencedChirho)
    }
}

/// One immutable node-control-signed transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationCheckpointChirho {
    pub domain_chirho: String,
    pub schema_chirho: String,
    pub tenant_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub source_node_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_path_chirho: String,
    pub attempt_digest_chirho: String,
    pub operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
    pub preliminary_source_cut_chirho: TenantMigrationCutClaimChirho,
    pub post_fence_source_cut_chirho: Option<TenantMigrationCutClaimChirho>,
    pub fence_identity_digest_chirho: Option<String>,
    pub transition_seq_chirho: u64,
    pub previous_checkpoint_ref_chirho: Option<String>,
    pub phase_chirho: TenantMigrationPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// Fixed O(1)-addressed pointer to the latest migration checkpoint for one source node/group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationHeadChirho {
    pub domain_chirho: String,
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub source_node_chirho: String,
    pub attempt_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub transition_seq_chirho: u64,
    pub phase_chirho: TenantMigrationPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveTenantMigrationChirho {
    pub(crate) checkpoint_ref_chirho: String,
    pub(crate) checkpoint_chirho: TenantMigrationCheckpointChirho,
}

impl ActiveTenantMigrationChirho {
    pub fn attempt_digest_chirho(&self) -> &str {
        &self.checkpoint_chirho.attempt_digest_chirho
    }

    pub fn checkpoint_ref_chirho(&self) -> &str {
        &self.checkpoint_ref_chirho
    }

    pub fn checkpoint_chirho(&self) -> &TenantMigrationCheckpointChirho {
        &self.checkpoint_chirho
    }

    pub fn phase_chirho(&self) -> TenantMigrationPhaseChirho {
        self.checkpoint_chirho.phase_chirho
    }

    pub fn operation_authority_chirho(&self) -> &TenantMigrationOperationAuthorityBindingChirho {
        &self.checkpoint_chirho.operation_authority_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedTenantMigrationChirho {
    pub active_chirho: ActiveTenantMigrationChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMigrationCommitOutcomeChirho {
    DurableChirho(CommittedTenantMigrationChirho),
    DurabilityUnconfirmedChirho(CommittedTenantMigrationChirho),
}

impl TenantMigrationCommitOutcomeChirho {
    pub fn into_parts_chirho(self) -> (CommittedTenantMigrationChirho, bool) {
        match self {
            Self::DurableChirho(committed_chirho) => (committed_chirho, true),
            Self::DurabilityUnconfirmedChirho(committed_chirho) => (committed_chirho, false),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationStoreRefusalChirho {
    InvalidIdentityChirho,
    WrongNodeSignerChirho,
    ActiveAttemptMismatchChirho,
    WrongExpectedPriorChirho,
    InvalidTransitionChirho,
    /// The fence identity the caller independently verified is not the one this attempt recorded
    /// when it fenced. Distinct from `InvalidTransitionChirho` on purpose: the phase order was
    /// legal and the BINDING was wrong, and an arm that cannot tell those apart proves neither.
    FenceIdentityMismatchChirho,
    MalformedHeadChirho,
    MalformedCheckpointChirho,
    NonCanonicalHeadChirho,
    NonCanonicalCheckpointChirho,
    OversizedHeadChirho,
    OversizedCheckpointChirho,
    InvalidHeadSignatureChirho,
    InvalidCheckpointSignatureChirho,
    MissingCheckpointChirho,
    DigestMismatchChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for TenantMigrationStoreRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl Error for TenantMigrationStoreRefusalChirho {}
