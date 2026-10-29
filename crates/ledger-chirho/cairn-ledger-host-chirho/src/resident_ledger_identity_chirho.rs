// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Signed, canonical identity bytes for an elected resident ledger composition.
//!
//! The generic writer-head primitive deliberately treats these bytes as opaque. This module binds
//! them to the exact canonical root and storage directory identities, consistency group, logical
//! journal key, cluster, opening epoch, complete verified genesis, and pre-provisioned elected node
//! key. Verification is bounded and occurs before journal history access or repair. Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md` §4.

use crate::resident_authority_chirho::sink_term_lifecycle_chirho::VerifiedResidentSinkTermCellAtBirthChirho;
use crate::storage_chirho::{FsLedgerStorageChirho, StableLedgerNamespaceSnapshotChirho};
use anyhow::{bail, Context, Result};
use cairn_ledger_log_chirho::journal_chirho::{
    PreparedLedgerGenesisChirho, MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    parse_canonical_ledger_journal_line_chirho, stored_line_digest_chirho, LedgerJournalLineChirho,
};
use cairn_signer_chirho::signer_chirho::{
    sign_with_existing_key_possession_chirho, verify_with_pubkey_chirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_head_chirho::resident_writer_chirho::{
    canonical_filesystem_path_digest_chirho, MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, ConsistencyGroupIdChirho,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path};

pub(crate) const RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO: &str = "resident-ledger-identity-v4-chirho";
pub(crate) const RESIDENT_LEDGER_LEGACY_V3_IDENTITY_KIND_CHIRHO: &str =
    "resident-ledger-identity-v3-chirho";
const RESIDENT_LEDGER_PENDING_SCHEMA_CHIRHO: &str = "resident-ledger-pending-identity-v4-chirho";
const RESIDENT_LEDGER_BOUND_SCHEMA_CHIRHO: &str = "resident-ledger-bound-identity-v4-chirho";
#[cfg(test)]
const RESIDENT_LEDGER_LEGACY_V3_PENDING_SCHEMA_CHIRHO: &str =
    "resident-ledger-pending-identity-v3-chirho";
const RESIDENT_LEDGER_LEGACY_V3_BOUND_SCHEMA_CHIRHO: &str =
    "resident-ledger-bound-identity-v3-chirho";
const CANONICAL_PATH_DIGEST_PREFIX_CHIRHO: &str = "canonical-filesystem-path-blake3-v1-chirho:";
const LOGICAL_STORAGE_DIGEST_PREFIX_CHIRHO: &str = "root-relative-storage-blake3-v1-chirho:";
const CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO: &str = "writer-fence-group-blake3-chirho:";
const MAX_CLUSTER_IDENTITY_BYTES_CHIRHO: usize = 128;
const MAX_LOGICAL_STORAGE_NAMESPACE_BYTES_CHIRHO: usize = 4_096;

#[derive(Clone, Copy)]
pub(crate) struct ResidentLedgerCoordinateSourceChirho<'source_chirho> {
    pub root_chirho: &'source_chirho Path,
    pub authority_root_snapshot_chirho: &'source_chirho StableLedgerNamespaceSnapshotChirho,
    pub group_chirho: &'source_chirho ConsistencyGroupIdChirho,
    pub storage_chirho: &'source_chirho FsLedgerStorageChirho,
    pub storage_snapshot_chirho: &'source_chirho StableLedgerNamespaceSnapshotChirho,
    pub identity_storage_namespace_chirho: &'source_chirho Path,
    pub journal_path_chirho: &'source_chirho StoragePathChirho,
    pub cluster_id_chirho: &'source_chirho ClusterIdChirho,
    pub opening_epoch_chirho: u64,
    pub local_node_chirho: &'source_chirho NodeIdChirho,
}

pub(crate) struct VerifiedResidentLedgerBoundIdentityChirho {
    verified_genesis_line_chirho: String,
    verified_genesis_digest_chirho: DigestChirho,
    sink_term_fence_birth_term_chirho: Option<u64>,
}

pub(crate) struct VerifiedResidentLedgerPendingIdentityChirho {
    prepared_genesis_line_chirho: String,
    prepared_genesis_digest_chirho: DigestChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResidentLedgerBoundIdentityVerificationRefusalChirho {
    CurrentBirthTermMissingChirho,
}

impl fmt::Display for ResidentLedgerBoundIdentityVerificationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentBirthTermMissingChirho => formatter_chirho
                .write_str("current Bound identity is missing its signed sink-cell birth term"),
        }
    }
}

impl Error for ResidentLedgerBoundIdentityVerificationRefusalChirho {}

impl VerifiedResidentLedgerPendingIdentityChirho {
    pub(crate) fn prepared_genesis_line_chirho(&self) -> &str {
        &self.prepared_genesis_line_chirho
    }

    pub(crate) fn prepared_genesis_digest_chirho(&self) -> &DigestChirho {
        &self.prepared_genesis_digest_chirho
    }
}

impl VerifiedResidentLedgerBoundIdentityChirho {
    pub(crate) fn verified_genesis_line_chirho(&self) -> &str {
        &self.verified_genesis_line_chirho
    }

    pub(crate) fn verified_genesis_digest_chirho(&self) -> &DigestChirho {
        &self.verified_genesis_digest_chirho
    }

    pub(crate) fn sink_term_fence_birth_term_chirho(
        &self,
    ) -> Result<u64, ResidentLedgerBoundIdentityVerificationRefusalChirho> {
        self.sink_term_fence_birth_term_chirho.ok_or(
            ResidentLedgerBoundIdentityVerificationRefusalChirho::CurrentBirthTermMissingChirho,
        )
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentLedgerCoordinateChirho {
    canonical_root_digest_chirho: String,
    authority_root_device_chirho: u64,
    authority_root_inode_chirho: u64,
    consistency_group_digest_chirho: String,
    cluster_id_chirho: String,
    opening_epoch_chirho: u64,
    logical_storage_namespace_digest_chirho: String,
    storage_namespace_device_chirho: u64,
    storage_namespace_inode_chirho: u64,
    journal_storage_key_chirho: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ResidentLedgerIdentityStateChirho {
    #[serde(rename = "pending_chirho")]
    PendingChirho,
    #[serde(rename = "bound_chirho")]
    BoundChirho,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentLedgerPendingIdentityChirho {
    schema_chirho: String,
    state_chirho: ResidentLedgerIdentityStateChirho,
    coordinate_chirho: ResidentLedgerCoordinateChirho,
    prepared_genesis_line_chirho: String,
    prepared_genesis_digest_chirho: String,
    signer_key_id_chirho: String,
    sig_chirho: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentLedgerBoundIdentityChirho {
    schema_chirho: String,
    state_chirho: ResidentLedgerIdentityStateChirho,
    coordinate_chirho: ResidentLedgerCoordinateChirho,
    verified_genesis_line_chirho: String,
    verified_genesis_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sink_term_fence_birth_term_chirho: Option<u64>,
    signer_key_id_chirho: String,
    sig_chirho: String,
}

pub(crate) fn canonical_pending_identity_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    prepared_genesis_chirho: &PreparedLedgerGenesisChirho,
) -> Result<Vec<u8>> {
    if prepared_genesis_chirho.cluster_id_chirho() != source_chirho.cluster_id_chirho
        || prepared_genesis_chirho.opening_epoch_chirho() != source_chirho.opening_epoch_chirho
    {
        bail!("ResidentLedgerPreparedGenesisCoordinateMismatchChirho");
    }
    let coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    let canonical_chirho = canonical_pending_identity_for_coordinate_chirho(
        source_chirho.root_chirho,
        source_chirho.local_node_chirho,
        coordinate_chirho,
        prepared_genesis_chirho.canonical_line_chirho(),
        prepared_genesis_chirho.digest_chirho(),
    )?;
    let verified_chirho = verify_pending_identity_chirho(&canonical_chirho, source_chirho)?;
    if verified_chirho.prepared_genesis_line_chirho()
        != prepared_genesis_chirho.canonical_line_chirho()
        || verified_chirho.prepared_genesis_digest_chirho()
            != prepared_genesis_chirho.digest_chirho()
    {
        bail!("ResidentLedgerPendingGenesisSelfVerificationMismatchChirho");
    }
    Ok(canonical_chirho)
}

fn canonical_pending_identity_for_coordinate_chirho(
    root_chirho: &Path,
    local_node_chirho: &NodeIdChirho,
    coordinate_chirho: ResidentLedgerCoordinateChirho,
    prepared_genesis_line_chirho: &str,
    prepared_genesis_digest_chirho: &DigestChirho,
) -> Result<Vec<u8>> {
    canonical_pending_identity_for_coordinate_with_schema_chirho(
        root_chirho,
        local_node_chirho,
        coordinate_chirho,
        prepared_genesis_line_chirho,
        prepared_genesis_digest_chirho,
        RESIDENT_LEDGER_PENDING_SCHEMA_CHIRHO,
    )
}

fn canonical_pending_identity_for_coordinate_with_schema_chirho(
    root_chirho: &Path,
    local_node_chirho: &NodeIdChirho,
    coordinate_chirho: ResidentLedgerCoordinateChirho,
    prepared_genesis_line_chirho: &str,
    prepared_genesis_digest_chirho: &DigestChirho,
    schema_chirho: &str,
) -> Result<Vec<u8>> {
    let mut identity_chirho = ResidentLedgerPendingIdentityChirho {
        schema_chirho: schema_chirho.to_owned(),
        state_chirho: ResidentLedgerIdentityStateChirho::PendingChirho,
        coordinate_chirho,
        prepared_genesis_line_chirho: prepared_genesis_line_chirho.to_owned(),
        prepared_genesis_digest_chirho: prepared_genesis_digest_chirho.0.clone(),
        signer_key_id_chirho: local_node_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    let signed_content_chirho = serde_json::to_vec(&identity_chirho)?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(root_chirho, &signed_content_chirho)?;
    if possession_chirho.key_id_chirho() != local_node_chirho.0 {
        bail!("ResidentLedgerIdentitySignerNodeMismatchChirho");
    }
    verify_signature_chirho(
        possession_chirho.key_id_chirho(),
        &signed_content_chirho,
        possession_chirho.signature_hex_chirho(),
    )?;
    identity_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(serde_json::to_vec(&identity_chirho)?)
}

pub(crate) fn canonical_bound_identity_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    verified_genesis_line_chirho: &str,
    verified_genesis_digest_chirho: &DigestChirho,
    sink_term_cell_birth_chirho: VerifiedResidentSinkTermCellAtBirthChirho,
) -> Result<Vec<u8>> {
    let coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    if coordinate_chirho.consistency_group_digest_chirho
        != sink_term_cell_birth_chirho.group_digest_chirho()
    {
        bail!("ResidentLedgerSinkTermCellBirthCoordinateMismatchChirho");
    }
    let sink_term_fence_birth_term_chirho = sink_term_cell_birth_chirho.accepted_term_chirho();
    validate_complete_genesis_commitment_chirho(
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        &coordinate_chirho,
        "bound",
    )?;
    let canonical_chirho = canonical_bound_identity_for_coordinate_chirho(
        source_chirho.root_chirho,
        source_chirho.local_node_chirho,
        coordinate_chirho,
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        RESIDENT_LEDGER_BOUND_SCHEMA_CHIRHO,
        Some(sink_term_fence_birth_term_chirho),
    )?;
    let verified_chirho = verify_bound_identity_chirho(&canonical_chirho, source_chirho)?;
    if verified_chirho.verified_genesis_line_chirho() != verified_genesis_line_chirho
        || verified_chirho.verified_genesis_digest_chirho() != verified_genesis_digest_chirho
        || verified_chirho.sink_term_fence_birth_term_chirho()? != sink_term_fence_birth_term_chirho
    {
        bail!("ResidentLedgerBoundGenesisSelfVerificationMismatchChirho");
    }
    Ok(canonical_chirho)
}

#[cfg(test)]
pub(crate) fn canonical_legacy_v3_pending_identity_for_test_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    prepared_genesis_chirho: &PreparedLedgerGenesisChirho,
) -> Result<Vec<u8>> {
    let coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    canonical_pending_identity_for_coordinate_with_schema_chirho(
        source_chirho.root_chirho,
        source_chirho.local_node_chirho,
        coordinate_chirho,
        prepared_genesis_chirho.canonical_line_chirho(),
        prepared_genesis_chirho.digest_chirho(),
        RESIDENT_LEDGER_LEGACY_V3_PENDING_SCHEMA_CHIRHO,
    )
}

#[cfg(test)]
pub(crate) fn canonical_legacy_v3_bound_identity_for_test_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    verified_genesis_line_chirho: &str,
    verified_genesis_digest_chirho: &DigestChirho,
) -> Result<Vec<u8>> {
    let coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    validate_complete_genesis_commitment_chirho(
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        &coordinate_chirho,
        "legacy-v3-bound",
    )?;
    canonical_bound_identity_for_coordinate_chirho(
        source_chirho.root_chirho,
        source_chirho.local_node_chirho,
        coordinate_chirho,
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        RESIDENT_LEDGER_LEGACY_V3_BOUND_SCHEMA_CHIRHO,
        None,
    )
}

#[cfg(test)]
pub(crate) fn canonical_current_v4_bound_identity_without_birth_term_for_test_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    verified_genesis_line_chirho: &str,
    verified_genesis_digest_chirho: &DigestChirho,
) -> Result<Vec<u8>> {
    let coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    validate_complete_genesis_commitment_chirho(
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        &coordinate_chirho,
        "current-v4-bound-without-birth-term",
    )?;
    canonical_bound_identity_for_coordinate_chirho(
        source_chirho.root_chirho,
        source_chirho.local_node_chirho,
        coordinate_chirho,
        verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        RESIDENT_LEDGER_BOUND_SCHEMA_CHIRHO,
        None,
    )
}

fn canonical_bound_identity_for_coordinate_chirho(
    root_chirho: &Path,
    local_node_chirho: &NodeIdChirho,
    coordinate_chirho: ResidentLedgerCoordinateChirho,
    verified_genesis_line_chirho: &str,
    verified_genesis_digest_chirho: &DigestChirho,
    schema_chirho: &str,
    sink_term_fence_birth_term_chirho: Option<u64>,
) -> Result<Vec<u8>> {
    let mut identity_chirho = ResidentLedgerBoundIdentityChirho {
        schema_chirho: schema_chirho.to_owned(),
        state_chirho: ResidentLedgerIdentityStateChirho::BoundChirho,
        coordinate_chirho,
        verified_genesis_line_chirho: verified_genesis_line_chirho.to_owned(),
        verified_genesis_digest_chirho: verified_genesis_digest_chirho.0.clone(),
        sink_term_fence_birth_term_chirho,
        signer_key_id_chirho: local_node_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    let signed_content_chirho = serde_json::to_vec(&identity_chirho)?;
    let possession_chirho =
        sign_with_existing_key_possession_chirho(root_chirho, &signed_content_chirho)?;
    if possession_chirho.key_id_chirho() != local_node_chirho.0 {
        bail!("ResidentLedgerIdentitySignerNodeMismatchChirho");
    }
    verify_signature_chirho(
        possession_chirho.key_id_chirho(),
        &signed_content_chirho,
        possession_chirho.signature_hex_chirho(),
    )?;
    identity_chirho.sig_chirho = possession_chirho.into_signature_hex_chirho();
    Ok(serde_json::to_vec(&identity_chirho)?)
}

pub(crate) fn verify_pending_identity_chirho(
    canonical_chirho: &[u8],
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<VerifiedResidentLedgerPendingIdentityChirho> {
    let identity_chirho: ResidentLedgerPendingIdentityChirho =
        parse_canonical_identity_chirho(canonical_chirho)?;
    if identity_chirho.schema_chirho != RESIDENT_LEDGER_PENDING_SCHEMA_CHIRHO
        || identity_chirho.state_chirho != ResidentLedgerIdentityStateChirho::PendingChirho
    {
        bail!("ResidentLedgerPendingIdentitySchemaMismatchChirho");
    }
    let expected_coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    validate_and_verify_pending_identity_chirho(
        &identity_chirho,
        &expected_coordinate_chirho,
        source_chirho,
    )
}

/// Why a Bound identity is being verified. Fixes ALL THREE verification parameters together.
///
/// The variants are the three CALLERS, not three flag tuples. A role makes a call site declare why it
/// verifies instead of choosing a combination, and every invalid combination becomes unrepresentable.
/// The governance property matters more than the type safety: a FOURTH shape now costs a named role
/// defended in review, whereas the previous form — `expected_schema` followed by two adjacent
/// same-typed bools — let a new call site pair them wrongly, or transpose them, and still compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum BoundIdentityVerificationRoleChirho {
    /// Admitting the active resident writer: current schema, signed birth term, and proven current
    /// private-key possession.
    ActiveWriterAdmissionChirho,
    /// Classifying a legacy v3 Bound identity so active reopen can refuse it BY NAME. Never serving
    /// authority, and legacy identities predate the birth term, so requiring one would refuse every
    /// legitimate legacy identity.
    LegacyEvidenceClassificationChirho,
    /// Reading as the deposed side. Current schema and signed birth term still required; possession is
    /// NOT, because a deposed reader intentionally may not retain the former writer's private key.
    DeposedReaderChirho,
}

impl BoundIdentityVerificationRoleChirho {
    fn expected_schema_chirho(self) -> &'static str {
        match self {
            Self::ActiveWriterAdmissionChirho | Self::DeposedReaderChirho => {
                RESIDENT_LEDGER_BOUND_SCHEMA_CHIRHO
            }
            Self::LegacyEvidenceClassificationChirho => {
                RESIDENT_LEDGER_LEGACY_V3_BOUND_SCHEMA_CHIRHO
            }
        }
    }

    fn requires_birth_term_chirho(self) -> bool {
        match self {
            Self::ActiveWriterAdmissionChirho | Self::DeposedReaderChirho => true,
            Self::LegacyEvidenceClassificationChirho => false,
        }
    }

    fn requires_possession_chirho(self) -> bool {
        match self {
            Self::ActiveWriterAdmissionChirho | Self::LegacyEvidenceClassificationChirho => true,
            Self::DeposedReaderChirho => false,
        }
    }
}

pub(crate) fn verify_bound_identity_chirho(
    canonical_chirho: &[u8],
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<VerifiedResidentLedgerBoundIdentityChirho> {
    verify_bound_identity_for_role_chirho(
        canonical_chirho,
        source_chirho,
        BoundIdentityVerificationRoleChirho::ActiveWriterAdmissionChirho,
    )
}

/// Fully verify a signed legacy v3 Bound identity only so active reopen can refuse it by name.
///
/// A successful return is evidence classification, never serving authority. Current production
/// construction cannot mint this schema or its outer identity kind.
pub(crate) fn verify_legacy_v3_bound_identity_chirho(
    canonical_chirho: &[u8],
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<VerifiedResidentLedgerBoundIdentityChirho> {
    verify_bound_identity_for_role_chirho(
        canonical_chirho,
        source_chirho,
        BoundIdentityVerificationRoleChirho::LegacyEvidenceClassificationChirho,
    )
}

/// Verify an exact retained bound identity using only its public key.
///
/// A held/deposed reader intentionally may not retain the former writer's private key. It still
/// verifies canonical bytes, the full external coordinate, the persisted node signature, and the
/// exact genesis commitment. Active writer admission continues through
/// [`verify_bound_identity_chirho`], which additionally proves current private-key possession.
pub(crate) fn verify_bound_identity_public_chirho(
    canonical_chirho: &[u8],
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<VerifiedResidentLedgerBoundIdentityChirho> {
    verify_bound_identity_for_role_chirho(
        canonical_chirho,
        source_chirho,
        BoundIdentityVerificationRoleChirho::DeposedReaderChirho,
    )
}

/// Verify a Bound identity under exactly one role, which supplies every verification parameter.
///
/// Named for the role rather than for possession: possession is one of three parameters the role
/// fixes, so a name asserting only that dimension would describe a third of what the function does.
fn verify_bound_identity_for_role_chirho(
    canonical_chirho: &[u8],
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    role_chirho: BoundIdentityVerificationRoleChirho,
) -> Result<VerifiedResidentLedgerBoundIdentityChirho> {
    let expected_schema_chirho = role_chirho.expected_schema_chirho();
    let require_birth_term_chirho = role_chirho.requires_birth_term_chirho();
    let require_possession_chirho = role_chirho.requires_possession_chirho();
    let identity_chirho: ResidentLedgerBoundIdentityChirho =
        parse_canonical_identity_chirho(canonical_chirho)?;
    if identity_chirho.schema_chirho != expected_schema_chirho
        || identity_chirho.state_chirho != ResidentLedgerIdentityStateChirho::BoundChirho
    {
        bail!("ResidentLedgerBoundIdentitySchemaMismatchChirho");
    }
    let expected_coordinate_chirho = resident_ledger_coordinate_chirho(source_chirho)?;
    validate_identity_coordinate_chirho(
        &identity_chirho.coordinate_chirho,
        &expected_coordinate_chirho,
    )?;
    validate_signer_key_chirho(&identity_chirho.signer_key_id_chirho, source_chirho)?;
    validate_lower_hex_chirho(&identity_chirho.sig_chirho, 128, "identity signature")?;
    let mut unsigned_chirho = identity_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    verify_signature_chirho(
        &identity_chirho.signer_key_id_chirho,
        &serde_json::to_vec(&unsigned_chirho)?,
        &identity_chirho.sig_chirho,
    )?;
    if require_possession_chirho {
        prove_current_signer_possession_chirho(
            source_chirho,
            &identity_chirho.signer_key_id_chirho,
            &serde_json::to_vec(&unsigned_chirho)?,
        )?;
    }
    if require_birth_term_chirho && identity_chirho.sink_term_fence_birth_term_chirho.is_none() {
        return Err(
            ResidentLedgerBoundIdentityVerificationRefusalChirho::CurrentBirthTermMissingChirho
                .into(),
        );
    }
    if !require_birth_term_chirho && identity_chirho.sink_term_fence_birth_term_chirho.is_some() {
        bail!("ResidentLedgerLegacyBoundIdentityUnexpectedSinkTermBirthProofChirho");
    }
    let verified_genesis_digest_chirho =
        DigestChirho(identity_chirho.verified_genesis_digest_chirho.clone());
    validate_complete_genesis_commitment_chirho(
        &identity_chirho.verified_genesis_line_chirho,
        &verified_genesis_digest_chirho,
        &identity_chirho.coordinate_chirho,
        "bound",
    )?;
    Ok(VerifiedResidentLedgerBoundIdentityChirho {
        verified_genesis_line_chirho: identity_chirho.verified_genesis_line_chirho,
        verified_genesis_digest_chirho,
        sink_term_fence_birth_term_chirho: identity_chirho.sink_term_fence_birth_term_chirho,
    })
}

/// Read the self-declared opening epoch needed to construct the full external coordinate verifier.
///
/// This is not an acceptance step. The caller must immediately pass the result into
/// [`verify_bound_identity_chirho`] or [`verify_bound_identity_public_chirho`], which verifies the
/// complete coordinate, signature, and exact signed genesis commitment. Active writers additionally
/// require current key possession.
pub(crate) fn inspect_bound_identity_opening_epoch_chirho(canonical_chirho: &[u8]) -> Result<u64> {
    let identity_chirho: ResidentLedgerBoundIdentityChirho =
        parse_canonical_identity_chirho(canonical_chirho)?;
    if identity_chirho.schema_chirho != RESIDENT_LEDGER_BOUND_SCHEMA_CHIRHO
        || identity_chirho.state_chirho != ResidentLedgerIdentityStateChirho::BoundChirho
    {
        bail!("ResidentLedgerBoundIdentitySchemaMismatchChirho");
    }
    validate_complete_genesis_commitment_chirho(
        &identity_chirho.verified_genesis_line_chirho,
        &DigestChirho(identity_chirho.verified_genesis_digest_chirho),
        &identity_chirho.coordinate_chirho,
        "bound-opening-epoch",
    )?;
    Ok(identity_chirho.coordinate_chirho.opening_epoch_chirho)
}

fn validate_and_verify_pending_identity_chirho(
    identity_chirho: &ResidentLedgerPendingIdentityChirho,
    expected_coordinate_chirho: &ResidentLedgerCoordinateChirho,
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<VerifiedResidentLedgerPendingIdentityChirho> {
    validate_identity_coordinate_chirho(
        &identity_chirho.coordinate_chirho,
        expected_coordinate_chirho,
    )?;
    validate_signer_key_chirho(&identity_chirho.signer_key_id_chirho, source_chirho)?;
    validate_lower_hex_chirho(&identity_chirho.sig_chirho, 128, "identity signature")?;
    let mut unsigned_chirho = identity_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    verify_signature_chirho(
        &identity_chirho.signer_key_id_chirho,
        &serde_json::to_vec(&unsigned_chirho)?,
        &identity_chirho.sig_chirho,
    )?;
    prove_current_signer_possession_chirho(
        source_chirho,
        &identity_chirho.signer_key_id_chirho,
        &serde_json::to_vec(&unsigned_chirho)?,
    )?;
    let actual_digest_chirho = DigestChirho(identity_chirho.prepared_genesis_digest_chirho.clone());
    validate_complete_genesis_commitment_chirho(
        &identity_chirho.prepared_genesis_line_chirho,
        &actual_digest_chirho,
        &identity_chirho.coordinate_chirho,
        "pending",
    )?;
    Ok(VerifiedResidentLedgerPendingIdentityChirho {
        prepared_genesis_line_chirho: identity_chirho.prepared_genesis_line_chirho.clone(),
        prepared_genesis_digest_chirho: actual_digest_chirho,
    })
}

fn validate_complete_genesis_commitment_chirho(
    canonical_line_chirho: &str,
    digest_chirho: &DigestChirho,
    coordinate_chirho: &ResidentLedgerCoordinateChirho,
    state_label_chirho: &str,
) -> Result<()> {
    if canonical_line_chirho.len() > MAX_EXPECTED_GENESIS_LINE_BYTES_CHIRHO {
        bail!("ResidentLedgerGenesisLineBoundsChirho:{state_label_chirho}");
    }
    validate_lower_hex_chirho(&digest_chirho.0, 64, "genesis digest")?;
    let genesis_chirho = match parse_canonical_ledger_journal_line_chirho(canonical_line_chirho)
        .map_err(|error_chirho| {
            anyhow::anyhow!("resident {state_label_chirho} genesis wire refusal: {error_chirho:?}")
        })? {
        LedgerJournalLineChirho::GenesisChirho(genesis_chirho) => genesis_chirho,
        LedgerJournalLineChirho::RecordChirho(_) => {
            bail!("ResidentLedgerGenesisLineKindMismatchChirho:{state_label_chirho}");
        }
    };
    if genesis_chirho.cluster_id_chirho.0 != coordinate_chirho.cluster_id_chirho
        || genesis_chirho.epoch_chirho != coordinate_chirho.opening_epoch_chirho
    {
        bail!("ResidentLedgerGenesisCoordinateMismatchChirho:{state_label_chirho}");
    }
    if stored_line_digest_chirho(canonical_line_chirho) != *digest_chirho {
        bail!("ResidentLedgerGenesisDigestMismatchChirho:{state_label_chirho}");
    }
    Ok(())
}

fn parse_canonical_identity_chirho<IdentityChirho>(
    canonical_chirho: &[u8],
) -> Result<IdentityChirho>
where
    IdentityChirho: DeserializeOwned + Serialize,
{
    if canonical_chirho.len() > MAX_RESIDENT_WRITER_IDENTITY_BYTES_CHIRHO {
        bail!("ResidentLedgerIdentityBoundsChirho");
    }
    let identity_chirho: IdentityChirho = serde_json::from_slice(canonical_chirho)
        .context("parse canonical resident ledger identity")?;
    if serde_json::to_vec(&identity_chirho)? != canonical_chirho {
        bail!("ResidentLedgerIdentityNonCanonicalChirho");
    }
    Ok(identity_chirho)
}

fn resident_ledger_coordinate_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<ResidentLedgerCoordinateChirho> {
    source_chirho
        .authority_root_snapshot_chirho
        .verify_current_path_chirho(source_chirho.root_chirho)?;
    let canonical_root_chirho = source_chirho
        .root_chirho
        .canonicalize()
        .context("canonicalize resident ledger root")?;
    if canonical_root_chirho.to_str().is_none() {
        bail!("ResidentLedgerRootMustBeUtf8Chirho");
    }
    let actual_group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
    if actual_group_chirho != *source_chirho.group_chirho {
        bail!("ResidentLedgerConsistencyGroupMismatchChirho");
    }
    let storage_root_chirho = source_chirho.storage_chirho.namespace_root_chirho();
    source_chirho
        .storage_snapshot_chirho
        .verify_current_path_chirho(storage_root_chirho)?;
    if storage_root_chirho.to_str().is_none() {
        bail!("ResidentLedgerStorageNamespaceMustBeUtf8Chirho");
    }
    if storage_root_chirho == canonical_root_chirho
        || !storage_root_chirho.starts_with(&canonical_root_chirho)
    {
        bail!("ResidentLedgerStorageOutsideRootChirho");
    }
    let logical_storage_namespace_digest_chirho = logical_storage_namespace_digest_chirho(
        &canonical_root_chirho,
        source_chirho.identity_storage_namespace_chirho,
    )?;
    source_chirho
        .storage_chirho
        .validate_resident_identity_path_chirho(source_chirho.journal_path_chirho)?;
    validate_bounded_label_chirho(
        &source_chirho.cluster_id_chirho.0,
        MAX_CLUSTER_IDENTITY_BYTES_CHIRHO,
        "cluster identity",
    )?;
    validate_lower_hex_chirho(&source_chirho.local_node_chirho.0, 64, "elected node key")?;
    let authority_identity_chirho = source_chirho
        .authority_root_snapshot_chirho
        .identity_chirho()?;
    let storage_identity_chirho = source_chirho.storage_snapshot_chirho.identity_chirho()?;
    source_chirho
        .authority_root_snapshot_chirho
        .verify_current_path_chirho(&canonical_root_chirho)?;
    source_chirho
        .storage_snapshot_chirho
        .verify_current_path_chirho(storage_root_chirho)?;
    Ok(ResidentLedgerCoordinateChirho {
        canonical_root_digest_chirho: canonical_filesystem_path_digest_chirho(
            &canonical_root_chirho,
        )?,
        authority_root_device_chirho: authority_identity_chirho.device_chirho,
        authority_root_inode_chirho: authority_identity_chirho.inode_chirho,
        consistency_group_digest_chirho: consistency_group_digest_chirho(
            source_chirho.group_chirho,
        )?,
        cluster_id_chirho: source_chirho.cluster_id_chirho.0.clone(),
        opening_epoch_chirho: source_chirho.opening_epoch_chirho,
        logical_storage_namespace_digest_chirho,
        storage_namespace_device_chirho: storage_identity_chirho.device_chirho,
        storage_namespace_inode_chirho: storage_identity_chirho.inode_chirho,
        journal_storage_key_chirho: source_chirho.journal_path_chirho.key_chirho().to_owned(),
    })
}

fn validate_identity_coordinate_chirho(
    actual_chirho: &ResidentLedgerCoordinateChirho,
    expected_chirho: &ResidentLedgerCoordinateChirho,
) -> Result<()> {
    validate_prefixed_digest_chirho(
        &actual_chirho.canonical_root_digest_chirho,
        CANONICAL_PATH_DIGEST_PREFIX_CHIRHO,
        "canonical root digest",
    )?;
    validate_prefixed_digest_chirho(
        &actual_chirho.consistency_group_digest_chirho,
        CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO,
        "consistency group digest",
    )?;
    validate_prefixed_digest_chirho(
        &actual_chirho.logical_storage_namespace_digest_chirho,
        LOGICAL_STORAGE_DIGEST_PREFIX_CHIRHO,
        "logical storage namespace digest",
    )?;
    validate_bounded_label_chirho(
        &actual_chirho.cluster_id_chirho,
        MAX_CLUSTER_IDENTITY_BYTES_CHIRHO,
        "cluster identity",
    )?;
    if actual_chirho != expected_chirho {
        bail!("ResidentLedgerIdentityCoordinateMismatchChirho");
    }
    Ok(())
}

pub(crate) fn logical_storage_namespace_digest_chirho(
    canonical_root_chirho: &Path,
    identity_storage_namespace_chirho: &Path,
) -> Result<String> {
    if !identity_storage_namespace_chirho.is_absolute() {
        bail!("ResidentLedgerLogicalStorageMustBeAbsoluteChirho");
    }
    let relative_chirho = identity_storage_namespace_chirho
        .strip_prefix(canonical_root_chirho)
        .context("resident logical storage is outside the selected root")?;
    let mut normalized_chirho = String::new();
    for component_chirho in relative_chirho.components() {
        let Component::Normal(component_chirho) = component_chirho else {
            bail!("ResidentLedgerLogicalStorageComponentRefusedChirho");
        };
        let component_chirho = component_chirho
            .to_str()
            .context("resident logical storage must be UTF-8")?;
        if !normalized_chirho.is_empty() {
            normalized_chirho.push('/');
        }
        normalized_chirho.push_str(component_chirho);
        if normalized_chirho.len() > MAX_LOGICAL_STORAGE_NAMESPACE_BYTES_CHIRHO {
            bail!("ResidentLedgerLogicalStorageBoundsChirho");
        }
    }
    if normalized_chirho.is_empty() {
        bail!("ResidentLedgerLogicalStorageMustBeBelowRootChirho");
    }
    Ok(format!(
        "{LOGICAL_STORAGE_DIGEST_PREFIX_CHIRHO}{}",
        blake3::hash(normalized_chirho.as_bytes()).to_hex()
    ))
}

fn validate_signer_key_chirho(
    signer_key_id_chirho: &str,
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
) -> Result<()> {
    validate_lower_hex_chirho(signer_key_id_chirho, 64, "signer key")?;
    validate_lower_hex_chirho(&source_chirho.local_node_chirho.0, 64, "elected node key")?;
    if signer_key_id_chirho != source_chirho.local_node_chirho.0 {
        bail!("ResidentLedgerIdentitySignerNodeMismatchChirho");
    }
    Ok(())
}

fn prove_current_signer_possession_chirho(
    source_chirho: ResidentLedgerCoordinateSourceChirho<'_>,
    persisted_signer_chirho: &str,
    signed_content_chirho: &[u8],
) -> Result<()> {
    let possession_chirho =
        sign_with_existing_key_possession_chirho(source_chirho.root_chirho, signed_content_chirho)?;
    validate_signer_key_chirho(possession_chirho.key_id_chirho(), source_chirho)?;
    if possession_chirho.key_id_chirho() != persisted_signer_chirho {
        bail!("ResidentLedgerIdentitySignerPossessionMismatchChirho");
    }
    verify_signature_chirho(
        possession_chirho.key_id_chirho(),
        signed_content_chirho,
        possession_chirho.signature_hex_chirho(),
    )
}

fn verify_signature_chirho(
    signer_key_id_chirho: &str,
    signed_content_chirho: &[u8],
    signature_chirho: &str,
) -> Result<()> {
    if !verify_with_pubkey_chirho(
        signer_key_id_chirho,
        signed_content_chirho,
        signature_chirho,
    )? {
        bail!("ResidentLedgerIdentitySignatureInvalidChirho");
    }
    Ok(())
}

fn validate_prefixed_digest_chirho(
    value_chirho: &str,
    prefix_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    let suffix_chirho = value_chirho
        .strip_prefix(prefix_chirho)
        .with_context(|| format!("{label_chirho} prefix mismatch"))?;
    validate_lower_hex_chirho(suffix_chirho, 64, label_chirho)
}

fn validate_lower_hex_chirho(
    value_chirho: &str,
    exact_len_chirho: usize,
    label_chirho: &str,
) -> Result<()> {
    if value_chirho.len() != exact_len_chirho
        || !value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("{label_chirho} must be exact lowercase hex");
    }
    Ok(())
}

fn validate_bounded_label_chirho(
    value_chirho: &str,
    max_len_chirho: usize,
    label_chirho: &str,
) -> Result<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > max_len_chirho
        || !value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'-' | b'_' | b'.' | b':')
        })
    {
        bail!("{label_chirho} is not a bounded identifier");
    }
    Ok(())
}

#[cfg(test)]
mod golden_tests_chirho {
    use super::*;
    use cairn_ledger_model_chirho::record_chirho::{HlcChirho, LedgerGenesisRecordChirho};
    use cairn_ledger_model_chirho::wire_chirho::{
        canonical_ledger_genesis_line_chirho, LEDGER_FORMAT_VERSION_V1_CHIRHO,
        LEDGER_GENESIS_SCHEMA_V1_CHIRHO,
    };
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, Ordering};

    const GOLDEN_PENDING_IDENTITY_CHIRHO: &str = "{\"schema_chirho\":\"resident-ledger-pending-identity-v3-chirho\",\"state_chirho\":\"pending_chirho\",\"coordinate_chirho\":{\"canonical_root_digest_chirho\":\"canonical-filesystem-path-blake3-v1-chirho:0000000000000000000000000000000000000000000000000000000000000000\",\"authority_root_device_chirho\":9,\"authority_root_inode_chirho\":10,\"consistency_group_digest_chirho\":\"writer-fence-group-blake3-chirho:1111111111111111111111111111111111111111111111111111111111111111\",\"cluster_id_chirho\":\"golden-cluster-chirho\",\"opening_epoch_chirho\":7,\"logical_storage_namespace_digest_chirho\":\"root-relative-storage-blake3-v1-chirho:2222222222222222222222222222222222222222222222222222222222222222\",\"storage_namespace_device_chirho\":11,\"storage_namespace_inode_chirho\":12,\"journal_storage_key_chirho\":\"journals/golden-chirho.jsonl\"},\"prepared_genesis_line_chirho\":\"{\\\"schema_chirho\\\":\\\"ledger-genesis-v1-chirho\\\",\\\"format_version_chirho\\\":1,\\\"cluster_id_chirho\\\":\\\"golden-cluster-chirho\\\",\\\"epoch_chirho\\\":7,\\\"hlc_chirho\\\":{\\\"physical_ms_chirho\\\":123456,\\\"logical_chirho\\\":0},\\\"sig_chirho\\\":\\\"44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\\\",\\\"key_id_chirho\\\":\\\"5555555555555555555555555555555555555555555555555555555555555555\\\"}\",\"prepared_genesis_digest_chirho\":\"df7b2c85eee00f627d7501f7fc16da46988b596d628afb60b978e8ba028b9e2f\",\"signer_key_id_chirho\":\"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12\",\"sig_chirho\":\"ebf688329042f34a46fd95344c3e0d193f297e6bac08c1197b32e9589b177d919c4e1f8816e5ae8be2d9b685e4b8db0fe17f1854b057337ef59959106c671803\"}";
    const GOLDEN_BOUND_IDENTITY_CHIRHO: &str = "{\"schema_chirho\":\"resident-ledger-bound-identity-v3-chirho\",\"state_chirho\":\"bound_chirho\",\"coordinate_chirho\":{\"canonical_root_digest_chirho\":\"canonical-filesystem-path-blake3-v1-chirho:0000000000000000000000000000000000000000000000000000000000000000\",\"authority_root_device_chirho\":9,\"authority_root_inode_chirho\":10,\"consistency_group_digest_chirho\":\"writer-fence-group-blake3-chirho:1111111111111111111111111111111111111111111111111111111111111111\",\"cluster_id_chirho\":\"golden-cluster-chirho\",\"opening_epoch_chirho\":7,\"logical_storage_namespace_digest_chirho\":\"root-relative-storage-blake3-v1-chirho:2222222222222222222222222222222222222222222222222222222222222222\",\"storage_namespace_device_chirho\":11,\"storage_namespace_inode_chirho\":12,\"journal_storage_key_chirho\":\"journals/golden-chirho.jsonl\"},\"verified_genesis_line_chirho\":\"{\\\"schema_chirho\\\":\\\"ledger-genesis-v1-chirho\\\",\\\"format_version_chirho\\\":1,\\\"cluster_id_chirho\\\":\\\"golden-cluster-chirho\\\",\\\"epoch_chirho\\\":7,\\\"hlc_chirho\\\":{\\\"physical_ms_chirho\\\":123456,\\\"logical_chirho\\\":0},\\\"sig_chirho\\\":\\\"44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\\\",\\\"key_id_chirho\\\":\\\"5555555555555555555555555555555555555555555555555555555555555555\\\"}\",\"verified_genesis_digest_chirho\":\"df7b2c85eee00f627d7501f7fc16da46988b596d628afb60b978e8ba028b9e2f\",\"signer_key_id_chirho\":\"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12\",\"sig_chirho\":\"5ca17950b70fba96d677538eb139ed99fef7fc4af6987df863c4ca78238c491b4fb4f8db315d2b0d8884258a10dec0a68a44b0d5f68c36973bcf879f42406507\"}";

    fn golden_root_chirho(label_chirho: &str) -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "resident-ledger-identity-golden-{label_chirho}-{}-{counter_chirho}-chirho",
            std::process::id()
        ))
    }

    fn provision_golden_key_chirho(root_chirho: &Path) -> NodeIdChirho {
        let signing_key_chirho = SigningKey::from_bytes(&[0x42; 32]);
        std::fs::create_dir_all(root_chirho).unwrap();
        let private_path_chirho = root_chirho.join("signing-key-chirho.bin");
        std::fs::write(&private_path_chirho, signing_key_chirho.to_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_path_chirho, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        let public_key_chirho = signing_key_chirho.verifying_key().to_bytes();
        let public_hex_chirho = public_key_chirho
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect::<String>();
        std::fs::write(root_chirho.join("pubkey-chirho.hex"), &public_hex_chirho).unwrap();
        NodeIdChirho(public_hex_chirho)
    }

    fn golden_coordinate_chirho() -> ResidentLedgerCoordinateChirho {
        ResidentLedgerCoordinateChirho {
            canonical_root_digest_chirho: format!(
                "{CANONICAL_PATH_DIGEST_PREFIX_CHIRHO}{}",
                "00".repeat(32)
            ),
            authority_root_device_chirho: 9,
            authority_root_inode_chirho: 10,
            consistency_group_digest_chirho: format!(
                "{CONSISTENCY_GROUP_DIGEST_PREFIX_CHIRHO}{}",
                "11".repeat(32)
            ),
            cluster_id_chirho: "golden-cluster-chirho".to_owned(),
            opening_epoch_chirho: 7,
            logical_storage_namespace_digest_chirho: format!(
                "{LOGICAL_STORAGE_DIGEST_PREFIX_CHIRHO}{}",
                "22".repeat(32)
            ),
            storage_namespace_device_chirho: 11,
            storage_namespace_inode_chirho: 12,
            journal_storage_key_chirho: "journals/golden-chirho.jsonl".to_owned(),
        }
    }

    fn golden_genesis_line_chirho() -> String {
        canonical_ledger_genesis_line_chirho(&LedgerGenesisRecordChirho {
            schema_chirho: LEDGER_GENESIS_SCHEMA_V1_CHIRHO.to_owned(),
            format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
            cluster_id_chirho: ClusterIdChirho("golden-cluster-chirho".to_owned()),
            epoch_chirho: 7,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 123_456,
                logical_chirho: 0,
            },
            sig_chirho: "44".repeat(64),
            key_id_chirho: "55".repeat(32),
        })
        .unwrap()
    }

    #[test]
    fn legacy_resident_identity_v3_complete_golden_bytes_remain_verifiable_chirho() {
        let first_root_chirho = golden_root_chirho("first");
        let second_root_chirho = golden_root_chirho("second");
        let first_node_chirho = provision_golden_key_chirho(&first_root_chirho);
        let second_node_chirho = provision_golden_key_chirho(&second_root_chirho);
        assert_eq!(first_node_chirho, second_node_chirho);
        let genesis_line_chirho = golden_genesis_line_chirho();
        let genesis_digest_chirho = stored_line_digest_chirho(&genesis_line_chirho);

        let first_pending_chirho = canonical_pending_identity_for_coordinate_with_schema_chirho(
            &first_root_chirho,
            &first_node_chirho,
            golden_coordinate_chirho(),
            &genesis_line_chirho,
            &genesis_digest_chirho,
            RESIDENT_LEDGER_LEGACY_V3_PENDING_SCHEMA_CHIRHO,
        )
        .unwrap();
        let second_pending_chirho = canonical_pending_identity_for_coordinate_with_schema_chirho(
            &second_root_chirho,
            &second_node_chirho,
            golden_coordinate_chirho(),
            &genesis_line_chirho,
            &genesis_digest_chirho,
            RESIDENT_LEDGER_LEGACY_V3_PENDING_SCHEMA_CHIRHO,
        )
        .unwrap();
        assert_eq!(first_pending_chirho, second_pending_chirho);
        assert_eq!(
            String::from_utf8(first_pending_chirho).unwrap(),
            GOLDEN_PENDING_IDENTITY_CHIRHO
        );

        let bound_digest_chirho = genesis_digest_chirho.clone();
        let first_bound_chirho = canonical_bound_identity_for_coordinate_chirho(
            &first_root_chirho,
            &first_node_chirho,
            golden_coordinate_chirho(),
            &genesis_line_chirho,
            &bound_digest_chirho,
            RESIDENT_LEDGER_LEGACY_V3_BOUND_SCHEMA_CHIRHO,
            None,
        )
        .unwrap();
        let second_bound_chirho = canonical_bound_identity_for_coordinate_chirho(
            &second_root_chirho,
            &second_node_chirho,
            golden_coordinate_chirho(),
            &genesis_line_chirho,
            &bound_digest_chirho,
            RESIDENT_LEDGER_LEGACY_V3_BOUND_SCHEMA_CHIRHO,
            None,
        )
        .unwrap();
        assert_eq!(first_bound_chirho, second_bound_chirho);
        assert_eq!(
            String::from_utf8(first_bound_chirho).unwrap(),
            GOLDEN_BOUND_IDENTITY_CHIRHO
        );

        std::fs::remove_dir_all(first_root_chirho).unwrap();
        std::fs::remove_dir_all(second_root_chirho).unwrap();
    }
}
