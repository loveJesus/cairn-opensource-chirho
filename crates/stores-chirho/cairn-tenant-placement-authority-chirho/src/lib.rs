// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Durable, bounded tenant-placement authority.
//!
//! A placement intent is hashed without readiness receipts. Each of the three serving nodes and the
//! distinct held observer sign that intent digest under their existing node identities, then the
//! placement authority signs the complete role-separated receipt population. This two-level order is
//! load-bearing: including receipts in the intent digest would make the binding circular.
//!
//! A peer readiness receipt proves prepared-at-signing-time, not current liveness. Only the local
//! composition can reopen and compare its actual tenant-root binding. Stale peer receipts therefore
//! remain a bounded-by-operations availability exposure, never evidence that transport is live.
//!
//! The fixed current-record file is signed against corruption and substitution. It does not prevent
//! replacement with an older validly signed record. Rollback resistance is owed by the shared
//! monotonic-head substrate also owed by tenant migration.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.

use cairn_core_chirho::model_chirho::ConsistencyGroupIdChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use cairn_tenant_chirho::tenant_chirho::validate_tenant_id_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

pub mod attestation_stores_chirho;
pub mod capacity_admission_impl_chirho;
pub mod control_plane_authorities_chirho;
pub mod lifecycle_composition_proof_chirho;
pub mod placement_registry_load_chirho;
pub mod population_projection_chirho;
pub mod topology_chirho;

pub const TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO: &str = "tenant-placement-intent-v1-chirho";
pub const TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO: &str =
    "tenant-placement-node-readiness-v1-chirho";
pub const TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO: &str =
    "tenant-placement-node-readiness-v2-chirho";
pub const TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO: &str =
    "tenant-placement-held-observer-readiness-v1-chirho";
pub const TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO: &str = "tenant-placement-record-v1-chirho";
pub const TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO: &str = "tenant-placement-record-v2-chirho";
pub const TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO: &str =
    "tenant-placement-intent-digest-v1-chirho";
pub const TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO: &str =
    "tenant-placement-node-readiness-v1-chirho";
pub const TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO: &str =
    "tenant-placement-node-readiness-v2-chirho";
pub const TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO: &str =
    "tenant-placement-held-observer-readiness-v1-chirho";
pub const TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO: &str =
    "tenant-placement-record-signature-v1-chirho";
pub const TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO: &str =
    "tenant-placement-record-signature-v2-chirho";
pub const TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO: &str = "tenant-root-binding-blake3-v1-chirho:";
pub const TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO: usize = 3;
pub const TENANT_PLACEMENT_MIN_PROVIDER_COUNT_CHIRHO: usize = 2;
pub const TENANT_PLACEMENT_MIN_REGION_COUNT_CHIRHO: usize = 3;
pub const TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO: u64 = 128 * 1024;
const TENANT_PLACEMENT_TOKEN_MAX_BYTES_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementNodeBindingChirho {
    pub node_id_chirho: String,
    pub failure_domain_chirho: FailureDomainChirho,
    pub expected_root_binding_chirho: String,
    pub expected_cluster_config_blake3_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementResidencyChirho {
    pub allowed_domains_chirho: Vec<FailureDomainChirho>,
}

/// The receipt-free decision whose digest is safe for every assigned node to sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementIntentChirho {
    pub schema_chirho: String,
    pub digest_domain_chirho: String,
    pub revision_chirho: u64,
    /// Signed predecessor claim. The fixed-record verifier checks only its shape; it does not walk
    /// ancestry and provides no rollback resistance. Both are owed by the shared monotonic-head
    /// substrate.
    pub previous_assignment_digest_chirho: Option<String>,
    pub tenant_id_chirho: String,
    pub consistency_group_id_chirho: String,
    pub assigned_nodes_chirho: Vec<TenantPlacementNodeBindingChirho>,
    /// The one GD7 held-evidence learner for this tenant group.
    ///
    /// This per-group fact can live in this per-tenant record because tenant consistency-group ids
    /// are injectively derived from tenant ids and `validate_intent_chirho` rejects any mismatch.
    pub held_observer_node_chirho: TenantPlacementNodeBindingChirho,
    pub preferred_node_chirho: String,
    pub demand_chirho: AllocatableCapacityChirho,
    pub residency_chirho: TenantPlacementResidencyChirho,
    /// Placement-authority-signed cross-reference. This verifier neither loads nor validates the
    /// referenced plan, and this field does not prove that the referent exists.
    pub topology_plan_digest_chirho: String,
}

/// One node's signed statement that the exact receipt-free intent was prepared locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementNodeReadinessReceiptChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_digest_chirho: String,
    pub node_id_chirho: String,
    pub failure_domain_chirho: FailureDomainChirho,
    pub root_binding_chirho: String,
    pub cluster_config_blake3_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_anchor_digest_chirho: Option<String>,
    pub prepared_at_ms_chirho: u64,
    pub signer_key_id_chirho: String,
    pub sig_chirho: String,
}

/// One held observer's signed statement that its evidence destination root/config was prepared.
///
/// This does not assert serving readiness or transport liveness. The distinct type and domain keep a
/// serving receipt from being replayed into the observer role, or the reverse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementHeldObserverReadinessReceiptChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_digest_chirho: String,
    pub node_id_chirho: String,
    pub failure_domain_chirho: FailureDomainChirho,
    pub root_binding_chirho: String,
    pub cluster_config_blake3_chirho: String,
    pub prepared_at_ms_chirho: u64,
    pub signer_key_id_chirho: String,
    pub sig_chirho: String,
}

/// The placement-authority-signed record consumed by runtime membership derivation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantPlacementRecordChirho {
    pub schema_chirho: String,
    pub signature_domain_chirho: String,
    pub intent_chirho: TenantPlacementIntentChirho,
    pub intent_digest_chirho: String,
    pub serving_readiness_receipts_chirho: Vec<TenantPlacementNodeReadinessReceiptChirho>,
    pub held_observer_readiness_receipt_chirho: TenantPlacementHeldObserverReadinessReceiptChirho,
    pub placement_key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantPlacementRefusalChirho {
    StoreUnavailableChirho,
    StoreEntryTypeChirho,
    StoreTooLargeChirho,
    /// The path passed its entry-type and size checks and then was NOT one identity-stable single-link
    /// regular file: hard-linked, or replaced/grown between the stat, the open, and the read.
    ///
    /// Deliberately NOT folded into `StoreEntryTypeChirho`. "You handed me the wrong kind of thing" and
    /// "the thing changed under me while I read it" are different operator problems with different
    /// fixes, and collapsing them is the conflation this repo keeps paying for.
    StoreIdentityUnstableChirho,
    DecodeChirho,
    SchemaChirho,
    SignatureDomainChirho,
    TenantIdentityChirho,
    ConsistencyGroupIdentityChirho,
    RevisionBindingChirho,
    AssignedNodePopulationChirho,
    AssignedNodeOrderChirho,
    AssignedNodeIdentityChirho,
    HeldObserverIdentityChirho,
    FailureDomainChirho,
    FailureDomainSpreadChirho,
    RootBindingChirho,
    ClusterConfigBindingChirho,
    PreferredNodeChirho,
    DemandChirho,
    ResidencyChirho,
    TopologyPlanBindingChirho,
    IntentDigestChirho,
    ReadinessPopulationChirho,
    ReadinessSchemaChirho,
    ReadinessBindingChirho,
    ActivationAnchorBindingChirho,
    ReadinessSignerChirho,
    ReadinessSignatureChirho,
    HeldObserverReadinessSchemaChirho,
    HeldObserverReadinessBindingChirho,
    HeldObserverReadinessSignerChirho,
    HeldObserverReadinessSignatureChirho,
    PlacementKeyChirho,
    AuthorityKeySeparationChirho,
    PlacementSignatureChirho,
}

impl fmt::Display for TenantPlacementRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl std::error::Error for TenantPlacementRefusalChirho {}

pub type TenantPlacementResultChirho<T> = Result<T, TenantPlacementRefusalChirho>;

/// Opaque verified authority. It has no public constructor or serde implementation.
#[derive(Clone, Debug)]
pub struct VerifiedTenantPlacementChirho {
    record_chirho: TenantPlacementRecordChirho,
    assignment_digest_chirho: String,
}

impl VerifiedTenantPlacementChirho {
    pub fn record_schema_chirho(&self) -> &str {
        &self.record_chirho.schema_chirho
    }

    pub fn intent_chirho(&self) -> &TenantPlacementIntentChirho {
        &self.record_chirho.intent_chirho
    }

    pub fn assigned_nodes_chirho(&self) -> &[TenantPlacementNodeBindingChirho] {
        &self.record_chirho.intent_chirho.assigned_nodes_chirho
    }

    pub fn held_observer_node_chirho(&self) -> &TenantPlacementNodeBindingChirho {
        &self.record_chirho.intent_chirho.held_observer_node_chirho
    }

    pub fn preferred_node_chirho(&self) -> &str {
        &self.record_chirho.intent_chirho.preferred_node_chirho
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn serving_readiness_receipts_chirho(
        &self,
    ) -> &[TenantPlacementNodeReadinessReceiptChirho] {
        &self.record_chirho.serving_readiness_receipts_chirho
    }

    pub fn activation_anchor_digest_for_node_chirho(&self, node_id_chirho: &str) -> Option<&str> {
        self.record_chirho
            .serving_readiness_receipts_chirho
            .iter()
            .find(|receipt_chirho| receipt_chirho.node_id_chirho == node_id_chirho)
            .and_then(|receipt_chirho| receipt_chirho.activation_anchor_digest_chirho.as_deref())
    }

    pub fn held_observer_readiness_receipt_chirho(
        &self,
    ) -> &TenantPlacementHeldObserverReadinessReceiptChirho {
        &self.record_chirho.held_observer_readiness_receipt_chirho
    }

    pub fn assigned_node_chirho(
        &self,
        node_id_chirho: &str,
    ) -> Option<&TenantPlacementNodeBindingChirho> {
        self.assigned_nodes_chirho()
            .iter()
            .find(|node_chirho| node_chirho.node_id_chirho == node_id_chirho)
    }
}

pub fn tenant_placement_intent_digest_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
) -> TenantPlacementResultChirho<String> {
    validate_intent_chirho(intent_chirho)?;
    let bytes_chirho = serde_json::to_vec(intent_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

pub fn unsigned_tenant_placement_readiness_message_chirho(
    receipt_chirho: &TenantPlacementNodeReadinessReceiptChirho,
) -> TenantPlacementResultChirho<Vec<u8>> {
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_vec(&unsigned_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)
}

pub fn unsigned_tenant_placement_held_observer_readiness_message_chirho(
    receipt_chirho: &TenantPlacementHeldObserverReadinessReceiptChirho,
) -> TenantPlacementResultChirho<Vec<u8>> {
    let mut unsigned_chirho = receipt_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_vec(&unsigned_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)
}

pub fn unsigned_tenant_placement_record_message_chirho(
    record_chirho: &TenantPlacementRecordChirho,
) -> TenantPlacementResultChirho<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_vec(&unsigned_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)
}

pub fn tenant_placement_assignment_digest_chirho(
    record_chirho: &TenantPlacementRecordChirho,
) -> TenantPlacementResultChirho<String> {
    let bytes_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)?;
    Ok(blake3::hash(&bytes_chirho).to_hex().to_string())
}

pub fn verify_tenant_placement_record_chirho(
    record_chirho: TenantPlacementRecordChirho,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> TenantPlacementResultChirho<VerifiedTenantPlacementChirho> {
    let record_v2_chirho = match record_chirho.schema_chirho.as_str() {
        TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO => false,
        TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO => true,
        _ => return Err(TenantPlacementRefusalChirho::SchemaChirho),
    };
    let expected_domain_chirho = if record_v2_chirho {
        TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO
    } else {
        TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO
    };
    if record_chirho.signature_domain_chirho != expected_domain_chirho {
        return Err(TenantPlacementRefusalChirho::SignatureDomainChirho);
    }
    validate_key_chirho(expected_placement_key_chirho)?;
    validate_key_chirho(roster_operator_key_chirho)?;
    validate_key_chirho(geo_plan_authority_key_chirho)?;
    if record_chirho.placement_key_id_chirho != expected_placement_key_chirho {
        return Err(TenantPlacementRefusalChirho::PlacementKeyChirho);
    }
    let authority_keys_chirho = [
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if authority_keys_chirho.len() != 3 {
        return Err(TenantPlacementRefusalChirho::AuthorityKeySeparationChirho);
    }
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&record_chirho.intent_chirho)?;
    if record_chirho.intent_digest_chirho != intent_digest_chirho {
        return Err(TenantPlacementRefusalChirho::IntentDigestChirho);
    }
    verify_receipts_chirho(&record_chirho, &intent_digest_chirho, record_v2_chirho)?;
    let unsigned_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho)?;
    if !verify_with_pubkey_chirho(
        expected_placement_key_chirho,
        &unsigned_chirho,
        &record_chirho.sig_chirho,
    )
    .unwrap_or(false)
    {
        return Err(TenantPlacementRefusalChirho::PlacementSignatureChirho);
    }
    let assignment_digest_chirho = tenant_placement_assignment_digest_chirho(&record_chirho)?;
    Ok(VerifiedTenantPlacementChirho {
        record_chirho,
        assignment_digest_chirho,
    })
}

pub fn load_and_verify_tenant_placement_record_chirho(
    path_chirho: &Path,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> TenantPlacementResultChirho<VerifiedTenantPlacementChirho> {
    let metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::StoreUnavailableChirho)?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        return Err(TenantPlacementRefusalChirho::StoreEntryTypeChirho);
    }
    if metadata_chirho.len() > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        return Err(TenantPlacementRefusalChirho::StoreTooLargeChirho);
    }
    // The read itself goes through the workspace's hardened primitive rather than a local
    // File::open. This crate was the ODD ONE OUT: seven other crates already read reviewed objects
    // this way, and the local version lacked O_NOFOLLOW, refused no hard link, and re-checked only
    // the SIZE rather than the file identity. Those gaps do not permit a forgery, because the record
    // is signature-verified below -- but they widen the substitution window the crate's own header
    // already names, and the stronger primitive was one dependency line away.
    //
    // The entry-type and size checks above are KEPT deliberately: the primitive collapses file-type,
    // size and link-count into one InvalidData, and those are two distinct refusal identities that
    // callers and arms already depend on.
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        path_chirho,
        TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        // Having already passed the checks above, InvalidData now means hard-linked, or replaced or
        // grown between the stat, the open and the read.
        std::io::ErrorKind::InvalidData => {
            TenantPlacementRefusalChirho::StoreIdentityUnstableChirho
        }
        _ => TenantPlacementRefusalChirho::StoreUnavailableChirho,
    })?;
    let record_chirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::DecodeChirho)?;
    verify_tenant_placement_record_chirho(
        record_chirho,
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
}

fn validate_intent_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
) -> TenantPlacementResultChirho<()> {
    if intent_chirho.schema_chirho != TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO {
        return Err(TenantPlacementRefusalChirho::SchemaChirho);
    }
    if intent_chirho.digest_domain_chirho != TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO {
        return Err(TenantPlacementRefusalChirho::SignatureDomainChirho);
    }
    validate_tenant_id_chirho(&intent_chirho.tenant_id_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::TenantIdentityChirho)?;
    let expected_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: intent_chirho.tenant_id_chirho.clone(),
    }
    .canonical_id_chirho();
    if intent_chirho.consistency_group_id_chirho != expected_group_chirho {
        return Err(TenantPlacementRefusalChirho::ConsistencyGroupIdentityChirho);
    }
    match (
        intent_chirho.revision_chirho,
        &intent_chirho.previous_assignment_digest_chirho,
    ) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => {
            return Err(TenantPlacementRefusalChirho::RevisionBindingChirho)
        }
        (_, Some(digest_chirho)) if !is_lower_hex_digest_chirho(digest_chirho) => {
            return Err(TenantPlacementRefusalChirho::RevisionBindingChirho)
        }
        _ => {}
    }
    if intent_chirho.assigned_nodes_chirho.len() != TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO {
        return Err(TenantPlacementRefusalChirho::AssignedNodePopulationChirho);
    }
    let mut prior_node_id_chirho: Option<&str> = None;
    let mut providers_chirho = BTreeSet::new();
    let mut regions_chirho = BTreeSet::new();
    for node_chirho in &intent_chirho.assigned_nodes_chirho {
        validate_key_chirho(&node_chirho.node_id_chirho)
            .map_err(|_error_chirho| TenantPlacementRefusalChirho::AssignedNodeIdentityChirho)?;
        if prior_node_id_chirho
            .is_some_and(|prior_chirho| prior_chirho >= node_chirho.node_id_chirho.as_str())
        {
            return Err(TenantPlacementRefusalChirho::AssignedNodeOrderChirho);
        }
        prior_node_id_chirho = Some(&node_chirho.node_id_chirho);
        validate_domain_chirho(&node_chirho.failure_domain_chirho)?;
        validate_root_binding_chirho(&node_chirho.expected_root_binding_chirho)?;
        if !is_lower_hex_digest_chirho(&node_chirho.expected_cluster_config_blake3_chirho) {
            return Err(TenantPlacementRefusalChirho::ClusterConfigBindingChirho);
        }
        providers_chirho.insert(node_chirho.failure_domain_chirho.provider_chirho.as_str());
        regions_chirho.insert((
            node_chirho.failure_domain_chirho.provider_chirho.as_str(),
            node_chirho.failure_domain_chirho.region_chirho.as_str(),
        ));
    }
    let held_observer_chirho = &intent_chirho.held_observer_node_chirho;
    validate_key_chirho(&held_observer_chirho.node_id_chirho)
        .map_err(|_error_chirho| TenantPlacementRefusalChirho::HeldObserverIdentityChirho)?;
    if intent_chirho
        .assigned_nodes_chirho
        .iter()
        .any(|node_chirho| node_chirho.node_id_chirho == held_observer_chirho.node_id_chirho)
    {
        return Err(TenantPlacementRefusalChirho::HeldObserverIdentityChirho);
    }
    validate_domain_chirho(&held_observer_chirho.failure_domain_chirho)?;
    validate_root_binding_chirho(&held_observer_chirho.expected_root_binding_chirho)?;
    if !is_lower_hex_digest_chirho(&held_observer_chirho.expected_cluster_config_blake3_chirho) {
        return Err(TenantPlacementRefusalChirho::ClusterConfigBindingChirho);
    }
    if providers_chirho.len() < TENANT_PLACEMENT_MIN_PROVIDER_COUNT_CHIRHO
        || regions_chirho.len() < TENANT_PLACEMENT_MIN_REGION_COUNT_CHIRHO
    {
        return Err(TenantPlacementRefusalChirho::FailureDomainSpreadChirho);
    }
    if !intent_chirho
        .assigned_nodes_chirho
        .iter()
        .any(|node_chirho| node_chirho.node_id_chirho == intent_chirho.preferred_node_chirho)
    {
        return Err(TenantPlacementRefusalChirho::PreferredNodeChirho);
    }
    if intent_chirho.demand_chirho.cpu_millicores_chirho == 0
        || intent_chirho.demand_chirho.memory_bytes_chirho == 0
        || intent_chirho.demand_chirho.durable_bytes_chirho == 0
    {
        return Err(TenantPlacementRefusalChirho::DemandChirho);
    }
    validate_residency_chirho(intent_chirho)?;
    if !is_lower_hex_digest_chirho(&intent_chirho.topology_plan_digest_chirho) {
        return Err(TenantPlacementRefusalChirho::TopologyPlanBindingChirho);
    }
    Ok(())
}

fn validate_residency_chirho(
    intent_chirho: &TenantPlacementIntentChirho,
) -> TenantPlacementResultChirho<()> {
    if intent_chirho
        .residency_chirho
        .allowed_domains_chirho
        .is_empty()
    {
        return Err(TenantPlacementRefusalChirho::ResidencyChirho);
    }
    let mut previous_chirho: Option<&FailureDomainChirho> = None;
    for domain_chirho in &intent_chirho.residency_chirho.allowed_domains_chirho {
        validate_domain_chirho(domain_chirho)?;
        if previous_chirho.is_some_and(|prior_chirho| prior_chirho >= domain_chirho) {
            return Err(TenantPlacementRefusalChirho::ResidencyChirho);
        }
        previous_chirho = Some(domain_chirho);
    }
    if intent_chirho
        .assigned_nodes_chirho
        .iter()
        .any(|node_chirho| {
            !intent_chirho
                .residency_chirho
                .allowed_domains_chirho
                .contains(&node_chirho.failure_domain_chirho)
        })
    {
        return Err(TenantPlacementRefusalChirho::ResidencyChirho);
    }
    Ok(())
}

fn verify_receipts_chirho(
    record_chirho: &TenantPlacementRecordChirho,
    intent_digest_chirho: &str,
    record_v2_chirho: bool,
) -> TenantPlacementResultChirho<()> {
    if record_chirho.serving_readiness_receipts_chirho.len()
        != TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO
    {
        return Err(TenantPlacementRefusalChirho::ReadinessPopulationChirho);
    }
    for (node_chirho, receipt_chirho) in record_chirho
        .intent_chirho
        .assigned_nodes_chirho
        .iter()
        .zip(&record_chirho.serving_readiness_receipts_chirho)
    {
        let receipt_version_matches_chirho = if record_v2_chirho {
            receipt_chirho.schema_chirho == TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO
                && receipt_chirho.signature_domain_chirho
                    == TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO
        } else {
            receipt_chirho.schema_chirho == TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO
                && receipt_chirho.signature_domain_chirho
                    == TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO
        };
        if !receipt_version_matches_chirho {
            return Err(TenantPlacementRefusalChirho::ReadinessSchemaChirho);
        }
        let activation_anchor_valid_chirho = receipt_chirho
            .activation_anchor_digest_chirho
            .as_deref()
            .is_some_and(is_lower_hex_digest_chirho);
        if (record_v2_chirho && !activation_anchor_valid_chirho)
            || (!record_v2_chirho && receipt_chirho.activation_anchor_digest_chirho.is_some())
        {
            return Err(TenantPlacementRefusalChirho::ActivationAnchorBindingChirho);
        }
        if receipt_chirho.intent_digest_chirho != intent_digest_chirho
            || receipt_chirho.node_id_chirho != node_chirho.node_id_chirho
            || receipt_chirho.failure_domain_chirho != node_chirho.failure_domain_chirho
            || receipt_chirho.root_binding_chirho != node_chirho.expected_root_binding_chirho
            || receipt_chirho.cluster_config_blake3_chirho
                != node_chirho.expected_cluster_config_blake3_chirho
            || receipt_chirho.prepared_at_ms_chirho == 0
        {
            return Err(TenantPlacementRefusalChirho::ReadinessBindingChirho);
        }
        if receipt_chirho.signer_key_id_chirho != node_chirho.node_id_chirho {
            return Err(TenantPlacementRefusalChirho::ReadinessSignerChirho);
        }
        let unsigned_chirho = unsigned_tenant_placement_readiness_message_chirho(receipt_chirho)?;
        if !verify_with_pubkey_chirho(
            &node_chirho.node_id_chirho,
            &unsigned_chirho,
            &receipt_chirho.sig_chirho,
        )
        .unwrap_or(false)
        {
            return Err(TenantPlacementRefusalChirho::ReadinessSignatureChirho);
        }
    }
    let held_observer_chirho = &record_chirho.intent_chirho.held_observer_node_chirho;
    let receipt_chirho = &record_chirho.held_observer_readiness_receipt_chirho;
    if receipt_chirho.schema_chirho != TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO
        || receipt_chirho.signature_domain_chirho
            != TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
    {
        return Err(TenantPlacementRefusalChirho::HeldObserverReadinessSchemaChirho);
    }
    if receipt_chirho.intent_digest_chirho != intent_digest_chirho
        || receipt_chirho.node_id_chirho != held_observer_chirho.node_id_chirho
        || receipt_chirho.failure_domain_chirho != held_observer_chirho.failure_domain_chirho
        || receipt_chirho.root_binding_chirho != held_observer_chirho.expected_root_binding_chirho
        || receipt_chirho.cluster_config_blake3_chirho
            != held_observer_chirho.expected_cluster_config_blake3_chirho
        || receipt_chirho.prepared_at_ms_chirho == 0
    {
        return Err(TenantPlacementRefusalChirho::HeldObserverReadinessBindingChirho);
    }
    if receipt_chirho.signer_key_id_chirho != held_observer_chirho.node_id_chirho {
        return Err(TenantPlacementRefusalChirho::HeldObserverReadinessSignerChirho);
    }
    let unsigned_chirho =
        unsigned_tenant_placement_held_observer_readiness_message_chirho(receipt_chirho)?;
    if !verify_with_pubkey_chirho(
        &held_observer_chirho.node_id_chirho,
        &unsigned_chirho,
        &receipt_chirho.sig_chirho,
    )
    .unwrap_or(false)
    {
        return Err(TenantPlacementRefusalChirho::HeldObserverReadinessSignatureChirho);
    }
    Ok(())
}

fn validate_key_chirho(value_chirho: &str) -> TenantPlacementResultChirho<()> {
    if is_lower_hex_digest_chirho(value_chirho) {
        Ok(())
    } else {
        Err(TenantPlacementRefusalChirho::PlacementKeyChirho)
    }
}

fn validate_root_binding_chirho(value_chirho: &str) -> TenantPlacementResultChirho<()> {
    let Some(digest_chirho) = value_chirho.strip_prefix(TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO)
    else {
        return Err(TenantPlacementRefusalChirho::RootBindingChirho);
    };
    if is_lower_hex_digest_chirho(digest_chirho) {
        Ok(())
    } else {
        Err(TenantPlacementRefusalChirho::RootBindingChirho)
    }
}

fn validate_domain_chirho(domain_chirho: &FailureDomainChirho) -> TenantPlacementResultChirho<()> {
    if is_bounded_token_chirho(&domain_chirho.provider_chirho)
        && is_bounded_token_chirho(&domain_chirho.region_chirho)
    {
        Ok(())
    } else {
        Err(TenantPlacementRefusalChirho::FailureDomainChirho)
    }
}

fn is_bounded_token_chirho(value_chirho: &str) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= TENANT_PLACEMENT_TOKEN_MAX_BYTES_CHIRHO
        && !value_chirho.starts_with('-')
        && !value_chirho.ends_with('-')
        && value_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        })
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

#[cfg(test)]
mod tests_chirho;

#[cfg(test)]
mod population_projection_tests_chirho;
