// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The explicit A6 authority selection for a served geo voter.
//!
//! This boundary can only retain the elector already assembled by the deployable
//! [`ClusterNodeChirho`]. It mints no election state, owns no ticker, and has no fallback to the
//! resident actor's process-local single-voter opener. The caller must keep the cluster node alive
//! for the actor's full lifetime.

use anyhow::{Context, Result};
use axum::Router;
use cairn_config_chirho::config_chirho::{
    load_digest_bound_config_chirho, DigestBoundConfigRefusalChirho, LedgerHostConfigChirho,
};
use cairn_ledger_host_chirho::reconciliation_chirho::Gd7LedgerRecordVerifierPortChirho;
use cairn_ledger_host_chirho::{
    configured_resident_gd7_journal_verifier_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
    verify_host_ledger_config_custody_chirho, ResidentEffectJournalHandleChirho,
    TenantMigrationCapacityAdmissionCompositionChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::LedgerMirrorRuntimePortsChirho;
use cairn_ledger_mirror_http_chirho::{
    compose_ledger_append_mirror_chirho, ledger_mirror_live_head_report_chirho,
    read_live_ledger_mirror_recovery_head_receipt_chirho, LedgerMirrorJournalVerifierBindingChirho,
    LedgerMirrorLiveHeadReadRefusalChirho, LedgerMirrorLiveHeadReportChirho,
    LedgerMirrorPeerEndpointChirho,
};
use cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho;
use cairn_writer_elector_chirho::elector_port_chirho::LeaseTierChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::ClusterNodeChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

pub use cairn_ledger_mirror_http_chirho::{
    ledger_mirror_live_head_bound_verdict_bytes_chirho,
    ledger_mirror_live_head_bound_verdict_chirho, ledger_mirror_live_head_report_bytes_chirho,
    verify_ledger_mirror_live_head_bound_verdict_bytes_chirho,
    LedgerMirrorLiveHeadBoundVerdictChirho, LedgerMirrorLiveHeadBoundVerdictRefusalChirho,
    LedgerMirrorLiveHeadReportRefusalChirho, LedgerMirrorLiveHeadReportStatusChirho,
    MAX_LEDGER_MIRROR_LIVE_HEAD_BOUND_VERDICT_BYTES_CHIRHO,
    MAX_LEDGER_MIRROR_LIVE_HEAD_REPORT_BYTES_CHIRHO,
};

pub const MIN_FAULT_TOLERANT_GEO_VOTERS_CHIRHO: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho {
    ConfigDigestRefusedChirho,
    ConfigCustodyRefusedChirho,
    ConfigDecodeRefusedChirho,
    ConfigRootBindingRefusedChirho,
    LedgerHostConfigAbsentChirho,
    RootIdentityRefusedChirho,
    JournalVerifierRefusedChirho,
    LiveHeadReadRefusedChirho(LedgerMirrorLiveHeadReadRefusalChirho),
    ReportShapeRefusedChirho,
}

impl ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ConfigDigestRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportConfigDigestRefusedChirho"
            }
            Self::ConfigCustodyRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportConfigCustodyRefusedChirho"
            }
            Self::ConfigDecodeRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportConfigDecodeRefusedChirho"
            }
            Self::ConfigRootBindingRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportConfigRootBindingRefusedChirho"
            }
            Self::LedgerHostConfigAbsentChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportLedgerHostConfigAbsentChirho"
            }
            Self::RootIdentityRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportRootIdentityRefusedChirho"
            }
            Self::JournalVerifierRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportJournalVerifierRefusedChirho"
            }
            Self::LiveHeadReadRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::ReportShapeRefusedChirho => {
                "ConfiguredLedgerMirrorLiveHeadReportShapeRefusedChirho"
            }
        }
    }
}

impl fmt::Display for ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho {}

/// Compose one live-high-water report from the same custody-checked root/config boundary used by
/// the shipping geo node. This function opens no elector or resident authority and creates no mirror
/// coordinate.
pub fn configured_ledger_mirror_live_head_report_read_only_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    expected_config_digest_chirho: &str,
) -> std::result::Result<
    LedgerMirrorLiveHeadReportChirho,
    ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho,
> {
    let runtime_config_chirho = load_digest_bound_config_chirho(
        config_path_chirho,
        expected_config_digest_chirho,
    )
    .map_err(|error_chirho| {
        if error_chirho
            .downcast_ref::<DigestBoundConfigRefusalChirho>()
            .is_some()
        {
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigDigestRefusedChirho
        } else {
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigDecodeRefusedChirho
        }
    })?;
    verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho).map_err(
        |_| ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigCustodyRefusedChirho,
    )?;
    crate::verify_resident_gd7_geo_config_root_binding_chirho(
        selected_root_chirho,
        &runtime_config_chirho,
    )
    .map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
    })?;
    let ledger_config_chirho = runtime_config_chirho.ledger_host_chirho.as_ref().ok_or(
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::LedgerHostConfigAbsentChirho,
    )?;
    let canonical_root_chirho = selected_root_chirho.canonicalize().map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::RootIdentityRefusedChirho
    })?;
    let node_id_chirho = cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(
        &canonical_root_chirho,
    )
    .map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::RootIdentityRefusedChirho
    })?;
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho).map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::RootIdentityRefusedChirho
    })?;
    let writer_fence_group_digest_chirho =
        consistency_group_digest_chirho(&group_chirho).map_err(|_| {
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::RootIdentityRefusedChirho
        })?;
    let configured_journal_verifier_chirho = configured_resident_gd7_journal_verifier_chirho(
        &canonical_root_chirho,
        ledger_config_chirho,
        &node_id_chirho,
    )
    .map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::JournalVerifierRefusedChirho
    })?;
    let journal_verifying_key_hex_chirho = ledger_config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .ok_or(
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::JournalVerifierRefusedChirho,
        )?
        .journal_verifying_key_hex_chirho
        .clone();
    let journal_verifier_chirho = LedgerMirrorJournalVerifierBindingChirho::new_chirho(
        configured_journal_verifier_chirho.key_id_chirho(),
        journal_verifying_key_hex_chirho,
    )
    .map_err(|_| {
        ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::JournalVerifierRefusedChirho
    })?;
    let receipt_chirho = read_live_ledger_mirror_recovery_head_receipt_chirho(
        &canonical_root_chirho,
        &canonical_root_chirho,
        &node_id_chirho,
        journal_verifier_chirho,
    )
    .map_err(ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::LiveHeadReadRefusedChirho)?;
    ledger_mirror_live_head_report_chirho(
        node_id_chirho,
        writer_fence_group_digest_chirho,
        receipt_chirho,
    )
    .map_err(|_| ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ReportShapeRefusedChirho)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum A6GeoAuthorityCompositionRefusalChirho {
    FaultTolerantVoterFloorChirho { voter_count_chirho: usize },
    MonotonicLeaseRequiredChirho { actual_tier_chirho: LeaseTierChirho },
}

impl fmt::Display for A6GeoAuthorityCompositionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FaultTolerantVoterFloorChirho { voter_count_chirho } => write!(
                formatter_chirho,
                "A6GeoFaultTolerantVoterFloorChirho: observed {voter_count_chirho}, required at least {MIN_FAULT_TOLERANT_GEO_VOTERS_CHIRHO}"
            ),
            Self::MonotonicLeaseRequiredChirho { actual_tier_chirho } => write!(
                formatter_chirho,
                "A6GeoMonotonicLeaseRequiredChirho: observed {actual_tier_chirho:?}"
            ),
        }
    }
}

impl std::error::Error for A6GeoAuthorityCompositionRefusalChirho {}

pub(crate) fn require_fault_tolerant_voter_floor_chirho(
    voter_count_chirho: usize,
) -> std::result::Result<(), A6GeoAuthorityCompositionRefusalChirho> {
    if voter_count_chirho < MIN_FAULT_TOLERANT_GEO_VOTERS_CHIRHO {
        return Err(
            A6GeoAuthorityCompositionRefusalChirho::FaultTolerantVoterFloorChirho {
                voter_count_chirho,
            },
        );
    }
    Ok(())
}

/// One checked reference to the exact deployable geo elector used by the resident mutation actor.
pub struct A6GeoResidentAuthorityCompositionChirho {
    elector_chirho: Arc<RaftWriterElectorChirho>,
    mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
    capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
}

impl A6GeoResidentAuthorityCompositionChirho {
    pub fn from_cluster_node_chirho(cluster_node_chirho: &ClusterNodeChirho) -> Result<Self> {
        let (voters_chirho, _learners_chirho) = cluster_node_chirho
            .elector_chirho()
            .membership_snapshot_chirho()
            .context("read the deployable geo elector membership before authority composition")?;
        require_fault_tolerant_voter_floor_chirho(voters_chirho.len())?;

        let elector_chirho = Arc::clone(cluster_node_chirho.elector_chirho());
        let actual_tier_chirho = elector_chirho.lease_tier_chirho();
        if actual_tier_chirho != LeaseTierChirho::MonotonicDecayChirho {
            return Err(
                A6GeoAuthorityCompositionRefusalChirho::MonotonicLeaseRequiredChirho {
                    actual_tier_chirho,
                }
                .into(),
            );
        }
        Ok(Self {
            elector_chirho,
            mirror_runtime_chirho: None,
            capacity_admission_chirho: None,
        })
    }

    pub fn elector_chirho(&self) -> &Arc<RaftWriterElectorChirho> {
        &self.elector_chirho
    }

    fn install_mirror_runtime_chirho(
        &mut self,
        mirror_runtime_chirho: LedgerMirrorRuntimePortsChirho,
    ) -> Result<()> {
        if self.mirror_runtime_chirho.is_some() {
            anyhow::bail!("A6GeoMirrorRuntimeAlreadyInstalledChirho");
        }
        self.mirror_runtime_chirho = Some(mirror_runtime_chirho);
        Ok(())
    }

    /// Compose and install the placement-bound F1 mirror beside the exact deployable geo elector.
    /// A non-resident placement posture returns no router and retains no mirror authority.
    pub(crate) fn install_configured_append_mirror_chirho(
        &mut self,
        selected_root_chirho: &Path,
        config_chirho: &LedgerHostConfigChirho,
        sign_root_chirho: &Path,
        local_node_id_chirho: &str,
        placement_chirho: Option<Arc<VerifiedTenantPlacementChirho>>,
        peer_endpoints_chirho: Vec<LedgerMirrorPeerEndpointChirho>,
    ) -> Result<Option<Router>> {
        let Some(placement_chirho) = placement_chirho else {
            return Ok(None);
        };
        let configured_journal_verifier_chirho = configured_resident_gd7_journal_verifier_chirho(
            selected_root_chirho,
            config_chirho,
            local_node_id_chirho,
        )
        .context("bind the resident journal secret to its public verifier pin")?;
        let journal_verifying_key_hex_chirho = config_chirho
            .held_verifier_pins_chirho
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorJournalVerifierPinMissingChirho"))?
            .journal_verifying_key_hex_chirho
            .clone();
        let journal_verifier_chirho = LedgerMirrorJournalVerifierBindingChirho::new_chirho(
            configured_journal_verifier_chirho.key_id_chirho(),
            journal_verifying_key_hex_chirho,
        )
        .context("construct role-bound F1 journal verifier")?;
        let mirror_composition_chirho = compose_ledger_append_mirror_chirho(
            selected_root_chirho,
            sign_root_chirho,
            local_node_id_chirho,
            placement_chirho,
            journal_verifier_chirho,
            Arc::clone(&self.elector_chirho),
            peer_endpoints_chirho,
        )
        .context("compose placement-bound F1 ledger mirror on the private mesh")?;
        self.install_mirror_runtime_chirho(mirror_composition_chirho.runtime_ports_chirho)
            .context(
                "install the paired F1 runtime into the sole resident authority composition",
            )?;
        Ok(Some(mirror_composition_chirho.router_chirho))
    }

    pub fn mirror_runtime_chirho(&self) -> Option<LedgerMirrorRuntimePortsChirho> {
        self.mirror_runtime_chirho.clone()
    }

    pub(crate) fn install_capacity_admission_chirho(
        &mut self,
        capacity_admission_chirho: TenantMigrationCapacityAdmissionCompositionChirho,
    ) -> Result<()> {
        if self.capacity_admission_chirho.is_some() {
            anyhow::bail!("A6GeoCapacityAdmissionAlreadyInstalledChirho");
        }
        self.capacity_admission_chirho = Some(capacity_admission_chirho);
        Ok(())
    }

    pub fn capacity_admission_chirho(
        &self,
    ) -> Option<TenantMigrationCapacityAdmissionCompositionChirho> {
        self.capacity_admission_chirho.clone()
    }

    /// Shipping geo-owner door. It cannot open a resident journal until the placement-bound F1
    /// mirror has been installed; an omitted selector therefore refuses startup before any append.
    pub fn open_required_mirrored_resident_effect_journal_chirho(
        &self,
        selected_root_chirho: &Path,
        config_path_chirho: &Path,
        config_chirho: &LedgerHostConfigChirho,
    ) -> Result<ResidentEffectJournalHandleChirho> {
        let mirror_runtime_chirho = require_mirror_runtime_chirho(&self.mirror_runtime_chirho)?;
        self.open_resident_effect_journal_with_mirror_chirho(
            selected_root_chirho,
            config_path_chirho,
            config_chirho,
            mirror_runtime_chirho,
        )
    }

    fn open_resident_effect_journal_with_mirror_chirho(
        &self,
        selected_root_chirho: &Path,
        config_path_chirho: &Path,
        config_chirho: &LedgerHostConfigChirho,
        mirror_runtime_chirho: LedgerMirrorRuntimePortsChirho,
    ) -> Result<ResidentEffectJournalHandleChirho> {
        match self.capacity_admission_chirho() {
            Some(capacity_admission_chirho) => {
                open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho(
                    selected_root_chirho,
                    config_path_chirho,
                    config_chirho,
                    &self.elector_chirho,
                    Some(mirror_runtime_chirho),
                    None,
                    capacity_admission_chirho,
                )
            }
            None => open_resident_effect_journal_handle_with_shared_elector_chirho(
                selected_root_chirho,
                config_path_chirho,
                config_chirho,
                &self.elector_chirho,
                Some(mirror_runtime_chirho),
                None,
            ),
        }
    }
}

fn require_mirror_runtime_chirho(
    mirror_runtime_chirho: &Option<LedgerMirrorRuntimePortsChirho>,
) -> Result<LedgerMirrorRuntimePortsChirho> {
    mirror_runtime_chirho
        .clone()
        .ok_or_else(|| anyhow::anyhow!("A6GeoMirrorRuntimeRequiredChirho"))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
    use cairn_ledger_model_chirho::record_chirho::{
        AttributionChirho, HlcChirho, LedgerOpChirho, LedgerRecordChirho,
    };
    use cairn_ledger_model_chirho::wire_chirho::{
        canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
        stored_line_digest_chirho,
    };
    use cairn_secret_chirho::secret_chirho::set_secret_chirho;
    use cairn_signer_chirho::signer_chirho::{
        existing_keypair_pubkey_hex_chirho, sign_message_chirho,
        sign_message_with_existing_key_chirho,
    };
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use std::fs;
    use std::path::PathBuf;

    const LIVE_HEAD_JOURNAL_SECRET_CHIRHO: &str = "live-head-journal-chirho";
    const LIVE_HEAD_CONFIG_SECRET_CHIRHO: &str = "live-head-config-chirho";
    const LIVE_HEAD_FEEDER_SECRET_CHIRHO: &str = "live-head-feeder-chirho";
    const LIVE_HEAD_KIND_ROOT_SECRET_CHIRHO: &str = "live-head-kind-root-chirho";
    const LIVE_HEAD_EFFECT_INTENT_SECRET_CHIRHO: &str = "live-head-effect-intent-chirho";
    const LIVE_HEAD_EFFECT_TERMINAL_SECRET_CHIRHO: &str = "live-head-effect-terminal-chirho";
    const LIVE_HEAD_JOURNAL_KEY_ID_CHIRHO: &str = "journal-chirho:live-head-journal-chirho";
    const LIVE_HEAD_JOURNAL_GENESIS_DIGEST_CHIRHO: &str =
        "5555555555555555555555555555555555555555555555555555555555555555";

    #[derive(Serialize)]
    struct LiveHeadRecordFixtureChirho {
        cluster_id_chirho: String,
        journal_genesis_digest_chirho: String,
        predecessor_seq_chirho: u64,
        predecessor_digest_chirho: String,
        record_seq_chirho: u64,
        record_digest_chirho: String,
        record_epoch_chirho: u64,
        record_hlc_physical_ms_chirho: u64,
        record_hlc_logical_chirho: u32,
        canonical_record_line_chirho: String,
    }

    #[derive(Serialize)]
    struct LiveHeadHighWaterFixtureChirho {
        schema_chirho: String,
        consistency_group_digest_chirho: String,
        origin_leader_node_id_chirho: String,
        holder_node_id_chirho: String,
        assignment_digest_chirho: String,
        assigned_node_ids_chirho: [String; 3],
        membership_view_digest_chirho: String,
        historical_term_chirho: u64,
        mirror_closure_id_chirho: String,
        prepare_frame_digest_chirho: String,
        caller_idempotency_key_digest_chirho: String,
        record_chirho: LiveHeadRecordFixtureChirho,
        state_digest_chirho: String,
        sig_hex_chirho: String,
    }

    fn write_live_head_config_chirho(root_chirho: &Path, journal_seed_chirho: [u8; 32]) -> PathBuf {
        for (secret_name_chirho, secret_value_chirho) in [
            (LIVE_HEAD_JOURNAL_SECRET_CHIRHO, journal_seed_chirho),
            (LIVE_HEAD_CONFIG_SECRET_CHIRHO, [2; 32]),
            (LIVE_HEAD_FEEDER_SECRET_CHIRHO, [3; 32]),
            (LIVE_HEAD_KIND_ROOT_SECRET_CHIRHO, [4; 32]),
            (LIVE_HEAD_EFFECT_INTENT_SECRET_CHIRHO, [5; 32]),
            (LIVE_HEAD_EFFECT_TERMINAL_SECRET_CHIRHO, [6; 32]),
        ] {
            set_secret_chirho(root_chirho, secret_name_chirho, &secret_value_chirho).unwrap();
        }
        let journal_key_chirho = lower_hex_chirho(
            SigningKey::from_bytes(&journal_seed_chirho)
                .verifying_key()
                .as_bytes(),
        );
        let issuer_key_chirho =
            lower_hex_chirho(SigningKey::from_bytes(&[80; 32]).verifying_key().as_bytes());
        let activation_key_chirho =
            lower_hex_chirho(SigningKey::from_bytes(&[91; 32]).verifying_key().as_bytes());
        let config_path_chirho = root_chirho.join("live-head-config-chirho.toml");
        fs::write(
            &config_path_chirho,
            format!(
                r#"root_chirho = "{}"

[ledger_host_chirho]
schema_chirho = "ledger-host-config-v3-chirho"
storage_namespace_chirho = "ledger-namespace-chirho"
monitor_evidence_namespace_chirho = "ops-chirho"
monitor_evidence_path_chirho = "monitor/cycles-chirho.jsonl"
money_group_id_chirho = "money-group-live-head-chirho"
cluster_id_chirho = "cluster-live-head-chirho"
journal_path_chirho = "journals/main-chirho.jsonl"
local_epoch_chirho = 1
members_chirho = [{{ owner_chirho = "live-head-owner-chirho", kind_id_chirho = "credits-chirho" }}]
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "kind-registry-live-head-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "projection-registry-live-head-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "source-registry-live-head-chirho"
projection_routes_chirho = [{{ projection_name_chirho = "credits-balance-chirho", head_path_chirho = "published/credits-balance-head-chirho.json" }}]
monitor_cadence_ms_chirho = 5000

[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "live-head-issuer-chirho"
verifying_key_hex_chirho = "{issuer_key_chirho}"

[ledger_host_chirho.activation_authority_chirho]
principal_chirho = "live-head-activation-chirho"
verifying_key_hex_chirho = "{activation_key_chirho}"

[ledger_host_chirho.held_verifier_pins_chirho]
journal_verifying_key_hex_chirho = "{journal_key_chirho}"

[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "{LIVE_HEAD_JOURNAL_SECRET_CHIRHO}"
config_chirho = "{LIVE_HEAD_CONFIG_SECRET_CHIRHO}"
feeder_chirho = "{LIVE_HEAD_FEEDER_SECRET_CHIRHO}"
kind_root_chirho = "{LIVE_HEAD_KIND_ROOT_SECRET_CHIRHO}"
effect_intent_chirho = "{LIVE_HEAD_EFFECT_INTENT_SECRET_CHIRHO}"
effect_terminal_chirho = "{LIVE_HEAD_EFFECT_TERMINAL_SECRET_CHIRHO}"
"#,
                root_chirho.display(),
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
        }
        config_path_chirho
    }

    fn lower_hex_chirho(bytes_chirho: &[u8]) -> String {
        bytes_chirho
            .iter()
            .map(|byte_chirho| format!("{byte_chirho:02x}"))
            .collect()
    }

    fn config_digest_chirho(config_path_chirho: &Path) -> String {
        blake3::hash(&fs::read(config_path_chirho).unwrap())
            .to_hex()
            .to_string()
    }

    fn provision_fixture_signing_key_chirho(root_chirho: &Path, seed_chirho: [u8; 32]) -> String {
        let signing_key_chirho = SigningKey::from_bytes(&seed_chirho);
        let public_key_chirho = lower_hex_chirho(signing_key_chirho.verifying_key().as_bytes());
        let private_path_chirho = root_chirho.join("signing-key-chirho.bin");
        let public_path_chirho = root_chirho.join("pubkey-chirho.hex");
        fs::write(&private_path_chirho, seed_chirho).unwrap();
        fs::write(&public_path_chirho, public_key_chirho.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&private_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&public_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            existing_keypair_pubkey_hex_chirho(root_chirho).unwrap(),
            public_key_chirho
        );
        public_key_chirho
    }

    fn live_head_record_fixture_chirho(
        journal_sign_root_chirho: &Path,
    ) -> LiveHeadRecordFixtureChirho {
        let mut record_chirho = LedgerRecordChirho {
            schema_chirho: "ledger-record-v1-chirho".to_string(),
            format_version_chirho: 1,
            seq_chirho: 1,
            prev_chirho: DigestChirho(LIVE_HEAD_JOURNAL_GENESIS_DIGEST_CHIRHO.to_string()),
            epoch_chirho: 1,
            hlc_chirho: HlcChirho {
                physical_ms_chirho: 1_000,
                logical_chirho: 0,
            },
            legs_chirho: Vec::new(),
            op_chirho: LedgerOpChirho::TimerChirho {
                fires_at_hlc_chirho: HlcChirho {
                    physical_ms_chirho: 1_001,
                    logical_chirho: 0,
                },
                purpose_chirho: "live-head-authority-fixture-chirho".to_string(),
            },
            idempotency_key_chirho: "live-head-authority-fixture-chirho".to_string(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
            anchor_chirho: None,
            sig_chirho: String::new(),
            key_id_chirho: LIVE_HEAD_JOURNAL_KEY_ID_CHIRHO.to_string(),
        };
        let signed_content_chirho =
            ledger_record_signed_content_line_chirho(&record_chirho).unwrap();
        record_chirho.sig_chirho = sign_message_with_existing_key_chirho(
            journal_sign_root_chirho,
            signed_content_chirho.as_bytes(),
        )
        .unwrap();
        let canonical_record_line_chirho =
            canonical_ledger_record_line_chirho(&record_chirho).unwrap();
        LiveHeadRecordFixtureChirho {
            cluster_id_chirho: "cluster-live-head-chirho".to_string(),
            journal_genesis_digest_chirho: LIVE_HEAD_JOURNAL_GENESIS_DIGEST_CHIRHO.to_string(),
            predecessor_seq_chirho: 0,
            predecessor_digest_chirho: LIVE_HEAD_JOURNAL_GENESIS_DIGEST_CHIRHO.to_string(),
            record_seq_chirho: record_chirho.seq_chirho,
            record_digest_chirho: stored_line_digest_chirho(&canonical_record_line_chirho).0,
            record_epoch_chirho: record_chirho.epoch_chirho,
            record_hlc_physical_ms_chirho: record_chirho.hlc_chirho.physical_ms_chirho,
            record_hlc_logical_chirho: record_chirho.hlc_chirho.logical_chirho,
            canonical_record_line_chirho,
        }
    }

    fn install_live_head_fixture_chirho(
        selected_root_chirho: &Path,
        holder_node_id_chirho: &str,
        journal_sign_root_chirho: &Path,
    ) -> (PathBuf, PathBuf, String) {
        let writer_node_id_chirho = if holder_node_id_chirho == "b".repeat(64) {
            "c".repeat(64)
        } else {
            "b".repeat(64)
        };
        let third_node_id_chirho =
            if holder_node_id_chirho != "d".repeat(64) && writer_node_id_chirho != "d".repeat(64) {
                "d".repeat(64)
            } else {
                "e".repeat(64)
            };
        let record_chirho = live_head_record_fixture_chirho(journal_sign_root_chirho);
        let record_digest_chirho = record_chirho.record_digest_chirho.clone();
        let record_seq_chirho = record_chirho.record_seq_chirho;
        let canonical_record_line_chirho = record_chirho.canonical_record_line_chirho.clone();
        let mut high_water_chirho = LiveHeadHighWaterFixtureChirho {
            schema_chirho: "ledger-mirror-f1-high-water-v2-chirho".to_string(),
            consistency_group_digest_chirho: "1".repeat(64),
            origin_leader_node_id_chirho: writer_node_id_chirho.clone(),
            holder_node_id_chirho: holder_node_id_chirho.to_string(),
            assignment_digest_chirho: "2".repeat(64),
            assigned_node_ids_chirho: [
                writer_node_id_chirho,
                holder_node_id_chirho.to_string(),
                third_node_id_chirho,
            ],
            membership_view_digest_chirho: "3".repeat(64),
            historical_term_chirho: 7,
            mirror_closure_id_chirho: "4".repeat(64),
            prepare_frame_digest_chirho: "5".repeat(64),
            caller_idempotency_key_digest_chirho: "6".repeat(64),
            record_chirho,
            state_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        let unsigned_bytes_chirho = serde_json::to_vec(&high_water_chirho).unwrap();
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(b"ledger-mirror-f1-high-water-v2-chirho");
        hasher_chirho.update(&(unsigned_bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&unsigned_bytes_chirho);
        let state_digest_chirho = hasher_chirho.finalize();
        high_water_chirho.state_digest_chirho = state_digest_chirho.to_hex().to_string();
        high_water_chirho.sig_hex_chirho = sign_message_with_existing_key_chirho(
            selected_root_chirho,
            state_digest_chirho.as_bytes(),
        )
        .unwrap();

        let follower_root_chirho = selected_root_chirho
            .join("ledger-mirror-f1-chirho")
            .join("follower-f1-chirho");
        let records_root_chirho = follower_root_chirho.join("records-chirho");
        fs::create_dir_all(&records_root_chirho).unwrap();
        let high_water_path_chirho = follower_root_chirho.join("high-water-chirho.json");
        fs::write(
            &high_water_path_chirho,
            serde_json::to_vec(&high_water_chirho).unwrap(),
        )
        .unwrap();
        let record_path_chirho = records_root_chirho.join(format!(
            "{record_seq_chirho:020}-{record_digest_chirho}.jsonl"
        ));
        fs::write(
            &record_path_chirho,
            format!("{canonical_record_line_chirho}\n"),
        )
        .unwrap();
        (
            high_water_path_chirho,
            record_path_chirho,
            record_digest_chirho,
        )
    }

    #[test]
    fn configured_live_head_report_derives_root_authority_without_creating_mirror_state_chirho() {
        let selected_root_chirho = tempfile::tempdir().unwrap();
        sign_message_chirho(
            selected_root_chirho.path(),
            b"provision configured live-head node identity",
        )
        .unwrap();
        let node_id_chirho =
            existing_keypair_pubkey_hex_chirho(selected_root_chirho.path()).unwrap();
        let config_path_chirho =
            write_live_head_config_chirho(selected_root_chirho.path(), [1; 32]);
        let expected_config_digest_chirho = config_digest_chirho(&config_path_chirho);
        let mirror_root_chirho = selected_root_chirho.path().join("ledger-mirror-f1-chirho");
        assert!(!mirror_root_chirho.exists());

        let absent_root_chirho = selected_root_chirho.path().join("absent-root-chirho");
        assert_eq!(
            configured_ledger_mirror_live_head_report_read_only_chirho(
                &absent_root_chirho,
                &config_path_chirho,
                &"00".repeat(32),
            )
            .unwrap_err(),
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigDigestRefusedChirho
        );

        let report_chirho = configured_ledger_mirror_live_head_report_read_only_chirho(
            selected_root_chirho.path(),
            &config_path_chirho,
            &expected_config_digest_chirho,
        )
        .unwrap();
        let canonical_root_chirho = selected_root_chirho.path().canonicalize().unwrap();
        let expected_group_chirho = consistency_group_digest_chirho(
            &consistency_group_for_root_chirho(&canonical_root_chirho).unwrap(),
        )
        .unwrap();
        assert_eq!(report_chirho.node_id_chirho, node_id_chirho);
        assert_eq!(
            report_chirho.writer_fence_group_digest_chirho,
            expected_group_chirho
        );
        assert_eq!(
            report_chirho.status_chirho,
            LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAbsentChirho
        );
        assert!(report_chirho.receipt_chirho.is_none());
        assert!(!mirror_root_chirho.exists());

        let foreign_root_chirho = tempfile::tempdir().unwrap();
        assert_eq!(
            configured_ledger_mirror_live_head_report_read_only_chirho(
                foreign_root_chirho.path(),
                &config_path_chirho,
                &expected_config_digest_chirho,
            )
            .unwrap_err(),
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
        );
    }

    #[test]
    fn configured_live_head_report_reaches_exact_journal_signature_authority_chirho() {
        let selected_root_chirho = tempfile::tempdir().unwrap();
        sign_message_chirho(
            selected_root_chirho.path(),
            b"provision configured available live-head node identity",
        )
        .unwrap();
        let node_id_chirho =
            existing_keypair_pubkey_hex_chirho(selected_root_chirho.path()).unwrap();
        let journal_sign_root_chirho = tempfile::tempdir().unwrap();
        let journal_key_chirho =
            provision_fixture_signing_key_chirho(journal_sign_root_chirho.path(), [1; 32]);
        assert_ne!(journal_key_chirho, node_id_chirho);
        let config_path_chirho =
            write_live_head_config_chirho(selected_root_chirho.path(), [1; 32]);
        let expected_config_digest_chirho = config_digest_chirho(&config_path_chirho);
        let (high_water_path_chirho, record_path_chirho, record_digest_chirho) =
            install_live_head_fixture_chirho(
                selected_root_chirho.path(),
                &node_id_chirho,
                journal_sign_root_chirho.path(),
            );
        let high_water_bytes_chirho = fs::read(&high_water_path_chirho).unwrap();
        let record_bytes_chirho = fs::read(&record_path_chirho).unwrap();

        let report_chirho = configured_ledger_mirror_live_head_report_read_only_chirho(
            selected_root_chirho.path(),
            &config_path_chirho,
            &expected_config_digest_chirho,
        )
        .unwrap();
        assert_eq!(
            report_chirho.status_chirho,
            LedgerMirrorLiveHeadReportStatusChirho::LiveHighWaterAvailableChirho
        );
        let receipt_chirho = report_chirho
            .receipt_chirho
            .as_ref()
            .expect("configured fixture must reach the available live receipt");
        assert_eq!(receipt_chirho.holder_node_id_chirho(), node_id_chirho);
        assert_eq!(
            receipt_chirho.tail_record_digest_chirho(),
            record_digest_chirho
        );
        assert_eq!(
            fs::read(&high_water_path_chirho).unwrap(),
            high_water_bytes_chirho
        );
        assert_eq!(fs::read(&record_path_chirho).unwrap(), record_bytes_chirho);

        let wrong_journal_seed_chirho = [71; 32];
        let wrong_journal_key_chirho = lower_hex_chirho(
            SigningKey::from_bytes(&wrong_journal_seed_chirho)
                .verifying_key()
                .as_bytes(),
        );
        assert_ne!(wrong_journal_key_chirho, journal_key_chirho);
        assert_ne!(wrong_journal_key_chirho, node_id_chirho);
        let rotated_config_path_chirho =
            write_live_head_config_chirho(selected_root_chirho.path(), wrong_journal_seed_chirho);
        let rotated_config_digest_chirho = config_digest_chirho(&rotated_config_path_chirho);
        let refusal_chirho = configured_ledger_mirror_live_head_report_read_only_chirho(
            selected_root_chirho.path(),
            &rotated_config_path_chirho,
            &rotated_config_digest_chirho,
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::LiveHeadReadRefusedChirho(
                LedgerMirrorLiveHeadReadRefusalChirho::LiveHeadInvalidChirho,
            )
        );
        assert_ne!(
            refusal_chirho,
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::JournalVerifierRefusedChirho
        );
        assert_ne!(
            refusal_chirho,
            ConfiguredLedgerMirrorLiveHeadReportBuildRefusalChirho::RootIdentityRefusedChirho
        );
        assert_eq!(
            fs::read(&high_water_path_chirho).unwrap(),
            high_water_bytes_chirho
        );
        assert_eq!(fs::read(&record_path_chirho).unwrap(), record_bytes_chirho);
    }

    #[test]
    fn shipping_resident_requirement_refuses_an_uninstalled_append_mirror_chirho() {
        let absent_chirho: Option<LedgerMirrorRuntimePortsChirho> = None;
        let error_chirho = match require_mirror_runtime_chirho(&absent_chirho) {
            Ok(_) => panic!("shipping resident composition accepted an absent mirror"),
            Err(error_chirho) => error_chirho,
        };
        assert!(error_chirho
            .to_string()
            .contains("A6GeoMirrorRuntimeRequiredChirho"));
    }
}
