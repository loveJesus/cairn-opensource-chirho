// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reviewed-config boundary for one bounded, path-free shadow-canary report.
//!
//! The caller selects only a root and its private runtime config. This module re-derives the
//! effective root, consistency group, node identity, signer, monitor namespace, and canary store.
//! A missing store remains a named report member; it is never silently dropped or accepted as a
//! verified window.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.

use crate::custody_chirho::verify_host_ledger_config_custody_chirho;
use crate::resident_authority_chirho::RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO;
use cairn_config_chirho::config_chirho::{load_config_chirho, ConfigChirho};
use cairn_tenant_chirho::tenant_chirho::tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::ShadowCanaryGenerationStoreChirho;
use cairn_writer_elector_chirho::shadow_canary_proof_chirho::{
    require_green_shadow_canary_writer_window_chirho, verify_shadow_canary_window_proof_chirho,
    ShadowCanaryProofLedgerCutChirho, ShadowCanaryWindowProofRefusalChirho,
    ShadowCanaryWriterWindowRequirementsChirho, SignedShadowCanaryAdoptionProofProjectionChirho,
    SignedShadowCanaryWindowProofChirho, VerifiedShadowCanaryWindowProofChirho,
    MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub const CONFIGURED_SHADOW_CANARY_REPORT_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-configured-shadow-canary-report-v1-chirho";
pub const MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO: usize =
    MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO + 4 * 1024;
pub const CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO: &str =
    "ledger-host-configured-shadow-canary-bound-verdict-v1-chirho";
pub const CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO: &str =
    "ledger-host-configured-shadow-canary-bound-verdict-v2-chirho";
pub const CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V3_CHIRHO: &str =
    "ledger-host-configured-shadow-canary-bound-verdict-v3-chirho";
pub const MAX_CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfiguredShadowCanaryReportStatusChirho {
    ProofAvailableChirho,
    StoreAbsentChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredShadowCanaryReportChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub status_chirho: ConfiguredShadowCanaryReportStatusChirho,
    pub proof_chirho: Option<SignedShadowCanaryWindowProofChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfiguredShadowCanaryQualificationChirho {
    WindowQualifiedChirho,
    ActivationOnlyChirho,
    PresentNotWindowQualifiedChirho,
    StoreAbsentChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfiguredShadowCanaryBoundVerdictRequirementsChirho {
    pub minimum_observation_count_chirho: u64,
    pub minimum_interval_millis_chirho: u64,
}

/// One fixed-schema Rust verdict bound to the exact report bytes.
///
/// This is the node-local verification boundary in
/// `cf8-canary-window-loss-sequence-chirho.md`. It deliberately does not name an elected role: the
/// later fleet gate derives that role from signed authority and permits exactly one qualified node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredShadowCanaryBoundVerdictChirho {
    pub schema_chirho: String,
    pub report_sha256_chirho: String,
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub generation_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adoption_proof_projection_chirho: Option<SignedShadowCanaryAdoptionProofProjectionChirho>,
    pub qualification_chirho: ConfiguredShadowCanaryQualificationChirho,
    pub window_len_chirho: Option<u64>,
    pub permit_count_chirho: Option<u64>,
    pub refusal_count_chirho: Option<u64>,
    pub oldest_observed_at_ms_chirho: Option<u64>,
    pub latest_observed_at_ms_chirho: Option<u64>,
    pub latest_ledger_cut_chirho: Option<ShadowCanaryProofLedgerCutChirho>,
    pub minimum_observation_count_chirho: u64,
    pub minimum_interval_millis_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfiguredShadowCanaryBoundVerdictRefusalChirho {
    RequirementsRefusedChirho,
    ReportRefusedChirho(ConfiguredShadowCanaryReportRefusalChirho),
    WindowRefusedChirho(ShadowCanaryWindowProofRefusalChirho),
    BytesRefusedChirho,
    DecodeRefusedChirho,
    ShapeRefusedChirho,
    BindingRefusedChirho,
    ActivationAnchorRequiredChirho,
}

impl ConfiguredShadowCanaryBoundVerdictRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::RequirementsRefusedChirho => {
                "ConfiguredShadowCanaryBoundVerdictRequirementsRefusedChirho"
            }
            Self::ReportRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::WindowRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::BytesRefusedChirho => "ConfiguredShadowCanaryBoundVerdictBytesRefusedChirho",
            Self::DecodeRefusedChirho => "ConfiguredShadowCanaryBoundVerdictDecodeRefusedChirho",
            Self::ShapeRefusedChirho => "ConfiguredShadowCanaryBoundVerdictShapeRefusedChirho",
            Self::BindingRefusedChirho => "ConfiguredShadowCanaryBoundVerdictBindingRefusedChirho",
            Self::ActivationAnchorRequiredChirho => {
                "ConfiguredShadowCanaryBoundVerdictActivationAnchorRequiredChirho"
            }
        }
    }
}

impl fmt::Display for ConfiguredShadowCanaryBoundVerdictRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for ConfiguredShadowCanaryBoundVerdictRefusalChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfiguredShadowCanaryReportBuildRefusalChirho {
    ConfigCustodyRefusedChirho,
    ConfigDecodeRefusedChirho,
    ConfigRootBindingRefusedChirho,
    LedgerHostConfigAbsentChirho,
    RootIdentityRefusedChirho,
    StoreUnreadableChirho,
    ProofBuildRefusedChirho,
    ReportShapeRefusedChirho,
}

impl ConfiguredShadowCanaryReportBuildRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ConfigCustodyRefusedChirho => {
                "ConfiguredShadowCanaryReportConfigCustodyRefusedChirho"
            }
            Self::ConfigDecodeRefusedChirho => {
                "ConfiguredShadowCanaryReportConfigDecodeRefusedChirho"
            }
            Self::ConfigRootBindingRefusedChirho => {
                "ConfiguredShadowCanaryReportConfigRootBindingRefusedChirho"
            }
            Self::LedgerHostConfigAbsentChirho => {
                "ConfiguredShadowCanaryReportLedgerHostConfigAbsentChirho"
            }
            Self::RootIdentityRefusedChirho => {
                "ConfiguredShadowCanaryReportRootIdentityRefusedChirho"
            }
            Self::StoreUnreadableChirho => "ConfiguredShadowCanaryReportStoreUnreadableChirho",
            Self::ProofBuildRefusedChirho => "ConfiguredShadowCanaryReportProofBuildRefusedChirho",
            Self::ReportShapeRefusedChirho => "ConfiguredShadowCanaryReportShapeRefusedChirho",
        }
    }
}

impl fmt::Display for ConfiguredShadowCanaryReportBuildRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for ConfiguredShadowCanaryReportBuildRefusalChirho {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfiguredShadowCanaryReportRefusalChirho {
    BytesRefusedChirho,
    DecodeRefusedChirho,
    ShapeRefusedChirho,
    StoreAbsentChirho,
    ProofRefusedChirho(ShadowCanaryWindowProofRefusalChirho),
    BindingRefusedChirho,
}

impl ConfiguredShadowCanaryReportRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::BytesRefusedChirho => "ConfiguredShadowCanaryReportBytesRefusedChirho",
            Self::DecodeRefusedChirho => "ConfiguredShadowCanaryReportDecodeRefusedChirho",
            Self::ShapeRefusedChirho => "ConfiguredShadowCanaryReportShapeRefusedChirho",
            Self::StoreAbsentChirho => "ConfiguredShadowCanaryReportStoreAbsentChirho",
            Self::ProofRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::BindingRefusedChirho => "ConfiguredShadowCanaryReportBindingRefusedChirho",
        }
    }
}

impl fmt::Display for ConfiguredShadowCanaryReportRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl Error for ConfiguredShadowCanaryReportRefusalChirho {}

/// Export the local report defined by
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
pub fn configured_shadow_canary_report_read_only_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
) -> Result<ConfiguredShadowCanaryReportChirho, ConfiguredShadowCanaryReportBuildRefusalChirho> {
    verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigCustodyRefusedChirho)?;
    let runtime_config_chirho = load_config_chirho(config_path_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigDecodeRefusedChirho)?;
    verify_config_root_binding_chirho(selected_root_chirho, &runtime_config_chirho)?;
    let ledger_config_chirho = runtime_config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or(ConfiguredShadowCanaryReportBuildRefusalChirho::LedgerHostConfigAbsentChirho)?;
    let canonical_root_chirho = selected_root_chirho.canonicalize().map_err(|_| {
        ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
    })?;
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::RootIdentityRefusedChirho)?;
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::RootIdentityRefusedChirho)?;
    let node_id_chirho =
        cairn_signer_chirho::signer_chirho::existing_pubkey_hex_chirho(&canonical_root_chirho)
            .map_err(|_| {
                ConfiguredShadowCanaryReportBuildRefusalChirho::RootIdentityRefusedChirho
            })?;
    let canary_root_chirho = canonical_root_chirho
        .join(&ledger_config_chirho.monitor_evidence_namespace_chirho)
        .join(RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO);
    let proof_chirho = match std::fs::symlink_metadata(&canary_root_chirho) {
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => None,
        Err(_) => {
            return Err(ConfiguredShadowCanaryReportBuildRefusalChirho::StoreUnreadableChirho)
        }
        Ok(metadata_chirho) if !metadata_chirho.file_type().is_dir() => {
            return Err(ConfiguredShadowCanaryReportBuildRefusalChirho::StoreUnreadableChirho)
        }
        Ok(_) => {
            let store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
                &canary_root_chirho,
                &canonical_root_chirho,
                group_chirho,
                NodeIdChirho(node_id_chirho.clone()),
            )
            .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::StoreUnreadableChirho)?;
            Some(
                store_chirho
                    .export_current_window_proof_read_only_chirho()
                    .map_err(|_| {
                        ConfiguredShadowCanaryReportBuildRefusalChirho::ProofBuildRefusedChirho
                    })?,
            )
        }
    };
    let report_chirho = ConfiguredShadowCanaryReportChirho {
        schema_chirho: CONFIGURED_SHADOW_CANARY_REPORT_SCHEMA_V1_CHIRHO.to_owned(),
        node_id_chirho,
        consistency_group_digest_chirho: group_digest_chirho,
        status_chirho: if proof_chirho.is_some() {
            ConfiguredShadowCanaryReportStatusChirho::ProofAvailableChirho
        } else {
            ConfiguredShadowCanaryReportStatusChirho::StoreAbsentChirho
        },
        proof_chirho,
    };
    configured_shadow_canary_report_bytes_chirho(&report_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportBuildRefusalChirho::ReportShapeRefusedChirho)?;
    if report_chirho.proof_chirho.is_some() {
        verify_required_configured_shadow_canary_report_chirho(&report_chirho).map_err(|_| {
            ConfiguredShadowCanaryReportBuildRefusalChirho::ReportShapeRefusedChirho
        })?;
    }
    Ok(report_chirho)
}

pub fn configured_shadow_canary_report_bytes_chirho(
    report_chirho: &ConfiguredShadowCanaryReportChirho,
) -> Result<Vec<u8>, ConfiguredShadowCanaryReportRefusalChirho> {
    validate_report_shape_chirho(report_chirho)?;
    if report_chirho.proof_chirho.is_some() {
        verify_required_configured_shadow_canary_report_chirho(report_chirho)?;
    }
    let bytes_chirho = serde_json::to_vec(report_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportRefusalChirho::DecodeRefusedChirho)?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO
    {
        return Err(ConfiguredShadowCanaryReportRefusalChirho::BytesRefusedChirho);
    }
    Ok(bytes_chirho)
}

pub fn verify_required_configured_shadow_canary_report_bytes_chirho(
    bytes_chirho: &[u8],
) -> Result<VerifiedShadowCanaryWindowProofChirho, ConfiguredShadowCanaryReportRefusalChirho> {
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO
    {
        return Err(ConfiguredShadowCanaryReportRefusalChirho::BytesRefusedChirho);
    }
    let report_chirho: ConfiguredShadowCanaryReportChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| ConfiguredShadowCanaryReportRefusalChirho::DecodeRefusedChirho)?;
    verify_required_configured_shadow_canary_report_chirho(&report_chirho)
}

pub fn verify_required_configured_shadow_canary_report_chirho(
    report_chirho: &ConfiguredShadowCanaryReportChirho,
) -> Result<VerifiedShadowCanaryWindowProofChirho, ConfiguredShadowCanaryReportRefusalChirho> {
    validate_report_shape_chirho(report_chirho)?;
    let proof_chirho = report_chirho
        .proof_chirho
        .as_ref()
        .ok_or(ConfiguredShadowCanaryReportRefusalChirho::StoreAbsentChirho)?;
    let verified_chirho = verify_shadow_canary_window_proof_chirho(proof_chirho)
        .map_err(ConfiguredShadowCanaryReportRefusalChirho::ProofRefusedChirho)?;
    if verified_chirho.node_id_chirho != report_chirho.node_id_chirho
        || verified_chirho.consistency_group_digest_chirho
            != report_chirho.consistency_group_digest_chirho
    {
        return Err(ConfiguredShadowCanaryReportRefusalChirho::BindingRefusedChirho);
    }
    Ok(verified_chirho)
}

pub fn configured_shadow_canary_bound_verdict_chirho(
    report_bytes_chirho: &[u8],
    requirements_chirho: ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
) -> Result<ConfiguredShadowCanaryBoundVerdictChirho, ConfiguredShadowCanaryBoundVerdictRefusalChirho>
{
    validate_bound_verdict_requirements_chirho(requirements_chirho)?;
    if report_bytes_chirho.is_empty()
        || report_bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO
    {
        return Err(
            ConfiguredShadowCanaryBoundVerdictRefusalChirho::ReportRefusedChirho(
                ConfiguredShadowCanaryReportRefusalChirho::BytesRefusedChirho,
            ),
        );
    }
    let report_chirho: ConfiguredShadowCanaryReportChirho =
        serde_json::from_slice(report_bytes_chirho).map_err(|_| {
            ConfiguredShadowCanaryBoundVerdictRefusalChirho::ReportRefusedChirho(
                ConfiguredShadowCanaryReportRefusalChirho::DecodeRefusedChirho,
            )
        })?;
    validate_report_shape_chirho(&report_chirho)
        .map_err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::ReportRefusedChirho)?;
    let report_sha256_chirho = sha256_hex_chirho(report_bytes_chirho);
    if report_chirho.status_chirho == ConfiguredShadowCanaryReportStatusChirho::StoreAbsentChirho {
        let verdict_chirho = ConfiguredShadowCanaryBoundVerdictChirho {
            schema_chirho: CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO.to_owned(),
            report_sha256_chirho,
            node_id_chirho: report_chirho.node_id_chirho,
            consistency_group_digest_chirho: report_chirho.consistency_group_digest_chirho,
            generation_chirho: None,
            activation_anchor_digest_chirho: None,
            prior_generation_chirho: None,
            adoption_proof_projection_chirho: None,
            qualification_chirho: ConfiguredShadowCanaryQualificationChirho::StoreAbsentChirho,
            window_len_chirho: None,
            permit_count_chirho: None,
            refusal_count_chirho: None,
            oldest_observed_at_ms_chirho: None,
            latest_observed_at_ms_chirho: None,
            latest_ledger_cut_chirho: None,
            minimum_observation_count_chirho: requirements_chirho.minimum_observation_count_chirho,
            minimum_interval_millis_chirho: requirements_chirho.minimum_interval_millis_chirho,
        };
        validate_bound_verdict_schema_shape_chirho(&verdict_chirho)?;
        return Ok(verdict_chirho);
    }
    let verified_chirho = verify_required_configured_shadow_canary_report_chirho(&report_chirho)
        .map_err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::ReportRefusedChirho)?;
    let activation_anchor_digest_chirho = verified_chirho
        .activation_anchor_digest_chirho
        .clone()
        .ok_or(
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::ActivationAnchorRequiredChirho,
    )?;
    let window_chirho = verified_chirho.window_chirho.as_ref();
    if window_chirho.is_some_and(|window_chirho| {
        window_chirho.refusal_count_chirho != 0
            || window_chirho.permit_count_chirho != window_chirho.window_len_chirho
    }) {
        return Err(
            ConfiguredShadowCanaryBoundVerdictRefusalChirho::WindowRefusedChirho(
                ShadowCanaryWindowProofRefusalChirho::WriterRefusalObservedChirho,
            ),
        );
    }
    let qualification_chirho = match require_green_shadow_canary_writer_window_chirho(
        &verified_chirho,
        ShadowCanaryWriterWindowRequirementsChirho {
            minimum_observation_count_chirho: requirements_chirho.minimum_observation_count_chirho,
            minimum_interval_millis_chirho: requirements_chirho.minimum_interval_millis_chirho,
        },
    ) {
        Ok(_) => ConfiguredShadowCanaryQualificationChirho::WindowQualifiedChirho,
        Err(ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho)
        | Err(ShadowCanaryWindowProofRefusalChirho::WriterIntervalRefusedChirho) => {
            if activation_only_window_chirho(&verified_chirho) {
                ConfiguredShadowCanaryQualificationChirho::ActivationOnlyChirho
            } else {
                ConfiguredShadowCanaryQualificationChirho::PresentNotWindowQualifiedChirho
            }
        }
        Err(refusal_chirho) => {
            return Err(
                ConfiguredShadowCanaryBoundVerdictRefusalChirho::WindowRefusedChirho(
                    refusal_chirho,
                ),
            )
        }
    };
    let expose_interval_chirho =
        qualification_chirho == ConfiguredShadowCanaryQualificationChirho::WindowQualifiedChirho;
    let (oldest_observed_at_ms_chirho, latest_observed_at_ms_chirho) = if expose_interval_chirho {
        let window_chirho = window_chirho.ok_or(
            ConfiguredShadowCanaryBoundVerdictRefusalChirho::WindowRefusedChirho(
                ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho,
            ),
        )?;
        (
            Some(window_chirho.oldest_observed_at_ms_chirho),
            Some(window_chirho.latest_observed_at_ms_chirho),
        )
    } else {
        (None, None)
    };
    let adoption_proof_projection_chirho = verified_chirho.adoption_proof_projection_chirho.clone();
    let verdict_chirho = ConfiguredShadowCanaryBoundVerdictChirho {
        schema_chirho: if adoption_proof_projection_chirho.is_some() {
            CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V3_CHIRHO.to_owned()
        } else {
            CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO.to_owned()
        },
        report_sha256_chirho,
        node_id_chirho: verified_chirho.node_id_chirho,
        consistency_group_digest_chirho: verified_chirho.consistency_group_digest_chirho,
        generation_chirho: Some(verified_chirho.generation_chirho),
        activation_anchor_digest_chirho: Some(activation_anchor_digest_chirho),
        prior_generation_chirho: verified_chirho.prior_generation_chirho,
        adoption_proof_projection_chirho,
        qualification_chirho,
        window_len_chirho: window_chirho.map(|window_chirho| window_chirho.window_len_chirho),
        permit_count_chirho: window_chirho.map(|window_chirho| window_chirho.permit_count_chirho),
        refusal_count_chirho: window_chirho.map(|window_chirho| window_chirho.refusal_count_chirho),
        oldest_observed_at_ms_chirho,
        latest_observed_at_ms_chirho,
        latest_ledger_cut_chirho: Some(verified_chirho.latest_ledger_cut_chirho),
        minimum_observation_count_chirho: requirements_chirho.minimum_observation_count_chirho,
        minimum_interval_millis_chirho: requirements_chirho.minimum_interval_millis_chirho,
    };
    validate_bound_verdict_schema_shape_chirho(&verdict_chirho)?;
    Ok(verdict_chirho)
}

pub fn configured_shadow_canary_bound_verdict_bytes_chirho(
    report_bytes_chirho: &[u8],
    requirements_chirho: ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
) -> Result<Vec<u8>, ConfiguredShadowCanaryBoundVerdictRefusalChirho> {
    let verdict_chirho =
        configured_shadow_canary_bound_verdict_chirho(report_bytes_chirho, requirements_chirho)?;
    let bytes_chirho = serde_json::to_vec(&verdict_chirho)
        .map_err(|_| ConfiguredShadowCanaryBoundVerdictRefusalChirho::DecodeRefusedChirho)?;
    if bytes_chirho.is_empty()
        || bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_BYTES_CHIRHO
    {
        return Err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::BytesRefusedChirho);
    }
    Ok(bytes_chirho)
}

pub fn verify_configured_shadow_canary_bound_verdict_bytes_chirho(
    report_bytes_chirho: &[u8],
    verdict_bytes_chirho: &[u8],
    requirements_chirho: ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
) -> Result<ConfiguredShadowCanaryBoundVerdictChirho, ConfiguredShadowCanaryBoundVerdictRefusalChirho>
{
    if verdict_bytes_chirho.is_empty()
        || verdict_bytes_chirho.len() > MAX_CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_BYTES_CHIRHO
    {
        return Err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::BytesRefusedChirho);
    }
    let supplied_chirho: ConfiguredShadowCanaryBoundVerdictChirho =
        serde_json::from_slice(verdict_bytes_chirho)
            .map_err(|_| ConfiguredShadowCanaryBoundVerdictRefusalChirho::DecodeRefusedChirho)?;
    validate_bound_verdict_schema_shape_chirho(&supplied_chirho)?;
    let expected_chirho =
        configured_shadow_canary_bound_verdict_chirho(report_bytes_chirho, requirements_chirho)?;
    if supplied_chirho != expected_chirho {
        return Err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::BindingRefusedChirho);
    }
    Ok(expected_chirho)
}

fn validate_bound_verdict_schema_shape_chirho(
    verdict_chirho: &ConfiguredShadowCanaryBoundVerdictChirho,
) -> Result<(), ConfiguredShadowCanaryBoundVerdictRefusalChirho> {
    if !matches!(
        (
            verdict_chirho.schema_chirho.as_str(),
            verdict_chirho.activation_anchor_digest_chirho.as_ref(),
            verdict_chirho.adoption_proof_projection_chirho.as_ref(),
        ),
        (
            CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO,
            None,
            None,
        ) | (
            CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO,
            Some(_),
            None,
        ) | (
            CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V3_CHIRHO,
            Some(_),
            Some(_),
        )
    ) {
        return Err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::ShapeRefusedChirho);
    }
    Ok(())
}

fn activation_only_window_chirho(proof_chirho: &VerifiedShadowCanaryWindowProofChirho) -> bool {
    proof_chirho.generation_chirho == 0
        && proof_chirho.prior_generation_chirho.is_none()
        && proof_chirho.adopted_ledger_cut_chirho.is_none()
        && proof_chirho
            .window_chirho
            .as_ref()
            .is_some_and(|window_chirho| {
                window_chirho.window_len_chirho == 1
                    && window_chirho.permit_count_chirho == 1
                    && window_chirho.refusal_count_chirho == 0
            })
}

fn validate_bound_verdict_requirements_chirho(
    requirements_chirho: ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
) -> Result<(), ConfiguredShadowCanaryBoundVerdictRefusalChirho> {
    if requirements_chirho.minimum_observation_count_chirho < 2
        || requirements_chirho.minimum_interval_millis_chirho == 0
    {
        return Err(ConfiguredShadowCanaryBoundVerdictRefusalChirho::RequirementsRefusedChirho);
    }
    Ok(())
}

fn sha256_hex_chirho(bytes_chirho: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes_chirho))
}

fn validate_report_shape_chirho(
    report_chirho: &ConfiguredShadowCanaryReportChirho,
) -> Result<(), ConfiguredShadowCanaryReportRefusalChirho> {
    if report_chirho.schema_chirho != CONFIGURED_SHADOW_CANARY_REPORT_SCHEMA_V1_CHIRHO
        || !is_lower_hex_chirho(&report_chirho.node_id_chirho, 64)
        || !writer_group_digest_has_shape_chirho(&report_chirho.consistency_group_digest_chirho)
        || !matches!(
            (report_chirho.status_chirho, &report_chirho.proof_chirho),
            (
                ConfiguredShadowCanaryReportStatusChirho::ProofAvailableChirho,
                Some(_)
            ) | (
                ConfiguredShadowCanaryReportStatusChirho::StoreAbsentChirho,
                None
            )
        )
    {
        return Err(ConfiguredShadowCanaryReportRefusalChirho::ShapeRefusedChirho);
    }
    Ok(())
}

fn verify_config_root_binding_chirho(
    selected_root_chirho: &Path,
    runtime_config_chirho: &ConfigChirho,
) -> Result<(), ConfiguredShadowCanaryReportBuildRefusalChirho> {
    let configured_root_chirho = PathBuf::from(&runtime_config_chirho.root_chirho);
    let effective_root_chirho = match runtime_config_chirho
        .tenant_chirho
        .as_deref()
        .filter(|tenant_chirho| !tenant_chirho.trim().is_empty())
    {
        Some(tenant_chirho) => {
            tenant_root_chirho(&configured_root_chirho, tenant_chirho).map_err(|_| {
                ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
            })?
        }
        None => configured_root_chirho,
    };
    let selected_chirho = selected_root_chirho.canonicalize().map_err(|_| {
        ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
    })?;
    let configured_chirho = effective_root_chirho.canonicalize().map_err(|_| {
        ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
    })?;
    if selected_chirho != configured_chirho {
        return Err(ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho);
    }
    Ok(())
}

fn writer_group_digest_has_shape_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix("writer-fence-group-blake3-chirho:")
        .is_some_and(|digest_chirho| is_lower_hex_chirho(digest_chirho, 64))
}

fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
