// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The injected CF4 published-projection read seam.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
//! Composition verifies the ledger/read-model evidence; this module derives the request from the
//! admitted Query capability plus verified request context and maps the verdict verbatim into the
//! schema-first app transport. It never opens a ledger, consults ambient configuration, or records
//! an effect. Fresh/Degraded views are allowed only under the verified standing-write-rate class.

use super::{
    query_prefix_within_scope_chirho, LegacyMoneyRoadChirho, LegacyMoneyRoadRefusedChirho,
    ScopedQueryRequestChirho,
};
use crate::model_chirho::{CapabilityChirho, RequestContextChirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_ledger_composition_chirho::{
    ComposedProjectionReadChirho, FollowerReadRefusalChirho, FollowerServeOutcomeChirho,
    ProjectionCostClassChirho, ProjectionReadOutcomeChirho, PublishedProjectionViewChirho,
    ServeGateRefusalChirho,
};
use cairn_ledger_model_chirho::projection_json_chirho::parse_canonical_projection_json_value_chirho;
use serde::{Deserialize, Serialize};

pub const PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO: &str =
    "published-projection-read-response-v2-chirho";

/// Root-derived request presented to the injected composition port. The legacy capability's
/// `caller_chirho` string is deliberately absent: strings grant no authority.
pub struct PublishedProjectionReadRequestChirho<'request_chirho> {
    pub projection_name_chirho: &'request_chirho str,
    pub requested_limit_chirho: u64,
    pub request_context_chirho: &'request_chirho RequestContextChirho,
}

/// Injection-only read authority. A host implementation owns all storage paths, registry roots,
/// feeder roots, and verified source opens; app cards and manifests can never construct this port.
pub trait PublishedProjectionReadPortChirho: Send + Sync {
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho>;
}

impl PublishedProjectionReadPortChirho
    for cairn_replication_http_chirho::projection_replication_chirho::ReplicaMountedProjectionReadPortChirho
{
    fn read_published_projection_chirho(
        &self,
        request_chirho: &PublishedProjectionReadRequestChirho<'_>,
    ) -> Result<ComposedProjectionReadChirho> {
        let replica_read_chirho = self.read_published_projection_chirho(
            request_chirho.projection_name_chirho,
            request_chirho.requested_limit_chirho,
        )?;
        Ok(ComposedProjectionReadChirho {
            view_bytes_chirho: Some(replica_read_chirho.view_bytes_chirho),
            verified_cost_class_chirho: Some(ProjectionCostClassChirho::StandingWriteRateChirho),
            outcome_chirho: FollowerServeOutcomeChirho::ReadChirho(
                ProjectionReadOutcomeChirho::DegradedChirho {
                    view_chirho: replica_read_chirho.view_chirho,
                    lag_ms_chirho: replica_read_chirho.lag_ms_chirho,
                    max_lag_ms_chirho: replica_read_chirho.max_lag_ms_chirho,
                },
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishedProjectionCostClassChirho {
    #[serde(rename = "standing-write-rate-chirho")]
    StandingWriteRateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionHlcChirho {
    pub physical_ms_chirho: u64,
    pub logical_chirho: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionEvidenceChirho {
    pub descriptor_ref_chirho: String,
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: PublishedProjectionHlcChirho,
    pub signed_prefix_digest_chirho: String,
    pub state_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason_chirho", deny_unknown_fields)]
pub enum PublishedProjectionClassifierRefusalChirho {
    #[serde(rename = "source-family-mismatch-chirho")]
    SourceFamilyMismatchChirho,
    #[serde(rename = "invalid-digest-evidence-chirho")]
    InvalidDigestEvidenceChirho,
    #[serde(rename = "descriptor-identity-mismatch-chirho")]
    DescriptorIdentityMismatchChirho,
    #[serde(rename = "view-watermark-evidence-mismatch-chirho")]
    ViewWatermarkEvidenceMismatchChirho,
    #[serde(rename = "watermark-beyond-verified-prefix-chirho")]
    WatermarkBeyondVerifiedPrefixChirho,
    #[serde(rename = "watermark-hlc-beyond-verified-head-chirho")]
    WatermarkHlcBeyondVerifiedHeadChirho,
    #[serde(rename = "equal-seq-head-mismatch-chirho")]
    EqualSeqHeadMismatchChirho,
    #[serde(rename = "effect-cut-behind-chirho")]
    EffectCutBehindChirho,
    #[serde(rename = "stale-beyond-contract-chirho")]
    StaleBeyondContractChirho {
        lag_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason_chirho", deny_unknown_fields)]
pub enum PublishedProjectionGateRefusalChirho {
    #[serde(rename = "receipt-signature-chirho")]
    ReceiptSignatureChirho,
    #[serde(rename = "projection-superseded-chirho")]
    ProjectionSupersededChirho,
    #[serde(rename = "projection-retired-chirho")]
    ProjectionRetiredChirho,
    #[serde(rename = "projection-unknown-chirho")]
    ProjectionUnknownChirho,
    #[serde(rename = "view-bytes-digest-mismatch-chirho")]
    ViewBytesDigestMismatchChirho,
    #[serde(rename = "descriptor-evidence-chirho")]
    DescriptorEvidenceChirho { detail_chirho: String },
    #[serde(rename = "source-instance-mismatch-chirho")]
    SourceInstanceMismatchChirho,
    #[serde(rename = "safe-frontier-mismatch-chirho")]
    SafeFrontierMismatchChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict_chirho", deny_unknown_fields)]
pub enum PublishedProjectionVerdictChirho {
    #[serde(rename = "fresh-chirho")]
    FreshChirho {
        evidence_chirho: PublishedProjectionEvidenceChirho,
        lag_ms_chirho: u64,
    },
    #[serde(rename = "degraded-chirho")]
    DegradedChirho {
        evidence_chirho: PublishedProjectionEvidenceChirho,
        lag_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    },
    #[serde(rename = "classifier-refused-chirho")]
    ClassifierRefusedChirho {
        refusal_chirho: PublishedProjectionClassifierRefusalChirho,
    },
    #[serde(rename = "gate-refused-chirho")]
    GateRefusedChirho {
        refusal_chirho: PublishedProjectionGateRefusalChirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionReadResponseChirho {
    pub schema_chirho: String,
    pub viewer_principal_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_class_chirho: Option<PublishedProjectionCostClassChirho>,
    pub outcome_chirho: PublishedProjectionVerdictChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_chirho: Option<serde_json::Value>,
}

pub(crate) fn run_published_projection_read_chirho(
    port_chirho: Option<&dyn PublishedProjectionReadPortChirho>,
    capability_chirho: &CapabilityChirho,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Vec<u8>> {
    let port_chirho = port_chirho.ok_or_else(query_composition_refused_chirho)?;
    // A missing request context is a DISTINCT TYPED refusal (#6082-E/#6084/#6087): an anonymous
    // read must be distinguishable BY TYPE from a missing composition port, so operator evidence
    // pins the exact viewer-scope negative and drift breaks a compiler-checked branch, not prose.
    let request_context_chirho = request_context_chirho.ok_or_else(|| {
        anyhow::Error::new(PublishedProjectionReadRefusalChirho::MissingViewerContextChirho)
    })?;
    let CapabilityChirho::QueryChirho {
        prefix_chirho: capability_prefix_chirho,
        max_rows_chirho,
        ..
    } = capability_chirho
    else {
        bail!("published projection port requires admitted QueryChirho capability");
    };
    let request_chirho: ScopedQueryRequestChirho =
        serde_json::from_slice(request_bytes_chirho).context("decode projection-read request")?;
    if !query_prefix_within_scope_chirho(capability_prefix_chirho, &request_chirho.prefix_chirho) {
        bail!(
            "projection '{}' is outside admitted QueryChirho prefix '{}'",
            request_chirho.prefix_chirho,
            capability_prefix_chirho
        );
    }
    let requested_limit_chirho = request_chirho.limit_chirho.unwrap_or(*max_rows_chirho);
    if requested_limit_chirho == 0 || requested_limit_chirho > *max_rows_chirho {
        bail!(
            "projection-read limit {} is outside admitted range 1..={}",
            requested_limit_chirho,
            max_rows_chirho
        );
    }
    let read_chirho =
        port_chirho.read_published_projection_chirho(&PublishedProjectionReadRequestChirho {
            projection_name_chirho: &request_chirho.prefix_chirho,
            requested_limit_chirho,
            request_context_chirho,
        })?;
    let response_chirho = response_from_composed_read_chirho(
        read_chirho,
        &request_context_chirho.user_principal_chirho,
    )?;
    serde_json::to_vec(&response_chirho).context("encode projection-read response")
}

/// Typed projection-read refusals surfaced to operators. `Display` emits the BOUNDED label the
/// served 400 body carries; the smoke pins that label while unit pins downcast the type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublishedProjectionReadRefusalChirho {
    MissingViewerContextChirho,
}

impl std::fmt::Display for PublishedProjectionReadRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingViewerContextChirho => formatter_chirho.write_str(
                "published-projection read refused: missing-viewer-context-refusal-chirho \
                 (an authenticated viewer is required)",
            ),
        }
    }
}

impl std::error::Error for PublishedProjectionReadRefusalChirho {}

fn query_composition_refused_chirho() -> anyhow::Error {
    anyhow::Error::new(LegacyMoneyRoadRefusedChirho::new_chirho(
        LegacyMoneyRoadChirho::QueryEffectChirho,
        "query_chirho",
    ))
}

fn response_from_composed_read_chirho(
    read_chirho: ComposedProjectionReadChirho,
    viewer_principal_chirho: &str,
) -> Result<PublishedProjectionReadResponseChirho> {
    let ComposedProjectionReadChirho {
        view_bytes_chirho,
        verified_cost_class_chirho,
        outcome_chirho,
    } = read_chirho;
    let (cost_class_chirho, outcome_chirho, view_chirho) = match outcome_chirho {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            view_chirho: evidence_chirho,
            lag_ms_chirho,
            ..
        }) => (
            Some(standing_cost_class_chirho(verified_cost_class_chirho)?),
            PublishedProjectionVerdictChirho::FreshChirho {
                evidence_chirho: projection_evidence_chirho(&evidence_chirho),
                lag_ms_chirho,
            },
            Some(exact_canonical_json_view_chirho(view_bytes_chirho)?),
        ),
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::DegradedChirho {
            view_chirho: evidence_chirho,
            lag_ms_chirho,
            max_lag_ms_chirho,
        }) => (
            Some(standing_cost_class_chirho(verified_cost_class_chirho)?),
            PublishedProjectionVerdictChirho::DegradedChirho {
                evidence_chirho: projection_evidence_chirho(&evidence_chirho),
                lag_ms_chirho,
                max_lag_ms_chirho,
            },
            Some(exact_canonical_json_view_chirho(view_bytes_chirho)?),
        ),
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            refusal_chirho,
        )) => {
            if view_bytes_chirho.is_some() {
                bail!("classifier-refused projection carried forbidden view bytes");
            }
            (
                Some(standing_cost_class_chirho(verified_cost_class_chirho)?),
                PublishedProjectionVerdictChirho::ClassifierRefusedChirho {
                    refusal_chirho: classifier_refusal_chirho(refusal_chirho),
                },
                None,
            )
        }
        FollowerServeOutcomeChirho::GateRefusedChirho(refusal_chirho) => {
            if view_bytes_chirho.is_some() || verified_cost_class_chirho.is_some() {
                bail!("gate-refused projection carried unverified view or cost authority");
            }
            (
                None,
                PublishedProjectionVerdictChirho::GateRefusedChirho {
                    refusal_chirho: gate_refusal_chirho(refusal_chirho),
                },
                None,
            )
        }
    };
    Ok(PublishedProjectionReadResponseChirho {
        schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
        viewer_principal_chirho: viewer_principal_chirho.to_string(),
        cost_class_chirho,
        outcome_chirho,
        view_chirho,
    })
}

fn standing_cost_class_chirho(
    cost_class_chirho: Option<ProjectionCostClassChirho>,
) -> Result<PublishedProjectionCostClassChirho> {
    match cost_class_chirho {
        Some(ProjectionCostClassChirho::StandingWriteRateChirho) => {
            Ok(PublishedProjectionCostClassChirho::StandingWriteRateChirho)
        }
        None => bail!("classified projection omitted its verified cost class"),
    }
}

fn exact_canonical_json_view_chirho(
    view_bytes_chirho: Option<Vec<u8>>,
) -> Result<serde_json::Value> {
    let view_bytes_chirho = view_bytes_chirho
        .ok_or_else(|| anyhow!("servable projection omitted its receipt-bound view bytes"))?;
    parse_canonical_projection_json_value_chirho(&view_bytes_chirho).map_err(anyhow::Error::new)
}

fn projection_evidence_chirho(
    view_chirho: &PublishedProjectionViewChirho,
) -> PublishedProjectionEvidenceChirho {
    PublishedProjectionEvidenceChirho {
        descriptor_ref_chirho: view_chirho.descriptor_ref_chirho.0.clone(),
        source_family_id_chirho: view_chirho.watermark_chirho.source_family_id_chirho.clone(),
        source_seq_chirho: view_chirho.watermark_chirho.source_seq_chirho,
        source_hlc_chirho: PublishedProjectionHlcChirho {
            physical_ms_chirho: view_chirho
                .watermark_chirho
                .source_hlc_chirho
                .physical_ms_chirho,
            logical_chirho: view_chirho
                .watermark_chirho
                .source_hlc_chirho
                .logical_chirho,
        },
        signed_prefix_digest_chirho: view_chirho
            .watermark_chirho
            .signed_prefix_digest_chirho
            .0
            .clone(),
        state_digest_chirho: view_chirho.state_digest_chirho.0.clone(),
    }
}

fn classifier_refusal_chirho(
    refusal_chirho: FollowerReadRefusalChirho,
) -> PublishedProjectionClassifierRefusalChirho {
    match refusal_chirho {
        FollowerReadRefusalChirho::SourceFamilyMismatchChirho => {
            PublishedProjectionClassifierRefusalChirho::SourceFamilyMismatchChirho
        }
        FollowerReadRefusalChirho::InvalidDigestEvidenceChirho => {
            PublishedProjectionClassifierRefusalChirho::InvalidDigestEvidenceChirho
        }
        FollowerReadRefusalChirho::DescriptorIdentityMismatchChirho => {
            PublishedProjectionClassifierRefusalChirho::DescriptorIdentityMismatchChirho
        }
        FollowerReadRefusalChirho::ViewWatermarkEvidenceMismatchChirho => {
            PublishedProjectionClassifierRefusalChirho::ViewWatermarkEvidenceMismatchChirho
        }
        FollowerReadRefusalChirho::WatermarkBeyondVerifiedPrefixChirho => {
            PublishedProjectionClassifierRefusalChirho::WatermarkBeyondVerifiedPrefixChirho
        }
        FollowerReadRefusalChirho::WatermarkHlcBeyondVerifiedHeadChirho => {
            PublishedProjectionClassifierRefusalChirho::WatermarkHlcBeyondVerifiedHeadChirho
        }
        FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho => {
            PublishedProjectionClassifierRefusalChirho::EqualSeqHeadMismatchChirho
        }
        FollowerReadRefusalChirho::EffectCutBehindChirho => {
            PublishedProjectionClassifierRefusalChirho::EffectCutBehindChirho
        }
        FollowerReadRefusalChirho::StaleBeyondContractChirho {
            lag_ms_chirho,
            max_lag_ms_chirho,
        } => PublishedProjectionClassifierRefusalChirho::StaleBeyondContractChirho {
            lag_ms_chirho,
            max_lag_ms_chirho,
        },
    }
}

fn gate_refusal_chirho(
    refusal_chirho: ServeGateRefusalChirho,
) -> PublishedProjectionGateRefusalChirho {
    match refusal_chirho {
        ServeGateRefusalChirho::ReceiptSignatureChirho => {
            PublishedProjectionGateRefusalChirho::ReceiptSignatureChirho
        }
        ServeGateRefusalChirho::ProjectionSupersededChirho => {
            PublishedProjectionGateRefusalChirho::ProjectionSupersededChirho
        }
        ServeGateRefusalChirho::ProjectionRetiredChirho => {
            PublishedProjectionGateRefusalChirho::ProjectionRetiredChirho
        }
        ServeGateRefusalChirho::ProjectionUnknownChirho => {
            PublishedProjectionGateRefusalChirho::ProjectionUnknownChirho
        }
        ServeGateRefusalChirho::ViewBytesDigestMismatchChirho => {
            PublishedProjectionGateRefusalChirho::ViewBytesDigestMismatchChirho
        }
        ServeGateRefusalChirho::DescriptorEvidenceChirho { reason_chirho } => {
            PublishedProjectionGateRefusalChirho::DescriptorEvidenceChirho {
                detail_chirho: reason_chirho,
            }
        }
        ServeGateRefusalChirho::SourceInstanceMismatchChirho => {
            PublishedProjectionGateRefusalChirho::SourceInstanceMismatchChirho
        }
        ServeGateRefusalChirho::SafeFrontierMismatchChirho => {
            PublishedProjectionGateRefusalChirho::SafeFrontierMismatchChirho
        }
    }
}

#[cfg(test)]
#[path = "projection_read_chirho/projection_read_tests_chirho.rs"]
mod projection_read_tests_chirho;
