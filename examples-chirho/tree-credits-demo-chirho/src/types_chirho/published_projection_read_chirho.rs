// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Guest-side exact parser for the H2 published-projection response. The transport's verdict and
//! verified cost class are consumed verbatim; app code never recomputes lag or cost authority.
//!
//! Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.

use serde::{Deserialize, Serialize};

pub const PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO: &str =
    "published-projection-read-response-v2-chirho";
pub const ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO: &str =
    "ledger-account-net-projection-view-v1-chirho";
pub const BALANCE_PROJECTION_NAME_CHIRHO: &str = "credits-balance-chirho";
pub const BALANCE_KIND_ID_CHIRHO: &str = "prepaid-credits-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedProjectionQueryV1Chirho {
    pub prefix_chirho: String,
    pub limit_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishedProjectionCostClassV2Chirho {
    #[serde(rename = "standing-write-rate-chirho")]
    StandingWriteRateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionHlcV2Chirho {
    pub physical_ms_chirho: u64,
    pub logical_chirho: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionEvidenceV2Chirho {
    pub descriptor_ref_chirho: String,
    pub source_family_id_chirho: String,
    pub source_seq_chirho: u64,
    pub source_hlc_chirho: PublishedProjectionHlcV2Chirho,
    pub signed_prefix_digest_chirho: String,
    pub state_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason_chirho", deny_unknown_fields)]
pub enum PublishedProjectionClassifierRefusalV2Chirho {
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

impl PublishedProjectionClassifierRefusalV2Chirho {
    pub fn label_chirho(&self) -> &'static str {
        match self {
            Self::SourceFamilyMismatchChirho => "source-family-mismatch-chirho",
            Self::InvalidDigestEvidenceChirho => "invalid-digest-evidence-chirho",
            Self::DescriptorIdentityMismatchChirho => "descriptor-identity-mismatch-chirho",
            Self::ViewWatermarkEvidenceMismatchChirho => "view-watermark-evidence-mismatch-chirho",
            Self::WatermarkBeyondVerifiedPrefixChirho => "watermark-beyond-verified-prefix-chirho",
            Self::WatermarkHlcBeyondVerifiedHeadChirho => {
                "watermark-hlc-beyond-verified-head-chirho"
            }
            Self::EqualSeqHeadMismatchChirho => "equal-seq-head-mismatch-chirho",
            Self::EffectCutBehindChirho => "effect-cut-behind-chirho",
            Self::StaleBeyondContractChirho { .. } => "stale-beyond-contract-chirho",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason_chirho", deny_unknown_fields)]
pub enum PublishedProjectionGateRefusalV2Chirho {
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

impl PublishedProjectionGateRefusalV2Chirho {
    pub fn label_chirho(&self) -> &'static str {
        match self {
            Self::ReceiptSignatureChirho => "receipt-signature-chirho",
            Self::ProjectionSupersededChirho => "projection-superseded-chirho",
            Self::ProjectionRetiredChirho => "projection-retired-chirho",
            Self::ProjectionUnknownChirho => "projection-unknown-chirho",
            Self::ViewBytesDigestMismatchChirho => "view-bytes-digest-mismatch-chirho",
            Self::DescriptorEvidenceChirho { .. } => "descriptor-evidence-chirho",
            Self::SourceInstanceMismatchChirho => "source-instance-mismatch-chirho",
            Self::SafeFrontierMismatchChirho => "safe-frontier-mismatch-chirho",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict_chirho", deny_unknown_fields)]
pub enum PublishedProjectionVerdictV2Chirho {
    #[serde(rename = "fresh-chirho")]
    FreshChirho {
        evidence_chirho: PublishedProjectionEvidenceV2Chirho,
        lag_ms_chirho: u64,
    },
    #[serde(rename = "degraded-chirho")]
    DegradedChirho {
        evidence_chirho: PublishedProjectionEvidenceV2Chirho,
        lag_ms_chirho: u64,
        max_lag_ms_chirho: u64,
    },
    #[serde(rename = "classifier-refused-chirho")]
    ClassifierRefusedChirho {
        refusal_chirho: PublishedProjectionClassifierRefusalV2Chirho,
    },
    #[serde(rename = "gate-refused-chirho")]
    GateRefusedChirho {
        refusal_chirho: PublishedProjectionGateRefusalV2Chirho,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountIdV1Chirho {
    pub owner_chirho: String,
    pub kind_id_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountNetProjectionRowV1Chirho {
    pub account_chirho: AccountIdV1Chirho,
    pub account_net_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountNetProjectionViewV1Chirho {
    pub schema_chirho: String,
    pub rows_chirho: Vec<AccountNetProjectionRowV1Chirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedProjectionReadResponseV2Chirho {
    pub schema_chirho: String,
    pub viewer_principal_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_class_chirho: Option<PublishedProjectionCostClassV2Chirho>,
    pub outcome_chirho: PublishedProjectionVerdictV2Chirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_chirho: Option<serde_json::Value>,
}

impl PublishedProjectionReadResponseV2Chirho {
    pub fn account_net_view_chirho(
        &self,
    ) -> Result<Option<AccountNetProjectionViewV1Chirho>, PublishedProjectionReadWireErrorChirho>
    {
        self.view_chirho
            .as_ref()
            .map(|view_chirho| {
                serde_json::from_value::<AccountNetProjectionViewV1Chirho>(view_chirho.clone())
                    .map_err(|_error_chirho| {
                        PublishedProjectionReadWireErrorChirho::InvalidEnvelopeChirho
                    })
            })
            .transpose()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishedProjectionReadWireErrorChirho {
    MalformedChirho,
    NonCanonicalChirho,
    UnsupportedSchemaChirho,
    InvalidEnvelopeChirho,
}

pub fn parse_exact_published_projection_read_chirho(
    bytes_chirho: &[u8],
) -> Result<PublishedProjectionReadResponseV2Chirho, PublishedProjectionReadWireErrorChirho> {
    let response_chirho: PublishedProjectionReadResponseV2Chirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_error_chirho| PublishedProjectionReadWireErrorChirho::MalformedChirho)?;
    let canonical_chirho = serde_json::to_vec(&response_chirho)
        .map_err(|_error_chirho| PublishedProjectionReadWireErrorChirho::MalformedChirho)?;
    if canonical_chirho != bytes_chirho {
        return Err(PublishedProjectionReadWireErrorChirho::NonCanonicalChirho);
    }
    if response_chirho.schema_chirho != PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO {
        return Err(PublishedProjectionReadWireErrorChirho::UnsupportedSchemaChirho);
    }
    if !bounded_demo_user_principal_chirho(&response_chirho.viewer_principal_chirho) {
        return Err(PublishedProjectionReadWireErrorChirho::InvalidEnvelopeChirho);
    }
    let envelope_valid_chirho = match &response_chirho.outcome_chirho {
        PublishedProjectionVerdictV2Chirho::FreshChirho { .. }
        | PublishedProjectionVerdictV2Chirho::DegradedChirho { .. } => {
            response_chirho.cost_class_chirho
                == Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho)
                && response_chirho
                    .account_net_view_chirho()?
                    .is_some_and(|view_chirho| {
                        view_chirho.schema_chirho == ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO
                    })
        }
        PublishedProjectionVerdictV2Chirho::ClassifierRefusedChirho { .. } => {
            response_chirho.cost_class_chirho
                == Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho)
                && response_chirho.view_chirho.is_none()
        }
        PublishedProjectionVerdictV2Chirho::GateRefusedChirho { .. } => {
            response_chirho.cost_class_chirho.is_none() && response_chirho.view_chirho.is_none()
        }
    };
    if !envelope_valid_chirho {
        return Err(PublishedProjectionReadWireErrorChirho::InvalidEnvelopeChirho);
    }
    Ok(response_chirho)
}

/// This dependency-light user-only mirror stays aligned with `identity_chirho::next_principal_chirho`
/// and cairn-config's single-coded H3 account-owner grammar.
fn bounded_demo_user_principal_chirho(principal_chirho: &str) -> bool {
    principal_chirho
        .strip_prefix("user/")
        .is_some_and(|id_chirho| {
            id_chirho.len() == 16
                && id_chirho.bytes().all(|byte_chirho| {
                    byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')
                })
        })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn checked_in_fresh_transport_is_exact_canonical_chirho() {
        let bytes_chirho = include_bytes!(
            "../../fixtures_chirho/node-inputs-chirho/render_balance_fresh_response_chirho.json"
        );
        let decoded_chirho: PublishedProjectionReadResponseV2Chirho =
            serde_json::from_slice(bytes_chirho).unwrap();
        let canonical_chirho = serde_json::to_vec(&decoded_chirho).unwrap();
        assert_eq!(
            bytes_chirho.as_slice(),
            canonical_chirho.as_slice(),
            "canonical transport: {}",
            String::from_utf8_lossy(&canonical_chirho)
        );
        let response_chirho = parse_exact_published_projection_read_chirho(bytes_chirho).unwrap();
        assert_eq!(
            response_chirho.viewer_principal_chirho,
            "user/0123456789abcdef"
        );
        assert!(matches!(
            response_chirho.outcome_chirho,
            PublishedProjectionVerdictV2Chirho::FreshChirho { .. }
        ));
    }

    #[test]
    fn classifier_refusal_cannot_smuggle_view_bytes_chirho() {
        let response_chirho = PublishedProjectionReadResponseV2Chirho {
            schema_chirho: PUBLISHED_PROJECTION_READ_RESPONSE_SCHEMA_V2_CHIRHO.to_string(),
            viewer_principal_chirho: "user/0123456789abcdef".to_string(),
            cost_class_chirho: Some(PublishedProjectionCostClassV2Chirho::StandingWriteRateChirho),
            outcome_chirho: PublishedProjectionVerdictV2Chirho::ClassifierRefusedChirho {
                refusal_chirho:
                    PublishedProjectionClassifierRefusalV2Chirho::SourceFamilyMismatchChirho,
            },
            view_chirho: Some(serde_json::json!({
                "schema_chirho": ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
                "rows_chirho": [],
            })),
        };
        let bytes_chirho = serde_json::to_vec(&response_chirho).unwrap();
        assert_eq!(
            parse_exact_published_projection_read_chirho(&bytes_chirho),
            Err(PublishedProjectionReadWireErrorChirho::InvalidEnvelopeChirho)
        );
    }

    #[test]
    fn email_shaped_viewer_principal_refuses_before_render_chirho() {
        let bytes_chirho = include_bytes!(
            "../../fixtures_chirho/node-inputs-chirho/render_balance_fresh_response_chirho.json"
        );
        let mut response_chirho: PublishedProjectionReadResponseV2Chirho =
            serde_json::from_slice(bytes_chirho).unwrap();
        response_chirho.viewer_principal_chirho = "viewer@example.com".to_string();
        let hostile_bytes_chirho = serde_json::to_vec(&response_chirho).unwrap();

        assert_eq!(
            parse_exact_published_projection_read_chirho(&hostile_bytes_chirho),
            Err(PublishedProjectionReadWireErrorChirho::InvalidEnvelopeChirho)
        );
    }
}
